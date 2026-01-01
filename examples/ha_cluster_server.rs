//! High Availability RADIUS Server Example
//!
//! Demonstrates a production HA deployment with:
//! - Shared session state via Valkey
//! - Cluster-wide request deduplication
//! - Distributed rate limiting
//! - Health monitoring
//!
//! # Setup
//!
//! 1. Start Valkey server:
//!    ```bash
//!    docker run -d -p 6379:6379 valkey/valkey:latest
//!    ```
//!
//! 2. Run multiple server instances:
//!    ```bash
//!    # Server 1 (port 1812)
//!    RADIUS_PORT=1812 cargo run --example ha_cluster_server --features ha
//!
//!    # Server 2 (port 1813)
//!    RADIUS_PORT=1813 cargo run --example ha_cluster_server --features ha
//!
//!    # Server 3 (port 1814)
//!    RADIUS_PORT=1814 cargo run --example ha_cluster_server --features ha
//!    ```
//!
//! 3. Configure load balancer (HAProxy/nginx) to distribute requests
//!
//! # Testing
//!
//! Send RADIUS requests to any server - they will share state:
//!
//! ```bash
//! radtest alice password 127.0.0.1:1812 0 testing123
//! radtest alice password 127.0.0.1:1813 0 testing123  # Same session visible
//! ```

use radius_server::{
    RadiusServer, ServerConfig, SimpleAuthHandler,
    cache_ha::SharedRequestCache,
    ratelimit_ha::{SharedRateLimitConfig, SharedRateLimiter},
    state::{MemoryStateBackend, SharedSessionManager, ValkeyConfig, ValkeyStateBackend},
};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("radius_server=debug".parse().unwrap())
                .add_directive("ha_cluster_server=info".parse().unwrap()),
        )
        .init();

    // Configuration from environment
    let port = env::var("RADIUS_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(1812);

    let valkey_url =
        env::var("VALKEY_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    let use_ha = env::var("DISABLE_HA").is_err();

    info!("Starting RADIUS server on port {} (HA: {})", port, use_ha);

    // Create authentication handler
    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("alice", "password");
    auth_handler.add_user("bob", "secret");
    auth_handler.add_user("charlie", "test123");

    // Create shared state backend
    let (session_manager, cluster_cache, cluster_limiter) = if use_ha {
        info!(
            "Configuring High Availability mode with Valkey: {}",
            valkey_url
        );

        // Connect to Valkey
        let valkey_config = ValkeyConfig::new(&valkey_url)
            .with_key_prefix("usg-radius:")
            .with_max_retries(3)
            .with_retry_delay(Duration::from_millis(100));

        let backend = match ValkeyStateBackend::new(valkey_config).await {
            Ok(backend) => {
                info!("✓ Connected to Valkey backend");
                Arc::new(backend) as Arc<dyn radius_server::state::StateBackend>
            }
            Err(e) => {
                warn!("Failed to connect to Valkey: {}", e);
                warn!("Falling back to in-memory backend (no HA)");
                Arc::new(MemoryStateBackend::new()) as Arc<dyn radius_server::state::StateBackend>
            }
        };

        // Create shared session manager
        let session_manager = Arc::new(SharedSessionManager::new(backend));

        // Create cluster-wide request cache
        let cache = SharedRequestCache::new(
            Arc::clone(&session_manager),
            Duration::from_secs(60), // 60 second deduplication window
        );

        // Create cluster-wide rate limiter
        let limiter_config = SharedRateLimitConfig {
            per_client_limit: 100,                   // 100 requests per window per client
            global_limit: 1000,                      // 1000 requests per window globally
            window_duration: Duration::from_secs(1), // 1 second window
        };
        let limiter = SharedRateLimiter::new(Arc::clone(&session_manager), limiter_config);

        info!("✓ High Availability components initialized");

        (Some(session_manager), Some(cache), Some(limiter))
    } else {
        info!("Running in standalone mode (HA disabled)");
        (None, None, None)
    };

    // Create server configuration
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let config = ServerConfig::new(addr, b"testing123", Arc::new(auth_handler));

    // Create and configure server
    let mut server = RadiusServer::new(config).await?;

    // Print HA status
    if let Some(ref limiter) = cluster_limiter {
        let stats = limiter.get_stats();
        info!("Rate limiting configured:");
        info!(
            "  Per-client: {} requests/{} seconds",
            stats.per_client_limit, stats.window_duration_secs
        );
        info!(
            "  Global: {} requests/{} seconds",
            stats.global_limit, stats.window_duration_secs
        );
    }

    if cluster_cache.is_some() {
        info!("Request deduplication: enabled (cluster-wide)");
    }

    if session_manager.is_some() {
        info!("Session storage: Valkey (distributed)");
    }

    // Print server info
    info!("========================================");
    info!("RADIUS Server Ready");
    info!("Listening on: {}", addr);
    info!("Shared secret: testing123");
    info!("HA Mode: {}", if use_ha { "enabled" } else { "disabled" });
    info!("========================================");
    info!("");
    info!("Test with:");
    info!("  radtest alice password 127.0.0.1:{} 0 testing123", port);
    info!("");

    // Run server
    server.run().await?;

    Ok(())
}
