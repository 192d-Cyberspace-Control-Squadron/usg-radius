//! RADIUS Proxy Server Example
//!
//! This example demonstrates how to configure a RADIUS proxy server
//! that routes requests to different home servers based on realm.
//!
//! # Setup
//!
//! 1. Configure your proxy settings in `examples/proxy_config.json`
//! 2. Run: `cargo run --example proxy_server`
//! 3. Test with: `radtest user@corp.example.com password localhost 0 testing123`
//!
//! # Features Demonstrated
//!
//! - Realm-based routing
//! - Multiple home server pools
//! - Load balancing strategies
//! - Realm stripping
//! - Retry and timeout handling

use radius_server::{
    AuthHandler, AuthResult, Config, RadiusServer, ServerConfig, SimpleAuthHandler,
};
use std::sync::Arc;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    println!("RADIUS Proxy Server Example");
    println!("===========================\n");

    // Load configuration from file
    let config_path = "examples/proxy_config.json";
    println!("Loading configuration from: {}", config_path);

    let config_data = std::fs::read_to_string(config_path).map_err(|e| {
        format!(
            "Failed to read config file '{}': {}. Please create it using the example below.",
            config_path, e
        )
    })?;

    let config: Config = serde_json::from_str(&config_data)?;

    println!("✓ Configuration loaded");
    println!(
        "  Proxy enabled: {:?}",
        config.proxy.as_ref().map(|p| p.enabled)
    );

    if let Some(ref proxy) = config.proxy {
        if proxy.enabled {
            println!("  Pools configured: {}", proxy.pools.len());
            for pool in &proxy.pools {
                println!(
                    "    - {}: {} servers ({})",
                    pool.name,
                    pool.servers.len(),
                    match pool.strategy {
                        radius_server::proxy::pool::LoadBalanceStrategy::RoundRobin =>
                            "round-robin",
                        radius_server::proxy::pool::LoadBalanceStrategy::LeastOutstanding =>
                            "least-outstanding",
                        radius_server::proxy::pool::LoadBalanceStrategy::Failover => "failover",
                        radius_server::proxy::pool::LoadBalanceStrategy::Random => "random",
                    }
                );
            }
            println!("  Realms configured: {}", proxy.realms.len());
            for realm in &proxy.realms {
                println!("    - {} -> {}", realm.name, realm.pool);
            }
        }
    }

    // Create fallback authentication handler for local realm
    // This handler is only used when proxy routing decision is "Local"
    let mut auth_handler = SimpleAuthHandler::new();
    auth_handler.add_user("local_user", "local_password");
    auth_handler.add_user("admin", "admin_password");

    println!("\nLocal authentication users:");
    println!("  - local_user / local_password");
    println!("  - admin / admin_password");

    // Create server configuration
    let server_config = ServerConfig::from_config(config, Arc::new(auth_handler))?;

    println!("\n✓ Server configuration created");
    println!("  Bind address: {}", server_config.bind_addr);

    // Create and start server
    let server = RadiusServer::new(server_config).await?;
    let actual_addr = server.local_addr()?;

    println!("\n✓ RADIUS Proxy Server started");
    println!("  Listening on: {}", actual_addr);
    println!("\nProxy server ready!");
    println!("==================\n");
    println!("Example test commands:");
    println!("  # Test corporate realm (will be proxied):");
    println!("  radtest user@corp.example.com password localhost 0 testing123");
    println!("\n  # Test guest realm (will be proxied):");
    println!("  radtest GUEST\\\\user password localhost 0 testing123");
    println!("\n  # Test local authentication:");
    println!("  radtest local_user local_password localhost 0 testing123");
    println!("\nPress Ctrl+C to stop the server\n");

    // Example: Get proxy statistics (uncomment to use)
    // if let Some(stats) = server.get_proxy_stats() {
    //     println!("Proxy Statistics:");
    //     println!("  Total Requests: {}", stats.total_requests);
    //     println!("  Total Responses: {}", stats.total_responses);
    //     println!("  Total Outstanding: {}", stats.total_outstanding);
    //     println!("  Pools: {}", stats.pools.len());
    //     for pool in &stats.pools {
    //         println!("    - {}: {} servers ({} available)",
    //             pool.name, pool.total_servers, pool.available_servers);
    //     }
    //     // Export as JSON
    //     // println!("{}", stats.to_json().unwrap());
    // }

    // Run server
    server.run().await?;

    Ok(())
}
