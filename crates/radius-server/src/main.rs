use radius_server::{Config, RadiusServer, ServerConfig, SimpleAuthHandler};
use std::env;
use std::process;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse command line arguments
    let config_path = if args.len() > 1 {
        &args[1]
    } else {
        "config.json"
    };

    // Load or create configuration (without logging first)
    let config = match Config::from_file(config_path) {
        Ok(cfg) => cfg,
        Err(_) => {
            // Initialize basic logging to show config creation messages
            tracing_subscriber::registry()
                .with(EnvFilter::new("info"))
                .with(tracing_subscriber::fmt::layer())
                .init();

            warn!("Could not load config file from: {}", config_path);
            info!("Creating example configuration at: {}", config_path);

            let example_config = Config::example();
            if let Err(e) = example_config.to_file(config_path) {
                error!("Error creating example config: {}", e);
                process::exit(1);
            }

            info!("Please edit {} and restart the server", config_path);
            process::exit(0);
        }
    };

    // Initialize tracing with configured log level
    let log_level = if let Some(ref level) = config.log_level {
        level.as_str()
    } else if config.verbose {
        "debug" // For backward compatibility with verbose flag
    } else {
        "info"
    };

    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(log_level))
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("USG RADIUS Server v{}", env!("CARGO_PKG_VERSION"));
    info!("Based on RFC 2865 (RADIUS)");
    info!("Loaded configuration from: {}", config_path);
    info!("");

    // Create authentication handler
    let mut auth_handler = SimpleAuthHandler::new();
    for user in &config.users {
        auth_handler.add_user(&user.username, &user.password);
        info!("Added user: {}", user.username);
    }

    // Display client configuration
    if config.clients.is_empty() {
        warn!("");
        warn!("⚠️  WARNING: No authorized clients configured!");
        warn!("   Server will accept requests from ANY IP address.");
        warn!("   Add clients to config.json for production use.");
    } else {
        info!("");
        info!("Authorized clients:");
        for client in &config.clients {
            let status = if client.enabled { "✓" } else { "✗" };
            let name = client.name.as_deref().unwrap_or("(unnamed)");
            info!("  {} {} - {}", status, client.address, name);
        }
    }

    // Create server configuration with client validation
    let server_config = match ServerConfig::from_config(config.clone(), Arc::new(auth_handler)) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Invalid configuration: {}", e);
            process::exit(1);
        }
    };

    // Display audit logging status
    if let Some(ref path) = config.audit_log_path {
        info!("");
        info!("Audit logging enabled: {}", path);
    }

    // Create and run server
    let server = match RadiusServer::new(server_config).await {
        Ok(srv) => srv,
        Err(e) => {
            error!("Failed to create server: {}", e);
            process::exit(1);
        }
    };

    info!("");
    info!("Server started successfully!");
    info!("Press Ctrl+C to stop");
    info!("");

    // Run server
    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        process::exit(1);
    }
}
