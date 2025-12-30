use radius_server::{Config, RadiusServer, ServerConfig, SimpleAuthHandler};
use std::env;
use std::process;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse command line arguments
    let config_path = if args.len() > 1 {
        &args[1]
    } else {
        "config.json"
    };

    println!("USG RADIUS Server v{}", env!("CARGO_PKG_VERSION"));
    println!("Based on RFC 2865 (RADIUS)");
    println!();

    // Load or create configuration
    let config = match Config::from_file(config_path) {
        Ok(cfg) => {
            println!("Loaded configuration from: {}", config_path);
            cfg
        }
        Err(e) => {
            eprintln!("Warning: Could not load config file: {}", e);
            eprintln!("Creating example configuration at: {}", config_path);

            let example_config = Config::example();
            if let Err(e) = example_config.to_file(config_path) {
                eprintln!("Error creating example config: {}", e);
                process::exit(1);
            }

            println!("Please edit {} and restart the server", config_path);
            process::exit(0);
        }
    };

    // Create authentication handler
    let mut auth_handler = SimpleAuthHandler::new();
    for user in &config.users {
        auth_handler.add_user(&user.username, &user.password);
        println!("Added user: {}", user.username);
    }

    // Display client configuration
    if config.clients.is_empty() {
        println!();
        println!("⚠️  WARNING: No authorized clients configured!");
        println!("   Server will accept requests from ANY IP address.");
        println!("   Add clients to config.json for production use.");
    } else {
        println!();
        println!("Authorized clients:");
        for client in &config.clients {
            let status = if client.enabled { "✓" } else { "✗" };
            let name = client.name.as_deref().unwrap_or("(unnamed)");
            println!("  {} {} - {}", status, client.address, name);
        }
    }

    // Create server configuration with client validation
    let server_config = match ServerConfig::from_config(config, Arc::new(auth_handler)) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Invalid configuration: {}", e);
            process::exit(1);
        }
    };

    // Create and run server
    let server = match RadiusServer::new(server_config).await {
        Ok(srv) => srv,
        Err(e) => {
            eprintln!("Failed to create server: {}", e);
            process::exit(1);
        }
    };

    println!();
    println!("Server started successfully!");
    println!("Press Ctrl+C to stop");
    println!();

    // Run server
    if let Err(e) = server.run().await {
        eprintln!("Server error: {}", e);
        process::exit(1);
    }
}
