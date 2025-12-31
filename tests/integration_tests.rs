//! Integration tests for USG RADIUS Server
//!
//! These tests verify end-to-end functionality including:
//! - Authentication flows
//! - Client validation
//! - Rate limiting
//! - Configuration validation
//! - Audit logging

use radius_proto::{Attribute, AttributeType, Code, Packet};
use radius_proto::auth::{encrypt_user_password, generate_request_authenticator};
use radius_server::{Config, RadiusServer, ServerConfig, SimpleAuthHandler};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Test helper to create a RADIUS Access-Request packet
fn create_access_request(
    username: &str,
    password: &str,
    secret: &[u8],
    identifier: u8,
) -> Packet {
    let req_auth = generate_request_authenticator();
    let mut packet = Packet::new(Code::AccessRequest, identifier, req_auth);

    // Add User-Name attribute
    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, username)
            .expect("Failed to create User-Name attribute"),
    );

    // Add encrypted User-Password
    let encrypted_pwd = encrypt_user_password(password, secret, &req_auth);
    packet.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd)
            .expect("Failed to create User-Password attribute"),
    );

    packet
}

/// Test helper to send a RADIUS packet and receive response
async fn send_radius_request(
    packet: &Packet,
    server_addr: SocketAddr,
) -> Result<Packet, Box<dyn std::error::Error>> {
    use tokio::net::UdpSocket as AsyncUdpSocket;
    use tokio::time::timeout;

    let socket = AsyncUdpSocket::bind("127.0.0.1:0").await?;

    let bytes = packet.encode()?;
    socket.send_to(&bytes, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;

    let response = Packet::decode(&buf[..len])?;
    Ok(response)
}

#[tokio::test]
async fn test_successful_authentication() {
    // Create test configuration
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0; // Let OS assign port
    config.secret = "testing123".to_string();

    // Create authentication handler
    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    // Create server
    let server_config = ServerConfig::from_config(config.clone(), Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config).await.expect("Failed to create server");

    // Get the actual port assigned
    let server_addr = server.local_addr().expect("Failed to get server address");

    // Start server in background
    tokio::spawn(async move {
        server.run().await.expect("Server failed");
    });

    // Wait for server to start
    sleep(Duration::from_millis(500)).await;

    // Create and send Access-Request
    let packet = create_access_request(
        "testuser",
        "testpass",
        b"testing123",
        1,
    );

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send request");

    // Verify Access-Accept response
    assert_eq!(response.code, Code::AccessAccept);
    assert_eq!(response.identifier, 1);
}

#[tokio::test]
async fn test_failed_authentication_wrong_password() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "correctpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config).await.expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send request with wrong password
    let packet = create_access_request(
        "testuser",
        "wrongpass",
        b"testing123",
        2,
    );

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send request");

    // Verify Access-Reject response
    assert_eq!(response.code, Code::AccessReject);
    assert_eq!(response.identifier, 2);
}

#[tokio::test]
async fn test_failed_authentication_unknown_user() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("realuser", "password");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config).await.expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send request for unknown user
    let packet = create_access_request(
        "unknownuser",
        "password",
        b"testing123",
        3,
    );

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send request");

    // Verify Access-Reject response
    assert_eq!(response.code, Code::AccessReject);
    assert_eq!(response.identifier, 3);
}

#[tokio::test]
async fn test_multiple_sequential_authentications() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("user1", "pass1");
    handler.add_user("user2", "pass2");
    handler.add_user("user3", "pass3");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config).await.expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Test multiple users sequentially
    for (i, (username, password)) in [("user1", "pass1"), ("user2", "pass2"), ("user3", "pass3")].iter().enumerate() {
        let packet = create_access_request(
            username,
            password,
            b"testing123",
            (i + 1) as u8,
        );

        let response = send_radius_request(&packet, server_addr)
            .await
            .expect("Failed to send request");

        assert_eq!(response.code, Code::AccessAccept, "Failed for user {}", username);
        assert_eq!(response.identifier, (i + 1) as u8);
    }
}

#[test]
fn test_env_var_expansion() {
    use std::env;
    use tempfile::NamedTempFile;
    use std::io::Write;

    // Set test environment variable
    env::set_var("TEST_RADIUS_SECRET", "env_secret_value");

    // Create temporary config file with env var
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(temp_file, r#"{{
        "listen_address": "::",
        "listen_port": 1812,
        "secret": "${{TEST_RADIUS_SECRET}}",
        "clients": [],
        "users": []
    }}"#).expect("Failed to write to temp file");

    // Load config
    let config = Config::from_file(temp_file.path())
        .expect("Failed to load config with env var");

    // Verify env var was expanded
    assert_eq!(config.secret, "env_secret_value");

    // Clean up
    env::remove_var("TEST_RADIUS_SECRET");
}

#[test]
fn test_env_var_not_found() {
    use tempfile::NamedTempFile;
    use std::io::Write;

    // Create config with non-existent env var
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(temp_file, r#"{{
        "listen_address": "::",
        "listen_port": 1812,
        "secret": "${{NONEXISTENT_VAR_12345}}",
        "clients": [],
        "users": []
    }}"#).expect("Failed to write to temp file");

    // Should fail to load
    let result = Config::from_file(temp_file.path());
    assert!(result.is_err(), "Should fail with missing env var");
}
