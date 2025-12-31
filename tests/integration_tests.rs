//! Integration tests for USG RADIUS Server
//!
//! These tests verify end-to-end functionality including:
//! - Authentication flows (PAP and CHAP)
//! - Multi-round authentication (Access-Challenge)
//! - Client validation
//! - Rate limiting
//! - Configuration validation
//! - Audit logging

use radius_proto::auth::{encrypt_user_password, generate_request_authenticator};
use radius_proto::chap::{compute_chap_response, ChapChallenge, ChapResponse};
use radius_proto::{Attribute, AttributeType, Code, Packet};
use radius_server::{AuthHandler, AuthResult, Config, RadiusServer, ServerConfig, SimpleAuthHandler};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Test helper to create a RADIUS Access-Request packet with PAP
fn create_access_request(username: &str, password: &str, secret: &[u8], identifier: u8) -> Packet {
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

/// Test helper to create a RADIUS Access-Request packet with CHAP
fn create_chap_access_request(
    username: &str,
    password: &str,
    identifier: u8,
    chap_ident: u8,
) -> Packet {
    let req_auth = generate_request_authenticator();
    let mut packet = Packet::new(Code::AccessRequest, identifier, req_auth);

    // Add User-Name attribute
    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, username)
            .expect("Failed to create User-Name attribute"),
    );

    // Compute CHAP response using Request Authenticator as challenge
    let challenge = ChapChallenge::from_authenticator(&req_auth);
    let response_hash = compute_chap_response(chap_ident, password, challenge.as_bytes());
    let chap_response = ChapResponse {
        ident: chap_ident,
        response: response_hash,
    };

    // Add CHAP-Password attribute (17 bytes: 1 byte ident + 16 bytes hash)
    packet.add_attribute(
        Attribute::new(AttributeType::ChapPassword as u8, chap_response.to_bytes())
            .expect("Failed to create CHAP-Password attribute"),
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
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");

    // Get the actual port assigned
    let server_addr = server.local_addr().expect("Failed to get server address");

    // Start server in background
    tokio::spawn(async move {
        server.run().await.expect("Server failed");
    });

    // Wait for server to start
    sleep(Duration::from_millis(500)).await;

    // Create and send Access-Request
    let packet = create_access_request("testuser", "testpass", b"testing123", 1);

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
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send request with wrong password
    let packet = create_access_request("testuser", "wrongpass", b"testing123", 2);

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
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send request for unknown user
    let packet = create_access_request("unknownuser", "password", b"testing123", 3);

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
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Test multiple users sequentially
    for (i, (username, password)) in [("user1", "pass1"), ("user2", "pass2"), ("user3", "pass3")]
        .iter()
        .enumerate()
    {
        let packet = create_access_request(username, password, b"testing123", (i + 1) as u8);

        let response = send_radius_request(&packet, server_addr)
            .await
            .expect("Failed to send request");

        assert_eq!(
            response.code,
            Code::AccessAccept,
            "Failed for user {}",
            username
        );
        assert_eq!(response.identifier, (i + 1) as u8);
    }
}

#[test]
fn test_env_var_expansion() {
    use std::env;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Set test environment variable
    env::set_var("TEST_RADIUS_SECRET", "env_secret_value");

    // Create temporary config file with env var
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(
        temp_file,
        r#"{{
        "listen_address": "::",
        "listen_port": 1812,
        "secret": "${{TEST_RADIUS_SECRET}}",
        "clients": [],
        "users": []
    }}"#
    )
    .expect("Failed to write to temp file");

    // Load config
    let config = Config::from_file(temp_file.path()).expect("Failed to load config with env var");

    // Verify env var was expanded
    assert_eq!(config.secret, "env_secret_value");

    // Clean up
    env::remove_var("TEST_RADIUS_SECRET");
}

#[test]
fn test_env_var_not_found() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create config with non-existent env var
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(
        temp_file,
        r#"{{
        "listen_address": "::",
        "listen_port": 1812,
        "secret": "${{NONEXISTENT_VAR_12345}}",
        "clients": [],
        "users": []
    }}"#
    )
    .expect("Failed to write to temp file");

    // Should fail to load
    let result = Config::from_file(temp_file.path());
    assert!(result.is_err(), "Should fail with missing env var");
}

#[tokio::test]
async fn test_rate_limiting() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    // Set very low rate limits for testing
    config.rate_limit_per_client_rps = Some(2);
    config.rate_limit_per_client_burst = Some(3);

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send requests rapidly to trigger rate limit
    // First 3 should succeed (burst), then rate limit kicks in
    let mut success_count = 0;
    let mut rate_limited = false;

    for i in 0..10 {
        let packet = create_access_request("testuser", "testpass", b"testing123", i);

        // Try to send request with short timeout
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            send_radius_request(&packet, server_addr),
        )
        .await;

        match result {
            Ok(Ok(_response)) => {
                success_count += 1;
            }
            Ok(Err(_)) | Err(_) => {
                rate_limited = true;
            }
        }
    }

    // Should have some successful requests and some rate limited
    assert!(success_count > 0, "Should have some successful requests");
    assert!(rate_limited, "Should have triggered rate limiting");
    assert!(
        success_count < 10,
        "Not all requests should succeed due to rate limiting"
    );
}

#[tokio::test]
async fn test_client_ip_validation() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create config with specific client IP restrictions
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(
        temp_file,
        r#"{{
        "listen_address": "127.0.0.1",
        "listen_port": 1812,
        "secret": "testing123",
        "clients": [
            {{
                "name": "Test Client",
                "address": "127.0.0.1",
                "secret": "testing123"
            }}
        ],
        "users": [
            {{
                "username": "testuser",
                "password": "testpass"
            }}
        ]
    }}"#
    )
    .expect("Failed to write to temp file");

    let mut config = Config::from_file(temp_file.path()).expect("Failed to load config");

    // Override to use OS-assigned port for testing
    config.listen_port = 0;

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send request from authorized IP (127.0.0.1)
    let packet = create_access_request("testuser", "testpass", b"testing123", 1);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send request");

    // Should succeed because 127.0.0.1 is authorized
    assert_eq!(response.code, Code::AccessAccept);
}

#[tokio::test]
async fn test_ipv6_support() {
    use tokio::net::UdpSocket as AsyncUdpSocket;

    // Check if IPv6 is available on this system
    let ipv6_test = AsyncUdpSocket::bind("[::1]:0").await;
    if ipv6_test.is_err() {
        // IPv6 not available, skip test
        println!("IPv6 not available on this system, skipping test");
        return;
    }
    drop(ipv6_test);

    let mut config = Config::default();
    config.listen_address = "::1".to_string(); // IPv6 loopback
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config).await;

    // If server creation fails (IPv6 not supported), skip test
    if server.is_err() {
        println!("IPv6 server creation failed, skipping test");
        return;
    }

    let server = server.unwrap();
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send request over IPv6
    let packet = create_access_request("testuser", "testpass", b"testing123", 1);

    // Try to send request over IPv6
    let result = send_radius_request(&packet, server_addr).await;

    // If we get a routing error, IPv6 isn't fully configured, skip test
    if let Err(ref e) = result {
        if e.to_string().contains("No route to host") || e.to_string().contains("HostUnreachable") {
            println!("IPv6 routing not configured, skipping test");
            return;
        }
    }

    let response = result.expect("Failed to send request over IPv6");
    assert_eq!(response.code, Code::AccessAccept);
    assert_eq!(response.identifier, 1);
}

#[tokio::test]
async fn test_duplicate_request_detection() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();
    config.request_cache_ttl = Some(10); // 10 second TTL

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("testuser", "testpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send same request twice
    let packet = create_access_request(
        "testuser",
        "testpass",
        b"testing123",
        42, // Use specific ID
    );

    // First request should succeed
    let response1 = send_radius_request(&packet, server_addr)
        .await
        .expect("First request failed");
    assert_eq!(response1.code, Code::AccessAccept);

    // Immediate duplicate should be silently dropped (no response)
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        send_radius_request(&packet, server_addr),
    )
    .await;

    // Should timeout because duplicate requests are silently dropped
    assert!(
        result.is_err(),
        "Duplicate request should timeout (be silently dropped)"
    );
}

#[tokio::test]
async fn test_chap_successful_authentication() {
    // Create test configuration
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    // Create authentication handler
    let mut handler = SimpleAuthHandler::new();
    handler.add_user("chapuser", "chappass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Create and send CHAP Access-Request
    let packet = create_chap_access_request("chapuser", "chappass", 1, 42);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send CHAP request");

    // Verify Access-Accept response
    assert_eq!(response.code, Code::AccessAccept);
    assert_eq!(response.identifier, 1);
}

#[tokio::test]
async fn test_chap_failed_authentication_wrong_password() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("chapuser", "correctpass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send CHAP request with wrong password
    let packet = create_chap_access_request("chapuser", "wrongpass", 2, 42);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send CHAP request");

    // Verify Access-Reject response
    assert_eq!(response.code, Code::AccessReject);
    assert_eq!(response.identifier, 2);
}

#[tokio::test]
async fn test_chap_failed_authentication_unknown_user() {
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("realuser", "password");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Send CHAP request for unknown user
    let packet = create_chap_access_request("unknownuser", "password", 3, 42);

    let response = send_radius_request(&packet, server_addr)
        .await
        .expect("Failed to send CHAP request");

    // Verify Access-Reject response
    assert_eq!(response.code, Code::AccessReject);
    assert_eq!(response.identifier, 3);
}

#[tokio::test]
async fn test_chap_and_pap_interleaved() {
    // Test that server can handle both PAP and CHAP requests
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("user1", "pass1");
    handler.add_user("user2", "pass2");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Test PAP request
    let pap_packet = create_access_request("user1", "pass1", b"testing123", 1);
    let response = send_radius_request(&pap_packet, server_addr)
        .await
        .expect("Failed to send PAP request");
    assert_eq!(response.code, Code::AccessAccept);

    // Test CHAP request
    let chap_packet = create_chap_access_request("user2", "pass2", 2, 42);
    let response = send_radius_request(&chap_packet, server_addr)
        .await
        .expect("Failed to send CHAP request");
    assert_eq!(response.code, Code::AccessAccept);

    // Test another PAP request
    let pap_packet2 = create_access_request("user1", "pass1", b"testing123", 3);
    let response = send_radius_request(&pap_packet2, server_addr)
        .await
        .expect("Failed to send second PAP request");
    assert_eq!(response.code, Code::AccessAccept);
}

#[tokio::test]
async fn test_chap_different_identifiers() {
    // Test that CHAP works with different CHAP identifiers
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    let mut handler = SimpleAuthHandler::new();
    handler.add_user("chapuser", "chappass");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // Test with different CHAP identifiers
    for chap_ident in [0x01, 0x42, 0x7F, 0xFF] {
        let packet = create_chap_access_request("chapuser", "chappass", chap_ident, chap_ident);
        let response = send_radius_request(&packet, server_addr)
            .await
            .expect("Failed to send CHAP request");
        assert_eq!(
            response.code,
            Code::AccessAccept,
            "Failed with CHAP identifier {}",
            chap_ident
        );
    }
}

/// Custom authentication handler for testing Access-Challenge
struct ChallengeAuthHandler {
    users: std::collections::HashMap<String, String>,
    pin: String,
}

impl ChallengeAuthHandler {
    fn new() -> Self {
        ChallengeAuthHandler {
            users: std::collections::HashMap::new(),
            pin: "1234".to_string(),
        }
    }

    fn add_user(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.users.insert(username.into(), password.into());
    }
}

impl AuthHandler for ChallengeAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        // Simple password check
        self.users.get(username).map(|p| p == password).unwrap_or(false)
    }

    fn get_user_password(&self, username: &str) -> Option<String> {
        self.users.get(username).cloned()
    }

    fn authenticate_with_challenge(
        &self,
        username: &str,
        password: Option<&str>,
        state: Option<&[u8]>,
    ) -> AuthResult {
        // Check if user exists
        if !self.users.contains_key(username) {
            return AuthResult::Reject;
        }

        // If no state, this is the first request - send challenge
        if state.is_none() {
            return AuthResult::Challenge {
                message: Some("Please enter your PIN".to_string()),
                state: b"challenge_state_123".to_vec(),
                attributes: vec![],
            };
        }

        // If we have state, verify it and check the PIN
        if state == Some(b"challenge_state_123" as &[u8]) {
            // Password should be the PIN
            if let Some(pwd) = password {
                if pwd == self.pin {
                    return AuthResult::Accept;
                }
            }
        }

        AuthResult::Reject
    }
}

#[tokio::test]
async fn test_access_challenge() {
    // Create test configuration
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    // Create challenge authentication handler
    let mut handler = ChallengeAuthHandler::new();
    handler.add_user("challengeuser", "password");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // First request - should get Access-Challenge
    let packet1 = create_access_request("challengeuser", "password", b"testing123", 1);
    let response1 = send_radius_request(&packet1, server_addr)
        .await
        .expect("Failed to send first request");

    assert_eq!(response1.code, Code::AccessChallenge);
    assert_eq!(response1.identifier, 1);

    // Extract State attribute from challenge
    let state_attr = response1
        .find_attribute(AttributeType::State as u8)
        .expect("State attribute should be present in Access-Challenge");

    // Verify Reply-Message is present
    let reply_msg = response1
        .find_attribute(AttributeType::ReplyMessage as u8)
        .and_then(|attr| attr.as_string().ok());
    assert_eq!(reply_msg, Some("Please enter your PIN".to_string()));

    // Second request - with State and correct PIN
    let req_auth2 = generate_request_authenticator();
    let mut packet2 = Packet::new(Code::AccessRequest, 2, req_auth2);

    // Add User-Name
    packet2.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "challengeuser")
            .expect("Failed to create User-Name attribute"),
    );

    // Add encrypted PIN as User-Password
    let encrypted_pin = encrypt_user_password("1234", b"testing123", &req_auth2);
    packet2.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pin)
            .expect("Failed to create User-Password attribute"),
    );

    // Add State attribute from previous response
    packet2.add_attribute(
        Attribute::new(AttributeType::State as u8, state_attr.value.clone())
            .expect("Failed to create State attribute"),
    );

    let response2 = send_radius_request(&packet2, server_addr)
        .await
        .expect("Failed to send second request");

    // Should now get Access-Accept
    assert_eq!(response2.code, Code::AccessAccept);
    assert_eq!(response2.identifier, 2);
}

#[tokio::test]
async fn test_access_challenge_wrong_pin() {
    // Create test configuration
    let mut config = Config::default();
    config.listen_address = "127.0.0.1".to_string();
    config.listen_port = 0;
    config.secret = "testing123".to_string();

    // Create challenge authentication handler
    let mut handler = ChallengeAuthHandler::new();
    handler.add_user("challengeuser", "password");

    let server_config = ServerConfig::from_config(config, Arc::new(handler))
        .expect("Failed to create server config");
    let server = RadiusServer::new(server_config)
        .await
        .expect("Failed to create server");
    let server_addr = server.local_addr().expect("Failed to get server address");

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(500)).await;

    // First request - should get Access-Challenge
    let packet1 = create_access_request("challengeuser", "password", b"testing123", 1);
    let response1 = send_radius_request(&packet1, server_addr)
        .await
        .expect("Failed to send first request");

    assert_eq!(response1.code, Code::AccessChallenge);

    // Extract State attribute
    let state_attr = response1
        .find_attribute(AttributeType::State as u8)
        .expect("State attribute should be present");

    // Second request - with State but WRONG PIN
    let req_auth2 = generate_request_authenticator();
    let mut packet2 = Packet::new(Code::AccessRequest, 2, req_auth2);

    packet2.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "challengeuser")
            .expect("Failed to create User-Name attribute"),
    );

    // Add wrong PIN
    let encrypted_pin = encrypt_user_password("9999", b"testing123", &req_auth2);
    packet2.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pin)
            .expect("Failed to create User-Password attribute"),
    );

    packet2.add_attribute(
        Attribute::new(AttributeType::State as u8, state_attr.value.clone())
            .expect("Failed to create State attribute"),
    );

    let response2 = send_radius_request(&packet2, server_addr)
        .await
        .expect("Failed to send second request");

    // Should get Access-Reject for wrong PIN
    assert_eq!(response2.code, Code::AccessReject);
    assert_eq!(response2.identifier, 2);
}
