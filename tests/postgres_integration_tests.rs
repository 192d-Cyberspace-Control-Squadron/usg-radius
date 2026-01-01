//! PostgreSQL Integration Tests
//!
//! These tests require a real PostgreSQL server running via Docker.
//!
//! To run these tests:
//! 1. Start the test environment: `docker-compose -f docker-compose.test.yml up -d postgres`
//! 2. Wait for PostgreSQL to be ready: `docker-compose -f docker-compose.test.yml ps`
//! 3. Run tests: `cargo test --test postgres_integration_tests -- --ignored --test-threads=1`
//! 4. Stop the test environment: `docker-compose -f docker-compose.test.yml down`
//!
//! Note: These tests are ignored by default and must be explicitly run with --ignored flag.

use radius_server::{AuthHandler, PostgresAuthHandler, PostgresConfig};

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_postgres_connection() {
    let config = PostgresConfig {
        url: "postgresql://radius:testpass@localhost:15432/radius_test".to_string(),
        max_connections: 5,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true"
            .to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
        ..Default::default()
    };

    let _handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create PostgreSQL handler");

    // If we got here, connection pool was created successfully
    // Test passes if we reach this point without panicking
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_postgres_authentication_success() {
    let config = PostgresConfig {
        url: "postgresql://radius:testpass@localhost:15432/radius_test".to_string(),
        max_connections: 5,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true"
            .to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
        ..Default::default()
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create PostgreSQL handler");

    // Test authentication with valid credentials
    // testuser: password123 (from test-data.sql)
    let result = handler.authenticate("testuser", "password123");
    assert!(
        result,
        "Authentication should succeed with valid credentials"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_postgres_authentication_failure_wrong_password() {
    let config = PostgresConfig {
        url: "postgresql://radius:testpass@localhost:15432/radius_test".to_string(),
        max_connections: 5,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true"
            .to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
        ..Default::default()
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create PostgreSQL handler");

    // Test authentication with wrong password
    let result = handler.authenticate("testuser", "wrongpassword");
    assert!(!result, "Authentication should fail with wrong password");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_postgres_authentication_user_not_found() {
    let config = PostgresConfig {
        url: "postgresql://radius:testpass@localhost:15432/radius_test".to_string(),
        max_connections: 5,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true"
            .to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
        ..Default::default()
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create PostgreSQL handler");

    // Test authentication with non-existent user
    let result = handler.authenticate("nonexistent", "password");
    assert!(!result, "Authentication should fail for non-existent user");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_postgres_disabled_user() {
    let config = PostgresConfig {
        url: "postgresql://radius:testpass@localhost:15432/radius_test".to_string(),
        max_connections: 5,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true"
            .to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
        ..Default::default()
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create PostgreSQL handler");

    // Test authentication with disabled user
    // disabled: disabled123 (but enabled = false in test-data.sql)
    let result = handler.authenticate("disabled", "disabled123");
    assert!(!result, "Authentication should fail for disabled user");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_postgres_multiple_users() {
    let config = PostgresConfig {
        url: "postgresql://radius:testpass@localhost:15432/radius_test".to_string(),
        max_connections: 5,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true"
            .to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
        ..Default::default()
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create PostgreSQL handler");

    // Test multiple users from test-data.sql
    // testuser: password123
    assert!(
        handler.authenticate("testuser", "password123"),
        "testuser authentication failed"
    );

    // alice: alice123
    assert!(
        handler.authenticate("alice", "alice123"),
        "alice authentication failed"
    );

    // bob: bob456
    assert!(
        handler.authenticate("bob", "bob456"),
        "bob authentication failed"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_postgres_user_attributes() {
    let config = PostgresConfig {
        url: "postgresql://radius:testpass@localhost:15432/radius_test".to_string(),
        max_connections: 5,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true"
            .to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: Some(
            "SELECT attribute_type, attribute_value FROM user_attributes WHERE username = $1"
                .to_string(),
        ),
        ..Default::default()
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create PostgreSQL handler");

    // Get attributes for testuser
    let attributes = handler.get_accept_attributes("testuser");

    // testuser should have 2 attributes from test-data.sql:
    // - Service-Type (6): 2
    // - Session-Timeout (27): 3600
    assert!(
        attributes.len() >= 2,
        "testuser should have at least 2 attributes"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_postgres_connection_pool() {
    let config = PostgresConfig {
        url: "postgresql://radius:testpass@localhost:15432/radius_test".to_string(),
        max_connections: 5,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true"
            .to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
        ..Default::default()
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create PostgreSQL handler");

    use std::sync::Arc;
    let handler = Arc::new(handler);
    let mut handles = vec![];

    // Spawn 10 concurrent authentication requests to test connection pooling
    for i in 0..10 {
        let h = handler.clone();
        let handle = tokio::spawn(async move {
            let user = match i % 3 {
                0 => "testuser",
                1 => "alice",
                _ => "bob",
            };
            let pass = match i % 3 {
                0 => "password123",
                1 => "alice123",
                _ => "bob456",
            };
            h.authenticate(user, pass)
        });
        handles.push(handle);
    }

    // Wait for all requests and verify they all succeeded
    for handle in handles {
        let result = handle.await.expect("Task panicked");
        assert!(result, "Concurrent authentication failed");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_postgres_custom_query() {
    // Test with a more complex query joining tables
    let config = PostgresConfig {
        url: "postgresql://radius:testpass@localhost:15432/radius_test".to_string(),
        max_connections: 5,
        timeout: 10,
        query: "SELECT u.username, u.password_hash FROM users u WHERE u.username = $1 AND u.enabled = true".to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
        ..Default::default()
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create PostgreSQL handler");

    let result = handler.authenticate("testuser", "password123");
    assert!(result, "Authentication should work with custom query");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_postgres_bcrypt_verification() {
    let config = PostgresConfig {
        url: "postgresql://radius:testpass@localhost:15432/radius_test".to_string(),
        max_connections: 5,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1".to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
        ..Default::default()
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create PostgreSQL handler");

    // Test that bcrypt verification works correctly
    assert!(
        handler.authenticate("testuser", "password123"),
        "Bcrypt verification should succeed with correct password"
    );

    assert!(
        !handler.authenticate("testuser", "wrongpassword"),
        "Bcrypt verification should fail with wrong password"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_postgres_connection_timeout() {
    // Test with a very short timeout to verify timeout handling
    let config = PostgresConfig {
        url: "postgresql://radius:testpass@localhost:15432/radius_test".to_string(),
        max_connections: 1,
        timeout: 1, // 1 second timeout
        query: "SELECT username, password_hash FROM users WHERE username = $1".to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
        ..Default::default()
    };

    // This should still succeed if database is responsive
    let result = PostgresAuthHandler::new(config).await;
    assert!(
        result.is_ok(),
        "Should be able to connect even with short timeout"
    );
}
