//! PostgreSQL Authentication Handler Tests
//!
//! These tests verify the PostgreSQL authentication handler functionality.
//! Note: Most tests are unit tests that don't require a real PostgreSQL server.
//! Integration tests with a real PostgreSQL server would require Docker or similar setup.

use radius_server::PostgresConfig;

#[test]
fn test_postgres_config_default() {
    let config = PostgresConfig::default();
    assert_eq!(config.max_connections, 10);
    assert_eq!(config.timeout, 10);
    assert_eq!(config.password_hash, "bcrypt");
    assert!(config.url.contains("postgresql://"));
    assert!(config.query.contains("SELECT"));
}

#[test]
fn test_postgres_config_serialization() {
    use serde_json;

    let config = PostgresConfig {
        url: "postgresql://radius:secret@db.example.com:5432/radius".to_string(),
        max_connections: 20,
        timeout: 15,
        query: "SELECT username, password_hash FROM users WHERE username = $1".to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: Some(
            "SELECT attribute_type, attribute_value FROM user_attributes WHERE username = $1"
                .to_string(),
        ),
    };

    // Test serialization
    let json = serde_json::to_string_pretty(&config).expect("Failed to serialize");
    assert!(json.contains("postgresql://"));
    assert!(json.contains("bcrypt"));
    assert!(json.contains("user_attributes"));

    // Test deserialization
    let deserialized: PostgresConfig = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(deserialized.url, config.url);
    assert_eq!(deserialized.max_connections, config.max_connections);
    assert_eq!(deserialized.query, config.query);
    assert_eq!(deserialized.password_hash, config.password_hash);
}

#[test]
fn test_postgres_config_with_defaults() {
    use serde_json;

    let json = r#"{
        "url": "postgresql://user:pass@localhost/db"
    }"#;

    let config: PostgresConfig = serde_json::from_str(json).expect("Failed to parse");

    // Verify defaults are applied
    assert_eq!(config.url, "postgresql://user:pass@localhost/db");
    assert_eq!(config.max_connections, 10); // default
    assert_eq!(config.timeout, 10); // default
    assert_eq!(config.password_hash, "bcrypt"); // default
    assert!(config.query.contains("SELECT")); // default query
    assert!(config.attributes_query.is_none());
}

#[test]
fn test_postgres_config_environment_variable_support() {
    use serde_json;

    // Config with environment variable placeholders
    let json = r#"{
        "url": "postgresql://radius:${DB_PASSWORD}@localhost:5432/radius",
        "max_connections": 10,
        "timeout": 10,
        "query": "SELECT username, password_hash FROM users WHERE username = $1",
        "password_hash": "bcrypt"
    }"#;

    let config: PostgresConfig = serde_json::from_str(json).expect("Failed to parse");

    // URL should contain the placeholder (expansion happens in Config, not PostgresConfig)
    assert!(config.url.contains("${DB_PASSWORD}"));
}

#[test]
fn test_postgres_config_custom_query() {
    use serde_json;

    let json = r#"{
        "url": "postgresql://localhost/radius",
        "query": "SELECT u.username, u.password_hash FROM users u JOIN departments d ON u.dept_id = d.id WHERE u.username = $1 AND d.active = true",
        "password_hash": "bcrypt"
    }"#;

    let config: PostgresConfig = serde_json::from_str(json).expect("Failed to parse");
    assert!(config.query.contains("JOIN departments"));
    assert!(config.query.contains("d.active = true"));
}

#[test]
fn test_postgres_config_bcrypt_algorithm() {
    use serde_json;

    let json = r#"{
        "url": "postgresql://localhost/radius",
        "password_hash": "bcrypt"
    }"#;

    let config: PostgresConfig = serde_json::from_str(json).expect("Failed to parse");
    assert_eq!(config.password_hash, "bcrypt");
}

#[test]
fn test_postgres_config_plain_algorithm() {
    use serde_json;

    let json = r#"{
        "url": "postgresql://localhost/radius",
        "password_hash": "plain"
    }"#;

    let config: PostgresConfig = serde_json::from_str(json).expect("Failed to parse");
    assert_eq!(config.password_hash, "plain");
}

#[test]
fn test_postgres_config_with_attributes_query() {
    use serde_json;

    let json = r#"{
        "url": "postgresql://localhost/radius",
        "attributes_query": "SELECT attribute_type, attribute_value FROM user_attributes WHERE username = $1"
    }"#;

    let config: PostgresConfig = serde_json::from_str(json).expect("Failed to parse");
    assert!(config.attributes_query.is_some());
    assert!(config.attributes_query.unwrap().contains("user_attributes"));
}

#[test]
fn test_postgres_config_connection_pool_settings() {
    use serde_json;

    let json = r#"{
        "url": "postgresql://localhost/radius",
        "max_connections": 50,
        "timeout": 30
    }"#;

    let config: PostgresConfig = serde_json::from_str(json).expect("Failed to parse");
    assert_eq!(config.max_connections, 50);
    assert_eq!(config.timeout, 30);
}

// Note: The following tests would require a real PostgreSQL server
// They are commented out but serve as documentation for integration testing

/*
#[tokio::test]
#[ignore] // Requires PostgreSQL server
async fn test_postgres_connection() {
    use radius_server::AuthHandler;

    let config = PostgresConfig {
        url: "postgresql://radius:password@localhost:5432/radius_test".to_string(),
        max_connections: 10,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true".to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create handler");

    // Test authentication with valid credentials
    // Assumes testuser exists with bcrypt hash of "password123"
    let result = handler.authenticate("testuser", "password123");
    assert!(result);
}

#[tokio::test]
#[ignore] // Requires PostgreSQL server
async fn test_postgres_authentication_failure() {
    use radius_server::AuthHandler;

    let config = PostgresConfig {
        url: "postgresql://radius:password@localhost:5432/radius_test".to_string(),
        max_connections: 10,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true".to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create handler");

    // Test authentication with invalid password
    let result = handler.authenticate("testuser", "wrongpassword");
    assert!(!result);

    // Test authentication with non-existent user
    let result = handler.authenticate("nonexistent", "password");
    assert!(!result);
}

#[tokio::test]
#[ignore] // Requires PostgreSQL server
async fn test_postgres_user_attributes() {
    use radius_server::AuthHandler;

    let config = PostgresConfig {
        url: "postgresql://radius:password@localhost:5432/radius_test".to_string(),
        max_connections: 10,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true".to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: Some("SELECT attribute_type, attribute_value FROM user_attributes WHERE username = $1".to_string()),
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create handler");

    // Get attributes for a user
    let attributes = handler.get_accept_attributes("testuser");
    assert!(!attributes.is_empty());
}

#[tokio::test]
#[ignore] // Requires PostgreSQL server with plain text password support
async fn test_postgres_plain_password() {
    use radius_server::AuthHandler;

    let config = PostgresConfig {
        url: "postgresql://radius:password@localhost:5432/radius_test".to_string(),
        max_connections: 10,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1".to_string(),
        password_hash: "plain".to_string(),
        attributes_query: None,
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create handler");

    // Test with plain text password
    // Assumes plainuser exists with plain password "testpass"
    let result = handler.authenticate("plainuser", "testpass");
    assert!(result);

    let result = handler.authenticate("plainuser", "wrongpass");
    assert!(!result);
}

#[tokio::test]
#[ignore] // Requires PostgreSQL server
async fn test_postgres_disabled_user() {
    use radius_server::AuthHandler;

    let config = PostgresConfig {
        url: "postgresql://radius:password@localhost:5432/radius_test".to_string(),
        max_connections: 10,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true".to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
    };

    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create handler");

    // Test authentication with disabled user
    // Assumes disableduser exists but enabled = false
    let result = handler.authenticate("disableduser", "password");
    assert!(!result);
}

#[tokio::test]
#[ignore] // Requires PostgreSQL server
async fn test_postgres_connection_pool() {
    let config = PostgresConfig {
        url: "postgresql://radius:password@localhost:5432/radius_test".to_string(),
        max_connections: 5,
        timeout: 10,
        query: "SELECT username, password_hash FROM users WHERE username = $1".to_string(),
        password_hash: "bcrypt".to_string(),
        attributes_query: None,
    };

    // Create handler (establishes connection pool)
    let handler = PostgresAuthHandler::new(config)
        .await
        .expect("Failed to create handler");

    // Verify we can make multiple concurrent requests
    use radius_server::AuthHandler;
    use std::sync::Arc;

    let handler = Arc::new(handler);
    let mut handles = vec![];

    for _ in 0..10 {
        let h = handler.clone();
        let handle = tokio::spawn(async move {
            h.authenticate("testuser", "password123")
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    for handle in handles {
        handle.await.expect("Task panicked");
    }
}
*/
