//! LDAP Integration Tests
//!
//! These tests require a real LDAP server running via Docker.
//!
//! To run these tests:
//! 1. Start the test environment: `docker-compose -f docker-compose.test.yml up -d openldap`
//! 2. Wait for LDAP to be ready: `docker-compose -f docker-compose.test.yml ps`
//! 3. Run tests: `cargo test --test ldap_integration_tests -- --ignored --test-threads=1`
//! 4. Stop the test environment: `docker-compose -f docker-compose.test.yml down`
//!
//! Note: These tests are ignored by default and must be explicitly run with --ignored flag.

use radius_server::{AuthHandler, LdapAuthHandler, LdapConfig};

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_ldap_connection() {
    let config = LdapConfig {
        url: "ldap://localhost:1389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin".to_string()),
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string(), "cn".to_string()],
        timeout: 10,
        verify_tls: false,
        ..Default::default()
    };

    let _handler = LdapAuthHandler::new(config);

    // Test that we can create the handler without errors
    // The actual connection happens on first authentication attempt
    // Test passes if we reach this point without panicking
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_ldap_authentication_success() {
    let config = LdapConfig {
        url: "ldap://localhost:1389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin".to_string()),
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string(), "cn".to_string()],
        timeout: 10,
        verify_tls: false,
        ..Default::default()
    };

    let handler = LdapAuthHandler::new(config);

    // Test authentication with valid credentials
    // Password: password123 (from users.ldif)
    let result = handler.authenticate("testuser", "password123");
    assert!(
        result,
        "Authentication should succeed with valid credentials"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_ldap_authentication_failure_wrong_password() {
    let config = LdapConfig {
        url: "ldap://localhost:1389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin".to_string()),
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string(), "cn".to_string()],
        timeout: 10,
        verify_tls: false,
        ..Default::default()
    };

    let handler = LdapAuthHandler::new(config);

    // Test authentication with invalid password
    let result = handler.authenticate("testuser", "wrongpassword");
    assert!(!result, "Authentication should fail with wrong password");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_ldap_authentication_user_not_found() {
    let config = LdapConfig {
        url: "ldap://localhost:1389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin".to_string()),
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string(), "cn".to_string()],
        timeout: 10,
        verify_tls: false,
        ..Default::default()
    };

    let handler = LdapAuthHandler::new(config);

    // Test authentication with non-existent user
    let result = handler.authenticate("nonexistent", "password");
    assert!(!result, "Authentication should fail for non-existent user");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_ldap_multiple_users() {
    let config = LdapConfig {
        url: "ldap://localhost:1389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin".to_string()),
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string(), "cn".to_string()],
        timeout: 10,
        verify_tls: false,
        ..Default::default()
    };

    let handler = LdapAuthHandler::new(config);

    // Test multiple users from users.ldif
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
async fn test_ldap_anonymous_bind() {
    let config = LdapConfig {
        url: "ldap://localhost:1389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: None,
        bind_password: None,
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string(), "cn".to_string()],
        timeout: 10,
        verify_tls: false,
        ..Default::default()
    };

    let handler = LdapAuthHandler::new(config);

    // Test with anonymous bind (no service account)
    // This may fail depending on LDAP server configuration
    let result = handler.authenticate("testuser", "password123");
    // Note: We don't assert here as anonymous bind may not be allowed
    println!("Anonymous bind result: {}", result);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_ldap_search_filter_variations() {
    // Test with different search filters

    // Filter 1: uid
    let config1 = LdapConfig {
        url: "ldap://localhost:1389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin".to_string()),
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string()],
        timeout: 10,
        verify_tls: false,
        ..Default::default()
    };
    let handler1 = LdapAuthHandler::new(config1);
    assert!(handler1.authenticate("testuser", "password123"));

    // Filter 2: cn
    let config2 = LdapConfig {
        url: "ldap://localhost:1389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin".to_string()),
        search_filter: "(cn={username})".to_string(),
        attributes: vec!["dn".to_string()],
        timeout: 10,
        verify_tls: false,
        ..Default::default()
    };
    let handler2 = LdapAuthHandler::new(config2);
    // This should work with "Test User" as cn
    assert!(handler2.authenticate("Test User", "password123"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Requires Docker
async fn test_ldap_concurrent_authentications() {
    use std::sync::Arc;

    let config = LdapConfig {
        url: "ldap://localhost:1389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin".to_string()),
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string()],
        timeout: 10,
        verify_tls: false,
        ..Default::default()
    };

    let handler = Arc::new(LdapAuthHandler::new(config));
    let mut handles = vec![];

    // Spawn 10 concurrent authentication requests
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
