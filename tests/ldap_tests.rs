//! LDAP Authentication Handler Tests
//!
//! These tests verify the LDAP authentication handler functionality.
//! Note: Most tests are unit tests that don't require a real LDAP server.
//! Integration tests with a real LDAP server would require Docker or similar setup.

use radius_server::{LdapAuthHandler, LdapConfig};

#[test]
fn test_ldap_handler_creation() {
    let config = LdapConfig {
        url: "ldap://localhost:389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin_password".to_string()),
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string(), "cn".to_string()],
        timeout: 10,
        verify_tls: true,
        ..Default::default()
    };

    let _handler = LdapAuthHandler::new(config.clone());

    // Handler should be created successfully
    // We can't test much without a real LDAP server, but we can verify creation
    // Test passes if we reach this point without panicking
}

#[test]
fn test_ldap_config_serialization() {
    use serde_json;

    let config = LdapConfig {
        url: "ldaps://ldap.example.com:636".to_string(),
        base_dn: "dc=corp,dc=example,dc=com".to_string(),
        bind_dn: Some("cn=service,dc=corp,dc=example,dc=com".to_string()),
        bind_password: Some("secret".to_string()),
        search_filter: "(sAMAccountName={username})".to_string(),
        attributes: vec!["dn".to_string(), "memberOf".to_string()],
        timeout: 15,
        verify_tls: true,
        ..Default::default()
    };

    // Test serialization
    let json = serde_json::to_string_pretty(&config).expect("Failed to serialize");
    assert!(json.contains("ldaps://ldap.example.com:636"));
    assert!(json.contains("sAMAccountName"));

    // Test deserialization
    let deserialized: LdapConfig = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(deserialized.url, config.url);
    assert_eq!(deserialized.base_dn, config.base_dn);
    assert_eq!(deserialized.search_filter, config.search_filter);
}

#[test]
fn test_ldap_config_with_defaults() {
    use serde_json;

    let json = r#"{
        "url": "ldap://ldap.local:389",
        "base_dn": "dc=local"
    }"#;

    let config: LdapConfig = serde_json::from_str(json).expect("Failed to parse");

    // Verify defaults are applied
    assert_eq!(config.url, "ldap://ldap.local:389");
    assert_eq!(config.base_dn, "dc=local");
    assert_eq!(config.search_filter, "(uid={username})"); // default
    assert_eq!(config.timeout, 10); // default
    assert!(config.verify_tls); // default
    assert!(config.bind_dn.is_none());
    assert!(config.bind_password.is_none());
}

#[test]
fn test_search_filter_templates() {
    // Test different search filter templates
    let filters = vec![
        ("(uid={username})", "testuser", "(uid=testuser)"),
        (
            "(sAMAccountName={username})",
            "jdoe",
            "(sAMAccountName=jdoe)",
        ),
        (
            "(mail={username}@example.com)",
            "alice",
            "(mail=alice@example.com)",
        ),
        (
            "(|(uid={username})(cn={username}))",
            "bob",
            "(|(uid=bob)(cn=bob))",
        ),
    ];

    for (template, username, expected) in filters {
        let result = template.replace("{username}", username);
        assert_eq!(result, expected, "Filter template failed for: {}", template);
    }
}

#[test]
fn test_ldap_config_environment_variable_support() {
    use serde_json;

    // Config with environment variable placeholders
    let json = r#"{
        "url": "ldaps://ldap.example.com:636",
        "base_dn": "dc=example,dc=com",
        "bind_dn": "cn=service,dc=example,dc=com",
        "bind_password": "${LDAP_PASSWORD}",
        "search_filter": "(uid={username})"
    }"#;

    let config: LdapConfig = serde_json::from_str(json).expect("Failed to parse");

    // Password should contain the placeholder (expansion happens in Config, not LdapConfig)
    assert_eq!(config.bind_password.as_ref().unwrap(), "${LDAP_PASSWORD}");
}

#[test]
fn test_active_directory_config() {
    use serde_json;

    let json = r#"{
        "url": "ldaps://dc1.corp.example.com:636",
        "base_dn": "dc=corp,dc=example,dc=com",
        "bind_dn": "CN=RADIUS Service,OU=Service Accounts,DC=corp,DC=example,DC=com",
        "bind_password": "service_password",
        "search_filter": "(sAMAccountName={username})",
        "attributes": ["dn", "cn", "sAMAccountName", "memberOf", "userPrincipalName"],
        "timeout": 15,
        "verify_tls": true
    }"#;

    let config: LdapConfig = serde_json::from_str(json).expect("Failed to parse AD config");

    assert_eq!(config.url, "ldaps://dc1.corp.example.com:636");
    assert_eq!(config.search_filter, "(sAMAccountName={username})");
    assert_eq!(config.timeout, 15);
    assert!(config.attributes.contains(&"memberOf".to_string()));
    assert!(config.attributes.contains(&"userPrincipalName".to_string()));
}

#[test]
fn test_openldap_config() {
    use serde_json;

    let json = r#"{
        "url": "ldaps://ldap.example.com:636",
        "base_dn": "dc=example,dc=com",
        "bind_dn": "cn=radius-service,ou=service-accounts,dc=example,dc=com",
        "bind_password": "service_password",
        "search_filter": "(uid={username})",
        "attributes": ["dn", "cn", "uid", "memberOf"],
        "timeout": 10,
        "verify_tls": true
    }"#;

    let config: LdapConfig = serde_json::from_str(json).expect("Failed to parse LDAP config");

    assert_eq!(config.url, "ldaps://ldap.example.com:636");
    assert_eq!(config.search_filter, "(uid={username})");
    assert_eq!(config.timeout, 10);
}

// Note: The following tests would require a real LDAP server
// They are commented out but serve as documentation for integration testing

/*
#[tokio::test]
#[ignore] // Requires LDAP server
async fn test_ldap_connection() {
    use radius_server::AuthHandler;

    let config = LdapConfig {
        url: "ldap://localhost:389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin".to_string()),
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string()],
        timeout: 10,
        verify_tls: false,
    };

    let handler = LdapAuthHandler::new(config);

    // Test authentication with valid credentials
    let result = handler.authenticate("testuser", "testpass");
    assert!(result); // Should succeed if testuser exists with testpass
}

#[tokio::test]
#[ignore] // Requires LDAP server
async fn test_ldap_authentication_failure() {
    use radius_server::AuthHandler;

    let config = LdapConfig {
        url: "ldap://localhost:389".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin".to_string()),
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string()],
        timeout: 10,
        verify_tls: false,
    };

    let handler = LdapAuthHandler::new(config);

    // Test authentication with invalid credentials
    let result = handler.authenticate("testuser", "wrongpassword");
    assert!(!result); // Should fail
}

#[tokio::test]
#[ignore] // Requires Active Directory
async fn test_active_directory_authentication() {
    use radius_server::AuthHandler;

    let config = LdapConfig {
        url: "ldaps://dc1.corp.example.com:636".to_string(),
        base_dn: "dc=corp,dc=example,dc=com".to_string(),
        bind_dn: Some("CN=RADIUS Service,OU=Services,DC=corp,DC=example,DC=com".to_string()),
        bind_password: Some("service_password".to_string()),
        search_filter: "(sAMAccountName={username})".to_string(),
        attributes: vec!["dn".to_string(), "memberOf".to_string()],
        timeout: 15,
        verify_tls: true,
    };

    let handler = LdapAuthHandler::new(config);

    // Test AD authentication
    let result = handler.authenticate("jdoe", "userpassword");
    assert!(result); // Should succeed if user exists
}
*/

#[test]
fn test_ldap_handler_implements_auth_handler() {
    use radius_server::AuthHandler;

    let config = LdapConfig::default();
    let handler = LdapAuthHandler::new(config);

    // Verify the handler implements AuthHandler trait
    // This is a compile-time check, but we can call the methods
    let _attrs = handler.get_accept_attributes("testuser");
    let _reject_attrs = handler.get_reject_attributes("testuser");

    // Both should return something
    // Test passes if we reach this point without panicking
}

#[test]
fn test_ldap_failover_config_multiple_urls() {
    use serde_json;

    // Test configuration with multiple LDAP servers for failover
    let json = r#"{
        "urls": [
            "ldap://ldap1.example.com:389",
            "ldap://ldap2.example.com:389",
            "ldap://ldap3.example.com:389"
        ],
        "base_dn": "dc=example,dc=com",
        "bind_dn": "cn=admin,dc=example,dc=com",
        "bind_password": "secret",
        "search_filter": "(uid={username})"
    }"#;

    let config: LdapConfig = serde_json::from_str(json).expect("Failed to parse failover config");

    // Verify all URLs are loaded
    assert_eq!(config.urls.len(), 3);
    assert_eq!(config.urls[0], "ldap://ldap1.example.com:389");
    assert_eq!(config.urls[1], "ldap://ldap2.example.com:389");
    assert_eq!(config.urls[2], "ldap://ldap3.example.com:389");

    // Test get_server_urls() method
    let server_urls = config.get_server_urls();
    assert_eq!(server_urls.len(), 3);
    assert_eq!(server_urls[0], "ldap://ldap1.example.com:389");
}

#[test]
fn test_ldap_failover_config_backward_compatibility() {
    use serde_json;

    // Test that old single-URL config still works
    let json = r#"{
        "url": "ldap://ldap.example.com:389",
        "base_dn": "dc=example,dc=com"
    }"#;

    let config: LdapConfig = serde_json::from_str(json).expect("Failed to parse single URL config");

    // Verify single URL is used
    assert_eq!(config.url, "ldap://ldap.example.com:389");
    assert_eq!(config.urls.len(), 0);

    // get_server_urls() should return the single URL
    let server_urls = config.get_server_urls();
    assert_eq!(server_urls.len(), 1);
    assert_eq!(server_urls[0], "ldap://ldap.example.com:389");
}

#[test]
fn test_ldap_failover_config_urls_take_precedence() {
    use serde_json;

    // Test that urls field takes precedence over url field
    let json = r#"{
        "url": "ldap://old.example.com:389",
        "urls": [
            "ldap://new1.example.com:389",
            "ldap://new2.example.com:389"
        ],
        "base_dn": "dc=example,dc=com"
    }"#;

    let config: LdapConfig = serde_json::from_str(json).expect("Failed to parse config");

    // get_server_urls() should return urls field, not url field
    let server_urls = config.get_server_urls();
    assert_eq!(server_urls.len(), 2);
    assert_eq!(server_urls[0], "ldap://new1.example.com:389");
    assert_eq!(server_urls[1], "ldap://new2.example.com:389");
}

#[test]
fn test_ldap_failover_active_directory_config() {
    use serde_json;

    // Test Active Directory with multiple domain controllers
    let json = r#"{
        "urls": [
            "ldaps://dc1.corp.example.com:636",
            "ldaps://dc2.corp.example.com:636",
            "ldaps://dc3.corp.example.com:636"
        ],
        "base_dn": "dc=corp,dc=example,dc=com",
        "bind_dn": "CN=RADIUS Service,OU=Service Accounts,DC=corp,DC=example,DC=com",
        "bind_password": "service_password",
        "search_filter": "(sAMAccountName={username})",
        "attributes": ["dn", "cn", "sAMAccountName", "memberOf"],
        "timeout": 15,
        "verify_tls": true
    }"#;

    let config: LdapConfig = serde_json::from_str(json).expect("Failed to parse AD failover config");

    assert_eq!(config.urls.len(), 3);
    assert!(config.urls[0].starts_with("ldaps://dc1"));
    assert!(config.urls[1].starts_with("ldaps://dc2"));
    assert!(config.urls[2].starts_with("ldaps://dc3"));
}

#[test]
fn test_ldap_failover_handler_creation() {
    // Test creating handler with multiple servers
    let config = LdapConfig {
        url: String::new(), // Empty single URL
        urls: vec![
            "ldap://ldap1.example.com:389".to_string(),
            "ldap://ldap2.example.com:389".to_string(),
        ],
        base_dn: "dc=example,dc=com".to_string(),
        bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
        bind_password: Some("admin_password".to_string()),
        search_filter: "(uid={username})".to_string(),
        attributes: vec!["dn".to_string(), "cn".to_string()],
        timeout: 10,
        verify_tls: true,
        max_connections: 10,
        acquire_timeout: 10,
        group_attribute: "memberOf".to_string(),
        group_attribute_mapping: std::collections::HashMap::new(),
    };

    let _handler = LdapAuthHandler::new(config.clone());

    // Handler should be created successfully with multiple servers
    // Test passes if we reach this point without panicking
}
