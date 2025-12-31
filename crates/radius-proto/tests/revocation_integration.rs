//! Integration tests for CRL revocation checking
//!
//! These tests validate the end-to-end revocation checking flow with
//! real certificate and CRL data structures.
//!
//! # Test PKI Setup
//!
//! For full integration testing, you'll need to generate:
//!
//! 1. **Root CA**: Self-signed root certificate
//! 2. **Intermediate CA**: Signed by root CA
//! 3. **Server Certificate**: For RADIUS server (signed by intermediate)
//! 4. **Client Certificates**: For EAP-TLS clients (signed by intermediate)
//! 5. **CRL**: Certificate Revocation List (signed by intermediate)
//!
//! ## Generating Test PKI (OpenSSL)
//!
//! ```bash
//! # Generate Root CA
//! openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
//!   -keyout root-key.pem -out root-cert.pem \
//!   -subj "/CN=Test Root CA"
//!
//! # Generate Intermediate CA
//! openssl req -newkey rsa:2048 -nodes \
//!   -keyout intermediate-key.pem -out intermediate-req.pem \
//!   -subj "/CN=Test Intermediate CA"
//!
//! openssl x509 -req -in intermediate-req.pem \
//!   -CA root-cert.pem -CAkey root-key.pem -CAcreateserial \
//!   -out intermediate-cert.pem -days 365 \
//!   -extensions v3_ca -extfile openssl.cnf
//!
//! # Generate Client Certificate with CRL Distribution Point
//! openssl req -newkey rsa:2048 -nodes \
//!   -keyout client-key.pem -out client-req.pem \
//!   -subj "/CN=test-client"
//!
//! # Add CRL Distribution Point extension
//! cat > client-ext.cnf <<EOF
//! crlDistributionPoints = URI:http://localhost:8000/test.crl
//! EOF
//!
//! openssl x509 -req -in client-req.pem \
//!   -CA intermediate-cert.pem -CAkey intermediate-key.pem -CAcreateserial \
//!   -out client-cert.pem -days 365 \
//!   -extfile client-ext.cnf
//!
//! # Generate Empty CRL
//! openssl ca -gencrl -keyfile intermediate-key.pem \
//!   -cert intermediate-cert.pem -out empty.crl
//!
//! # Revoke Client Certificate and Generate CRL
//! openssl ca -revoke client-cert.pem \
//!   -keyfile intermediate-key.pem -cert intermediate-cert.pem
//! openssl ca -gencrl -keyfile intermediate-key.pem \
//!   -cert intermediate-cert.pem -out revoked.crl
//! ```

#![cfg(feature = "revocation")]

use radius_proto::revocation::{
    CrlConfig, FallbackBehavior, RevocationCheckMode, RevocationConfig,
};

/// Test configuration creation
#[test]
fn test_revocation_config_integration() {
    // Test creating a production-like configuration
    let config = RevocationConfig {
        check_mode: RevocationCheckMode::CrlOnly,
        fallback_behavior: FallbackBehavior::FailClosed,
        crl_config: CrlConfig {
            static_crl_paths: vec!["/etc/radius/crls/ca.crl".to_string()],
            enable_http_fetch: true,
            http_timeout_secs: 5,
            cache_ttl_secs: 3600,
            max_cache_entries: 100,
            max_crl_size_bytes: 10 * 1024 * 1024,
        },
    };

    assert_eq!(config.check_mode, RevocationCheckMode::CrlOnly);
    assert_eq!(config.fallback_behavior, FallbackBehavior::FailClosed);
    assert_eq!(config.crl_config.http_timeout_secs, 5);
    assert_eq!(config.crl_config.cache_ttl_secs, 3600);
}

/// Test fail-open vs fail-closed behavior
#[test]
fn test_fallback_behavior_modes() {
    // Fail-closed for production (high security)
    let fail_closed = RevocationConfig {
        check_mode: RevocationCheckMode::CrlOnly,
        fallback_behavior: FallbackBehavior::FailClosed,
        crl_config: CrlConfig::default(),
    };

    assert_eq!(fail_closed.fallback_behavior, FallbackBehavior::FailClosed);

    // Fail-open for testing/development (availability over security)
    let fail_open = RevocationConfig {
        check_mode: RevocationCheckMode::CrlOnly,
        fallback_behavior: FallbackBehavior::FailOpen,
        crl_config: CrlConfig::default(),
    };

    assert_eq!(fail_open.fallback_behavior, FallbackBehavior::FailOpen);
}

/// Test disabled mode (bypass revocation checking)
#[test]
fn test_disabled_mode() {
    let config = RevocationConfig {
        check_mode: RevocationCheckMode::Disabled,
        fallback_behavior: FallbackBehavior::FailClosed,
        crl_config: CrlConfig::default(),
    };

    assert_eq!(config.check_mode, RevocationCheckMode::Disabled);
}

/// Test static CRL file configuration
#[test]
fn test_static_crl_configuration() {
    let config = RevocationConfig::static_files(
        vec![
            "/etc/radius/crls/root-ca.crl".to_string(),
            "/etc/radius/crls/intermediate-ca.crl".to_string(),
        ],
        FallbackBehavior::FailClosed,
    );

    assert_eq!(config.crl_config.static_crl_paths.len(), 2);
    assert!(!config.crl_config.enable_http_fetch);
}

/// Test HTTP fetch configuration
#[test]
fn test_http_fetch_configuration() {
    let config = RevocationConfig::crl_only(
        CrlConfig::http_fetch(5, 3600, 100),
        FallbackBehavior::FailClosed,
    );

    assert!(config.crl_config.enable_http_fetch);
    assert_eq!(config.crl_config.http_timeout_secs, 5);
    assert_eq!(config.crl_config.cache_ttl_secs, 3600);
    assert_eq!(config.crl_config.max_cache_entries, 100);
}

/// Test configuration serialization
#[test]
fn test_config_json_serialization() {
    let config = RevocationConfig::default();

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&config).unwrap();
    assert!(json.contains("check_mode"));
    assert!(json.contains("fallback_behavior"));

    // Deserialize from JSON
    let deserialized: RevocationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.check_mode, config.check_mode);
}

// Note: The following tests would require actual certificate/CRL data.
// They are documented here but marked as ignored until test PKI is generated.

/// Integration test with real CRL parsing
///
/// This test requires a real CRL file generated with the commands in the module docs.
/// To run: `cargo test --features revocation test_real_crl_parsing -- --ignored`
///
/// Note: CrlInfo is internal, so this test demonstrates the expected behavior
/// without direct access to the parsing API.
#[test]
#[ignore]
fn test_real_crl_parsing() {
    // This would require a real CRL file and would be tested through
    // the RevocationCheckingVerifier API rather than directly.
    //
    // Example flow:
    // 1. Create verifier with static CRL file
    // 2. Verify client certificate
    // 3. Verifier internally parses CRL and checks revocation

    // Placeholder for now
    assert!(true, "Real CRL parsing test requires test PKI generation");
}

/// Integration test with revoked certificate
#[test]
#[ignore]
fn test_revoked_certificate_detection() {
    // This would require:
    // 1. A client certificate
    // 2. A CRL with that certificate's serial number
    // 3. Full verifier setup

    // Placeholder documentation
    assert!(
        true,
        "Revoked certificate detection requires test PKI generation"
    );
}

/// Integration test with CRL caching
#[test]
#[ignore]
fn test_crl_cache_integration() {
    // This would test:
    // 1. First request: cache miss → HTTP fetch → cache store
    // 2. Second request: cache hit → no HTTP fetch
    // 3. After TTL: cache expired → HTTP fetch → cache update

    assert!(true, "CRL caching integration requires HTTP server setup");
}

/// Integration test with EAP-TLS
#[test]
#[ignore]
fn test_eap_tls_revocation_integration() {
    // This would test the full EAP-TLS authentication flow:
    // 1. TLS handshake with client cert
    // 2. Extract CRL distribution points
    // 3. Fetch CRL
    // 4. Check revocation
    // 5. Accept or reject authentication

    assert!(
        true,
        "EAP-TLS integration requires full TLS handshake setup"
    );
}

// Future integration tests to add:
// - test_multiple_distribution_points: Test fallback when first URL fails
// - test_crl_expiration: Test behavior with expired CRL
// - test_http_timeout: Test timeout handling
// - test_size_limit: Test CRL size limit enforcement
// - test_concurrent_requests: Test cache under concurrent load
// - test_fail_open_mode: Test authentication succeeds on CRL fetch failure
// - test_fail_closed_mode: Test authentication fails on CRL fetch failure

/// Test that verifies the module is properly feature-gated
#[test]
fn test_feature_gate() {
    // This test ensures the revocation module is only available with the feature flag
    // The fact that this compiles means the feature is working
    let _config = RevocationConfig::default();
}

/// Documentation test showing production configuration
///
/// This demonstrates how a production RADIUS server would configure
/// certificate revocation checking.
#[test]
fn test_production_configuration_example() {
    // High-security deployment with fail-closed mode
    let production_config = RevocationConfig {
        check_mode: RevocationCheckMode::CrlOnly,
        fallback_behavior: FallbackBehavior::FailClosed, // Reject on errors
        crl_config: CrlConfig {
            static_crl_paths: vec![
                "/etc/radius/crls/root-ca.crl".to_string(),
                "/etc/radius/crls/intermediate-ca.crl".to_string(),
            ],
            enable_http_fetch: true, // Allow fetching from cert extensions
            http_timeout_secs: 5,    // 5 second timeout for CRL fetch
            cache_ttl_secs: 3600,    // Cache CRLs for 1 hour
            max_cache_entries: 100,  // Cache up to 100 CRLs
            max_crl_size_bytes: 10 * 1024 * 1024, // 10 MB limit
        },
    };

    // Verify configuration
    assert_eq!(
        production_config.fallback_behavior,
        FallbackBehavior::FailClosed
    );
    assert!(production_config.crl_config.enable_http_fetch);
    assert_eq!(production_config.crl_config.cache_ttl_secs, 3600);

    // Serialize for storage
    let json = serde_json::to_string_pretty(&production_config).unwrap();
    assert!(!json.is_empty());

    println!("Production configuration:\n{}", json);
}
