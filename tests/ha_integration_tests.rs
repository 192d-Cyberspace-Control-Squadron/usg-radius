//! High Availability Integration Tests
//!
//! These tests verify that HA features work correctly across multiple
//! RADIUS server instances sharing state via Valkey.
//!
//! Run with: cargo test --test ha_integration_tests --features ha

#![cfg(feature = "ha")]

use radius_server::{
    cache_ha::SharedRequestCache,
    ratelimit_ha::{SharedRateLimitConfig, SharedRateLimiter},
    state::{MemoryStateBackend, SharedSessionManager, StateBackend},
    RequestFingerprint,
};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Test that request cache works across multiple "servers" (session managers)
#[tokio::test]
async fn test_cross_server_request_deduplication() {
    // Simulate 2 servers sharing the same backend
    let backend: Arc<dyn StateBackend> = Arc::new(MemoryStateBackend::new());
    let server1_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));
    let server2_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));

    let cache1 = SharedRequestCache::new(server1_manager, Duration::from_secs(60));
    let cache2 = SharedRequestCache::new(server2_manager, Duration::from_secs(60));

    let fingerprint = RequestFingerprint {
        source_ip: "192.168.1.100".parse().unwrap(),
        identifier: 42,
        auth_prefix: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    let authenticator = [1u8; 16];

    // Server 1 sees the request first
    let is_dup1 = cache1.is_duplicate(fingerprint.clone(), authenticator).await;
    assert!(!is_dup1, "First request should not be duplicate");

    // Server 2 sees the same request - should detect as duplicate
    let is_dup2 = cache2.is_duplicate(fingerprint.clone(), authenticator).await;
    assert!(is_dup2, "Second request on different server should be duplicate");

    // Different authenticator should not be duplicate
    let different_auth = [2u8; 16];
    let is_dup3 = cache2.is_duplicate(fingerprint, different_auth).await;
    assert!(
        !is_dup3,
        "Same fingerprint but different authenticator should not be duplicate"
    );
}

/// Test that rate limiting is coordinated across servers
#[tokio::test]
async fn test_cross_server_rate_limiting() {
    let backend: Arc<dyn StateBackend> = Arc::new(MemoryStateBackend::new());
    let server1_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));
    let server2_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));

    let config = SharedRateLimitConfig {
        per_client_limit: 5,
        global_limit: 10,
        window_duration: Duration::from_secs(1),
    };

    let limiter1 = SharedRateLimiter::new(Arc::clone(&server1_manager), config.clone());
    let limiter2 = SharedRateLimiter::new(Arc::clone(&server2_manager), config);

    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Server 1 handles 3 requests
    for i in 1..=3 {
        assert!(
            limiter1.check_rate_limit(client_ip).await,
            "Server 1 request {} should be allowed",
            i
        );
    }

    // Server 2 handles 2 more requests from same client
    for i in 1..=2 {
        assert!(
            limiter2.check_rate_limit(client_ip).await,
            "Server 2 request {} should be allowed",
            i
        );
    }

    // Now at limit (5 total across both servers)
    // Next request on either server should be blocked
    assert!(
        !limiter1.check_rate_limit(client_ip).await,
        "Server 1 should block 6th request"
    );
    assert!(
        !limiter2.check_rate_limit(client_ip).await,
        "Server 2 should block 6th request"
    );
}

/// Test global rate limiting across servers
#[tokio::test]
async fn test_cross_server_global_rate_limit() {
    let backend: Arc<dyn StateBackend> = Arc::new(MemoryStateBackend::new());
    let server1_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));
    let server2_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));

    let config = SharedRateLimitConfig {
        per_client_limit: 0, // Disabled
        global_limit: 5,
        window_duration: Duration::from_secs(1),
    };

    let limiter1 = SharedRateLimiter::new(Arc::clone(&server1_manager), config.clone());
    let limiter2 = SharedRateLimiter::new(Arc::clone(&server2_manager), config);

    let client1: IpAddr = "192.168.1.1".parse().unwrap();
    let client2: IpAddr = "192.168.1.2".parse().unwrap();

    // Server 1: 3 requests from client1
    for _ in 0..3 {
        assert!(limiter1.check_rate_limit(client1).await);
    }

    // Server 2: 2 requests from client2
    for _ in 0..2 {
        assert!(limiter2.check_rate_limit(client2).await);
    }

    // Global limit reached (5 total)
    assert!(
        !limiter1.check_rate_limit(client1).await,
        "Should hit global limit"
    );
    assert!(
        !limiter2.check_rate_limit(client2).await,
        "Should hit global limit"
    );
}

/// Test that accounting sessions are shared across servers
#[tokio::test]
async fn test_cross_server_accounting_sessions() {
    use radius_server::accounting::Session;

    let backend: Arc<dyn StateBackend> = Arc::new(MemoryStateBackend::new());
    // Use very short cache TTL for testing to avoid stale cache issues
    let server1_manager = Arc::new(SharedSessionManager::with_cache_ttl(
        Arc::clone(&backend),
        Duration::from_millis(1),
    ));
    let server2_manager = Arc::new(SharedSessionManager::with_cache_ttl(
        Arc::clone(&backend),
        Duration::from_millis(1),
    ));

    let session = Session {
        session_id: "test-session-123".to_string(),
        username: "alice".to_string(),
        nas_ip: "192.168.1.1".parse().unwrap(),
        framed_ip: Some("10.0.0.1".parse().unwrap()),
        start_time: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        last_update: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        input_octets: 1000,
        output_octets: 2000,
        input_packets: 10,
        output_packets: 20,
        session_time: 300,
        terminate_cause: None,
    };

    // Server 1 stores the session
    server1_manager
        .store_accounting("test-session-123", &session, Some(Duration::from_secs(300)))
        .await
        .expect("Failed to store session");

    // Server 2 retrieves the same session
    let retrieved = server2_manager
        .get_accounting("test-session-123")
        .await
        .expect("Failed to get session")
        .expect("Session not found");

    assert_eq!(retrieved.session_id, session.session_id);
    assert_eq!(retrieved.username, session.username);
    assert_eq!(retrieved.nas_ip, session.nas_ip);
    assert_eq!(retrieved.input_octets, session.input_octets);

    // Server 2 deletes the session
    server2_manager
        .delete_accounting("test-session-123")
        .await
        .expect("Failed to delete session");

    // Wait for cache to expire (2ms to be safe)
    tokio::time::sleep(Duration::from_millis(2)).await;

    // Server 1 confirms deletion
    let deleted = server1_manager
        .get_accounting("test-session-123")
        .await
        .expect("Failed to get session");
    assert!(deleted.is_none(), "Session should be deleted");
}

/// Test EAP session sharing across servers (when ha feature is enabled)
#[tokio::test]
async fn test_cross_server_eap_sessions() {
    use radius_proto::eap::{EapSession, EapState, EapType};

    let backend: Arc<dyn StateBackend> = Arc::new(MemoryStateBackend::new());
    // Use very short cache TTL for testing to avoid stale cache issues
    let server1_manager = Arc::new(SharedSessionManager::with_cache_ttl(
        Arc::clone(&backend),
        Duration::from_millis(1),
    ));
    let server2_manager = Arc::new(SharedSessionManager::with_cache_ttl(
        Arc::clone(&backend),
        Duration::from_millis(1),
    ));

    let eap_session = EapSession {
        session_id: "eap-session-456".to_string(),
        state: EapState::MethodRequested,
        current_identifier: 1,
        eap_method: Some(EapType::Tls),
        identity: Some("bob@example.com".to_string()),
        last_request: None,
        challenge: None,
        created_at: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        last_activity: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        attempt_count: 0,
    };

    // Server 1 stores EAP session
    server1_manager
        .store_eap("eap-session-456", &eap_session, Some(Duration::from_secs(600)))
        .await
        .expect("Failed to store EAP session");

    // Server 2 retrieves the same EAP session
    let retrieved = server2_manager
        .get_eap("eap-session-456")
        .await
        .expect("Failed to get EAP session")
        .expect("EAP session not found");

    assert_eq!(retrieved.session_id, eap_session.session_id);
    assert_eq!(retrieved.state, eap_session.state);
    assert_eq!(retrieved.eap_method, eap_session.eap_method);
    assert_eq!(retrieved.identity, eap_session.identity);

    // Server 2 deletes the session
    server2_manager
        .delete_eap("eap-session-456")
        .await
        .expect("Failed to delete EAP session");

    // Wait for cache to expire (2ms to be safe)
    tokio::time::sleep(Duration::from_millis(2)).await;

    // Server 1 confirms deletion
    let deleted = server1_manager
        .get_eap("eap-session-456")
        .await
        .expect("Failed to get EAP session");
    assert!(deleted.is_none(), "EAP session should be deleted");
}

/// Test that cache statistics are independent per server
#[tokio::test]
async fn test_independent_local_cache_stats() {
    use radius_server::accounting::Session;

    let backend: Arc<dyn StateBackend> = Arc::new(MemoryStateBackend::new());
    let server1_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));
    let server2_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));

    let session = Session {
        session_id: "cache-test".to_string(),
        username: "test".to_string(),
        nas_ip: "192.168.1.1".parse().unwrap(),
        framed_ip: None,
        start_time: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        last_update: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        input_octets: 0,
        output_octets: 0,
        input_packets: 0,
        output_packets: 0,
        session_time: 0,
        terminate_cause: None,
    };

    // Server 1 stores and retrieves (populates its cache)
    server1_manager
        .store_accounting("cache-test", &session, Some(Duration::from_secs(300)))
        .await
        .unwrap();
    server1_manager.get_accounting("cache-test").await.unwrap();

    // Server 2 retrieves (populates its cache)
    server2_manager.get_accounting("cache-test").await.unwrap();

    // Both should have 1 entry in their local cache
    let stats1 = server1_manager.cache_stats();
    let stats2 = server2_manager.cache_stats();

    assert_eq!(stats1.entries, 1, "Server 1 should have 1 cached entry");
    assert_eq!(stats2.entries, 1, "Server 2 should have 1 cached entry");

    // Cleanup should only affect local cache
    server1_manager.cleanup_expired_cache();
    let _stats1_after = server1_manager.cache_stats();
    let stats2_after = server2_manager.cache_stats();

    // Server 2 cache unchanged
    assert_eq!(
        stats2_after.entries, 1,
        "Server 2 cache should be unaffected"
    );
}

/// Test backend health check from multiple servers
#[tokio::test]
async fn test_backend_health_check() {
    let backend: Arc<dyn StateBackend> = Arc::new(MemoryStateBackend::new());
    let server1_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));
    let server2_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));

    // Both servers should report healthy backend
    assert!(
        server1_manager.health_check().await.is_ok(),
        "Server 1 health check should pass"
    );
    assert!(
        server2_manager.health_check().await.is_ok(),
        "Server 2 health check should pass"
    );
}

/// Test rate limiter statistics consistency
#[tokio::test]
async fn test_rate_limiter_stats_consistency() {
    let backend: Arc<dyn StateBackend> = Arc::new(MemoryStateBackend::new());
    let server1_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));
    let server2_manager = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));

    let config = SharedRateLimitConfig {
        per_client_limit: 100,
        global_limit: 1000,
        window_duration: Duration::from_secs(60),
    };

    let limiter1 = SharedRateLimiter::new(Arc::clone(&server1_manager), config.clone());
    let limiter2 = SharedRateLimiter::new(Arc::clone(&server2_manager), config);

    // Both should report the same configuration
    let stats1 = limiter1.get_stats();
    let stats2 = limiter2.get_stats();

    assert_eq!(stats1.per_client_limit, stats2.per_client_limit);
    assert_eq!(stats1.global_limit, stats2.global_limit);
    assert_eq!(stats1.window_duration_secs, stats2.window_duration_secs);
}

/// Test concurrent access to shared state
#[tokio::test]
async fn test_concurrent_session_access() {
    use radius_server::accounting::Session;

    let backend: Arc<dyn StateBackend> = Arc::new(MemoryStateBackend::new());
    let manager = Arc::new(SharedSessionManager::new(backend));

    let session = Session {
        session_id: "concurrent-test".to_string(),
        username: "concurrent".to_string(),
        nas_ip: "192.168.1.1".parse().unwrap(),
        framed_ip: None,
        start_time: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        last_update: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        input_octets: 1000,
        output_octets: 2000,
        input_packets: 10,
        output_packets: 20,
        session_time: 300,
        terminate_cause: None,
    };

    // Store session
    manager
        .store_accounting("concurrent-test", &session, Some(Duration::from_secs(300)))
        .await
        .unwrap();

    // Spawn multiple tasks reading the same session
    let mut handles = vec![];
    for _ in 0..10 {
        let mgr = Arc::clone(&manager);
        let handle = tokio::spawn(async move {
            mgr.get_accounting("concurrent-test")
                .await
                .expect("Failed to get session")
                .expect("Session not found")
        });
        handles.push(handle);
    }

    // All should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert_eq!(result.session_id, "concurrent-test");
    }
}

/// Test window reset in rate limiting
#[tokio::test]
async fn test_rate_limit_window_reset() {
    let backend: Arc<dyn StateBackend> = Arc::new(MemoryStateBackend::new());
    let manager = Arc::new(SharedSessionManager::new(backend));

    let config = SharedRateLimitConfig {
        per_client_limit: 2,
        global_limit: 0,
        window_duration: Duration::from_millis(100),
    };

    let limiter = SharedRateLimiter::new(manager, config);
    let client_ip: IpAddr = "192.168.1.100".parse().unwrap();

    // Use up limit
    assert!(limiter.check_rate_limit(client_ip).await);
    assert!(limiter.check_rate_limit(client_ip).await);
    assert!(!limiter.check_rate_limit(client_ip).await);

    // Wait for window to reset
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Should allow requests again
    assert!(
        limiter.check_rate_limit(client_ip).await,
        "Requests should be allowed after window reset"
    );
}
