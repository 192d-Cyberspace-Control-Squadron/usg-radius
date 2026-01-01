//! Cluster-aware request deduplication cache
//!
//! Provides distributed duplicate detection across a RADIUS server cluster
//! using SharedSessionManager for coordination.

use crate::cache::{RequestFingerprint, CacheStats};
use crate::state::SharedSessionManager;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Cluster-aware request cache for duplicate detection
///
/// Uses SharedSessionManager to provide cluster-wide request deduplication.
/// When a request arrives at any server in the cluster, all servers can
/// detect if it's a duplicate by checking the shared state backend.
///
/// # Deduplication Strategy
///
/// Uses atomic SET NX (set if not exists) operation to ensure only one
/// server accepts a given request:
/// - First server to receive request: SET NX succeeds → process request
/// - Other servers (duplicates): SET NX fails → reject as duplicate
///
/// # Key Format
///
/// Cache keys use the format: `req_cache:{source_ip}:{identifier}:{auth_prefix}`
///
/// Example: `req_cache:192.168.1.100:42:0102030405060708`
///
/// # TTL Management
///
/// Entries expire automatically via backend TTL (typically 30-60 seconds).
/// No background cleanup needed - backend handles expiry.
///
/// # Example
///
/// ```no_run
/// use radius_server::cache_ha::SharedRequestCache;
/// use radius_server::cache::RequestFingerprint;
/// use radius_server::state::{SharedSessionManager, MemoryStateBackend};
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let backend = Arc::new(MemoryStateBackend::new());
/// let session_manager = Arc::new(SharedSessionManager::new(backend));
///
/// let cache = SharedRequestCache::new(
///     session_manager,
///     Duration::from_secs(60),
/// );
///
/// let fingerprint = RequestFingerprint::new(
///     "192.168.1.1".parse()?,
///     42,
///     &[1u8; 16],
/// );
///
/// if cache.is_duplicate(fingerprint, [1u8; 16]).await {
///     println!("Duplicate request detected across cluster");
/// }
/// # Ok(())
/// # }
/// ```
pub struct SharedRequestCache {
    session_manager: Arc<SharedSessionManager>,
    ttl: Duration,
}

impl SharedRequestCache {
    /// Create a new cluster-aware request cache
    ///
    /// # Arguments
    /// * `session_manager` - Shared session manager for distributed state
    /// * `ttl` - Time-to-live for cache entries (typically 30-60 seconds)
    pub fn new(session_manager: Arc<SharedSessionManager>, ttl: Duration) -> Self {
        SharedRequestCache {
            session_manager,
            ttl,
        }
    }

    /// Check if a request is a duplicate across the cluster
    ///
    /// Returns `true` if this request was seen recently by any server, `false` otherwise.
    /// Also adds the request to the cluster-wide cache if it's new.
    ///
    /// # Atomicity
    ///
    /// Uses SET NX to ensure atomic check-and-set operation. This prevents race
    /// conditions when multiple servers receive the same request simultaneously.
    pub async fn is_duplicate(&self, fingerprint: RequestFingerprint, authenticator: [u8; 16]) -> bool {
        let key = self.fingerprint_to_key(&fingerprint);

        // Serialize the cache entry (just store timestamp)
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Store: timestamp (8 bytes) + full authenticator (16 bytes)
        let mut value = Vec::with_capacity(24);
        value.extend_from_slice(&now_secs.to_be_bytes());
        value.extend_from_slice(&authenticator);

        // Atomic SET NX with TTL
        match self.session_manager.backend.set_nx(&key, &value, Some(self.ttl)).await {
            Ok(true) => {
                // SET NX succeeded - this is the first time we've seen this request
                debug!(
                    source_ip = %fingerprint.source_ip,
                    identifier = fingerprint.identifier,
                    "New request cached (cluster-wide)"
                );
                false
            }
            Ok(false) => {
                // SET NX failed - request already exists (duplicate)
                debug!(
                    source_ip = %fingerprint.source_ip,
                    identifier = fingerprint.identifier,
                    "Duplicate request detected (cluster-wide)"
                );
                true
            }
            Err(e) => {
                // Backend error - fail safe by treating as non-duplicate
                // Log the error but don't block request processing
                debug!(
                    error = %e,
                    source_ip = %fingerprint.source_ip,
                    identifier = fingerprint.identifier,
                    "Request cache backend error, treating as non-duplicate"
                );
                false
            }
        }
    }

    /// Get cache statistics (cluster-wide)
    ///
    /// Note: Counting all entries requires scanning all keys, which may be
    /// expensive on large clusters. Use sparingly.
    pub async fn stats(&self) -> CacheStats {
        let pattern = "req_cache:*";

        let entries = match self.session_manager.backend.keys(pattern).await {
            Ok(keys) => keys.len(),
            Err(_) => 0,
        };

        CacheStats {
            entries,
            max_entries: 0, // No hard limit in distributed cache
            ttl_seconds: self.ttl.as_secs(),
        }
    }

    /// Clear all entries from the cache (cluster-wide)
    ///
    /// WARNING: This affects all servers in the cluster.
    pub async fn clear(&self) -> Result<(), String> {
        let pattern = "req_cache:*";

        let keys = self.session_manager.backend.keys(pattern).await
            .map_err(|e| format!("Failed to list cache keys: {}", e))?;

        let count = keys.len();

        for key in keys {
            self.session_manager.backend.delete(&key).await
                .map_err(|e| format!("Failed to delete key {}: {}", key, e))?;
        }

        debug!(count = count, "Cleared request cache (cluster-wide)");
        Ok(())
    }

    /// Convert fingerprint to cache key
    fn fingerprint_to_key(&self, fingerprint: &RequestFingerprint) -> String {
        // Format: req_cache:{source_ip}:{identifier}:{auth_prefix_hex}
        // Use uppercase hex encoding for consistency
        let auth_hex = fingerprint.auth_prefix
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        format!(
            "req_cache:{}:{}:{}",
            fingerprint.source_ip,
            fingerprint.identifier,
            auth_hex
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::MemoryStateBackend;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_fingerprint_to_key() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let cache = SharedRequestCache::new(session_manager, Duration::from_secs(60));

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let fingerprint = RequestFingerprint::new(ip, 42, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let key = cache.fingerprint_to_key(&fingerprint);
        assert_eq!(key, "req_cache:192.168.1.1:42:0102030405060708");
    }

    #[tokio::test]
    async fn test_duplicate_detection() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let cache = SharedRequestCache::new(session_manager, Duration::from_secs(60));

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];
        let fingerprint = RequestFingerprint::new(ip, 42, &auth);

        // First request should not be a duplicate
        let is_dup = cache.is_duplicate(fingerprint.clone(), auth).await;
        assert!(!is_dup);

        // Second request with same fingerprint should be a duplicate
        let is_dup = cache.is_duplicate(fingerprint.clone(), auth).await;
        assert!(is_dup);
    }

    #[tokio::test]
    async fn test_different_requests() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let cache = SharedRequestCache::new(session_manager, Duration::from_secs(60));

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let auth1 = [1u8; 16];
        let auth2 = [2u8; 16];

        let fp1 = RequestFingerprint::new(ip, 42, &auth1);
        let fp2 = RequestFingerprint::new(ip, 42, &auth2);

        // Different authenticators should not be duplicates
        assert!(!cache.is_duplicate(fp1, auth1).await);
        assert!(!cache.is_duplicate(fp2, auth2).await);
    }

    #[tokio::test]
    async fn test_different_identifiers() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let cache = SharedRequestCache::new(session_manager, Duration::from_secs(60));

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];

        let fp1 = RequestFingerprint::new(ip, 42, &auth);
        let fp2 = RequestFingerprint::new(ip, 43, &auth);

        // Different identifiers should not be duplicates
        assert!(!cache.is_duplicate(fp1, auth).await);
        assert!(!cache.is_duplicate(fp2, auth).await);
    }

    #[tokio::test]
    async fn test_expiry() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let cache = SharedRequestCache::new(session_manager, Duration::from_millis(100));

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];
        let fingerprint = RequestFingerprint::new(ip, 42, &auth);

        // Add request to cache
        assert!(!cache.is_duplicate(fingerprint.clone(), auth).await);

        // Should still be in cache immediately
        assert!(cache.is_duplicate(fingerprint.clone(), auth).await);

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be expired
        assert!(!cache.is_duplicate(fingerprint.clone(), auth).await);
    }

    #[tokio::test]
    async fn test_cluster_wide_deduplication() {
        // Simulate two servers sharing the same backend
        let backend: Arc<dyn crate::state::StateBackend> = Arc::new(MemoryStateBackend::new());

        let session_manager1 = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));
        let cache1 = SharedRequestCache::new(session_manager1, Duration::from_secs(60));

        let session_manager2 = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));
        let cache2 = SharedRequestCache::new(session_manager2, Duration::from_secs(60));

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];
        let fingerprint = RequestFingerprint::new(ip, 42, &auth);

        // Server 1 receives request first
        let is_dup_server1 = cache1.is_duplicate(fingerprint.clone(), auth).await;
        assert!(!is_dup_server1); // Not a duplicate

        // Server 2 receives same request (should detect as duplicate)
        let is_dup_server2 = cache2.is_duplicate(fingerprint.clone(), auth).await;
        assert!(is_dup_server2); // Duplicate detected!
    }

    #[tokio::test]
    async fn test_stats() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let cache = SharedRequestCache::new(session_manager, Duration::from_secs(60));

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.ttl_seconds, 60);

        // Add a request
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];
        let fp = RequestFingerprint::new(ip, 42, &auth);
        cache.is_duplicate(fp, auth).await;

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));
        let cache = SharedRequestCache::new(session_manager, Duration::from_secs(60));

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let auth = [1u8; 16];
        let fp = RequestFingerprint::new(ip, 42, &auth);

        cache.is_duplicate(fp, auth).await;

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 1);

        cache.clear().await.unwrap();

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 0);
    }
}
