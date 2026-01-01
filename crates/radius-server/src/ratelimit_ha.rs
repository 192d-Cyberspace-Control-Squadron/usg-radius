//! Cluster-aware rate limiting
//!
//! Provides distributed rate limiting across a RADIUS server cluster
//! using SharedSessionManager for coordinated counter management.

use crate::state::SharedSessionManager;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Cluster-aware rate limiter configuration
#[derive(Debug, Clone)]
pub struct SharedRateLimitConfig {
    /// Maximum requests per window per client (0 = unlimited)
    pub per_client_limit: u32,
    /// Maximum requests per window globally (0 = unlimited)
    pub global_limit: u32,
    /// Time window duration for rate limiting
    pub window_duration: Duration,
}

impl Default for SharedRateLimitConfig {
    fn default() -> Self {
        SharedRateLimitConfig {
            per_client_limit: 100,              // 100 requests per window per client
            global_limit: 1000,                 // 1000 requests per window globally
            window_duration: Duration::from_secs(1), // 1 second window
        }
    }
}

/// Cluster-aware rate limiter
///
/// Uses SharedSessionManager with atomic INCR operations to provide
/// distributed rate limiting across a RADIUS server cluster.
///
/// # Algorithm
///
/// Uses a sliding window counter approach:
/// - Each request increments a counter (INCR is atomic)
/// - Counters have TTL equal to window_duration
/// - If counter exceeds limit, request is rejected
///
/// # Key Format
///
/// - Per-client: `ratelimit:client:{ip}:{window_id}`
/// - Global: `ratelimit:global:{window_id}`
///
/// Where window_id = current_timestamp / window_duration_secs
///
/// # Tradeoffs
///
/// - **Pros**: Simple, atomic, no synchronization needed
/// - **Cons**: Hard window boundaries (burst at boundary possible)
///
/// # Example
///
/// ```no_run
/// use radius_server::ratelimit_ha::{SharedRateLimiter, SharedRateLimitConfig};
/// use radius_server::state::{SharedSessionManager, MemoryStateBackend};
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let backend = Arc::new(MemoryStateBackend::new());
/// let session_manager = Arc::new(SharedSessionManager::new(backend));
///
/// let config = SharedRateLimitConfig {
///     per_client_limit: 100,
///     global_limit: 1000,
///     window_duration: Duration::from_secs(1),
/// };
///
/// let limiter = SharedRateLimiter::new(session_manager, config);
///
/// let client_ip = "192.168.1.1".parse()?;
/// if limiter.check_rate_limit(client_ip).await {
///     println!("Request allowed");
/// } else {
///     println!("Rate limit exceeded");
/// }
/// # Ok(())
/// # }
/// ```
pub struct SharedRateLimiter {
    session_manager: Arc<SharedSessionManager>,
    config: SharedRateLimitConfig,
}

impl SharedRateLimiter {
    /// Create a new cluster-aware rate limiter
    pub fn new(session_manager: Arc<SharedSessionManager>, config: SharedRateLimitConfig) -> Self {
        SharedRateLimiter {
            session_manager,
            config,
        }
    }

    /// Check if a request from the given IP should be allowed
    ///
    /// Returns true if the request is within rate limits, false otherwise.
    ///
    /// This method:
    /// 1. Checks global limit (if enabled)
    /// 2. Checks per-client limit (if enabled)
    /// 3. Uses atomic INCR to increment counters
    pub async fn check_rate_limit(&self, client_ip: IpAddr) -> bool {
        let window_id = self.current_window_id();

        // Check global rate limit first
        if self.config.global_limit > 0 {
            let global_key = format!("ratelimit:global:{}", window_id);

            match self.increment_counter(&global_key).await {
                Ok(count) => {
                    if count > self.config.global_limit as i64 {
                        debug!(
                            count = count,
                            limit = self.config.global_limit,
                            "Global rate limit exceeded"
                        );
                        return false;
                    }
                }
                Err(e) => {
                    // Fail open on backend error
                    debug!(error = %e, "Global rate limit backend error, allowing request");
                }
            }
        }

        // Check per-client rate limit
        if self.config.per_client_limit > 0 {
            let client_key = format!("ratelimit:client:{}:{}", client_ip, window_id);

            match self.increment_counter(&client_key).await {
                Ok(count) => {
                    if count > self.config.per_client_limit as i64 {
                        debug!(
                            client_ip = %client_ip,
                            count = count,
                            limit = self.config.per_client_limit,
                            "Per-client rate limit exceeded"
                        );
                        return false;
                    }
                }
                Err(e) => {
                    // Fail open on backend error
                    debug!(error = %e, client_ip = %client_ip, "Per-client rate limit backend error, allowing request");
                }
            }
        }

        true
    }

    /// Get current request count for a client in current window
    pub async fn get_client_count(&self, client_ip: IpAddr) -> Result<i64, String> {
        let window_id = self.current_window_id();
        let client_key = format!("ratelimit:client:{}:{}", client_ip, window_id);

        // Try to get the value as a string first
        match self.session_manager.backend.get(&client_key).await {
            Ok(Some(bytes)) => {
                let s = String::from_utf8(bytes)
                    .map_err(|e| format!("Invalid UTF-8: {}", e))?;
                s.parse::<i64>()
                    .map_err(|e| format!("Invalid integer: {}", e))
            }
            Ok(None) => Ok(0),
            Err(e) => Err(format!("Backend error: {}", e)),
        }
    }

    /// Get current request count globally in current window
    pub async fn get_global_count(&self) -> Result<i64, String> {
        let window_id = self.current_window_id();
        let global_key = format!("ratelimit:global:{}", window_id);

        match self.session_manager.backend.get(&global_key).await {
            Ok(Some(bytes)) => {
                let s = String::from_utf8(bytes)
                    .map_err(|e| format!("Invalid UTF-8: {}", e))?;
                s.parse::<i64>()
                    .map_err(|e| format!("Invalid integer: {}", e))
            }
            Ok(None) => Ok(0),
            Err(e) => Err(format!("Backend error: {}", e)),
        }
    }

    /// Get rate limiter statistics
    pub fn get_stats(&self) -> SharedRateLimiterStats {
        SharedRateLimiterStats {
            per_client_limit: self.config.per_client_limit,
            global_limit: self.config.global_limit,
            window_duration_secs: self.config.window_duration.as_secs(),
        }
    }

    /// Calculate current window ID based on current time
    fn current_window_id(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let window_millis = self.config.window_duration.as_millis() as u64;
        if window_millis == 0 {
            return 0; // Avoid division by zero
        }

        now / window_millis
    }

    /// Atomically increment a counter and set TTL
    ///
    /// Uses INCR for atomic increment, then sets TTL if this is the first increment.
    async fn increment_counter(&self, key: &str) -> Result<i64, String> {
        // Atomic increment
        let count = self.session_manager.backend.incr(key).await
            .map_err(|e| format!("INCR failed: {}", e))?;

        // Set TTL if this is the first increment (count == 1)
        // For subsequent increments, TTL is already set
        if count == 1 {
            // Add a buffer to TTL to ensure cleanup even if clocks drift slightly
            let ttl = self.config.window_duration + Duration::from_secs(60);

            self.session_manager.backend.expire(key, ttl).await
                .map_err(|e| format!("EXPIRE failed: {}", e))?;
        }

        Ok(count)
    }
}

/// Cluster-aware rate limiter statistics
#[derive(Debug, Clone)]
pub struct SharedRateLimiterStats {
    pub per_client_limit: u32,
    pub global_limit: u32,
    pub window_duration_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::MemoryStateBackend;

    #[tokio::test]
    async fn test_per_client_limit() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));

        let config = SharedRateLimitConfig {
            per_client_limit: 5,
            global_limit: 0,
            window_duration: Duration::from_secs(1),
        };

        let limiter = SharedRateLimiter::new(session_manager, config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow 5 requests
        for i in 1..=5 {
            assert!(limiter.check_rate_limit(ip).await, "Request {} should be allowed", i);
        }

        // 6th request should be denied
        assert!(!limiter.check_rate_limit(ip).await, "Request 6 should be denied");
    }

    #[tokio::test]
    async fn test_global_limit() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));

        let config = SharedRateLimitConfig {
            per_client_limit: 100,
            global_limit: 3,
            window_duration: Duration::from_secs(1),
        };

        let limiter = SharedRateLimiter::new(session_manager, config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Global limit should apply across clients
        assert!(limiter.check_rate_limit(ip1).await);
        assert!(limiter.check_rate_limit(ip2).await);
        assert!(limiter.check_rate_limit(ip1).await);

        // 4th request should hit global limit
        assert!(!limiter.check_rate_limit(ip2).await);
    }

    #[tokio::test]
    async fn test_different_clients() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));

        let config = SharedRateLimitConfig {
            per_client_limit: 2,
            global_limit: 0,
            window_duration: Duration::from_secs(1),
        };

        let limiter = SharedRateLimiter::new(session_manager, config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Each client should have independent limits
        assert!(limiter.check_rate_limit(ip1).await);
        assert!(limiter.check_rate_limit(ip1).await);
        assert!(!limiter.check_rate_limit(ip1).await); // ip1 exhausted

        assert!(limiter.check_rate_limit(ip2).await);
        assert!(limiter.check_rate_limit(ip2).await);
        assert!(!limiter.check_rate_limit(ip2).await); // ip2 exhausted
    }

    #[tokio::test]
    async fn test_window_reset() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));

        let config = SharedRateLimitConfig {
            per_client_limit: 2,
            global_limit: 0,
            window_duration: Duration::from_millis(100), // Short window for testing
        };

        let limiter = SharedRateLimiter::new(session_manager, config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Exhaust limit
        assert!(limiter.check_rate_limit(ip).await);
        assert!(limiter.check_rate_limit(ip).await);
        assert!(!limiter.check_rate_limit(ip).await);

        // Wait for window to change
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be allowed again in new window
        assert!(limiter.check_rate_limit(ip).await);
    }

    #[tokio::test]
    async fn test_cluster_wide_limiting() {
        // Simulate two servers sharing the same backend
        let backend: Arc<dyn crate::state::StateBackend> = Arc::new(MemoryStateBackend::new());

        let session_manager1 = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));
        let config1 = SharedRateLimitConfig {
            per_client_limit: 3,
            global_limit: 0,
            window_duration: Duration::from_secs(1),
        };
        let limiter1 = SharedRateLimiter::new(session_manager1, config1);

        let session_manager2 = Arc::new(SharedSessionManager::new(Arc::clone(&backend)));
        let config2 = SharedRateLimitConfig {
            per_client_limit: 3,
            global_limit: 0,
            window_duration: Duration::from_secs(1),
        };
        let limiter2 = SharedRateLimiter::new(session_manager2, config2);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Server 1 receives 2 requests
        assert!(limiter1.check_rate_limit(ip).await);
        assert!(limiter1.check_rate_limit(ip).await);

        // Server 2 should see the limit is partially consumed (only 1 request left)
        assert!(limiter2.check_rate_limit(ip).await);

        // Both servers should now see limit exceeded
        assert!(!limiter1.check_rate_limit(ip).await);
        assert!(!limiter2.check_rate_limit(ip).await);
    }

    #[tokio::test]
    async fn test_get_client_count() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));

        let config = SharedRateLimitConfig {
            per_client_limit: 10,
            global_limit: 0,
            window_duration: Duration::from_secs(1),
        };

        let limiter = SharedRateLimiter::new(session_manager, config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Initial count should be 0
        assert_eq!(limiter.get_client_count(ip).await.unwrap(), 0);

        // Make 3 requests
        limiter.check_rate_limit(ip).await;
        limiter.check_rate_limit(ip).await;
        limiter.check_rate_limit(ip).await;

        // Count should be 3
        assert_eq!(limiter.get_client_count(ip).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_get_global_count() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));

        let config = SharedRateLimitConfig {
            per_client_limit: 0,
            global_limit: 100,
            window_duration: Duration::from_secs(1),
        };

        let limiter = SharedRateLimiter::new(session_manager, config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Initial count should be 0
        assert_eq!(limiter.get_global_count().await.unwrap(), 0);

        // Make requests from different IPs
        limiter.check_rate_limit(ip1).await;
        limiter.check_rate_limit(ip2).await;
        limiter.check_rate_limit(ip1).await;

        // Global count should be 3
        assert_eq!(limiter.get_global_count().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_no_limits() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));

        let config = SharedRateLimitConfig {
            per_client_limit: 0,
            global_limit: 0,
            window_duration: Duration::from_secs(1),
        };

        let limiter = SharedRateLimiter::new(session_manager, config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow unlimited requests
        for _ in 0..100 {
            assert!(limiter.check_rate_limit(ip).await);
        }
    }

    #[tokio::test]
    async fn test_get_stats() {
        let backend = Arc::new(MemoryStateBackend::new());
        let session_manager = Arc::new(SharedSessionManager::new(backend));

        let config = SharedRateLimitConfig {
            per_client_limit: 100,
            global_limit: 1000,
            window_duration: Duration::from_secs(60),
        };

        let limiter = SharedRateLimiter::new(session_manager, config);
        let stats = limiter.get_stats();

        assert_eq!(stats.per_client_limit, 100);
        assert_eq!(stats.global_limit, 1000);
        assert_eq!(stats.window_duration_secs, 60);
    }
}
