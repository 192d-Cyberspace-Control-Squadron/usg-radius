//! Rate limiting for RADIUS requests
//!
//! Implements token bucket rate limiting to prevent abuse and DoS attacks.
//! Supports both per-client and global rate limiting.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Rate limiter bucket for a single client or global limit
#[derive(Debug, Clone)]
struct Bucket {
    /// Number of tokens currently available
    tokens: f64,
    /// Maximum tokens the bucket can hold
    capacity: f64,
    /// Tokens added per second
    refill_rate: f64,
    /// Last time tokens were added
    last_refill: Instant,
}

impl Bucket {
    /// Create a new bucket
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Bucket {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume a token from the bucket
    ///
    /// Returns true if a token was available and consumed, false otherwise.
    fn try_consume(&mut self) -> bool {
        // Refill tokens based on time elapsed
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = elapsed * self.refill_rate;

        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_refill = now;

        // Try to consume a token
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Get current token count
    fn tokens(&self) -> f64 {
        self.tokens
    }
}

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per second per client (0 = unlimited)
    pub per_client_rps: u32,
    /// Burst capacity per client (allows temporary spikes)
    pub per_client_burst: u32,
    /// Maximum requests per second globally (0 = unlimited)
    pub global_rps: u32,
    /// Global burst capacity
    pub global_burst: u32,
    /// Maximum concurrent connections per client (0 = unlimited)
    pub max_concurrent_connections: u32,
    /// Maximum bandwidth in bytes per second per client (0 = unlimited)
    pub max_bandwidth_bps: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            per_client_rps: 100,             // 100 requests/sec per client
            per_client_burst: 200,           // Allow bursts up to 200
            global_rps: 1000,                // 1000 requests/sec globally
            global_burst: 2000,              // Allow bursts up to 2000
            max_concurrent_connections: 100, // 100 concurrent connections per client
            max_bandwidth_bps: 1_048_576,    // 1 MB/s per client
        }
    }
}

/// Connection tracking for a single client
#[derive(Debug, Clone)]
struct ConnectionTracker {
    /// Number of active connections
    active_connections: u32,
    /// Last activity timestamp
    last_activity: Instant,
}

impl ConnectionTracker {
    fn new() -> Self {
        ConnectionTracker {
            active_connections: 0,
            last_activity: Instant::now(),
        }
    }

    fn increment(&mut self) -> bool {
        self.active_connections += 1;
        self.last_activity = Instant::now();
        true
    }

    fn decrement(&mut self) {
        if self.active_connections > 0 {
            self.active_connections -= 1;
        }
        self.last_activity = Instant::now();
    }
}

/// Bandwidth tracking for a single client
#[derive(Debug, Clone)]
struct BandwidthTracker {
    /// Bytes consumed in current window
    bytes_consumed: u64,
    /// Window start time
    window_start: Instant,
    /// Bytes per second limit
    limit_bps: u64,
}

impl BandwidthTracker {
    fn new(limit_bps: u64) -> Self {
        BandwidthTracker {
            bytes_consumed: 0,
            window_start: Instant::now(),
            limit_bps,
        }
    }

    /// Try to consume bandwidth
    ///
    /// Returns true if bandwidth is available, false if limit exceeded
    fn try_consume(&mut self, bytes: u64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start).as_secs_f64();

        // Reset window if more than 1 second has passed
        if elapsed >= 1.0 {
            self.bytes_consumed = 0;
            self.window_start = now;
        }

        // Check if adding these bytes would exceed the limit
        if self.bytes_consumed + bytes <= self.limit_bps {
            self.bytes_consumed += bytes;
            true
        } else {
            false
        }
    }
}

/// Token bucket rate limiter
///
/// Implements the token bucket algorithm for rate limiting.
/// Supports both per-client and global rate limiting, concurrent
/// connection tracking, and bandwidth throttling.
pub struct RateLimiter {
    /// Per-client rate limit buckets
    client_buckets: Arc<DashMap<IpAddr, Bucket>>,
    /// Global rate limit bucket
    global_bucket: Option<Arc<tokio::sync::Mutex<Bucket>>>,
    /// Per-client connection tracking
    connection_trackers: Arc<DashMap<IpAddr, ConnectionTracker>>,
    /// Per-client bandwidth tracking
    bandwidth_trackers: Arc<DashMap<IpAddr, BandwidthTracker>>,
    /// Configuration
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        // Create global bucket if global rate limiting is enabled
        let global_bucket = if config.global_rps > 0 {
            Some(Arc::new(tokio::sync::Mutex::new(Bucket::new(
                config.global_burst as f64,
                config.global_rps as f64,
            ))))
        } else {
            None
        };

        RateLimiter {
            client_buckets: Arc::new(DashMap::new()),
            global_bucket,
            connection_trackers: Arc::new(DashMap::new()),
            bandwidth_trackers: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Check if a request from the given IP should be allowed
    ///
    /// Returns true if the request is within rate limits, false otherwise.
    pub async fn check_rate_limit(&self, client_ip: IpAddr) -> bool {
        // Check global rate limit first
        if let Some(ref global_bucket) = self.global_bucket {
            let mut bucket = global_bucket.lock().await;
            if !bucket.try_consume() {
                return false;
            }
        }

        // Check per-client rate limit
        if self.config.per_client_rps > 0 {
            let mut entry = self.client_buckets.entry(client_ip).or_insert_with(|| {
                Bucket::new(
                    self.config.per_client_burst as f64,
                    self.config.per_client_rps as f64,
                )
            });

            if !entry.try_consume() {
                return false;
            }
        }

        true
    }

    /// Get statistics for a specific client
    pub fn get_client_stats(&self, client_ip: IpAddr) -> Option<ClientStats> {
        self.client_buckets.get(&client_ip).map(|entry| {
            let bucket = entry.value();
            ClientStats {
                current_tokens: bucket.tokens(),
                capacity: bucket.capacity,
                refill_rate: bucket.refill_rate,
            }
        })
    }

    /// Get global rate limiter statistics
    pub fn get_global_stats(&self) -> Option<GlobalStats> {
        // This is a bit awkward due to async Mutex, but we can provide basic info
        if self.global_bucket.is_some() {
            Some(GlobalStats {
                enabled: true,
                capacity: self.config.global_burst as f64,
                refill_rate: self.config.global_rps as f64,
            })
        } else {
            None
        }
    }

    /// Track a new connection from the given IP
    ///
    /// Returns true if the connection is allowed, false if concurrent limit exceeded
    pub fn track_connection(&self, client_ip: IpAddr) -> bool {
        // Skip if no limit configured
        if self.config.max_concurrent_connections == 0 {
            return true;
        }

        let mut entry = self
            .connection_trackers
            .entry(client_ip)
            .or_insert_with(ConnectionTracker::new);

        // Check if adding this connection would exceed the limit
        if entry.active_connections >= self.config.max_concurrent_connections {
            return false;
        }

        entry.increment()
    }

    /// Release a connection from the given IP
    pub fn release_connection(&self, client_ip: IpAddr) {
        if let Some(mut entry) = self.connection_trackers.get_mut(&client_ip) {
            entry.decrement();
        }
    }

    /// Get current connection count for a client
    pub fn get_connection_count(&self, client_ip: IpAddr) -> u32 {
        self.connection_trackers
            .get(&client_ip)
            .map(|entry| entry.active_connections)
            .unwrap_or(0)
    }

    /// Check if bandwidth is available for this request
    ///
    /// Returns true if bandwidth is available, false if limit exceeded
    pub fn check_bandwidth(&self, client_ip: IpAddr, bytes: u64) -> bool {
        // Skip if no limit configured
        if self.config.max_bandwidth_bps == 0 {
            return true;
        }

        let mut entry = self
            .bandwidth_trackers
            .entry(client_ip)
            .or_insert_with(|| BandwidthTracker::new(self.config.max_bandwidth_bps));

        entry.try_consume(bytes)
    }

    /// Get current bandwidth usage for a client
    pub fn get_bandwidth_usage(&self, client_ip: IpAddr) -> Option<BandwidthStats> {
        self.bandwidth_trackers.get(&client_ip).map(|entry| {
            let tracker = entry.value();
            BandwidthStats {
                bytes_consumed: tracker.bytes_consumed,
                limit_bps: tracker.limit_bps,
                window_start: tracker.window_start,
            }
        })
    }

    /// Clean up old client buckets that haven't been used recently
    ///
    /// Should be called periodically to prevent memory growth
    pub fn cleanup_old_buckets(&self, max_age: Duration) {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        // Clean up rate limit buckets
        for entry in self.client_buckets.iter() {
            let age = now.duration_since(entry.value().last_refill);
            if age > max_age {
                to_remove.push(*entry.key());
            }
        }

        for ip in &to_remove {
            self.client_buckets.remove(ip);
        }

        // Clean up connection trackers (only if no active connections)
        to_remove.clear();
        for entry in self.connection_trackers.iter() {
            let age = now.duration_since(entry.value().last_activity);
            if age > max_age && entry.value().active_connections == 0 {
                to_remove.push(*entry.key());
            }
        }

        for ip in &to_remove {
            self.connection_trackers.remove(ip);
        }

        // Clean up bandwidth trackers
        to_remove.clear();
        for entry in self.bandwidth_trackers.iter() {
            let age = now.duration_since(entry.value().window_start);
            if age > max_age {
                to_remove.push(*entry.key());
            }
        }

        for ip in to_remove {
            self.bandwidth_trackers.remove(&ip);
        }
    }

    /// Get the number of tracked clients
    pub fn client_count(&self) -> usize {
        self.client_buckets.len()
    }
}

/// Bandwidth usage statistics
#[derive(Debug, Clone)]
pub struct BandwidthStats {
    pub bytes_consumed: u64,
    pub limit_bps: u64,
    pub window_start: Instant,
}

/// Client rate limit statistics
#[derive(Debug, Clone)]
pub struct ClientStats {
    pub current_tokens: f64,
    pub capacity: f64,
    pub refill_rate: f64,
}

/// Global rate limit statistics
#[derive(Debug, Clone)]
pub struct GlobalStats {
    pub enabled: bool,
    pub capacity: f64,
    pub refill_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_bucket_creation() {
        let bucket = Bucket::new(100.0, 10.0);
        assert_eq!(bucket.capacity, 100.0);
        assert_eq!(bucket.refill_rate, 10.0);
        assert_eq!(bucket.tokens, 100.0);
    }

    #[test]
    fn test_bucket_consume() {
        let mut bucket = Bucket::new(10.0, 1.0);
        assert!(bucket.try_consume());
        assert!((bucket.tokens() - 9.0).abs() < 0.1); // Allow for time-based refill
        assert!(bucket.try_consume());
        assert!((bucket.tokens() - 8.0).abs() < 0.1); // Allow for time-based refill
    }

    #[test]
    fn test_bucket_empty() {
        let mut bucket = Bucket::new(2.0, 1.0);
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(!bucket.try_consume()); // Should fail - bucket empty
    }

    #[test]
    fn test_bucket_refill() {
        let mut bucket = Bucket::new(10.0, 10.0); // 10 tokens/sec
        bucket.try_consume();
        assert_eq!(bucket.tokens(), 9.0);

        // Wait 100ms = 0.1 sec = 1 token
        thread::sleep(Duration::from_millis(110));

        bucket.try_consume();
        // Should have refilled ~1 token, so should have ~9 tokens after consuming
        assert!(bucket.tokens() >= 8.5 && bucket.tokens() <= 9.5);
    }

    #[test]
    fn test_bucket_max_capacity() {
        let mut bucket = Bucket::new(10.0, 100.0);
        // Wait for refill
        thread::sleep(Duration::from_millis(200));

        // Try to refill - should not exceed capacity
        bucket.try_consume();
        assert!(bucket.tokens() <= 10.0);
    }

    #[tokio::test]
    async fn test_rate_limiter_per_client() {
        let config = RateLimitConfig {
            per_client_rps: 10,
            per_client_burst: 5,
            global_rps: 0,
            global_burst: 0,
            max_concurrent_connections: 0,
            max_bandwidth_bps: 0,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow 5 requests (burst capacity)
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip).await);
        }

        // 6th request should be denied
        assert!(!limiter.check_rate_limit(ip).await);
    }

    #[tokio::test]
    async fn test_rate_limiter_different_clients() {
        let config = RateLimitConfig {
            per_client_rps: 10,
            per_client_burst: 2,
            global_rps: 0,
            global_burst: 0,
            max_concurrent_connections: 0,
            max_bandwidth_bps: 0,
        };

        let limiter = RateLimiter::new(config);
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
    async fn test_rate_limiter_global() {
        let config = RateLimitConfig {
            per_client_rps: 100,
            per_client_burst: 100,
            global_rps: 10,
            global_burst: 3,
            max_concurrent_connections: 0,
            max_bandwidth_bps: 0,
        };

        let limiter = RateLimiter::new(config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Global limit should apply across all clients
        assert!(limiter.check_rate_limit(ip1).await);
        assert!(limiter.check_rate_limit(ip2).await);
        assert!(limiter.check_rate_limit(ip1).await);

        // 4th request should hit global limit
        assert!(!limiter.check_rate_limit(ip2).await);
    }

    #[tokio::test]
    async fn test_rate_limiter_no_limits() {
        let config = RateLimitConfig {
            per_client_rps: 0,
            per_client_burst: 0,
            global_rps: 0,
            global_burst: 0,
            max_concurrent_connections: 0,
            max_bandwidth_bps: 0,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow unlimited requests
        for _ in 0..100 {
            assert!(limiter.check_rate_limit(ip).await);
        }
    }

    #[test]
    fn test_rate_limiter_client_stats() {
        let config = RateLimitConfig {
            per_client_rps: 10,
            per_client_burst: 20,
            global_rps: 0,
            global_burst: 0,
            max_concurrent_connections: 0,
            max_bandwidth_bps: 0,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Before any requests
        assert!(limiter.get_client_stats(ip).is_none());

        // After a request (using tokio::runtime::Runtime for sync test)
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            limiter.check_rate_limit(ip).await;
        });

        // Should have stats now
        let stats = limiter.get_client_stats(ip).unwrap();
        assert_eq!(stats.capacity, 20.0);
        assert_eq!(stats.refill_rate, 10.0);
        assert!(stats.current_tokens < 20.0); // One consumed
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let ip1: IpAddr = "192.168.1.1".parse().unwrap();
            let ip2: IpAddr = "192.168.1.2".parse().unwrap();

            limiter.check_rate_limit(ip1).await;
            limiter.check_rate_limit(ip2).await;

            assert_eq!(limiter.client_count(), 2);

            // Cleanup should remove nothing (buckets are fresh)
            limiter.cleanup_old_buckets(Duration::from_secs(60));
            assert_eq!(limiter.client_count(), 2);

            // Cleanup with 0 duration should remove all
            limiter.cleanup_old_buckets(Duration::from_secs(0));
            assert_eq!(limiter.client_count(), 0);
        });
    }

    #[test]
    fn test_connection_tracker_creation() {
        let tracker = ConnectionTracker::new();
        assert_eq!(tracker.active_connections, 0);
    }

    #[test]
    fn test_connection_tracker_increment() {
        let mut tracker = ConnectionTracker::new();
        assert!(tracker.increment());
        assert_eq!(tracker.active_connections, 1);

        assert!(tracker.increment());
        assert_eq!(tracker.active_connections, 2);
    }

    #[test]
    fn test_connection_tracker_decrement() {
        let mut tracker = ConnectionTracker::new();
        tracker.increment();
        tracker.increment();
        assert_eq!(tracker.active_connections, 2);

        tracker.decrement();
        assert_eq!(tracker.active_connections, 1);

        tracker.decrement();
        assert_eq!(tracker.active_connections, 0);

        // Shouldn't go negative
        tracker.decrement();
        assert_eq!(tracker.active_connections, 0);
    }

    #[test]
    fn test_bandwidth_tracker_creation() {
        let tracker = BandwidthTracker::new(1_000_000); // 1 MB/s
        assert_eq!(tracker.bytes_consumed, 0);
        assert_eq!(tracker.limit_bps, 1_000_000);
    }

    #[test]
    fn test_bandwidth_tracker_consume() {
        let mut tracker = BandwidthTracker::new(1_000_000); // 1 MB/s

        // Should allow consumption within limit
        assert!(tracker.try_consume(100_000)); // 100 KB
        assert_eq!(tracker.bytes_consumed, 100_000);

        assert!(tracker.try_consume(200_000)); // 200 KB more
        assert_eq!(tracker.bytes_consumed, 300_000);
    }

    #[test]
    fn test_bandwidth_tracker_limit() {
        let mut tracker = BandwidthTracker::new(1_000_000); // 1 MB/s

        // Consume up to limit
        assert!(tracker.try_consume(900_000));
        assert_eq!(tracker.bytes_consumed, 900_000);

        // Should allow small amount
        assert!(tracker.try_consume(100_000));
        assert_eq!(tracker.bytes_consumed, 1_000_000);

        // Should fail when limit exceeded
        assert!(!tracker.try_consume(1));
        assert_eq!(tracker.bytes_consumed, 1_000_000);
    }

    #[test]
    fn test_bandwidth_tracker_window_reset() {
        let mut tracker = BandwidthTracker::new(1_000_000); // 1 MB/s

        // Fill to limit
        assert!(tracker.try_consume(1_000_000));
        assert!(!tracker.try_consume(1)); // Should fail

        // Wait for window to reset (1 second + buffer)
        thread::sleep(Duration::from_millis(1100));

        // Should work again after window reset
        assert!(tracker.try_consume(100_000));
        assert_eq!(tracker.bytes_consumed, 100_000);
    }

    #[test]
    fn test_rate_limiter_track_connection() {
        let config = RateLimitConfig {
            per_client_rps: 10,
            per_client_burst: 10,
            global_rps: 0,
            global_burst: 0,
            max_concurrent_connections: 5,
            max_bandwidth_bps: 0,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow up to 5 connections
        for _ in 0..5 {
            assert!(limiter.track_connection(ip));
        }
        assert_eq!(limiter.get_connection_count(ip), 5);

        // 6th connection should fail
        assert!(!limiter.track_connection(ip));
        assert_eq!(limiter.get_connection_count(ip), 5);
    }

    #[test]
    fn test_rate_limiter_release_connection() {
        let config = RateLimitConfig {
            per_client_rps: 10,
            per_client_burst: 10,
            global_rps: 0,
            global_burst: 0,
            max_concurrent_connections: 2,
            max_bandwidth_bps: 0,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Track 2 connections (at limit)
        assert!(limiter.track_connection(ip));
        assert!(limiter.track_connection(ip));
        assert!(!limiter.track_connection(ip)); // Should fail

        // Release one connection
        limiter.release_connection(ip);
        assert_eq!(limiter.get_connection_count(ip), 1);

        // Should be able to track again
        assert!(limiter.track_connection(ip));
        assert_eq!(limiter.get_connection_count(ip), 2);
    }

    #[test]
    fn test_rate_limiter_check_bandwidth() {
        let config = RateLimitConfig {
            per_client_rps: 100,
            per_client_burst: 100,
            global_rps: 0,
            global_burst: 0,
            max_concurrent_connections: 0,
            max_bandwidth_bps: 1_000_000, // 1 MB/s
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow consumption within limit
        assert!(limiter.check_bandwidth(ip, 500_000)); // 500 KB
        assert!(limiter.check_bandwidth(ip, 300_000)); // 300 KB more

        // Should fail when exceeding limit
        assert!(!limiter.check_bandwidth(ip, 300_000)); // Would exceed 1 MB
    }

    #[test]
    fn test_rate_limiter_bandwidth_stats() {
        let config = RateLimitConfig {
            per_client_rps: 100,
            per_client_burst: 100,
            global_rps: 0,
            global_burst: 0,
            max_concurrent_connections: 0,
            max_bandwidth_bps: 1_000_000,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // No stats before any bandwidth checks
        assert!(limiter.get_bandwidth_usage(ip).is_none());

        // Consume some bandwidth
        limiter.check_bandwidth(ip, 250_000);

        // Should have stats now
        let stats = limiter.get_bandwidth_usage(ip).unwrap();
        assert_eq!(stats.bytes_consumed, 250_000);
        assert_eq!(stats.limit_bps, 1_000_000);
    }

    #[test]
    fn test_rate_limiter_no_connection_limit() {
        let config = RateLimitConfig {
            per_client_rps: 10,
            per_client_burst: 10,
            global_rps: 0,
            global_burst: 0,
            max_concurrent_connections: 0, // No limit
            max_bandwidth_bps: 0,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow unlimited connections when set to 0
        for _ in 0..100 {
            assert!(limiter.track_connection(ip));
        }
        // When limit is 0 (unlimited), connections are not tracked
        assert_eq!(limiter.get_connection_count(ip), 0);
    }

    #[test]
    fn test_rate_limiter_no_bandwidth_limit() {
        let config = RateLimitConfig {
            per_client_rps: 100,
            per_client_burst: 100,
            global_rps: 0,
            global_burst: 0,
            max_concurrent_connections: 0,
            max_bandwidth_bps: 0, // No limit
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow unlimited bandwidth when set to 0
        for _ in 0..100 {
            assert!(limiter.check_bandwidth(ip, 1_000_000));
        }
    }

    #[test]
    fn test_rate_limiter_cleanup_trackers() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Track connection and bandwidth
        limiter.track_connection(ip);
        limiter.check_bandwidth(ip, 1000);

        // Release connection so it can be cleaned up
        limiter.release_connection(ip);

        // Cleanup with 0 duration should remove old trackers
        limiter.cleanup_old_buckets(Duration::from_secs(0));

        // Counts should be reset after cleanup
        assert_eq!(limiter.get_connection_count(ip), 0);
        assert!(limiter.get_bandwidth_usage(ip).is_none());
    }
}
