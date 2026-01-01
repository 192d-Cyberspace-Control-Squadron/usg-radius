//! Valkey/Redis state backend implementation

use super::config::ValkeyConfig;
use super::{StateBackend, StateError};
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client, RedisError};
use std::time::Duration;

/// Valkey/Redis state backend
///
/// This backend stores data in a Valkey (or Redis) server, enabling
/// distributed state sharing across multiple RADIUS server instances.
///
/// # Features
///
/// - Connection pooling via `ConnectionManager`
/// - Automatic reconnection on connection loss
/// - Configurable timeouts and retries
/// - Key prefix for namespace isolation
///
/// # Connection URL Format
///
/// - `redis://host:port` - TCP connection
/// - `redis://host:port/db` - TCP with database selection
/// - `unix:///path/to/socket` - Unix socket
/// - `rediss://host:port` - TLS connection
///
/// # Example
///
/// ```no_run
/// use radius_server::state::{ValkeyStateBackend, ValkeyConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ValkeyConfig::new("redis://localhost:6379")
///     .with_key_prefix("usg-radius:");
///
/// let backend = ValkeyStateBackend::new(config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct ValkeyStateBackend {
    conn: ConnectionManager,
    config: ValkeyConfig,
}

impl ValkeyStateBackend {
    /// Create a new Valkey state backend
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Connection URL is invalid
    /// - Cannot connect to Valkey server
    /// - Authentication fails
    pub async fn new(config: ValkeyConfig) -> Result<Self, StateError> {
        // Parse connection URL
        let client = Client::open(config.url.clone())
            .map_err(|e| StateError::ConfigError(format!("Invalid Valkey URL: {}", e)))?;

        // Create connection manager (handles pooling and reconnection)
        let conn = ConnectionManager::new(client)
            .await
            .map_err(|e| StateError::ConnectionError(format!("Failed to connect to Valkey: {}", e)))?;

        Ok(Self { conn, config })
    }

    /// Get the full key with prefix
    fn prefixed_key(&self, key: &str) -> String {
        format!("{}{}", self.config.key_prefix, key)
    }

    /// Remove prefix from key
    fn unprefixed_key(&self, key: &str) -> String {
        key.strip_prefix(&self.config.key_prefix)
            .unwrap_or(key)
            .to_string()
    }

    /// Execute a command with retry logic
    async fn with_retry<F, T>(&self, mut f: F) -> Result<T, StateError>
    where
        F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, RedisError>> + Send>>,
    {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match f().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);

                    // Don't retry on the last attempt
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(self.config.retry_delay()).await;
                    }
                }
            }
        }

        Err(last_error.unwrap().into())
    }
}

#[async_trait]
impl StateBackend for ValkeyStateBackend {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StateError> {
        let prefixed_key = self.prefixed_key(key);
        let conn = self.conn.clone();

        self.with_retry(|| {
            let prefixed_key = prefixed_key.clone();
            let mut conn = conn.clone();
            Box::pin(async move {
                conn.get(&prefixed_key).await
            })
        })
        .await
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<(), StateError> {
        let prefixed_key = self.prefixed_key(key);
        let conn = self.conn.clone();
        let value = value.to_vec();

        self.with_retry(|| {
            let value = value.clone();
            let prefixed_key = prefixed_key.clone();
            let mut conn = conn.clone();
            Box::pin(async move {
                if let Some(ttl) = ttl {
                    // SET with expiration (EX for seconds)
                    let ttl_secs = ttl.as_secs().max(1); // Minimum 1 second
                    redis::cmd("SET")
                        .arg(&prefixed_key)
                        .arg(&value)
                        .arg("EX")
                        .arg(ttl_secs)
                        .query_async(&mut conn)
                        .await
                } else {
                    // SET without expiration
                    conn.set(&prefixed_key, &value).await
                }
            })
        })
        .await
    }

    async fn delete(&self, key: &str) -> Result<(), StateError> {
        let prefixed_key = self.prefixed_key(key);
        let conn = self.conn.clone();

        self.with_retry(|| {
            let prefixed_key = prefixed_key.clone();
            let mut conn = conn.clone();
            Box::pin(async move {
                conn.del(&prefixed_key).await
            })
        })
        .await
    }

    async fn exists(&self, key: &str) -> Result<bool, StateError> {
        let prefixed_key = self.prefixed_key(key);
        let conn = self.conn.clone();

        self.with_retry(|| {
            let prefixed_key = prefixed_key.clone();
            let mut conn = conn.clone();
            Box::pin(async move {
                conn.exists(&prefixed_key).await
            })
        })
        .await
    }

    async fn keys(&self, pattern: &str) -> Result<Vec<String>, StateError> {
        let prefixed_pattern = self.prefixed_key(pattern);
        let conn = self.conn.clone();

        let keys: Vec<String> = self
            .with_retry(|| {
                let prefixed_pattern = prefixed_pattern.clone();
                let mut conn = conn.clone();
                Box::pin(async move {
                    conn.keys(&prefixed_pattern).await
                })
            })
            .await?;

        // Remove prefix from returned keys
        let unprefixed_keys = keys
            .into_iter()
            .map(|k| self.unprefixed_key(&k))
            .collect();

        Ok(unprefixed_keys)
    }

    async fn set_nx(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<bool, StateError> {
        let prefixed_key = self.prefixed_key(key);
        let conn = self.conn.clone();
        let value = value.to_vec();

        self.with_retry(|| {
            let value = value.clone();
            let prefixed_key = prefixed_key.clone();
            let mut conn = conn.clone();
            Box::pin(async move {
                if let Some(ttl) = ttl {
                    // SET NX with expiration
                    let ttl_secs = ttl.as_secs().max(1);
                    redis::cmd("SET")
                        .arg(&prefixed_key)
                        .arg(&value)
                        .arg("EX")
                        .arg(ttl_secs)
                        .arg("NX")
                        .query_async(&mut conn)
                        .await
                } else {
                    // SET NX without expiration
                    conn.set_nx(&prefixed_key, &value).await
                }
            })
        })
        .await
    }

    async fn incr(&self, key: &str) -> Result<i64, StateError> {
        let prefixed_key = self.prefixed_key(key);
        let conn = self.conn.clone();

        self.with_retry(|| {
            let prefixed_key = prefixed_key.clone();
            let mut conn = conn.clone();
            Box::pin(async move {
                conn.incr(&prefixed_key, 1).await
            })
        })
        .await
    }

    async fn expire(&self, key: &str, ttl: Duration) -> Result<bool, StateError> {
        let prefixed_key = self.prefixed_key(key);
        let conn = self.conn.clone();
        let ttl_secs = ttl.as_secs().max(1);

        self.with_retry(|| {
            let prefixed_key = prefixed_key.clone();
            let mut conn = conn.clone();
            Box::pin(async move {
                conn.expire(&prefixed_key, ttl_secs as i64).await
            })
        })
        .await
    }

    async fn ping(&self) -> Result<(), StateError> {
        let conn = self.conn.clone();

        self.with_retry(|| {
            let mut conn = conn.clone();
            Box::pin(async move {
                redis::cmd("PING").query_async(&mut conn).await
            })
        })
        .await
    }
}

impl std::fmt::Debug for ValkeyStateBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValkeyStateBackend")
            .field("url", &self.config.url)
            .field("key_prefix", &self.config.key_prefix)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running Valkey/Redis instance
    // Run with: docker run -d -p 6379:6379 valkey/valkey:latest
    // Or: redis-server

    async fn create_test_backend() -> ValkeyStateBackend {
        let config = ValkeyConfig::new("redis://localhost:6379")
            .with_key_prefix("test:");

        ValkeyStateBackend::new(config).await.unwrap()
    }

    #[tokio::test]
    #[ignore] // Requires Valkey server
    async fn test_connection() {
        let backend = create_test_backend().await;
        backend.ping().await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Requires Valkey server
    async fn test_set_get() {
        let backend = create_test_backend().await;

        backend.set("test_key", b"test_value", None).await.unwrap();

        let result = backend.get("test_key").await.unwrap();
        assert_eq!(result, Some(b"test_value".to_vec()));

        // Cleanup
        backend.delete("test_key").await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Requires Valkey server
    async fn test_ttl() {
        let backend = create_test_backend().await;

        backend
            .set("ttl_key", b"value", Some(Duration::from_secs(1)))
            .await
            .unwrap();

        // Should exist immediately
        assert!(backend.exists("ttl_key").await.unwrap());

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should be expired
        assert!(!backend.exists("ttl_key").await.unwrap());
    }

    #[tokio::test]
    #[ignore] // Requires Valkey server
    async fn test_set_nx() {
        let backend = create_test_backend().await;

        // First set should succeed
        let result = backend.set_nx("nx_key", b"value1", None).await.unwrap();
        assert!(result);

        // Second set should fail
        let result = backend.set_nx("nx_key", b"value2", None).await.unwrap();
        assert!(!result);

        // Value should be unchanged
        let value = backend.get("nx_key").await.unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));

        // Cleanup
        backend.delete("nx_key").await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Requires Valkey server
    async fn test_incr() {
        let backend = create_test_backend().await;

        let val1 = backend.incr("counter").await.unwrap();
        assert_eq!(val1, 1);

        let val2 = backend.incr("counter").await.unwrap();
        assert_eq!(val2, 2);

        // Cleanup
        backend.delete("counter").await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Requires Valkey server
    async fn test_keys_pattern() {
        let backend = create_test_backend().await;

        backend.set("session:123", b"v1", None).await.unwrap();
        backend.set("session:456", b"v2", None).await.unwrap();
        backend.set("cache:789", b"v3", None).await.unwrap();

        let mut keys = backend.keys("session:*").await.unwrap();
        keys.sort();

        assert_eq!(keys, vec!["session:123", "session:456"]);

        // Cleanup
        backend.delete("session:123").await.unwrap();
        backend.delete("session:456").await.unwrap();
        backend.delete("cache:789").await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Requires Valkey server
    async fn test_expire() {
        let backend = create_test_backend().await;

        backend.set("exp_key", b"value", None).await.unwrap();

        let result = backend.expire("exp_key", Duration::from_secs(1)).await.unwrap();
        assert!(result);

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(!backend.exists("exp_key").await.unwrap());
    }
}
