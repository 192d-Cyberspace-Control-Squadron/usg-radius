//! In-memory state backend implementation

use super::{StateBackend, StateError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// In-memory state backend
///
/// This backend stores all data in local memory using a HashMap.
/// It does not provide high availability or persistence.
///
/// # Use Cases
///
/// - Single-server deployments (no HA)
/// - Development and testing
/// - Low-latency local caching
///
/// # Thread Safety
///
/// Uses `tokio::sync::RwLock` for concurrent access from multiple async tasks.
#[derive(Debug, Clone)]
pub struct MemoryStateBackend {
    store: Arc<RwLock<HashMap<String, StoredValue>>>,
}

#[derive(Debug, Clone)]
struct StoredValue {
    data: Vec<u8>,
    expires_at: Option<SystemTime>,
}

impl StoredValue {
    fn new(data: Vec<u8>, ttl: Option<Duration>) -> Self {
        let expires_at = ttl.map(|duration| SystemTime::now() + duration);
        Self { data, expires_at }
    }

    fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            SystemTime::now() > expires_at
        } else {
            false
        }
    }
}

impl Default for MemoryStateBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStateBackend {
    /// Create a new in-memory state backend
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Remove expired entries (garbage collection)
    ///
    /// This should be called periodically to prevent memory leaks.
    pub async fn cleanup_expired(&self) {
        let mut store = self.store.write().await;
        store.retain(|_, value| !value.is_expired());
    }

    /// Get the number of stored keys (including expired)
    pub async fn len(&self) -> usize {
        let store = self.store.read().await;
        store.len()
    }

    /// Check if the store is empty
    pub async fn is_empty(&self) -> bool {
        let store = self.store.read().await;
        store.is_empty()
    }

    /// Clear all stored data
    pub async fn clear(&self) {
        let mut store = self.store.write().await;
        store.clear();
    }
}

#[async_trait]
impl StateBackend for MemoryStateBackend {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StateError> {
        let store = self.store.read().await;

        if let Some(value) = store.get(key) {
            if value.is_expired() {
                // Don't return expired values
                Ok(None)
            } else {
                Ok(Some(value.data.clone()))
            }
        } else {
            Ok(None)
        }
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<(), StateError> {
        let mut store = self.store.write().await;
        let stored_value = StoredValue::new(value.to_vec(), ttl);
        store.insert(key.to_string(), stored_value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StateError> {
        let mut store = self.store.write().await;
        store.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, StateError> {
        let store = self.store.read().await;

        if let Some(value) = store.get(key) {
            Ok(!value.is_expired())
        } else {
            Ok(false)
        }
    }

    async fn keys(&self, pattern: &str) -> Result<Vec<String>, StateError> {
        let store = self.store.read().await;

        // Simple glob pattern matching
        let regex_pattern = pattern
            .replace(".", "\\.")
            .replace("*", ".*")
            .replace("?", ".");

        let regex = regex::Regex::new(&format!("^{}$", regex_pattern))
            .map_err(|e| StateError::InvalidInput(format!("Invalid pattern: {}", e)))?;

        let matching_keys: Vec<String> = store
            .iter()
            .filter(|(key, value)| !value.is_expired() && regex.is_match(key))
            .map(|(key, _)| key.clone())
            .collect();

        Ok(matching_keys)
    }

    async fn set_nx(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Result<bool, StateError> {
        let mut store = self.store.write().await;

        // Check if key exists and is not expired
        if let Some(existing) = store.get(key) {
            if !existing.is_expired() {
                return Ok(false); // Key already exists
            }
        }

        // Set the key
        let stored_value = StoredValue::new(value.to_vec(), ttl);
        store.insert(key.to_string(), stored_value);
        Ok(true)
    }

    async fn incr(&self, key: &str) -> Result<i64, StateError> {
        let mut store = self.store.write().await;

        // Get current value or default to 0
        let current_value = if let Some(value) = store.get(key) {
            if value.is_expired() {
                0
            } else {
                // Parse as i64
                let s = String::from_utf8(value.data.clone())
                    .map_err(|e| StateError::SerializationError(format!("Not UTF-8: {}", e)))?;
                s.parse::<i64>()
                    .map_err(|e| StateError::SerializationError(format!("Not an integer: {}", e)))?
            }
        } else {
            0
        };

        // Increment
        let new_value = current_value + 1;

        // Store new value (no expiration for counters by default)
        let stored_value = StoredValue::new(new_value.to_string().into_bytes(), None);
        store.insert(key.to_string(), stored_value);

        Ok(new_value)
    }

    async fn expire(&self, key: &str, ttl: Duration) -> Result<bool, StateError> {
        let mut store = self.store.write().await;

        if let Some(value) = store.get_mut(key) {
            if value.is_expired() {
                return Ok(false);
            }

            value.expires_at = Some(SystemTime::now() + ttl);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn ping(&self) -> Result<(), StateError> {
        // In-memory backend is always available
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_new() {
        let backend = MemoryStateBackend::new();
        assert!(backend.is_empty().await);
    }

    #[tokio::test]
    async fn test_set_get() {
        let backend = MemoryStateBackend::new();

        backend.set("key1", b"value1", None).await.unwrap();

        let result = backend.get("key1").await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let backend = MemoryStateBackend::new();

        let result = backend.get("nonexistent").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_delete() {
        let backend = MemoryStateBackend::new();

        backend.set("key1", b"value1", None).await.unwrap();
        backend.delete("key1").await.unwrap();

        let result = backend.get("key1").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_exists() {
        let backend = MemoryStateBackend::new();

        assert!(!backend.exists("key1").await.unwrap());

        backend.set("key1", b"value1", None).await.unwrap();

        assert!(backend.exists("key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let backend = MemoryStateBackend::new();

        // Set with 100ms TTL
        backend
            .set("key1", b"value1", Some(Duration::from_millis(100)))
            .await
            .unwrap();

        // Should exist immediately
        assert!(backend.exists("key1").await.unwrap());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be expired
        assert!(!backend.exists("key1").await.unwrap());
        let result = backend.get("key1").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_keys_pattern() {
        let backend = MemoryStateBackend::new();

        backend.set("session:123", b"v1", None).await.unwrap();
        backend.set("session:456", b"v2", None).await.unwrap();
        backend.set("cache:789", b"v3", None).await.unwrap();

        let mut keys = backend.keys("session:*").await.unwrap();
        keys.sort();

        assert_eq!(keys, vec!["session:123", "session:456"]);
    }

    #[tokio::test]
    async fn test_set_nx() {
        let backend = MemoryStateBackend::new();

        // First set should succeed
        let result = backend.set_nx("key1", b"value1", None).await.unwrap();
        assert!(result);

        // Second set should fail (key exists)
        let result = backend.set_nx("key1", b"value2", None).await.unwrap();
        assert!(!result);

        // Value should be unchanged
        let value = backend.get("key1").await.unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_set_nx_expired() {
        let backend = MemoryStateBackend::new();

        // Set with short TTL
        backend
            .set("key1", b"value1", Some(Duration::from_millis(50)))
            .await
            .unwrap();

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // SET NX should succeed on expired key
        let result = backend.set_nx("key1", b"value2", None).await.unwrap();
        assert!(result);

        let value = backend.get("key1").await.unwrap();
        assert_eq!(value, Some(b"value2".to_vec()));
    }

    #[tokio::test]
    async fn test_incr() {
        let backend = MemoryStateBackend::new();

        // First increment (0 -> 1)
        let result = backend.incr("counter").await.unwrap();
        assert_eq!(result, 1);

        // Second increment (1 -> 2)
        let result = backend.incr("counter").await.unwrap();
        assert_eq!(result, 2);

        // Third increment (2 -> 3)
        let result = backend.incr("counter").await.unwrap();
        assert_eq!(result, 3);
    }

    #[tokio::test]
    async fn test_expire() {
        let backend = MemoryStateBackend::new();

        // Set without expiration
        backend.set("key1", b"value1", None).await.unwrap();

        // Add expiration
        let result = backend
            .expire("key1", Duration::from_millis(100))
            .await
            .unwrap();
        assert!(result);

        // Should exist immediately
        assert!(backend.exists("key1").await.unwrap());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be expired
        assert!(!backend.exists("key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_expire_nonexistent() {
        let backend = MemoryStateBackend::new();

        let result = backend
            .expire("nonexistent", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let backend = MemoryStateBackend::new();

        backend
            .set("key1", b"v1", Some(Duration::from_millis(50)))
            .await
            .unwrap();
        backend.set("key2", b"v2", None).await.unwrap();

        assert_eq!(backend.len().await, 2);

        // Wait for one to expire
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Before cleanup, both entries still in map
        assert_eq!(backend.len().await, 2);

        // After cleanup, only non-expired entry remains
        backend.cleanup_expired().await;
        assert_eq!(backend.len().await, 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let backend = MemoryStateBackend::new();

        backend.set("key1", b"v1", None).await.unwrap();
        backend.set("key2", b"v2", None).await.unwrap();

        assert_eq!(backend.len().await, 2);

        backend.clear().await;

        assert_eq!(backend.len().await, 0);
        assert!(backend.is_empty().await);
    }

    #[tokio::test]
    async fn test_ping() {
        let backend = MemoryStateBackend::new();

        // Should always succeed
        backend.ping().await.unwrap();
    }
}
