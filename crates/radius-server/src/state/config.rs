//! State backend configuration

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Type of state backend to use
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StateBackendType {
    /// In-memory state backend (default, no HA)
    #[default]
    InMemory,

    /// Valkey/Redis state backend (for HA)
    #[cfg(feature = "ha")]
    Valkey,
}

/// Configuration for state backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateConfig {
    /// Backend type to use
    #[serde(default)]
    pub backend: StateBackendType,

    /// Valkey configuration (required if backend = Valkey)
    #[cfg(feature = "ha")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valkey: Option<ValkeyConfig>,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            backend: StateBackendType::InMemory,
            #[cfg(feature = "ha")]
            valkey: None,
        }
    }
}

impl StateConfig {
    /// Create a new in-memory state configuration
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Create a new Valkey state configuration
    #[cfg(feature = "ha")]
    pub fn valkey(config: ValkeyConfig) -> Self {
        Self {
            backend: StateBackendType::Valkey,
            valkey: Some(config),
        }
    }
}

/// Valkey/Redis connection configuration
#[cfg(feature = "ha")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValkeyConfig {
    /// Connection URL (e.g., "redis://localhost:6379" or "valkey://localhost:6379")
    /// Supports:
    /// - redis://host:port (TCP)
    /// - redis://host:port/db (TCP with database selection)
    /// - unix:///path/to/socket (Unix socket)
    /// - rediss://host:port (TLS)
    pub url: String,

    /// Key prefix for all keys stored in Valkey (default: "radius:")
    /// Prevents key collisions with other applications
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,

    /// Connection pool size (default: 10)
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    /// Connection timeout in milliseconds (default: 5000 = 5 seconds)
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,

    /// Command timeout in milliseconds (default: 2000 = 2 seconds)
    #[serde(default = "default_command_timeout_ms")]
    pub command_timeout_ms: u64,

    /// Maximum number of retries for failed commands (default: 3)
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Retry delay in milliseconds (default: 100)
    #[serde(default = "default_retry_delay_ms")]
    pub retry_delay_ms: u64,

    /// Enable TCP keepalive (default: true)
    #[serde(default = "default_tcp_keepalive")]
    pub tcp_keepalive: bool,
}

#[cfg(feature = "ha")]
fn default_key_prefix() -> String {
    "radius:".to_string()
}

#[cfg(feature = "ha")]
fn default_pool_size() -> u32 {
    10
}

#[cfg(feature = "ha")]
fn default_connect_timeout_ms() -> u64 {
    5000
}

#[cfg(feature = "ha")]
fn default_command_timeout_ms() -> u64 {
    2000
}

#[cfg(feature = "ha")]
fn default_max_retries() -> u32 {
    3
}

#[cfg(feature = "ha")]
fn default_retry_delay_ms() -> u64 {
    100
}

#[cfg(feature = "ha")]
fn default_tcp_keepalive() -> bool {
    true
}

#[cfg(feature = "ha")]
impl Default for ValkeyConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            key_prefix: default_key_prefix(),
            pool_size: default_pool_size(),
            connect_timeout_ms: default_connect_timeout_ms(),
            command_timeout_ms: default_command_timeout_ms(),
            max_retries: default_max_retries(),
            retry_delay_ms: default_retry_delay_ms(),
            tcp_keepalive: default_tcp_keepalive(),
        }
    }
}

#[cfg(feature = "ha")]
impl ValkeyConfig {
    /// Create a new Valkey configuration with the given URL
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Default::default()
        }
    }

    /// Set the key prefix
    pub fn with_key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    /// Set the connection pool size
    pub fn with_pool_size(mut self, size: u32) -> Self {
        self.pool_size = size;
        self
    }

    /// Set the connection timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout_ms = timeout.as_millis() as u64;
        self
    }

    /// Set the command timeout
    pub fn with_command_timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout_ms = timeout.as_millis() as u64;
        self
    }

    /// Set the maximum number of retries
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Set the retry delay
    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay_ms = delay.as_millis() as u64;
        self
    }

    /// Enable or disable TCP keepalive
    pub fn with_tcp_keepalive(mut self, enabled: bool) -> Self {
        self.tcp_keepalive = enabled;
        self
    }

    /// Get connection timeout as Duration
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    /// Get command timeout as Duration
    pub fn command_timeout(&self) -> Duration {
        Duration::from_millis(self.command_timeout_ms)
    }

    /// Get retry delay as Duration
    pub fn retry_delay(&self) -> Duration {
        Duration::from_millis(self.retry_delay_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_state_config() {
        let config = StateConfig::default();
        assert_eq!(config.backend, StateBackendType::InMemory);
    }

    #[test]
    fn test_in_memory_config() {
        let config = StateConfig::in_memory();
        assert_eq!(config.backend, StateBackendType::InMemory);
    }

    #[cfg(feature = "ha")]
    #[test]
    fn test_valkey_config_defaults() {
        let config = ValkeyConfig::default();
        assert_eq!(config.url, "redis://localhost:6379");
        assert_eq!(config.key_prefix, "radius:");
        assert_eq!(config.pool_size, 10);
        assert_eq!(config.connect_timeout_ms, 5000);
        assert_eq!(config.command_timeout_ms, 2000);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_ms, 100);
        assert!(config.tcp_keepalive);
    }

    #[cfg(feature = "ha")]
    #[test]
    fn test_valkey_config_builder() {
        let config = ValkeyConfig::new("redis://example.com:6379")
            .with_key_prefix("test:")
            .with_pool_size(20)
            .with_connect_timeout(Duration::from_secs(10))
            .with_command_timeout(Duration::from_secs(5))
            .with_max_retries(5)
            .with_retry_delay(Duration::from_millis(200))
            .with_tcp_keepalive(false);

        assert_eq!(config.url, "redis://example.com:6379");
        assert_eq!(config.key_prefix, "test:");
        assert_eq!(config.pool_size, 20);
        assert_eq!(config.connect_timeout_ms, 10000);
        assert_eq!(config.command_timeout_ms, 5000);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.retry_delay_ms, 200);
        assert!(!config.tcp_keepalive);
    }

    #[cfg(feature = "ha")]
    #[test]
    fn test_valkey_config_durations() {
        let config = ValkeyConfig::default();
        assert_eq!(config.connect_timeout(), Duration::from_secs(5));
        assert_eq!(config.command_timeout(), Duration::from_secs(2));
        assert_eq!(config.retry_delay(), Duration::from_millis(100));
    }

    #[test]
    fn test_serde_in_memory() {
        let config = StateConfig::in_memory();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: StateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.backend, StateBackendType::InMemory);
    }

    #[cfg(feature = "ha")]
    #[test]
    fn test_serde_valkey() {
        let valkey_config = ValkeyConfig::new("redis://localhost:6379");
        let config = StateConfig::valkey(valkey_config);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: StateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.backend, StateBackendType::Valkey);
        assert!(deserialized.valkey.is_some());
    }
}
