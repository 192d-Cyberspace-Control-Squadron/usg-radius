//! Home server (upstream RADIUS server) configuration and state tracking

use crate::proxy::error::{ProxyError, ProxyResult};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Home server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeServerConfig {
    /// Server address (host:port)
    pub address: String,

    /// Shared secret for this server
    pub secret: String,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Maximum outstanding requests to this server
    #[serde(default = "default_max_outstanding")]
    pub max_outstanding: usize,

    /// Optional server name/description
    #[serde(default)]
    pub name: Option<String>,
}

fn default_timeout() -> u64 {
    30
}

fn default_max_outstanding() -> usize {
    100
}

impl HomeServerConfig {
    /// Validate configuration
    pub fn validate(&self) -> ProxyResult<()> {
        // Parse address to validate format
        let _: SocketAddr = self.address.parse().map_err(|e: std::net::AddrParseError| {
            ProxyError::Configuration(format!("Invalid home server address '{}': {}", self.address, e))
        })?;

        if self.secret.is_empty() {
            return Err(ProxyError::Configuration(
                "Home server secret cannot be empty".to_string(),
            ));
        }

        if self.timeout == 0 {
            return Err(ProxyError::Configuration(
                "Home server timeout cannot be 0".to_string(),
            ));
        }

        Ok(())
    }
}

/// Home server state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeServerState {
    /// Server is operational and accepting requests
    Up,
    /// Server is down (health checks failing)
    Down,
    /// Server is being tested (health checks in progress)
    Testing,
}

impl Default for HomeServerState {
    fn default() -> Self {
        HomeServerState::Up
    }
}

/// Home server statistics
#[derive(Debug)]
pub struct HomeServerStats {
    /// Total requests sent to this server
    pub requests_sent: AtomicU64,
    /// Total responses received from this server
    pub responses_received: AtomicU64,
    /// Total timeouts from this server
    pub timeouts: AtomicU64,
    /// Total requests currently in flight
    pub outstanding: AtomicU64,
    /// Last response timestamp
    pub last_response: RwLock<Option<Instant>>,
}

impl Default for HomeServerStats {
    fn default() -> Self {
        HomeServerStats {
            requests_sent: AtomicU64::new(0),
            responses_received: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            outstanding: AtomicU64::new(0),
            last_response: RwLock::new(None),
        }
    }
}

impl HomeServerStats {
    /// Record a request sent
    pub fn record_request(&self) {
        self.requests_sent.fetch_add(1, Ordering::Relaxed);
        self.outstanding.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a response received
    pub fn record_response(&self) {
        self.responses_received.fetch_add(1, Ordering::Relaxed);
        self.outstanding.fetch_sub(1, Ordering::Relaxed);
        *self.last_response.write().unwrap() = Some(Instant::now());
    }

    /// Record a timeout
    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
        self.outstanding.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get current outstanding request count
    pub fn outstanding(&self) -> u64 {
        self.outstanding.load(Ordering::Relaxed)
    }

    /// Get total requests sent
    pub fn requests_sent(&self) -> u64 {
        self.requests_sent.load(Ordering::Relaxed)
    }

    /// Get total responses received
    pub fn responses_received(&self) -> u64 {
        self.responses_received.load(Ordering::Relaxed)
    }

    /// Get total timeouts
    pub fn timeouts(&self) -> u64 {
        self.timeouts.load(Ordering::Relaxed)
    }

    /// Get time since last response
    pub fn time_since_last_response(&self) -> Option<Duration> {
        self.last_response
            .read()
            .unwrap()
            .map(|t| t.elapsed())
    }
}

/// Home server (upstream RADIUS server)
pub struct HomeServer {
    /// Server name (for logging)
    pub name: String,
    /// Server socket address
    pub address: SocketAddr,
    /// Shared secret for this server
    pub secret: Vec<u8>,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum outstanding requests
    pub max_outstanding: usize,
    /// Current server state
    state: Arc<RwLock<HomeServerState>>,
    /// Server statistics
    stats: Arc<HomeServerStats>,
}

impl HomeServer {
    /// Create a new home server from configuration
    pub fn new(config: HomeServerConfig) -> ProxyResult<Self> {
        config.validate()?;

        let address: SocketAddr = config.address.parse()?;
        let name = config
            .name
            .unwrap_or_else(|| config.address.clone());

        Ok(HomeServer {
            name,
            address,
            secret: config.secret.into_bytes(),
            timeout: Duration::from_secs(config.timeout),
            max_outstanding: config.max_outstanding,
            state: Arc::new(RwLock::new(HomeServerState::Up)),
            stats: Arc::new(HomeServerStats::default()),
        })
    }

    /// Get current state
    pub fn state(&self) -> HomeServerState {
        *self.state.read().unwrap()
    }

    /// Set server state
    pub fn set_state(&self, new_state: HomeServerState) {
        *self.state.write().unwrap() = new_state;
    }

    /// Check if server is available for requests
    pub fn is_available(&self) -> bool {
        matches!(self.state(), HomeServerState::Up)
    }

    /// Check if server has capacity for more requests
    pub fn has_capacity(&self) -> bool {
        self.stats.outstanding() < self.max_outstanding as u64
    }

    /// Get server statistics
    pub fn stats(&self) -> &HomeServerStats {
        &self.stats
    }

    /// Get shared secret
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

impl std::fmt::Debug for HomeServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HomeServer")
            .field("name", &self.name)
            .field("address", &self.address)
            .field("state", &self.state())
            .field("outstanding", &self.stats.outstanding())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_home_server_config_validation() {
        let valid_config = HomeServerConfig {
            address: "192.168.1.1:1812".to_string(),
            secret: "test_secret".to_string(),
            timeout: 30,
            max_outstanding: 100,
            name: Some("Test Server".to_string()),
        };
        assert!(valid_config.validate().is_ok());
    }

    #[test]
    fn test_home_server_config_invalid_address() {
        let config = HomeServerConfig {
            address: "invalid_address".to_string(),
            secret: "test_secret".to_string(),
            timeout: 30,
            max_outstanding: 100,
            name: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_home_server_config_empty_secret() {
        let config = HomeServerConfig {
            address: "192.168.1.1:1812".to_string(),
            secret: "".to_string(),
            timeout: 30,
            max_outstanding: 100,
            name: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_home_server_creation() {
        let config = HomeServerConfig {
            address: "192.168.1.1:1812".to_string(),
            secret: "test_secret".to_string(),
            timeout: 30,
            max_outstanding: 100,
            name: Some("Test Server".to_string()),
        };

        let server = HomeServer::new(config).unwrap();
        assert_eq!(server.name, "Test Server");
        assert_eq!(server.address.to_string(), "192.168.1.1:1812");
        assert_eq!(server.secret, b"test_secret");
        assert!(server.is_available());
        assert!(server.has_capacity());
    }

    #[test]
    fn test_home_server_state_transitions() {
        let config = HomeServerConfig {
            address: "192.168.1.1:1812".to_string(),
            secret: "test_secret".to_string(),
            timeout: 30,
            max_outstanding: 100,
            name: None,
        };

        let server = HomeServer::new(config).unwrap();
        assert_eq!(server.state(), HomeServerState::Up);
        assert!(server.is_available());

        server.set_state(HomeServerState::Down);
        assert_eq!(server.state(), HomeServerState::Down);
        assert!(!server.is_available());

        server.set_state(HomeServerState::Testing);
        assert_eq!(server.state(), HomeServerState::Testing);
        assert!(!server.is_available());

        server.set_state(HomeServerState::Up);
        assert_eq!(server.state(), HomeServerState::Up);
        assert!(server.is_available());
    }

    #[test]
    fn test_home_server_stats() {
        let config = HomeServerConfig {
            address: "192.168.1.1:1812".to_string(),
            secret: "test_secret".to_string(),
            timeout: 30,
            max_outstanding: 100,
            name: None,
        };

        let server = HomeServer::new(config).unwrap();
        let stats = server.stats();

        // Initial state
        assert_eq!(stats.requests_sent(), 0);
        assert_eq!(stats.responses_received(), 0);
        assert_eq!(stats.timeouts(), 0);
        assert_eq!(stats.outstanding(), 0);

        // Record request
        stats.record_request();
        assert_eq!(stats.requests_sent(), 1);
        assert_eq!(stats.outstanding(), 1);

        // Record response
        stats.record_response();
        assert_eq!(stats.responses_received(), 1);
        assert_eq!(stats.outstanding(), 0);
        assert!(stats.time_since_last_response().is_some());

        // Record timeout
        stats.record_request();
        stats.record_timeout();
        assert_eq!(stats.timeouts(), 1);
        assert_eq!(stats.outstanding(), 0);
    }

    #[test]
    fn test_home_server_capacity() {
        let config = HomeServerConfig {
            address: "192.168.1.1:1812".to_string(),
            secret: "test_secret".to_string(),
            timeout: 30,
            max_outstanding: 2,
            name: None,
        };

        let server = HomeServer::new(config).unwrap();
        assert!(server.has_capacity());

        // Fill capacity
        server.stats().record_request();
        assert!(server.has_capacity());

        server.stats().record_request();
        assert!(!server.has_capacity());

        // Free up capacity
        server.stats().record_response();
        assert!(server.has_capacity());
    }
}
