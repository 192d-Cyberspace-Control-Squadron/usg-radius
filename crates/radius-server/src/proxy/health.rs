//! Health checking for home servers
//!
//! This module will implement health checks using Status-Server requests.
//! Phase 3 implementation - currently a stub.

use serde::{Deserialize, Serialize};

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Enable health checking
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Health check interval in seconds
    #[serde(default = "default_interval")]
    pub interval: u64,
    /// Health check timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Number of retries before marking server down
    #[serde(default = "default_retries")]
    pub retries: u8,
}

fn default_enabled() -> bool {
    true
}

fn default_interval() -> u64 {
    30
}

fn default_timeout() -> u64 {
    10
}

fn default_retries() -> u8 {
    3
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        HealthCheckConfig {
            enabled: default_enabled(),
            interval: default_interval(),
            timeout: default_timeout(),
            retries: default_retries(),
        }
    }
}

/// Health checker (stub for Phase 3)
pub struct HealthChecker {
    // TODO: Phase 3 implementation
}

impl HealthChecker {
    /// Create a new health checker (stub)
    pub fn new(_config: HealthCheckConfig) -> Self {
        HealthChecker {}
    }
}
