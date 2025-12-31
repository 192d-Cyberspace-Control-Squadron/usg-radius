//! Home server pools and load balancing
//!
//! This module will implement server pools with load balancing strategies.
//! Phase 3 implementation - currently a stub.

use crate::proxy::error::{ProxyError, ProxyResult};
use crate::proxy::home_server::{HomeServer, HomeServerConfig};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Load balancing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    /// Round-robin selection
    RoundRobin,
    /// Select server with fewest outstanding requests
    LeastOutstanding,
    /// Failover (primary + backups)
    Failover,
    /// Random selection
    Random,
}

impl Default for LoadBalanceStrategy {
    fn default() -> Self {
        LoadBalanceStrategy::RoundRobin
    }
}

/// Home server pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeServerPoolConfig {
    /// Pool name
    pub name: String,
    /// Load balancing strategy
    #[serde(default)]
    pub strategy: LoadBalanceStrategy,
    /// Servers in this pool
    pub servers: Vec<HomeServerConfig>,
}

impl HomeServerPoolConfig {
    /// Validate configuration
    pub fn validate(&self) -> ProxyResult<()> {
        if self.name.is_empty() {
            return Err(ProxyError::Configuration(
                "Pool name cannot be empty".to_string(),
            ));
        }

        if self.servers.is_empty() {
            return Err(ProxyError::Configuration(format!(
                "Pool '{}' has no servers configured",
                self.name
            )));
        }

        for server in &self.servers {
            server.validate()?;
        }

        Ok(())
    }
}

/// Home server pool (stub for Phase 3)
pub struct HomeServerPool {
    pub name: String,
    pub servers: Vec<Arc<HomeServer>>,
    pub strategy: LoadBalanceStrategy,
}

impl HomeServerPool {
    /// Create a new pool from configuration (stub)
    pub fn new(_config: HomeServerPoolConfig) -> ProxyResult<Self> {
        // TODO: Phase 3 implementation
        unimplemented!("Phase 3: Pool implementation")
    }

    /// Select next server based on strategy
    ///
    /// For Phase 2: Returns first available server with capacity
    /// Phase 3 will implement full load balancing strategies
    pub fn select_server(&self) -> Option<Arc<HomeServer>> {
        // Find first available server with capacity
        self.servers
            .iter()
            .find(|server| server.is_available() && server.has_capacity())
            .map(|server| Arc::clone(server))
    }
}
