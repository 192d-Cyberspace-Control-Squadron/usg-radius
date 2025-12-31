//! Realm matching and routing
//!
//! This module will implement realm-based routing.
//! Phase 2 implementation - currently a stub.

use crate::proxy::error::ProxyResult;
use crate::proxy::pool::HomeServerPool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Realm match configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmMatchConfig {
    /// Match type: "exact", "suffix", "regex"
    #[serde(rename = "type")]
    pub match_type: String,
    /// Pattern to match
    pub pattern: String,
}

/// Realm matcher
#[derive(Debug, Clone)]
pub enum RealmMatcher {
    /// Exact match
    Exact(String),
    /// Suffix match
    Suffix(String),
    /// Regex match (stub for Phase 2)
    Regex(String),
}

/// Realm configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmConfig {
    /// Realm name
    pub name: String,
    /// Match configuration
    #[serde(rename = "match")]
    pub match_config: RealmMatchConfig,
    /// Target pool name
    pub pool: String,
    /// Strip realm from username before forwarding
    #[serde(default)]
    pub strip_realm: bool,
}

/// Realm (stub for Phase 2)
pub struct Realm {
    pub name: String,
    pub matcher: RealmMatcher,
    pub pool: Arc<HomeServerPool>,
    pub strip_realm: bool,
}

impl Realm {
    /// Create a new realm (stub)
    pub fn new(_config: RealmConfig, _pool: Arc<HomeServerPool>) -> ProxyResult<Self> {
        // TODO: Phase 2 implementation
        unimplemented!("Phase 2: Realm implementation")
    }
}

/// Extract realm from username (stub for Phase 2)
pub fn extract_realm(_username: &str) -> Option<String> {
    // TODO: Phase 2 implementation
    None
}
