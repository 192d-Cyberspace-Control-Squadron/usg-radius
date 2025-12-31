//! RADIUS proxy routing engine
//!
//! This module will implement the routing decision logic.
//! Phase 2 implementation - currently a stub.

use crate::proxy::home_server::HomeServer;
use std::sync::Arc;

/// Routing decision
#[derive(Debug, Clone)]
pub enum RoutingDecision {
    /// Proxy the request to a home server
    Proxy {
        /// Target home server
        home_server: Arc<HomeServer>,
        /// Whether to strip realm from username
        strip_realm: bool,
    },
    /// Authenticate locally
    Local,
    /// Reject immediately (no route found)
    Reject,
}

/// Router (stub for Phase 2)
pub struct Router {
    // TODO: Phase 2 implementation
}

impl Router {
    /// Create a new router (stub)
    pub fn new() -> Self {
        Router {}
    }

    /// Route a request (stub)
    pub fn route_request(&self, _request: &radius_proto::Packet) -> RoutingDecision {
        // Default: authenticate locally
        RoutingDecision::Local
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}
