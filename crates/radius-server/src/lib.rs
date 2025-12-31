//! RADIUS Server Implementation
//!
//! This crate provides a production-ready RADIUS server built on top of
//! the `radius-proto` protocol implementation.
//!
//! # Features
//!
//! - Async I/O with Tokio
//! - Pluggable authentication handlers
//! - JSON configuration
//! - User and client management
//! - Logging and monitoring
//!
//! # Example
//!
//! ```rust,no_run
//! use radius_server::{RadiusServer, ServerConfig, SimpleAuthHandler};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create auth handler
//!     let mut handler = SimpleAuthHandler::new();
//!     handler.add_user("alice", "password");
//!
//!     // Create server
//!     let config = ServerConfig::new(
//!         "0.0.0.0:1812".parse()?,
//!         b"secret",
//!         Arc::new(handler)
//!     );
//!
//!     let server = RadiusServer::new(config).await?;
//!     server.run().await?;
//!
//!     Ok(())
//! }
//! ```

pub mod audit;
pub mod cache;
pub mod config;
pub mod ratelimit;
pub mod server;

pub use audit::{AuditEntry, AuditEventType, AuditLogger};
pub use cache::{RequestCache, RequestFingerprint};
pub use config::{Client, Config, ConfigError, User};
pub use ratelimit::{RateLimitConfig, RateLimiter};
pub use server::{AuthHandler, RadiusServer, ServerConfig, ServerError, SimpleAuthHandler};
