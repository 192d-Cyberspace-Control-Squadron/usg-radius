//! Certificate Revocation Checking (CRL/OCSP)
//!
//! This module provides production-grade certificate revocation checking for EAP-TLS
//! mutual authentication. It supports:
//!
//! - **CRL (Certificate Revocation Lists)**: RFC 5280
//! - **OCSP (Online Certificate Status Protocol)**: RFC 6960 (planned)
//!
//! # Features
//!
//! - CRL parsing and validation with signature verification
//! - HTTP fetching from CRL distribution points
//! - TTL-based caching with automatic expiry
//! - Fail-open and fail-closed modes
//! - Static CRL file loading
//! - Integration with rustls via custom ClientCertVerifier
//!
//! # Security Considerations
//!
//! - **Fail-Open vs Fail-Closed**: Choose based on security vs availability requirements
//! - **CRL Freshness**: Enforces `thisUpdate` and `nextUpdate` validation
//! - **Size Limits**: Protects against memory exhaustion (10 MB default)
//! - **HTTPS**: Recommended for CRL distribution points
//! - **Cache Poisoning**: Only caches CRLs with valid signatures
//!
//! # Example
//!
//! ```no_run
//! use radius_proto::revocation::{RevocationConfig, CrlConfig, FallbackBehavior};
//!
//! // Create configuration with fail-closed mode for high security
//! let crl_config = CrlConfig::http_fetch(
//!     5,      // 5 second HTTP timeout
//!     3600,   // 1 hour cache TTL
//!     100,    // Max 100 cached CRLs
//! );
//!
//! let config = RevocationConfig::crl_only(
//!     crl_config,
//!     FallbackBehavior::FailClosed,
//! );
//! ```
//!
//! # Phase 1: CRL Support (v0.6.0)
//!
//! Current implementation focuses on CRL checking only. OCSP support will be
//! added in Phase 2.

pub mod config;
pub mod error;

// CRL, caching, and fetching modules will be added in subsequent phases
#[cfg(feature = "revocation")]
pub(crate) mod crl;
#[cfg(feature = "revocation")]
pub(crate) mod cache;
#[cfg(feature = "revocation")]
pub(crate) mod fetch;

// Re-export public types
pub use config::{
    CrlConfig, FallbackBehavior, RevocationCheckMode, RevocationConfig,
};
pub use error::RevocationError;

// Internal types (will be made public as implementation progresses)
#[cfg(feature = "revocation")]
pub(crate) use cache::CrlCache;
#[cfg(feature = "revocation")]
pub(crate) use crl::CrlInfo;
#[cfg(feature = "revocation")]
pub(crate) use fetch::CrlFetcher;

/// Module version for tracking implementation progress
pub const VERSION: &str = "0.1.0-alpha (Phase 1.1: Core Types)";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_config_creation() {
        let config = RevocationConfig::default();
        assert_eq!(config.check_mode, RevocationCheckMode::Disabled);
    }
}
