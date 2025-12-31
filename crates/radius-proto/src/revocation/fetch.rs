//! CRL HTTP fetching
//!
//! This module handles HTTP fetching of CRLs from distribution points
//! with timeouts and error handling.
//!
//! **Status**: Stub - will be implemented in Phase 1.4

use super::error::RevocationError;

/// CRL fetcher with HTTP client
#[derive(Debug, Clone)]
pub struct CrlFetcher {
    /// HTTP timeout in seconds
    #[allow(dead_code)]
    timeout_secs: u64,
}

impl CrlFetcher {
    /// Create a new CRL fetcher
    ///
    /// **Status**: Stub - will be implemented in Phase 1.4
    #[allow(dead_code)]
    pub fn new(timeout_secs: u64) -> Result<Self, RevocationError> {
        Ok(Self { timeout_secs })
    }

    /// Fetch a CRL from an HTTP URL
    ///
    /// **Status**: Stub - will be implemented in Phase 1.4
    #[allow(dead_code)]
    pub fn fetch_crl(&self, _url: &str) -> Result<Vec<u8>, RevocationError> {
        // TODO: Implement HTTP GET with reqwest blocking client
        Err(RevocationError::FetchError(
            "CRL fetching not yet implemented (Phase 1.4)".to_string(),
        ))
    }
}

/// Extract CRL distribution point URLs from a certificate
///
/// **Status**: Stub - will be implemented in Phase 1.4
#[allow(dead_code)]
pub fn extract_crl_distribution_points(_cert_der: &[u8]) -> Result<Vec<String>, RevocationError> {
    // TODO: Parse certificate and extract CRL DP extension (2.5.29.31)
    Ok(vec![])
}
