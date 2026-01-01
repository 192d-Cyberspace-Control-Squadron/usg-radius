//! OCSP (Online Certificate Status Protocol) Support - RFC 6960
//!
//! This module implements OCSP request building, response parsing, and validation
//! for real-time certificate revocation checking.
//!
//! # OCSP Protocol Overview
//!
//! OCSP provides a lightweight alternative to CRLs by allowing clients to query
//! the revocation status of individual certificates in real-time.
//!
//! ## Request/Response Flow:
//!
//! 1. **Build Request**: Create OCSPRequest with certificate serial number and issuer
//! 2. **HTTP POST**: Send DER-encoded request to OCSP responder URL
//! 3. **Parse Response**: Decode DER-encoded OCSPResponse
//! 4. **Validate**: Check signature, nonce, and certificate status
//! 5. **Cache**: Store validated response with TTL
//!
//! ## ASN.1 Structures (RFC 6960):
//!
//! ```asn1
//! OCSPRequest ::= SEQUENCE {
//!     tbsRequest      TBSRequest,
//!     optionalSignature   [0] EXPLICIT Signature OPTIONAL
//! }
//!
//! TBSRequest ::= SEQUENCE {
//!     version             [0] EXPLICIT Version DEFAULT v1,
//!     requestorName       [1] EXPLICIT GeneralName OPTIONAL,
//!     requestList         SEQUENCE OF Request,
//!     requestExtensions   [2] EXPLICIT Extensions OPTIONAL
//! }
//!
//! Request ::= SEQUENCE {
//!     reqCert             CertID,
//!     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
//! }
//!
//! CertID ::= SEQUENCE {
//!     hashAlgorithm       AlgorithmIdentifier,
//!     issuerNameHash      OCTET STRING,
//!     issuerKeyHash       OCTET STRING,
//!     serialNumber        INTEGER
//! }
//!
//! OCSPResponse ::= SEQUENCE {
//!     responseStatus      OCSPResponseStatus,
//!     responseBytes       [0] EXPLICIT ResponseBytes OPTIONAL
//! }
//!
//! BasicOCSPResponse ::= SEQUENCE {
//!     tbsResponseData     ResponseData,
//!     signatureAlgorithm  AlgorithmIdentifier,
//!     signature           BIT STRING,
//!     certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
//! }
//!
//! SingleResponse ::= SEQUENCE {
//!     certID              CertID,
//!     certStatus          CertStatus,
//!     thisUpdate          GeneralizedTime,
//!     nextUpdate          [0] EXPLICIT GeneralizedTime OPTIONAL,
//!     singleExtensions    [1] EXPLICIT Extensions OPTIONAL
//! }
//!
//! CertStatus ::= CHOICE {
//!     good                [0] IMPLICIT NULL,
//!     revoked             [1] IMPLICIT RevokedInfo,
//!     unknown             [2] IMPLICIT UnknownInfo
//! }
//! ```
//!
//! # Implementation Strategy
//!
//! For Phase 1 (MVP), we'll use the `x509-parser` crate which already has some
//! OCSP support. For full control in Phase 2, we may migrate to `der` crate.
//!
//! **Dependencies**:
//! - `x509-parser`: OCSP response parsing (already in workspace)
//! - `sha2`: SHA-256/SHA-1 hashing for CertID
//! - `reqwest`: HTTP POST to OCSP responder (already in workspace)
//!
//! **Not needed** (x509-parser handles):
//! - Manual ASN.1 DER encoding/decoding
//! - Certificate parsing

use crate::revocation::error::RevocationError;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};
use x509_parser::prelude::*;

/// OCSP response status (RFC 6960 Section 2.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspResponseStatus {
    /// Response has valid confirmations
    Successful = 0,
    /// Illegal confirmation request
    MalformedRequest = 1,
    /// Internal error in issuer
    InternalError = 2,
    /// Try again later
    TryLater = 3,
    /// Must sign the request
    SigRequired = 5,
    /// Request unauthorized
    Unauthorized = 6,
}

impl OcspResponseStatus {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Successful),
            1 => Some(Self::MalformedRequest),
            2 => Some(Self::InternalError),
            3 => Some(Self::TryLater),
            5 => Some(Self::SigRequired),
            6 => Some(Self::Unauthorized),
            _ => None,
        }
    }
}

/// Certificate status in OCSP response
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateStatus {
    /// Certificate is not revoked
    Good,
    /// Certificate has been revoked
    Revoked {
        /// Revocation time
        revocation_time: SystemTime,
        /// Revocation reason (if present)
        reason: Option<u8>,
    },
    /// Certificate status is unknown
    Unknown,
}

/// OCSP request builder
///
/// Builds a minimal unsigned OCSP request for a single certificate.
/// For production use, this will be extended to support:
/// - Request signing (optional)
/// - Nonce extension (replay protection)
/// - Multiple certificates in one request
pub struct OcspRequestBuilder {
    /// Certificate serial number to check
    serial_number: Vec<u8>,
    /// Issuer name hash (SHA-256)
    issuer_name_hash: Vec<u8>,
    /// Issuer public key hash (SHA-256)
    issuer_key_hash: Vec<u8>,
    /// Optional nonce for replay protection
    nonce: Option<Vec<u8>>,
}

impl OcspRequestBuilder {
    /// Create a new OCSP request builder
    ///
    /// # Arguments
    /// * `cert` - The certificate to check (DER-encoded)
    /// * `issuer` - The issuer certificate (DER-encoded)
    ///
    /// This will be implemented in the next phase using x509-parser to extract:
    /// - Certificate serial number
    /// - Issuer DN (for name hash)
    /// - Issuer public key (for key hash)
    pub fn new(_cert: &[u8], _issuer: &[u8]) -> Result<Self, RevocationError> {
        // TODO: Parse certificates and extract needed fields
        // For now, return placeholder
        todo!("OCSP request building - Phase 2")
    }

    /// Add a nonce for replay protection
    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Build the OCSP request as DER-encoded bytes
    ///
    /// This constructs the ASN.1 OCSPRequest structure and encodes it to DER.
    pub fn build(&self) -> Result<Vec<u8>, RevocationError> {
        // TODO: Implement ASN.1 DER encoding
        // For now, return placeholder
        todo!("OCSP request DER encoding - Phase 2")
    }

    /// Compute SHA-256 hash of issuer name
    fn hash_issuer_name(_issuer_dn: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(_issuer_dn);
        hasher.finalize().to_vec()
    }

    /// Compute SHA-256 hash of issuer public key
    fn hash_issuer_key(_issuer_pubkey: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(_issuer_pubkey);
        hasher.finalize().to_vec()
    }
}

/// Parsed OCSP response
///
/// Contains the decoded and validated OCSP response data.
pub struct OcspResponse {
    /// Response status
    pub status: OcspResponseStatus,
    /// Certificate status (if response was successful)
    pub cert_status: Option<CertificateStatus>,
    /// When this response was produced
    pub produced_at: SystemTime,
    /// When this status was last updated
    pub this_update: SystemTime,
    /// When this status will be updated next (optional)
    pub next_update: Option<SystemTime>,
    /// Response nonce (if present)
    pub nonce: Option<Vec<u8>>,
    /// Raw response bytes (for caching)
    pub raw_bytes: Vec<u8>,
}

impl OcspResponse {
    /// Parse an OCSP response from DER-encoded bytes
    ///
    /// # Arguments
    /// * `der_bytes` - DER-encoded OCSP response
    ///
    /// # Returns
    /// Parsed OCSP response or error
    pub fn parse(_der_bytes: &[u8]) -> Result<Self, RevocationError> {
        // TODO: Implement OCSP response parsing using x509-parser
        // For now, return placeholder
        todo!("OCSP response parsing - Phase 2")
    }

    /// Verify the signature on this OCSP response
    ///
    /// # Arguments
    /// * `issuer_cert` - The issuer certificate (to verify signature)
    ///
    /// # Returns
    /// Ok(()) if signature is valid, Err otherwise
    pub fn verify_signature(&self, _issuer_cert: &[u8]) -> Result<(), RevocationError> {
        // TODO: Implement signature verification
        // For now, return placeholder
        todo!("OCSP signature verification - Phase 2")
    }

    /// Check if this response is still fresh (not expired)
    pub fn is_fresh(&self) -> bool {
        let now = SystemTime::now();

        // Must be after thisUpdate
        if now < self.this_update {
            return false;
        }

        // If nextUpdate is present, must be before it
        if let Some(next_update) = self.next_update {
            if now >= next_update {
                return false;
            }
        }

        true
    }

    /// Get the TTL for caching this response
    ///
    /// Returns the time until nextUpdate, or a default TTL if nextUpdate is missing
    pub fn cache_ttl(&self) -> Duration {
        if let Some(next_update) = self.next_update {
            if let Ok(duration) = next_update.duration_since(SystemTime::now()) {
                return duration;
            }
        }

        // Default: cache for 1 hour if no nextUpdate
        Duration::from_secs(3600)
    }

    /// Check if the certificate is revoked according to this response
    pub fn is_revoked(&self) -> bool {
        matches!(
            self.cert_status,
            Some(CertificateStatus::Revoked { .. })
        )
    }
}

/// OCSP client for querying responders
///
/// Handles HTTP POST requests to OCSP responders and response parsing.
pub struct OcspClient {
    /// HTTP timeout for OCSP requests
    timeout: Duration,
    /// HTTP client (reused for connection pooling)
    http_client: reqwest::blocking::Client,
}

impl OcspClient {
    /// Create a new OCSP client
    ///
    /// # Arguments
    /// * `timeout` - HTTP request timeout in seconds
    pub fn new(timeout: u64) -> Result<Self, RevocationError> {
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .build()
            .map_err(|e| {
                RevocationError::HttpError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            timeout: Duration::from_secs(timeout),
            http_client,
        })
    }

    /// Query an OCSP responder
    ///
    /// # Arguments
    /// * `url` - OCSP responder URL
    /// * `request` - DER-encoded OCSP request
    ///
    /// # Returns
    /// DER-encoded OCSP response or error
    pub fn query(&self, _url: &str, _request: &[u8]) -> Result<Vec<u8>, RevocationError> {
        // TODO: Implement HTTP POST to OCSP responder
        // Headers:
        //   Content-Type: application/ocsp-request
        //   Accept: application/ocsp-response
        // For now, return placeholder
        todo!("OCSP HTTP POST - Phase 2")
    }

    /// Extract OCSP responder URL from a certificate
    ///
    /// Parses the Authority Information Access extension to find OCSP URL.
    pub fn extract_ocsp_url(_cert: &[u8]) -> Result<String, RevocationError> {
        // TODO: Parse certificate and extract OCSP URL from AIA extension
        // For now, return placeholder
        todo!("OCSP URL extraction - Phase 2")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_response_status_conversion() {
        assert_eq!(
            OcspResponseStatus::from_u8(0),
            Some(OcspResponseStatus::Successful)
        );
        assert_eq!(
            OcspResponseStatus::from_u8(1),
            Some(OcspResponseStatus::MalformedRequest)
        );
        assert_eq!(OcspResponseStatus::from_u8(99), None);
    }

    #[test]
    fn test_certificate_status_equality() {
        let good1 = CertificateStatus::Good;
        let good2 = CertificateStatus::Good;
        assert_eq!(good1, good2);

        let unknown1 = CertificateStatus::Unknown;
        let unknown2 = CertificateStatus::Unknown;
        assert_eq!(unknown1, unknown2);
    }

    // TODO: Add more tests once implementation is complete
    // - OCSP request building
    // - OCSP response parsing
    // - Signature verification
    // - Nonce validation
    // - Freshness checking
}
