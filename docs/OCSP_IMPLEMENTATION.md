# OCSP Implementation Plan - v0.7.4 Phase 2

This document outlines the implementation plan for OCSP (Online Certificate Status Protocol) support in the USG RADIUS server.

## Overview

OCSP provides real-time certificate revocation checking as an alternative to CRLs. This implementation adds OCSP support alongside the existing CRL infrastructure.

## Status: Work in Progress (Foundation Complete)

### Completed ✅

1. **OCSP Module Structure** ([ocsp.rs](../crates/radius-proto/src/revocation/ocsp.rs))
   - RFC 6960 documentation with ASN.1 structures
   - `OcspResponseStatus` enum
   - `CertificateStatus` enum
   - `OcspRequestBuilder` struct (placeholders)
   - `OcspResponse` struct (placeholders)
   - `OcspClient` struct (placeholders)

2. **Configuration** ([config.rs](../crates/radius-proto/src/revocation/config.rs))
   - `OcspConfig` struct with full configuration options
   - Integration with `RevocationConfig`
   - `ocsp_only()` constructor
   - Backward compatibility maintained

3. **Module Integration**
   - Exported in public API
   - Feature gated with `revocation` feature
   - Code compiles successfully

### Remaining Work

The current implementation uses `todo!()` placeholders for the actual functionality. Here's the implementation plan:

## Phase 2A: Core OCSP Implementation (Week 1-2)

### 1. OCSP Request Building

**File**: `crates/radius-proto/src/revocation/ocsp.rs`

**Approach**: Use `x509-parser` to extract certificate data, then manually build ASN.1 DER:

```rust
impl OcspRequestBuilder {
    pub fn new(cert: &[u8], issuer: &[u8]) -> Result<Self, RevocationError> {
        // Parse certificate with x509-parser
        let (_, cert_parsed) = X509Certificate::from_der(cert)?;
        let (_, issuer_parsed) = X509Certificate::from_der(issuer)?;

        // Extract fields:
        // - serial_number from cert_parsed.serial
        // - issuer_name_hash: SHA-256 of issuer DN
        // - issuer_key_hash: SHA-256 of issuer public key

        // Return builder with these fields populated
    }

    pub fn build(&self) -> Result<Vec<u8>, RevocationError> {
        // Manually construct ASN.1 DER:
        // - Build CertID structure
        // - Build Request structure
        // - Build TBSRequest structure
        // - Build OCSPRequest structure
        // - Encode to DER bytes

        // For MVP: Use simple DER encoding without signature
    }
}
```

**Dependencies**: `x509-parser` (already available), `sha2` (already available)

**Testing**: Unit tests with known certificates and expected DER output

### 2. OCSP HTTP Communication

**File**: `crates/radius-proto/src/revocation/ocsp.rs`

```rust
impl OcspClient {
    pub fn query(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, RevocationError> {
        // HTTP POST to OCSP responder
        let response = self.http_client
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .body(request.to_vec())
            .send()?;

        // Check status code
        if !response.status().is_success() {
            return Err(RevocationError::HttpError(...));
        }

        // Read response body with size limit
        let bytes = response.bytes()?;
        if bytes.len() > self.max_response_size {
            return Err(RevocationError::ResponseTooLarge(...));
        }

        Ok(bytes.to_vec())
    }

    pub fn extract_ocsp_url(cert: &[u8]) -> Result<String, RevocationError> {
        // Parse certificate
        let (_, cert_parsed) = X509Certificate::from_der(cert)?;

        // Find Authority Information Access extension
        // Extract OCSP URL from accessLocation
        // Return URL string
    }
}
```

**Dependencies**: `reqwest` (already available), `x509-parser`

**Testing**: Integration tests with public OCSP responders (e.g., Let's Encrypt)

### 3. OCSP Response Parsing

**File**: `crates/radius-proto/src/revocation/ocsp.rs`

```rust
impl OcspResponse {
    pub fn parse(der_bytes: &[u8]) -> Result<Self, RevocationError> {
        // Use x509-parser OCSP support if available
        // OR manually parse ASN.1 DER:

        // 1. Parse OCSPResponse structure
        // 2. Check responseStatus
        // 3. Extract BasicOCSPResponse from responseBytes
        // 4. Parse ResponseData
        // 5. Extract SingleResponse
        // 6. Parse certStatus, thisUpdate, nextUpdate
        // 7. Extract nonce from extensions if present

        Ok(OcspResponse {
            status: ...,
            cert_status: ...,
            produced_at: ...,
            this_update: ...,
            next_update: ...,
            nonce: ...,
            raw_bytes: der_bytes.to_vec(),
        })
    }
}
```

**Approach**:
- First try x509-parser's OCSP support
- Fall back to manual ASN.1 parsing if needed
- Focus on BasicOCSPResponse (most common)

**Testing**: Unit tests with various OCSP response samples

## Phase 2B: Signature Verification & Caching (Week 3)

### 4. Signature Verification

**File**: `crates/radius-proto/src/revocation/ocsp.rs`

```rust
impl OcspResponse {
    pub fn verify_signature(&self, issuer_cert: &[u8]) -> Result<(), RevocationError> {
        // 1. Extract signature and signatureAlgorithm from BasicOCSPResponse
        // 2. Extract tbsResponseData
        // 3. Parse issuer certificate to get public key
        // 4. Verify signature using rustls/ring crypto
        // 5. Optionally verify responder certificate (if embedded)

        Ok(())
    }
}
```

**Dependencies**: `rustls`, `x509-parser`

**Testing**: Tests with signed vs unsigned responses

### 5. Response Caching

**File**: `crates/radius-proto/src/revocation/ocsp_cache.rs` (new)

Pattern matching the existing CRL cache:

```rust
pub struct OcspCache {
    // Cache key: certificate serial number
    cache: Arc<DashMap<Vec<u8>, CachedOcspResponse>>,
    max_entries: usize,
    default_ttl: Duration,
}

struct CachedOcspResponse {
    response: OcspResponse,
    cached_at: SystemTime,
    expires_at: SystemTime,
}

impl OcspCache {
    pub fn new(default_ttl: Duration, max_entries: usize) -> Self { ... }

    pub fn get(&self, serial: &[u8]) -> Option<OcspResponse> { ... }

    pub fn put(&self, serial: Vec<u8>, response: OcspResponse) { ... }

    pub fn evict_expired(&self) { ... }
}
```

**Dependencies**: `dashmap`, `chrono`

**Testing**: Cache hit/miss tests, expiry tests

## Phase 2C: Integration & Testing (Week 4)

### 6. Verifier Integration

**File**: `crates/radius-proto/src/revocation/verifier.rs`

Update `RevocationCheckingVerifier` to support OCSP:

```rust
impl RevocationCheckingVerifier {
    fn check_revocation(&self, cert: &Certificate) -> Result<(), RevocationError> {
        match self.config.check_mode {
            RevocationCheckMode::CrlOnly => {
                // Existing CRL check
            }
            RevocationCheckMode::OcspOnly => {
                // New OCSP check
                self.check_ocsp(cert)?;
            }
            RevocationCheckMode::PreferOcsp => {
                // Try OCSP first, fallback to CRL
                if let Err(e) = self.check_ocsp(cert) {
                    warn!("OCSP check failed: {}, trying CRL", e);
                    self.check_crl(cert)?;
                }
            }
            RevocationCheckMode::Both => {
                // Check both (AND logic)
                self.check_ocsp(cert)?;
                self.check_crl(cert)?;
            }
            RevocationCheckMode::Disabled => Ok(()),
        }
    }

    fn check_ocsp(&self, cert: &Certificate) -> Result<(), RevocationError> {
        // 1. Extract OCSP URL from certificate
        // 2. Build OCSP request
        // 3. Check cache first
        // 4. If not cached, query OCSP responder
        // 5. Parse and validate response
        // 6. Verify signature
        // 7. Check cert status
        // 8. Cache response
    }
}
```

### 7. Comprehensive Testing

**Test Files**:
- `crates/radius-proto/tests/ocsp_tests.rs` (new)
- Update existing `revocation_integration.rs`

**Test Coverage**:
1. OCSP request building
2. DER encoding/decoding
3. HTTP communication
4. Response parsing
5. Signature verification
6. Nonce validation
7. Cache behavior
8. Failover modes
9. Integration with TLS verification

## Phase 2D: Documentation & Examples (Week 4)

### 8. Documentation

**Files to Update**:
- `crates/radius-proto/src/revocation/README.md` - Add OCSP section
- `crates/radius-proto/src/revocation/mod.rs` - Update examples
- `docs/PERFORMANCE.md` - Add OCSP performance notes

**New Examples**:
- `examples/ocsp_check.rs` - Standalone OCSP checker
- Update `examples/eap_tls_server.rs` - Show OCSP configuration

### 9. Configuration Examples

**JSON Configuration**:

```json
{
  "revocation": {
    "check_mode": "prefer_ocsp",
    "fallback_behavior": "fail_closed",
    "ocsp_config": {
      "enabled": true,
      "http_timeout_secs": 5,
      "cache_ttl_secs": 3600,
      "max_cache_entries": 100,
      "enable_nonce": true,
      "max_response_size_bytes": 1048576,
      "prefer_ocsp": true
    },
    "crl_config": {
      "enable_http_fetch": true,
      "http_timeout_secs": 5,
      "cache_ttl_secs": 3600,
      "max_cache_entries": 100
    }
  }
}
```

## Implementation Considerations

### Nonce Support (RFC 8954)

Nonce is critical for replay protection:

```rust
impl OcspRequestBuilder {
    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    fn build_with_nonce(&self) -> Vec<u8> {
        // Add nonce extension to TBSRequest
        // Extension OID: 1.3.6.1.5.5.7.48.1.2
    }
}

impl OcspResponse {
    pub fn verify_nonce(&self, expected_nonce: &[u8]) -> Result<(), RevocationError> {
        match &self.nonce {
            Some(response_nonce) if response_nonce == expected_nonce => Ok(()),
            Some(_) => Err(RevocationError::NonceMismatch),
            None => Err(RevocationError::NonceNotPresent),
        }
    }
}
```

### Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| OCSP Latency | < 100ms | Includes HTTP round-trip |
| Cache Hit Rate | > 90% | For typical cert lifetimes |
| Memory per Response | < 10KB | Typical response size |
| Cache Size | ~1MB | 100 cached responses |

### Error Handling Strategy

Follow existing CRL pattern:

- **Fail-Closed**: Reject authentication on OCSP errors (production default)
- **Fail-Open**: Allow authentication on OCSP errors (development/testing)
- **Fallback**: Try CRL if OCSP fails (PreferOcsp mode)

### Known Limitations (MVP)

1. **No OCSP Stapling**: TLS OCSP stapling (RFC 6066) deferred to Phase 3
2. **No Request Signing**: Unsigned requests only (sufficient for most cases)
3. **BasicOCSPResponse Only**: No support for other response types
4. **Single Certificate**: One cert per request (could batch in future)

## Timeline

| Week | Focus | Deliverables |
|------|-------|--------------|
| 1 | Request building & HTTP | Working OCSP client |
| 2 | Response parsing | Full request/response cycle |
| 3 | Verification & caching | Production-ready validation |
| 4 | Integration & testing | Complete OCSP support |

**Total Estimated Effort**: 4 weeks for full OCSP implementation

## Success Criteria

- [x] OCSP module structure and configuration
- [ ] OCSP request building with DER encoding
- [ ] HTTP POST to OCSP responders
- [ ] Response parsing and validation
- [ ] Signature verification
- [ ] Nonce support
- [ ] Response caching
- [ ] Integration with RevocationCheckingVerifier
- [ ] Comprehensive test coverage (>80%)
- [ ] Documentation and examples
- [ ] Performance meets targets

## References

- [RFC 6960](https://tools.ietf.org/html/rfc6960) - OCSP Protocol
- [RFC 8954](https://tools.ietf.org/html/rfc8954) - OCSP Nonce Extension
- [RFC 6066](https://tools.ietf.org/html/rfc6066) - TLS OCSP Stapling (future)
- [x509-parser documentation](https://docs.rs/x509-parser/)
- Existing CRL implementation for patterns
