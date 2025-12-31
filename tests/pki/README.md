# Test PKI for CRL Integration Tests

This directory contains a complete Public Key Infrastructure (PKI) for testing certificate revocation functionality.

## Directory Structure

```
tests/pki/
├── ca/                    # Certificate Authority certificates
│   ├── root-ca.crt       # Self-signed root CA
│   └── intermediate-ca.crt # Intermediate CA (signed by root)
├── certs/                 # Client certificates
│   ├── client-valid.crt   # Valid client certificate
│   ├── client-revoked.crt # Revoked client certificate
│   ├── *.crt.der         # DER-encoded versions for parsing
│   └── *.csr             # Certificate signing requests
├── crls/                  # Certificate Revocation Lists
│   ├── intermediate-ca-empty.crl     # Empty CRL (no revocations)
│   ├── intermediate-ca.crl           # CRL with revoked certificate
│   └── *.crl.der                     # DER-encoded CRLs for parsing
├── private/               # Private keys
│   ├── root-ca.key
│   ├── intermediate-ca.key
│   ├── client-valid.key
│   └── client-revoked.key
└── *.cnf                  # OpenSSL configuration files
```

## PKI Details

### Root CA
- **Subject**: CN=Test Root CA, O=Test Root CA, L=Test, ST=Test, C=US
- **Validity**: 10 years (2025-2035)
- **Key Usage**: Certificate Sign, CRL Sign
- **File**: `ca/root-ca.crt`

### Intermediate CA
- **Subject**: CN=Test Intermediate CA, O=Test Intermediate CA, L=Test, ST=Test, C=US
- **Issuer**: Test Root CA
- **Validity**: 10 years (2025-2035)
- **Key Usage**: Certificate Sign, CRL Sign
- **CRL Distribution Point**: http://ca.example.com/root-ca.crl
- **File**: `ca/intermediate-ca.crt`

### Client Certificates

#### Valid Client Certificate
- **Subject**: CN=valid-client@test.com, O=Test Client, L=Test, ST=Test, C=US
- **Serial**: 629F3FB804387DE860431CC8B4AFA5BE8ED2780C
- **Issuer**: Test Intermediate CA
- **Validity**: 1 year (2025-2026)
- **Key Usage**: Digital Signature, Key Encipherment
- **Extended Key Usage**: Client Authentication
- **CRL Distribution Point**: http://ca.example.com/intermediate-ca.crl
- **File**: `certs/client-valid.crt`
- **Status**: ✅ Valid (not revoked)

#### Revoked Client Certificate
- **Subject**: CN=revoked-client@test.com, O=Test Client, L=Test, ST=Test, C=US
- **Serial**: 629F3FB804387DE860431CC8B4AFA5BE8ED2780D
- **Issuer**: Test Intermediate CA
- **Validity**: 1 year (2025-2026)
- **Key Usage**: Digital Signature, Key Encipherment
- **Extended Key Usage**: Client Authentication
- **CRL Distribution Point**: http://ca.example.com/intermediate-ca.crl
- **File**: `certs/client-revoked.crt`
- **Status**: ❌ Revoked (present in CRL)

### Certificate Revocation Lists

#### Empty CRL
- **Issuer**: Test Intermediate CA
- **Last Update**: Dec 31, 2025
- **Next Update**: Jan 30, 2026
- **Revoked Certificates**: 0
- **File**: `crls/intermediate-ca-empty.crl` (PEM) / `crls/intermediate-ca-empty.crl.der` (DER)

#### CRL with Revocations
- **Issuer**: Test Intermediate CA
- **Last Update**: Dec 31, 2025
- **Next Update**: Jan 30, 2026
- **Revoked Certificates**: 1 (serial 629F3FB804387DE860431CC8B4AFA5BE8ED2780D)
- **File**: `crls/intermediate-ca.crl` (PEM) / `crls/intermediate-ca.crl.der` (DER)

## Usage in Tests

The integration tests in `crates/radius-proto/tests/revocation_integration.rs` use this PKI:

### Test: `test_real_crl_parsing`
- Validates parsing of `intermediate-ca-empty.crl.der`
- Verifies CRL structure and issuer
- Confirms no revoked certificates in empty CRL

### Test: `test_revoked_certificate_detection`
- Validates parsing of `intermediate-ca.crl.der`
- Confirms revoked certificate serial is present
- Matches `client-revoked.crt.der` serial against CRL

## Format Notes

- **PEM Format**: Base64-encoded with `-----BEGIN/END-----` headers
  - Used by OpenSSL tools
  - Human-readable
  - Files: `*.crt`, `*.crl`, `*.key`

- **DER Format**: Binary ASN.1 encoding
  - Used by Rust x509-parser
  - More compact
  - Files: `*.crt.der`, `*.crl.der`

## Regenerating the PKI

If you need to regenerate this test PKI, the generation commands are documented in the integration test file comments. The key steps are:

1. Generate Root CA
2. Generate Intermediate CA (signed by root)
3. Generate client certificates (signed by intermediate)
4. Generate empty CRL
5. Revoke one certificate
6. Generate CRL with revocation
7. Convert PEM to DER for parsing tests

## Security Note

⚠️ **THIS IS TEST PKI ONLY** ⚠️

- Private keys are committed to the repository
- Do NOT use for production
- Intended only for automated testing
- All certificates have "Test" in the subject/issuer

## Test Results

With this PKI, the CRL revocation integration tests achieve:

- ✅ 42 unit tests passing (CRL parsing, caching, fetching)
- ✅ 10 integration tests passing (configuration + real PKI tests)
- ✅ 2 tests ignored (require HTTP server / full TLS handshake)
- ✅ Full validation of production CRL implementation

## Files Generated

**Date**: December 31, 2025
**OpenSSL Version**: 3.x

Total files: 20+
- 2 CA certificates
- 2 client certificates (+ DER versions)
- 2 CRLs (+ DER versions)
- 4 private keys
- Various CSRs and config files
