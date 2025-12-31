# USG RADIUS Development Roadmap

This document outlines the development roadmap for the USG RADIUS project, organized by release milestones.

## Current Status: v0.5.0 (Eap Methonds)

**Release Date**: December 2025
**Status**: ✅ Complete - Multi-method authentication ready

### Completed Features (v0.1.0 + v0.2.0 + v0.3.0)

#### **Core Protocol (v0.1.0)**

- ✅ Basic RADIUS protocol implementation (RFC 2865)
- ✅ PAP authentication
- ✅ User-Password encryption/decryption
- ✅ Packet encoding/decoding
- ✅ 60+ standard attributes
- ✅ Status-Server support (RFC 5997)
- ✅ Async I/O with Tokio
- ✅ JSON configuration
- ✅ Simple in-memory authentication
- ✅ Workspace structure with separate protocol and server crates
- ✅ IPv6 dual-stack support (IPv4 + IPv6)

#### **Security & Production Hardening (v0.2.0)**

- ✅ Client IP address validation
- ✅ Per-client shared secrets
- ✅ Client database with enable/disable flags
- ✅ Source IP verification
- ✅ Duplicate request detection
- ✅ Request identifier tracking
- ✅ Replay attack prevention
- ✅ Per-client rate limiting
- ✅ Global rate limiting
- ✅ Required attribute enforcement
- ✅ Enumerated value validation
- ✅ Attribute type-specific validation
- ✅ Malformed packet rejection
- ✅ Strict RFC compliance mode
- ✅ Structured logging (tracing crate)
- ✅ Configurable log levels
- ✅ Security event logging
- ✅ JSON audit trail
- ✅ Environment variable support for secrets
- ✅ Configuration validation on startup
- ✅ JSON Schema for configuration

#### Authentication Methods (v0.3.0)

- ✅ CHAP authentication (RFC 2865)
- ✅ Access-Challenge packet support (multi-round auth)
- ✅ Message-Authenticator (RFC 2869 HMAC-MD5)
- ✅ Proxy-State preservation (RFC 2865 Section 5.33)
- ✅ State attribute handling for multi-round flows
- ✅ AuthResult enum (Accept/Reject/Challenge)

### Known Limitations

- ⚠️ No EAP support (planned for v0.5.0)
- ⚠️ No hot reload (requires server restart for config changes)

See [RFC-COMPLIANCE.md](RFC-COMPLIANCE.md) for detailed gap analysis.

---

## v0.2.0 - Security & Production Hardening (Q4 2025)

**Goal**: Make the server production-ready for basic deployments
**Priority**: CRITICAL

### Security Enhancements

#### Client Validation & Authorization ✅ COMPLETED

- ✅ Implement client IP address validation
- ✅ Per-client shared secrets
- ✅ Client database with enable/disable flags
- ✅ Source IP verification against configuration
- ✅ NAS-Identifier validation

**Status**: ✅ Complete

#### Request Security ✅ COMPLETED

- ✅ Duplicate request detection (cache recent requests)
- ✅ Identifier tracking and validation
- ✅ Request timeout handling (via cache TTL)
- ✅ Replay attack prevention
- ✅ Request rate limiting per client

**Status**: ✅ Complete

#### Attribute Validation ✅ COMPLETED

- ✅ Required attribute enforcement (User-Name must be present)
- ✅ Enumerated value validation (Service-Type 1-13)
- ✅ Attribute type-specific validation
- ✅ Malformed packet rejection
- ✅ Strict RFC compliance mode

**Status**: ✅ Complete

### Operational Improvements

#### Logging & Monitoring ✅ COMPLETE

- ✅ Replace println! with proper logging (tracing crate)
- ✅ Structured logging with levels (trace, debug, info, warn, error)
- ✅ Configurable log levels via config file or environment variable
- ✅ Security event logging (rate limits, unauthorized clients, auth failures)
- ✅ Audit trail for authentication attempts (JSON format)
- [ ] Log rotation support (handled by external tools)

**Status**: ✅ Complete (log rotation delegated to system tools like logrotate)

#### Rate Limiting & DoS Protection ✅ COMPLETED

- ✅ Per-client request rate limiting
- ✅ Global request rate limiting
- ✅ Configurable limits (per-client and global RPS/burst)
- ✅ Concurrent connection limits
- ✅ Bandwidth throttling

**Status**: ✅ Complete

### Configuration

- ✅ Validate client CIDR networks
- ✅ Environment variable support for secrets
- ✅ Configuration file validation on startup
- [ ] Hot reload configuration (SIGHUP) - deferred to future release

**Status**: ✅ Complete (3/3 required features, hot reload marked as future enhancement)

**Total v0.2.0 Estimated Effort**: 6-8 weeks

---

## v0.3.0 - Authentication Methods (Q4 2025)

**Goal**: Support modern authentication methods
**Priority**: HIGH
**Status**: ✅ Complete (Dec 2025)

### CHAP Support ✅ COMPLETED

- ✅ CHAP-Password attribute handling
- ✅ CHAP-Challenge generation
- ✅ CHAP algorithm implementation (MD5-based)
- ✅ CHAP authentication validation
- ✅ Tests and examples (6 integration tests)
- ✅ Support for Request Authenticator as challenge
- ✅ ChapResponse and ChapChallenge types
- ✅ Interleaved PAP/CHAP authentication

**Status**: ✅ Complete (Dec 2025)

### Access-Challenge ✅ COMPLETED

- ✅ Access-Challenge packet generation
- ✅ State attribute handling
- ✅ Multi-round authentication flow
- ✅ AuthResult enum (Accept, Reject, Challenge)
- ✅ authenticate_with_challenge() trait method
- ✅ Challenge attribute support (Reply-Message, State)
- ✅ Integration tests demonstrating 2FA flow

**Status**: ✅ Complete (Dec 2025)

### Message-Authenticator (RFC 2869) ✅ COMPLETED

- ✅ HMAC-MD5 calculation
- ✅ calculate_message_authenticator() function
- ✅ verify_message_authenticator() function
- ✅ Server-side validation enforcement in Access-Request handler
- ✅ Comprehensive test suite (10 tests: 7 unit + 3 integration)
- ✅ Support for packet integrity verification
- ✅ Backward compatibility with clients not using it (validation only when present)

**Status**: ✅ Complete (Dec 2025)

### Proxy-State Support ✅ COMPLETED

- ✅ Preserve Proxy-State attributes in responses
- ✅ Multiple Proxy-State attribute handling
- ✅ Automatic copying in Access-Accept, Access-Challenge, Access-Reject
- ✅ RFC 2865 Section 5.33 compliance

**Status**: ✅ Complete (Dec 2025)

**Completed Features**:

- All 120 tests passing (35 proto + 49 server + 17 integration + 19 backend)
- Full CHAP authentication with MD5
- Multi-round authentication with Access-Challenge
- HMAC-MD5 Message-Authenticator integrity protection
- RFC-compliant Proxy-State preservation

**Total v0.3.0 Actual Effort**: ~3 weeks (faster than estimated due to clean architecture)

---

## v0.4.0 - Accounting & Session Management (Q4 2025)

**Goal**: Add RADIUS Accounting support (RFC 2866)
**Priority**: HIGH
**Status**: ✅ Complete (100%)

### Accounting Protocol ✅ COMPLETED

- ✅ Accounting-Request (Code 4) handling
- ✅ Accounting-Response (Code 5) generation
- ✅ Acct-Status-Type validation (Start, Stop, Interim-Update, Accounting-On/Off)
- ✅ Accounting packet processing
- ✅ Request Authenticator validation (RFC 2866 Section 3)
- ✅ Response Authenticator calculation
- ✅ NAS-related accounting (Accounting-On, Accounting-Off)

**Status**: ✅ Complete

### Session Tracking ✅ COMPLETED

- ✅ Session database (in-memory with DashMap)
- ✅ Session start/stop tracking
- ✅ Interim updates
- ✅ Session timeout handling (configurable)
- ✅ Concurrent session limits (per-user)
- ✅ Stale session cleanup
- ✅ Session query APIs (by user, by NAS, by ID)
- ✅ Session statistics (count, active sessions)

**Status**: ✅ Complete

### Accounting Storage

- ✅ Pluggable AccountingHandler trait (async)
- ✅ SimpleAccountingHandler (in-memory, for testing)
- ✅ File-based accounting logs (JSON Lines format)
  - ✅ FileAccountingHandler implementation
  - ✅ Async file I/O with Tokio
  - ✅ JSON Lines format (one record per line)
  - ✅ Auto-creates parent directories
  - ✅ Captures all event types and attributes
- ✅ Database accounting backends
  - ✅ PostgreSQL backend
    - ✅ PostgresAccountingHandler implementation
    - ✅ Schema design (radius_sessions, radius_accounting_events)
    - ✅ Connection pooling with sqlx
    - ✅ Automatic migrations
    - ✅ All accounting event types supported
    - ✅ Session query methods
- ✅ Accounting data retention policies
  - ✅ Configurable retention periods (accounting_retention_days)
  - ✅ Automated cleanup method for PostgreSQL backend
  - ✅ Deletes old sessions and events based on age

**Status**: ✅ Complete

### Usage Metrics

- ✅ Bytes in/out tracking (Acct-Input-Octets, Acct-Output-Octets)
- ✅ Session duration tracking (Acct-Session-Time)
- ✅ Termination cause tracking (Acct-Terminate-Cause)
- ✅ Packets in/out tracking (32-bit counter support)
- ✅ 64-bit counter support (Acct-Input-Gigawords, Acct-Output-Gigawords)
  - ✅ RFC 2869 gigaword attributes (52, 53)
  - ✅ Automatic 64-bit value calculation in all handlers
  - ✅ Backward compatible (gigawords optional)
- ✅ Usage reports and aggregation queries
  - ✅ PostgreSQL aggregation methods
  - ✅ Total usage by user (input/output octets, session time, count)
  - ✅ Total usage by NAS (aggregated network statistics)
  - ✅ Top users by bandwidth (ranked list with usage metrics)
  - ✅ Session duration statistics (avg/min/max/total)
  - ✅ Daily usage aggregation (time-series data)
  - ✅ Hourly usage aggregation (granular breakdowns)
  - ✅ Active session counts and grouping
  - ✅ Comprehensive test coverage for all queries
- ✅ Export functionality
  - ✅ CSV export for user usage (bandwidth and session stats)
  - ✅ CSV export for session details (active and completed)
  - ✅ JSON usage reports with summary statistics
  - ✅ Automatic MB conversion and time formatting
  - ✅ Time range filtering support
  - ✅ Comprehensive test coverage for export methods

**Status**: ✅ Complete

### Test Coverage

- ✅ Unit tests for accounting types (AcctStatusType, AcctTerminateCause, etc.)
- ✅ Unit tests for SimpleAccountingHandler
- ✅ Unit tests for FileAccountingHandler
- ✅ Integration tests for accounting protocol
- ✅ Integration tests for session management
- ✅ Integration tests for file-based accounting
- ✅ All 28 integration tests passing

**Status**: ✅ Complete

### Completed Features

- **Accounting Protocol Types** (radius-proto/accounting.rs):
  - AcctStatusType enum with all RFC 2866 values
  - AcctTerminateCause enum (18 termination reasons)
  - AcctAuthentic enum
  - AccountingError types with session management errors

- **Session Management** (radius-server/accounting.rs):
  - Session struct with comprehensive tracking
  - Configurable session timeout
  - Configurable concurrent session limits
  - Automatic stale session cleanup
  - Query APIs for sessions by user/NAS/ID

- **File-Based Backend** (radius-server/accounting/file.rs):
  - 468 lines of production-ready code
  - JSON Lines format for easy parsing
  - Captures: timestamps, events, session IDs, usernames, IPs, usage metrics
  - Async file operations with proper error handling

- **PostgreSQL Backend** (radius-server/accounting/postgres.rs):
  - 1900+ lines of production-ready code
  - Two-table schema: radius_sessions and radius_accounting_events
  - Automatic migrations with comprehensive indexes
  - Connection pooling with sqlx::PgPool
  - All AccountingHandler trait methods implemented
  - Session query APIs (get_active_sessions, get_session)
  - IP address conversion (IpAddr ↔ INET)
  - Configuration support via accounting_database_url
  - Data retention and cleanup (cleanup_old_data method)
  - Usage aggregation methods:
    - get_user_usage: Total usage by user with time range filtering
    - get_nas_usage: Total usage by NAS device
    - get_top_users_by_bandwidth: Ranked list of highest bandwidth consumers
    - get_user_session_stats: Session duration statistics (avg/min/max/total)
    - get_daily_usage_by_user: Daily time-series aggregation
    - get_hourly_usage: Hourly granular breakdowns
    - get_active_sessions_count: Real-time active session monitoring
    - get_active_sessions_by_nas: Active sessions grouped by NAS
  - Export functionality:
    - export_user_usage_csv: CSV export with bandwidth and session stats
    - export_sessions_csv: Detailed session export (active/all)
    - generate_usage_report_json: Comprehensive JSON reports with summaries
  - Comprehensive test coverage (6 test suites, 500+ lines of tests)

**Total v0.4.0 Actual Effort**: ~6 weeks (accounting protocol + session management + file backend + PostgreSQL + aggregation + export)

---

## v0.5.0 - EAP Support (Q4 2025)

**Goal**: Support modern 802.1X authentication
**Priority**: MEDIUM-HIGH
**Status**: 🔄 In Progress (EAP Framework Started)

### EAP Framework ✅ COMPLETE

- ✅ EAP-Message attribute (Type 79) handling
- ✅ EAP packet structure (Request, Response, Success, Failure)
- ✅ EAP packet encoding/decoding
- ✅ EAP type enumeration (Identity, Notification, NAK, MD5, TLS, TTLS, PEAP, MSCHAPv2, TEAP)
- ✅ EAP state machine with authentication flow states
- ✅ EAP session management with timeout and cleanup
- ✅ EAP-Message RADIUS integration helpers (RFC 3579)
- ✅ RADIUS-level fragmentation (EAP packets split across multiple RADIUS attributes)
- [ ] EAP packet-level fragmentation (Deferred to TLS-based EAP methods - EAP-TLS, PEAP, etc.)

**Status**: ✅ Core framework complete (Dec 2025)
**Note**: EAP packet-level fragmentation (L/M/S flags per RFC 3748) will be implemented alongside TLS-based EAP methods where it's required.

### EAP Methods

- ✅ **EAP-MD5 Challenge** (Type 4) - RFC 3748
  - ✅ Challenge generation and parsing
  - ✅ Response computation and verification
  - ✅ MD5 hash calculation (identifier + password + challenge)
  - ✅ Full authentication flow
  - ✅ Comprehensive test coverage (4 test suites)
- ✅ **EAP-TLS** (Type 13) - RFC 5216 (certificate-based) - **100% Complete**
  - ✅ EAP-TLS packet structure and parsing
  - ✅ TLS flags (L/M/S) implementation
  - ✅ Fragment assembler and reassembly
  - ✅ Message fragmentation (large TLS records)
  - ✅ MSK/EMSK key derivation (RFC 5216 Section 2.3)
  - ✅ TLS 1.2 PRF using SHA-256
  - ✅ TLS handshake state machine
  - ✅ EapTlsContext for session management
  - ✅ Fragment queue and outgoing buffer management
  - ✅ TlsCertificateConfig structure
  - ✅ Certificate/key loading with rustls-pemfile
  - ✅ X.509 certificate validation (validity period)
  - ✅ TLS-specific error types (TlsError, CertificateError, IoError)
  - ✅ Comprehensive test coverage (38 test suites)
  - ✅ Complete documentation with examples
  - ✅ Actual TLS handshake using rustls (EapTlsServer)
  - ✅ rustls ServerConnection wrapper with message processing
  - ✅ EapTlsAuthHandler trait for RADIUS integration
  - ✅ X.509 certificate chain verification
  - ✅ CA certificate loading and validation
  - ✅ Client certificate support (mutual TLS)
  - ✅ Client certificate identity verification
  - ✅ Integration with RADIUS server (EapAuthHandler implementation)
  - ✅ authenticate_request() method for full packet access
  - ✅ EAP-Message attribute extraction and reassembly
  - ✅ Complete authentication flow with session management
  - ✅ **Production key extraction (MSK/EMSK) using RFC 5705**
    - ✅ RFC 5705 Keying Material Exporter implementation
    - ✅ rustls export_keying_material() integration
    - ✅ Label "client EAP encryption" per RFC 5216 Section 2.3
    - ✅ 128-byte key derivation (64 MSK + 64 EMSK)
    - ✅ Direct key export without intermediate master_secret
    - ✅ Production-ready for wireless encryption keys

### Future EAP Methods

- [ ] **EAP-TEAP** (Type 55) - RFC 7170 - **PLANNED**
  - Tunnel Extensible Authentication Protocol
  - Modern replacement for EAP-TTLS, PEAP, and EAP-MSCHAPv2
  - More flexible and secure than legacy tunneled methods
  - Supports cryptographic binding, channel binding, and inner method negotiation
  - Estimated: 4-5 weeks

**Rationale**: EAP-TEAP is the modern IETF standard (RFC 7170) that supersedes legacy tunneled methods. It provides better security, flexibility, and is actively maintained. Organizations should migrate to EAP-TEAP rather than implement legacy protocols.

### Legacy EAP Methods (Not Planned)

The following legacy methods will **not** be implemented due to modern alternatives:

- **EAP-TTLS** (Type 21, RFC 5281) - **DROPPED**
  - Superseded by EAP-TEAP
  - Less flexible cryptographic binding
  - Recommend EAP-TEAP for new deployments

- **PEAP** (Type 25) - **DROPPED**
  - Superseded by EAP-TEAP
  - Microsoft/Cisco implementation differences cause compatibility issues
  - Never fully standardized (draft only)
  - Recommend EAP-TEAP for new deployments

- **EAP-MSCHAPv2** (Type 26) - **DROPPED**
  - Superseded by EAP-TEAP with modern inner methods
  - Known cryptographic weaknesses
  - Deprecated by Microsoft in favor of certificate-based auth
  - Recommend EAP-TLS or EAP-TEAP for new deployments

**Migration Path**: Organizations using EAP-TTLS, PEAP, or EAP-MSCHAPv2 should migrate to:

1. **EAP-TLS** (best security, certificate-based) - ✅ **Available now**
2. **EAP-TEAP** (modern tunneled method) - Planned for future release

**Status**: ✅ EAP-TLS 100% complete (Dec 2025), EAP-MD5 complete
**Future Work**: Implement EAP-TEAP as the modern tunneled EAP method

### Certificate Management

- ✅ Certificate validation
- ✅ CA certificate chain verification
- ✅ Certificate expiry checking
- ✅ Certificate/key pair validation
- ✅ PEM file loading (certificates and keys)
- ✅ X.509 DER parsing and validation
- [ ] **Certificate Revocation (CRL/OCSP)** - **PLANNED for v0.6.0**
  - Production-grade revocation checking
  - See v0.6.0 roadmap below for full architecture
  - Estimated: 6-8 weeks for full implementation
  - Phased approach: CRL-only (3-4 weeks), then OCSP (2-3 weeks), then optimization

**Status**: ✅ Core features complete (Dec 2025)
**Note**: For v0.5.0, manual certificate lifecycle management recommended. Use short-lived certificates (1-30 days) to minimize revocation needs until v0.6.0.

### Completed Features

- **EAP Protocol Module** (radius-proto/eap.rs):
  - 1700+ lines of production-ready code
  - EapCode enum (Request, Response, Success, Failure)
  - EapType enum (11 method types)
  - EapPacket structure with parsing/encoding
  - Full RFC 3748 compliance for packet format
  - 46 comprehensive unit tests (100% pass rate)

- **EAP State Machine**:
  - 9 authentication states (Initialize, IdentityRequested, IdentityReceived, MethodRequested, ChallengeRequested, ResponseReceived, Success, Failure, Timeout)
  - State transition validation with rules enforcement
  - Terminal state detection
  - Support for multi-round authentication flows

- **EAP Session Management** (EapSession & EapSessionManager):
  - Session lifecycle tracking with timestamps
  - EAP identifier management with wrapping
  - Timeout detection and cleanup
  - Attempt counting and max attempts enforcement
  - Concurrent session support with HashMap-based storage
  - Session statistics and monitoring
  - 25 dedicated test suites for state machine and sessions

- **EAP-Message RADIUS Integration** (RFC 3579):
  - `eap_to_radius_attributes()` - Convert EAP packet to RADIUS EAP-Message attribute(s)
  - `eap_from_radius_packet()` - Extract and reassemble EAP packet from RADIUS packet
  - `add_eap_to_radius_packet()` - Convenience function for adding EAP to RADIUS
  - Automatic fragmentation across multiple attributes (253 byte chunks)
  - Reassembly of fragmented EAP packets
  - 8 comprehensive integration tests (single/multi-attribute, round-trip, mixed attributes)

- **EAP-MD5 Implementation** (radius-proto/eap/eap_md5):
  - Challenge-response authentication
  - MD5 hash computation
  - Request/response packet creation
  - Challenge/response parsing
  - Authentication verification
  - 4 dedicated test suites including full authentication flow

**Total v0.5.0 Actual Effort**: ~2 weeks so far (EAP framework + EAP-MD5 + state machine + sessions + RADIUS integration)
**Total v0.5.0 Estimated Remaining**: ~9 weeks

---

## v0.6.0 - Enterprise Features (Q1 2026)

**Goal**: Enterprise-grade features
**Priority**: MEDIUM
**Status**: 🔄 In Progress (Backend Integration ✅ Complete)

### Database Integration ✅ COMPLETED

- ✅ PostgreSQL authentication backend
- ✅ User attribute storage (via attributes_query)
- ✅ Connection pooling
- ✅ Bcrypt password hashing
- ✅ Custom SQL queries
- ✅ PostgreSQL schema and migration examples
- [ ] Additional password hashing algorithms (argon2, pbkdf2)

**Status**: ✅ PostgreSQL complete, MySQL pending
**Completed**: Dec 2025

### LDAP/Active Directory ✅ COMPLETED

- ✅ LDAP authentication backend
- ✅ Active Directory integration
- ✅ LDAPS (LDAP over SSL/TLS) support
- ✅ Flexible search filters and attribute retrieval
- ✅ Service account binding
- ✅ Anonymous bind support
- ✅ Async/sync compatibility
- [ ] Group membership queries and RADIUS attribute mapping
- [ ] Connection pooling and failover

**Status**: ✅ Core features complete, advanced features pending
**Completed**: Dec 2025

### Documentation ✅ COMPLETED

- ✅ Backend integration comparison guide
- ✅ PostgreSQL integration guide (500+ lines)
- ✅ LDAP/Active Directory integration guide
- ✅ Example configurations (LDAP, AD, PostgreSQL)
- ✅ Database schema examples
- ✅ Migration guides between backends
- ✅ Security best practices
- ✅ Performance tuning recommendations
- ✅ Troubleshooting guides
- ✅ Documentation reorganization into docs/docs/ structure

**Status**: ✅ Complete
**Completed**: Dec 2025

### Testing ✅ COMPLETED

- ✅ 8 LDAP unit tests
- ✅ 9 PostgreSQL unit tests
- ✅ Configuration serialization tests
- ✅ Password hashing tests
- [ ] Docker-based LDAP integration tests
- [ ] Docker-based PostgreSQL integration tests
- [ ] End-to-end authentication tests

**Status**: 🔄 Unit tests complete, integration tests pending
**Completed**: Dec 2025 (partial)

### High Availability

- [ ] Multi-server deployment support
- [ ] Shared session state (Redis/database)
- [ ] Health checks
- [ ] Failover mechanisms
- [ ] Load balancing recommendations

**Estimated Effort**: 3 weeks

### Additional Backend Support

- [ ] Redis caching backend
- [ ] REST API authentication backend
- [ ] Multi-backend fallback chains

**Estimated Effort**: 3 weeks

### Performance Optimization

- [ ] Query optimization for database backends
- [ ] LDAP connection pooling improvements
- [ ] Request caching enhancements
- ✅ Performance benchmarking framework
- [ ] Memory optimization
- [ ] CPU profiling and optimization

**Status**: 🔄 Benchmarking framework exists, optimizations pending
**Estimated Effort**: 2 weeks

### Certificate Revocation (CRL/OCSP)

Production-grade certificate revocation checking for EAP-TLS mutual authentication.

**Architecture Overview**:

- Custom `RevocationCheckingVerifier` wrapping `WebPkiClientVerifier`
- Async HTTP fetching with sync verification bridge
- Shared caching layer (DashMap) with TTL management
- Configurable revocation policies (CRL, OCSP, both, prefer)
- Fail-open or fail-closed behavior on network errors

**Features**:

**Phase 1: CRL Support** (3-4 weeks)

- [ ] CRL parsing using x509-parser (RFC 5280)
- [ ] HTTP fetching from distribution points
- [ ] Static CRL file loading
- [ ] CRL signature verification
- [ ] Serial number revocation checking
- [ ] TTL-based caching with automatic refresh
- [ ] CRL size limits and validation

**Phase 2: OCSP Support** (2-3 weeks)

- [ ] OCSP request building (ASN.1 DER encoding)
- [ ] OCSP HTTP POST requests to responders
- [ ] OCSP response parsing and validation
- [ ] OCSP signature verification
- [ ] Nonce support for replay protection
- [ ] OCSP stapling (RFC 6066)
- [ ] Response caching with TTL

**Phase 3: Integration & Optimization** (1-2 weeks)

- [ ] Custom verifier integration with `build_server_config()`
- [ ] Async-sync bridge using `tokio::task::block_in_place`
- [ ] Background refresh tasks for CRL/OCSP updates
- [ ] Graceful fallback behavior (fail-open/fail-closed)
- [ ] Network timeout and retry logic
- [ ] Performance optimization and benchmarking

**Configuration API**:

```rust
RevocationConfig {
    check_mode: RevocationCheckMode,      // CrlOnly, OcspOnly, Both, PreferOcsp
    fallback_behavior: FallbackBehavior,  // FailOpen, FailClosed
    crl_config: CrlConfig,
    ocsp_config: OcspConfig,
}
```

**Dependencies** (behind `revocation` feature flag):

- `reqwest` - HTTP client for CRL/OCSP fetching
- `url` - URL parsing for distribution points
- `der` - ASN.1 DER encoding/decoding
- `x509-parser` (existing) - CRL parsing

**Testing**:

- [ ] Unit tests for CRL/OCSP parsing
- [ ] Mock HTTP server for integration tests
- [ ] Test PKI generation (revoked/valid certs)
- [ ] Performance benchmarks (cache hit/miss)
- [ ] Network failure simulation

**Documentation**:

- [ ] Configuration guide with examples
- [ ] Security considerations and best practices
- [ ] Troubleshooting guide for common issues
- [ ] Migration guide from v0.5.0

**Status**: 📋 Planned (architecture complete)
**Estimated Effort**: 6-8 weeks total
**Dependencies**: EAP-TLS (✅ complete), rustls 0.23 (✅ complete)
**Priority**: HIGH for production deployments

**Rationale**: While short-lived certificates (1-30 days) can mitigate revocation needs, production environments require robust revocation checking for compliance (PCI-DSS, HIPAA, NIST 800-53) and security. This implementation provides enterprise-grade revocation with minimal performance impact through caching.

**Total v0.6.0 Effort**:

- ✅ Completed: ~4 weeks (LDAP, PostgreSQL, docs, tests)
- ⏳ Remaining: ~14-16 weeks (HA, additional backends, optimization, CRL/OCSP)

---

## v0.7.0 - RADIUS Proxy (Q1 2026)

**Goal**: Support RADIUS proxy and routing
**Priority**: MEDIUM

### Proxy Core

- [ ] Proxy-State handling
- [ ] Request forwarding
- [ ] Response routing
- [ ] Proxy loops detection
- [ ] Timeout and retry handling

**Estimated Effort**: 3 weeks

### Routing

- [ ] Realm-based routing (@domain)
- [ ] Attribute-based routing
- [ ] Load balancing across servers
- [ ] Failover support
- [ ] Dynamic routing rules

**Estimated Effort**: 2 weeks

### Proxy Pools

- [ ] Server pool configuration
- [ ] Pool health monitoring
- [ ] Automatic server removal/addition
- [ ] Pool statistics

**Estimated Effort**: 2 weeks

**Total v0.7.0 Estimated Effort**: 7 weeks

---

## v0.8.0 - RadSec (RADIUS over TLS) (Q1 2026)

**Goal**: Secure RADIUS transport
**Priority**: MEDIUM

### TLS Support (RFC 6614)

- [ ] TLS 1.2+ support
- [ ] Certificate-based authentication
- [ ] RADIUS over TLS (RadSec)
- [ ] DTLS support
- [ ] Perfect Forward Secrecy

**Estimated Effort**: 4 weeks

### Certificate Management for RadSec

- [ ] Dynamic certificate loading
- [ ] Certificate rotation
- [ ] Mutual TLS authentication
- [ ] Certificate pinning

**Estimated Effort**: 2 weeks

**Total v0.8.0 Estimated Effort**: 6 weeks

---

## v0.9.0 - Change of Authorization (Q1 2026)

**Goal**: Dynamic session control
**Priority**: LOW-MEDIUM

### CoA Support (RFC 5176)

- [ ] CoA-Request packet handling
- [ ] CoA-ACK/NAK generation
- [ ] Disconnect-Request handling
- [ ] Disconnect-ACK/NAK generation
- [ ] Session identification

**Estimated Effort**: 3 weeks

### Dynamic Authorization

- [ ] Session attribute updates
- [ ] QoS changes
- [ ] Bandwidth modification
- [ ] Session termination

**Estimated Effort**: 2 weeks

**Total v0.9.0 Estimated Effort**: 5 weeks

---

## v1.0.0 - Production Release (Q1 2026)

**Goal**: Stable, feature-complete, production-ready
**Priority**: HIGH

### Final Hardening

- [ ] Security audit
- [ ] Performance testing at scale
- [ ] Stress testing
- [ ] Memory leak detection
- [ ] Code coverage >80%

**Estimated Effort**: 4 weeks

### Documentation

- [ ] Complete API documentation
- [ ] Deployment guides
- [ ] Integration examples (Cisco, Juniper, etc.)
- [ ] Troubleshooting guides
- [ ] Performance tuning guide

**Estimated Effort**: 2 weeks

### Packaging

- [ ] Debian/Ubuntu packages
- [ ] RPM packages (RHEL/CentOS)
- [ ] Docker images
- [ ] Kubernetes manifests
- [ ] systemd service files

**Estimated Effort**: 2 weeks

### Compliance

- [ ] Full RFC 2865 compliance
- [ ] Full RFC 2866 compliance
- [ ] Full RFC 2869 compliance
- [ ] Full RFC 5997 compliance
- [ ] Interoperability testing

**Estimated Effort**: 2 weeks

**Total v1.0.0 Estimated Effort**: 10 weeks

---

## Future Considerations (Post 1.0)

### Additional Crates

- [ ] `radius-client` - RADIUS client library
- [ ] `radius-proxy` - Standalone proxy server
- [ ] `radius-tools` - CLI tools (radtest, radclient, etc.)
- [ ] `radius-dict` - Dictionary file parser

### Additional Features

- ✅ IPv6 support (dual-stack IPv4/IPv6 for all network operations)
- [ ] RADIUS/JSON REST API
- [ ] WebSocket transport
- [ ] gRPC management API
- [ ] Prometheus metrics export
- [ ] Grafana dashboards
- [ ] Web-based admin UI
- [ ] Multi-tenancy support
- [ ] Vendor-Specific Attribute (VSA) plugins
- [ ] Custom attribute definitions
- [ ] Policy engine
- [ ] Geographic distribution

### Integration

- [ ] Kubernetes operator
- [ ] Terraform provider
- [ ] Ansible role
- [ ] Cloud-native deployment (AWS, GCP, Azure)

---

## Development Priorities

### Critical Path (Must Have for Production)

1. v0.5.0 - EAP Support
2. v0.6.0 - Database Integration

### Nice to Have

1. v0.7.0 - Proxy
2. v0.8.0 - RadSec
3. v0.9.0 - CoA

---

## Community Contributions

We welcome community contributions! Priority areas:

**High Priority**:

- EAP methods

**Medium Priority**:

- Performance optimizations

**Documentation**:

- Deployment guides
- Integration examples
- Troubleshooting guides
- Translation to other languages

---

## Timeline Summary

| Version | Quarter | Focus | Weeks |
| --------- | --------- | ------- | ------- |
| v0.1.0 | Now | Core Protocol | ✅ Done |
| v0.2.0 | Q4 2025 | Security & Production | ✅ Done |
| v0.3.0 | Q4 2025 | Auth Methods | ✅ Done |
| v0.4.0 | Q4 2025 | Accounting | ✅ Done |
| v0.5.0 | Q4 2025 | EAP Support | 11 |
| v0.6.0 | Q1 2026 | Enterprise Features | 11 |
| v0.7.0 | Q2 2026 | Proxy | 7 |
| v0.8.0 | Q3 2026 | RadSec | 6 |
| v0.9.0 | Q4 2026 | CoA | 5 |
| v1.0.0 | 2027 | Production Release | 10 |

**Total Estimated Development Time**: ~69 weeks (~16 months of full-time development)

---

## Getting Involved

### How to Contribute

1. Check the [RFC-COMPLIANCE.md](RFC-COMPLIANCE.md) for known gaps
2. Look for issues labeled "good first issue" or "help wanted"
3. Read [CONTRIBUTING.md](CONTRIBUTING.md)
4. Submit a pull request!

### Contact

- **GitHub Issues**: <https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/issues>
- **Author**: John Edward Willman V <john.willman.1@us.af.mil>

---

## Notes

- Timelines are estimates and subject to change based on:
  - Community contributions
  - Security findings
  - User feedback
  - Resource availability

- Features may be reordered based on user demand and critical needs

- Security issues will always take precedence over feature development

- This roadmap will be updated quarterly
