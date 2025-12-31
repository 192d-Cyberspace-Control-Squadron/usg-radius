# USG RADIUS Development Roadmap

This document outlines the development roadmap for the USG RADIUS project, organized by release milestones.

## Current Status: v0.3.0 (Authentication Methods)

**Release Date**: December 2024
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
- ⚠️ No accounting support (planned for v0.4.0)
- ⚠️ No hot reload (requires server restart for config changes)

See [RFC-COMPLIANCE.md](RFC-COMPLIANCE.md) for detailed gap analysis.

---

## v0.2.0 - Security & Production Hardening (Q1 2025)

**Goal**: Make the server production-ready for basic deployments
**Priority**: CRITICAL

### Security Enhancements

#### Client Validation & Authorization ✅ COMPLETED

- [x] Implement client IP address validation
- [x] Per-client shared secrets
- [x] Client database with enable/disable flags
- [x] Source IP verification against configuration
- [x] NAS-Identifier validation

**Status**: ✅ Complete

#### Request Security ✅ COMPLETED

- [x] Duplicate request detection (cache recent requests)
- [x] Identifier tracking and validation
- [x] Request timeout handling (via cache TTL)
- [x] Replay attack prevention
- [x] Request rate limiting per client

**Status**: ✅ Complete

#### Attribute Validation ✅ COMPLETED

- [x] Required attribute enforcement (User-Name must be present)
- [x] Enumerated value validation (Service-Type 1-13)
- [x] Attribute type-specific validation
- [x] Malformed packet rejection
- [x] Strict RFC compliance mode

**Status**: ✅ Complete

### Operational Improvements

#### Logging & Monitoring ✅ COMPLETE

- [x] Replace println! with proper logging (tracing crate)
- [x] Structured logging with levels (trace, debug, info, warn, error)
- [x] Configurable log levels via config file or environment variable
- [x] Security event logging (rate limits, unauthorized clients, auth failures)
- [x] Audit trail for authentication attempts (JSON format)
- [ ] Log rotation support (handled by external tools)

**Status**: ✅ Complete (log rotation delegated to system tools like logrotate)

#### Rate Limiting & DoS Protection ✅ COMPLETED

- [x] Per-client request rate limiting
- [x] Global request rate limiting
- [x] Configurable limits (per-client and global RPS/burst)
- [ ] Concurrent connection limits
- [ ] Bandwidth throttling

**Status**: ✅ Core features complete

### Configuration

- [x] Validate client CIDR networks
- [x] Environment variable support for secrets
- [x] Configuration file validation on startup
- [ ] Hot reload configuration (SIGHUP) - deferred to future release

**Status**: ✅ Complete (3/3 required features, hot reload marked as future enhancement)

**Total v0.2.0 Estimated Effort**: 6-8 weeks

---

## v0.3.0 - Authentication Methods (Q2 2025)

**Goal**: Support modern authentication methods
**Priority**: HIGH
**Status**: ✅ Complete (Dec 2024)

### CHAP Support ✅ COMPLETED

- [x] CHAP-Password attribute handling
- [x] CHAP-Challenge generation
- [x] CHAP algorithm implementation (MD5-based)
- [x] CHAP authentication validation
- [x] Tests and examples (6 integration tests)
- [x] Support for Request Authenticator as challenge
- [x] ChapResponse and ChapChallenge types
- [x] Interleaved PAP/CHAP authentication

**Status**: ✅ Complete (Dec 2024)

### Access-Challenge ✅ COMPLETED

- [x] Access-Challenge packet generation
- [x] State attribute handling
- [x] Multi-round authentication flow
- [x] AuthResult enum (Accept, Reject, Challenge)
- [x] authenticate_with_challenge() trait method
- [x] Challenge attribute support (Reply-Message, State)
- [x] Integration tests demonstrating 2FA flow

**Status**: ✅ Complete (Dec 2024)

### Message-Authenticator (RFC 2869) ✅ COMPLETED

- [x] HMAC-MD5 calculation
- [x] calculate_message_authenticator() function
- [x] verify_message_authenticator() function
- [x] Server-side validation enforcement in Access-Request handler
- [x] Comprehensive test suite (10 tests: 7 unit + 3 integration)
- [x] Support for packet integrity verification
- [x] Backward compatibility with clients not using it (validation only when present)

**Status**: ✅ Complete (Dec 2024)

### Proxy-State Support ✅ COMPLETED

- [x] Preserve Proxy-State attributes in responses
- [x] Multiple Proxy-State attribute handling
- [x] Automatic copying in Access-Accept, Access-Challenge, Access-Reject
- [x] RFC 2865 Section 5.33 compliance

**Status**: ✅ Complete (Dec 2024)

**Completed Features**:

- All 120 tests passing (35 proto + 49 server + 17 integration + 19 backend)
- Full CHAP authentication with MD5
- Multi-round authentication with Access-Challenge
- HMAC-MD5 Message-Authenticator integrity protection
- RFC-compliant Proxy-State preservation

**Total v0.3.0 Actual Effort**: ~3 weeks (faster than estimated due to clean architecture)

---

## v0.4.0 - Accounting & Session Management (Q3 2025)

**Goal**: Add RADIUS Accounting support (RFC 2866)
**Priority**: HIGH

### Accounting Protocol

- [ ] Accounting-Request (Code 4) handling
- [ ] Accounting-Response (Code 5) generation
- [ ] Acct-Status-Type validation (Start, Stop, Interim-Update)
- [ ] Accounting packet processing

**Estimated Effort**: 2 weeks

### Session Tracking

- [ ] Session database (in-memory initially)
- [ ] Session start/stop tracking
- [ ] Interim updates
- [ ] Session timeout handling
- [ ] Concurrent session limits

**Estimated Effort**: 2 weeks

### Accounting Storage

- [ ] Pluggable accounting backend trait
- [ ] File-based accounting logs
- [ ] Database accounting (PostgreSQL, MySQL)
- [ ] Accounting data retention policies

**Estimated Effort**: 2 weeks

### Usage Metrics

- [ ] Bytes in/out tracking
- [ ] Packets in/out tracking
- [ ] Session duration tracking
- [ ] Usage reports and queries

**Estimated Effort**: 1 week

**Total v0.4.0 Estimated Effort**: 7 weeks

---

## v0.5.0 - EAP Support (Q4 2025)

**Goal**: Support modern 802.1X authentication
**Priority**: MEDIUM-HIGH

### EAP Framework

- [ ] EAP-Message attribute (Type 79) handling
- [ ] EAP state machine
- [ ] EAP session management
- [ ] EAP packet fragmentation

**Estimated Effort**: 3 weeks

### EAP Methods

- [ ] EAP-MD5 (basic, for testing)
- [ ] EAP-TLS (certificate-based)
- [ ] EAP-TTLS (tunneled TLS)
- [ ] EAP-TEAP (certificate-based)
- [ ] PEAP (Protected EAP)
- [ ] EAP-MSCHAPv2

**Estimated Effort**: 6 weeks (1-2 weeks per method)

### Certificate Management

- [ ] Certificate validation
- [ ] CA certificate chain verification
- [ ] Certificate revocation (CRL/OCSP)
- [ ] Certificate expiry checking

**Estimated Effort**: 2 weeks

**Total v0.5.0 Estimated Effort**: 11 weeks

---

## v0.6.0 - Advanced Features (Q1 2025)

**Goal**: Enterprise-grade features
**Priority**: MEDIUM
**Status**: 🔄 In Progress (Backend Integration ✅ Complete)

### Database Integration ✅ COMPLETED

- [x] PostgreSQL authentication backend
- [x] User attribute storage (via attributes_query)
- [x] Connection pooling
- [x] Bcrypt password hashing
- [x] Custom SQL queries
- [x] PostgreSQL schema and migration examples
- [ ] MySQL/MariaDB authentication backend
- [ ] Additional password hashing algorithms (argon2, pbkdf2)

**Status**: ✅ PostgreSQL complete, MySQL pending
**Completed**: Dec 2024

### LDAP/Active Directory ✅ COMPLETED

- [x] LDAP authentication backend
- [x] Active Directory integration
- [x] LDAPS (LDAP over SSL/TLS) support
- [x] Flexible search filters and attribute retrieval
- [x] Service account binding
- [x] Anonymous bind support
- [x] Async/sync compatibility
- [ ] Group membership queries and RADIUS attribute mapping
- [ ] Connection pooling and failover

**Status**: ✅ Core features complete, advanced features pending
**Completed**: Dec 2024

### Documentation ✅ COMPLETED

- [x] Backend integration comparison guide
- [x] PostgreSQL integration guide (500+ lines)
- [x] LDAP/Active Directory integration guide
- [x] Example configurations (LDAP, AD, PostgreSQL)
- [x] Database schema examples
- [x] Migration guides between backends
- [x] Security best practices
- [x] Performance tuning recommendations
- [x] Troubleshooting guides
- [x] Documentation reorganization into docs/docs/ structure

**Status**: ✅ Complete
**Completed**: Dec 2024

### Testing ✅ COMPLETED

- [x] 8 LDAP unit tests
- [x] 9 PostgreSQL unit tests
- [x] Configuration serialization tests
- [x] Password hashing tests
- [ ] Docker-based LDAP integration tests
- [ ] Docker-based PostgreSQL integration tests
- [ ] End-to-end authentication tests

**Status**: 🔄 Unit tests complete, integration tests pending
**Completed**: Dec 2024 (partial)

### High Availability

- [ ] Multi-server deployment support
- [ ] Shared session state (Redis/database)
- [ ] Health checks
- [ ] Failover mechanisms
- [ ] Load balancing recommendations

**Estimated Effort**: 3 weeks

### Additional Backend Support

- [ ] MySQL/MariaDB authentication backend
- [ ] Redis caching backend
- [ ] REST API authentication backend
- [ ] Multi-backend fallback chains

**Estimated Effort**: 3 weeks

### Performance Optimization

- [ ] Query optimization for database backends
- [ ] LDAP connection pooling improvements
- [ ] Request caching enhancements
- [x] Performance benchmarking framework
- [ ] Memory optimization
- [ ] CPU profiling and optimization

**Status**: 🔄 Benchmarking framework exists, optimizations pending
**Estimated Effort**: 2 weeks

**Total v0.6.0 Effort**:

- ✅ Completed: ~4 weeks (LDAP, PostgreSQL, docs, tests)
- ⏳ Remaining: ~8 weeks (HA, additional backends, optimization)

---

## v0.7.0 - RADIUS Proxy (2026)

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

## v0.8.0 - RadSec (RADIUS over TLS) (2026)

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

## v0.9.0 - Change of Authorization (2026)

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

## v1.0.0 - Production Release (2026)

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

- [x] IPv6 support (dual-stack IPv4/IPv6 for all network operations)
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

1. v0.2.0 - Security & Hardening
2. v0.3.0 - Authentication Methods
3. v0.4.0 - Accounting

### Important (Should Have)

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

- Client validation implementation
- Rate limiting
- CHAP support
- Message-Authenticator
- Accounting support

**Medium Priority**:

- Database backends
- LDAP integration
- EAP methods
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
| v0.2.0 | Q1 2025 | Security & Production | 6-8 |
| v0.3.0 | Q2 2025 | Auth Methods | 6 |
| v0.4.0 | Q3 2025 | Accounting | 7 |
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
