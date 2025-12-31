# USG RADIUS Development Roadmap

This document outlines the development roadmap for the USG RADIUS project, organized by release milestones.

## Current Status: v0.1.0 (Development)

**Release Date**: TBD
**Status**: ✅ Core functionality complete, not production-ready

### Completed Features
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

### Known Limitations
- ⚠️ Only PAP authentication (no CHAP/EAP)
- ⚠️ No accounting support
- ⚠️ Basic logging only (println!)
- ⚠️ No attribute validation

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
- [ ] NAS-Identifier validation

**Status**: ✅ Complete (except NAS-Identifier)

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
- [ ] Environment variable support for secrets
- [x] Configuration file validation on startup
- [ ] Hot reload configuration (SIGHUP)

**Status**: Partial (2/4 complete)

**Total v0.2.0 Estimated Effort**: 6-8 weeks

---

## v0.3.0 - Authentication Methods (Q2 2025)

**Goal**: Support modern authentication methods
**Priority**: HIGH

### CHAP Support
- [ ] CHAP-Password attribute handling
- [ ] CHAP-Challenge generation
- [ ] CHAP algorithm implementation
- [ ] CHAP authentication validation
- [ ] Tests and examples

**Estimated Effort**: 2 weeks

### Access-Challenge
- [ ] Access-Challenge packet generation
- [ ] State attribute handling
- [ ] Multi-round authentication flow
- [ ] Session state management
- [ ] Challenge/response timing

**Estimated Effort**: 2 weeks

### Message-Authenticator (RFC 2869)
- [ ] HMAC-MD5 calculation
- [ ] Message-Authenticator validation on request
- [ ] Message-Authenticator generation in response
- [ ] Backward compatibility with clients not using it

**Estimated Effort**: 1 week

### Proxy-State Support
- [ ] Preserve Proxy-State attributes in responses
- [ ] Multiple Proxy-State attribute handling
- [ ] Proxy chain support

**Estimated Effort**: 1 week

**Total v0.3.0 Estimated Effort**: 6 weeks

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

## v0.6.0 - Advanced Features (2026)

**Goal**: Enterprise-grade features
**Priority**: MEDIUM

### Database Integration
- [ ] PostgreSQL authentication backend
- [ ] MySQL authentication backend
- [ ] User attribute storage
- [ ] Connection pooling
- [ ] Migration scripts

**Estimated Effort**: 3 weeks

### LDAP/Active Directory
- [ ] LDAP authentication backend
- [ ] Active Directory integration
- [ ] Group membership queries
- [ ] Attribute mapping
- [ ] Connection pooling and failover

**Estimated Effort**: 3 weeks

### High Availability
- [ ] Multi-server deployment support
- [ ] Shared session state (Redis/database)
- [ ] Health checks
- [ ] Failover mechanisms
- [ ] Load balancing recommendations

**Estimated Effort**: 3 weeks

### Performance Optimization
- [ ] Connection pooling for backends
- [ ] Request caching
- [ ] Performance benchmarking
- [ ] Memory optimization
- [ ] CPU profiling and optimization

**Estimated Effort**: 2 weeks

**Total v0.6.0 Estimated Effort**: 11 weeks

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

### Certificate Management
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
4. v0.5.0 - EAP Support
5. v0.6.0 - Database Integration

### Nice to Have
6. v0.7.0 - Proxy
7. v0.8.0 - RadSec
8. v0.9.0 - CoA

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
|---------|---------|-------|-------|
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
- **GitHub Issues**: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/issues
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
