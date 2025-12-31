# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - v0.5.0 (In Progress)

#### EAP Protocol Support

- **EAP-Message Attribute** (Type 79) - RFC 3579 support for EAP over RADIUS
- **EAP Protocol Module** (`radius-proto/eap.rs`):
  - Complete EAP packet structure (Request, Response, Success, Failure)
  - Full packet encoding and decoding with validation
  - Support for 11 EAP method types (Identity, MD5, TLS, TTLS, PEAP, MSCHAPv2, TEAP, etc.)
  - Comprehensive error handling with detailed error types
  - 1400+ lines of production-ready code
  - 38 unit tests with 100% pass rate

- **EAP State Machine**:
  - 9 authentication states (Initialize through Success/Failure/Timeout)
  - State transition validation with rules enforcement
  - Terminal state detection
  - Support for multi-round authentication flows
  - can_transition_to() method for validated state changes
  - is_terminal() method for terminal state detection

- **EAP Session Management**:
  - EapSession structure for individual session tracking
  - Session lifecycle management (creation, activity, timeout, cleanup)
  - EAP identifier auto-increment with wrapping
  - Attempt counting and max attempts enforcement
  - EapSessionManager for concurrent session support
  - HashMap-based session storage with CRUD operations
  - Session cleanup (timed out and terminal sessions)
  - Session statistics and monitoring (SessionStats)
  - 25 dedicated test suites for state machine and sessions

- **EAP-MD5 Challenge Implementation**:
  - Challenge generation and parsing
  - Response computation and verification
  - MD5 hash calculation (identifier + password + challenge)
  - Full authentication flow support
  - 4 dedicated test suites including full authentication flow

## [0.4.0] - 2024-12-31

### Added - Accounting Protocol (RFC 2866)

#### Core Accounting Features

- **RADIUS Accounting Packet Types**:
  - Accounting-Request (Code 4)
  - Accounting-Response (Code 5)
  - Request Authenticator calculation per RFC 2866

- **Accounting Attributes** (RFC 2866):
  - Acct-Status-Type (40) - Start, Stop, Interim-Update, Accounting-On, Accounting-Off
  - Acct-Delay-Time (41)
  - Acct-Input-Octets (42)
  - Acct-Output-Octets (43)
  - Acct-Session-Id (44)
  - Acct-Authentic (45) - RADIUS, Local, Remote
  - Acct-Session-Time (46)
  - Acct-Input-Packets (47)
  - Acct-Output-Packets (48)
  - Acct-Terminate-Cause (49) - 18 termination reasons
  - Acct-Multi-Session-Id (50)
  - Acct-Link-Count (51)
  - Acct-Input-Gigawords (52) - RFC 2869, high 32 bits for 64-bit counters
  - Acct-Output-Gigawords (53) - RFC 2869, high 32 bits for 64-bit counters

#### PostgreSQL Accounting Backend

- **Full-featured PostgreSQL backend** (`radius-server/accounting/postgres.rs`):
  - 1900+ lines of production-ready code
  - Async connection pooling with sqlx
  - Automatic schema initialization
  - Session lifecycle management (start, interim, stop)
  - Comprehensive session tracking with all accounting attributes
  - IPv4 and IPv6 support for NAS and client addresses

- **Data Export Functionality**:
  - `export_user_usage_csv()` - Aggregated user bandwidth and session statistics
    - Automatic unit conversion (bytes to MB, seconds to minutes)
    - Proper CSV escaping for special characters
    - Time range filtering support
    - 2-decimal precision for human-readable values
  - `export_sessions_csv()` - Detailed session export
    - Support for active-only or all sessions
    - Comprehensive session details (timestamps, octets, packets, terminate cause)
    - Time range filtering
  - `generate_usage_report_json()` - JSON reports with summary statistics
    - Total bandwidth and session statistics
    - Top 10 users by bandwidth consumption
    - Report metadata with time ranges
    - Manual JSON string building for performance

- **Query Operations**:
  - Session lookup by session ID
  - User session history with pagination
  - Active session queries
  - Session count and statistics
  - Aggregate usage calculations with SQL (SUM, COUNT, AVG, COALESCE)

#### Testing & Quality

- **Comprehensive Test Coverage**:
  - 6 test suites for PostgreSQL backend (500+ lines)
  - Export functionality tests (CSV and JSON validation)
  - Session lifecycle tests (start, interim, stop)
  - Active session tracking tests
  - Query operation validation
  - All tests passing with 100% success rate

#### AccountingHandler Trait

- **Trait-based design** for extensible accounting backends:
  - `start_session()` - Track session start
  - `update_session()` - Handle interim updates
  - `stop_session()` - Record session termination
  - `get_session()` - Query session by ID
  - `get_user_sessions()` - User session history
  - `get_active_sessions()` - Active session queries
  - `session_count()` - Statistics
  - `SimpleAccountingHandler` - In-memory reference implementation

#### Documentation

- Updated ROADMAP.md with v0.4.0 completion status (100%)
- Comprehensive feature documentation with metrics
- Implementation details and design rationale
- Test coverage statistics

### Technical Details

- **Total v0.4.0 Implementation**: ~6 weeks of development
- **Code Quality**: Clean compilation, no warnings, all tests passing
- **RFC Compliance**: Full RFC 2866 (Accounting) and partial RFC 2869 (Extensions)
- **Performance**: Async I/O with Tokio, efficient connection pooling

## [0.3.0] - 2024-11-15

### Added - Security & Operations

#### Security Features

- **Client Authorization**: IP/CIDR-based client validation
- **Request Deduplication**: Replay attack prevention with LRU caching
- **Rate Limiting**: Token bucket algorithm with per-client and global limits
- **Audit Logging**: JSON audit trail for compliance and forensics
- **Message-Authenticator**: HMAC-MD5 integrity protection (RFC 2869)

#### Operational Features

- **Structured Logging**: Configurable log levels with tracing framework
- **Status-Server**: RFC 5997 server health monitoring
- **Configuration Schema**: Full JSON Schema validation
- **DoS Protection**: Multiple layers of protection against attacks

#### Testing & Quality

- Comprehensive test suites for all security features
- Integration tests for rate limiting and deduplication
- Performance benchmarks

## [0.2.0] - 2024-10-01

### Added - Core Protocol

- **CHAP Support**: RFC 2865 CHAP-Password and CHAP-Challenge
  - CHAP response computation and verification
  - Comprehensive test coverage
- **Dual-Stack Networking**: Full IPv4 and IPv6 support
- **Attribute Validation**: RFC 2865 strict/lenient validation modes
- **Error Handling**: Comprehensive error types with detailed messages

### Changed

- Improved packet parsing performance
- Enhanced attribute handling with zero-copy where possible

## [0.1.0] - 2024-09-01

### Added - Initial Release

- **RFC 2865 Compliance**: Core RADIUS protocol implementation
- **Authentication**: Access-Request, Access-Accept, Access-Reject, Access-Challenge
- **Password Encryption**: MD5-based User-Password encryption per RFC 2865 Section 5.2
- **Authenticator Validation**: Request and Response authenticator calculation
- **Basic Attributes**: User-Name, User-Password, NAS-IP-Address, Reply-Message, and more
- **Simple Auth Handler**: In-memory authentication with JSON configuration
- **JSON Configuration**: Schema-validated configuration files
- **radtest Compatibility**: Works with FreeRADIUS radtest utility

### Technical Foundation

- Built on Tokio for async I/O
- Trait-based extensibility (AuthHandler)
- Comprehensive unit and integration tests
- Zero unsafe code
- Full documentation and examples

[Unreleased]: https://github.com/yourusername/usg-radius/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/yourusername/usg-radius/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/yourusername/usg-radius/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yourusername/usg-radius/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yourusername/usg-radius/releases/tag/v0.1.0
