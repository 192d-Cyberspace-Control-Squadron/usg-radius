# RADIUS Proxy Implementation Plan (v0.7.0)

## Overview

Implement RADIUS proxy functionality to enable request forwarding, realm-based routing, load balancing, and failover. This transforms the server from authentication-only to a full-featured RADIUS proxy that can route requests to upstream (home) servers based on flexible routing rules.

## Architecture

### High-Level Design

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  NAS Client     │────>│  Proxy Server    │────>│  Home Server 1  │
│  (WiFi AP)      │<────│  (This Server)   │<────│  (Upstream)     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                 │                ┌─────────────────┐
                                 └───────────────>│  Home Server 2  │
                                                  │  (Backup)       │
                                                  └─────────────────┘
```

### Key Components

1. **ProxyHandler** - Core proxy logic for forwarding requests
2. **Router** - Realm-based routing and server selection
3. **HomeServer** - Upstream server configuration and state tracking
4. **HomeServerPool** - Group of servers with load balancing
5. **ProxyCache** - Request/response correlation tracking
6. **RetryManager** - Timeout and retry handling

### Data Flow

```
Request Flow:
1. NAS → Proxy (receive Access-Request)
2. Proxy adds Proxy-State attribute (for correlation)
3. Router determines target home server based on realm
4. ProxyHandler forwards to home server
5. ProxyCache stores request metadata
6. Wait for response (with timeout)

Response Flow:
1. Home Server → Proxy (receive Access-Accept/Reject)
2. ProxyCache looks up original request by Proxy-State
3. ProxyHandler validates response authenticator
4. Proxy removes Proxy-State attribute (if proxy-added)
5. Proxy → NAS (forward response)
```

## Implementation Phases

### Phase 1: Core Proxy Infrastructure (Week 1-2)

#### Files to Create

**`crates/radius-server/src/proxy/mod.rs`** (~200 lines)
- Module declarations
- Public API exports
- ProxyConfig structure
- Feature flags and dependencies

**`crates/radius-server/src/proxy/home_server.rs`** (~400 lines)
- `HomeServer` struct - Upstream server configuration
- `HomeServerState` enum (Up, Down, Testing)
- Connection tracking (UDP socket management)
- Health check state
- Statistics (requests sent, responses received, timeouts)

```rust
pub struct HomeServer {
    pub name: String,
    pub address: SocketAddr,
    pub secret: Vec<u8>,
    pub timeout: Duration,
    pub max_outstanding: usize,
    state: Arc<RwLock<HomeServerState>>,
    stats: Arc<HomeServerStats>,
}

pub enum HomeServerState {
    Up,
    Down,
    Testing,  // Sending health checks
}

pub struct HomeServerStats {
    pub requests_sent: AtomicU64,
    pub responses_received: AtomicU64,
    pub timeouts: AtomicU64,
    pub last_response: RwLock<Option<Instant>>,
}
```

**`crates/radius-server/src/proxy/cache.rs`** (~350 lines)
- `ProxyCache` - In-flight request tracking
- `ProxyCacheEntry` - Request metadata and correlation
- Timeout-based cleanup (similar to RequestCache pattern)
- Maps Proxy-State → original request details

```rust
pub struct ProxyCache {
    // Key: Proxy-State value (our correlation ID)
    cache: Arc<DashMap<ProxyStateKey, ProxyCacheEntry>>,
    ttl: Duration,
    cleanup_running: Arc<AtomicBool>,
}

pub struct ProxyCacheEntry {
    pub original_request: Packet,
    pub original_source: SocketAddr,
    pub home_server: Arc<HomeServer>,
    pub sent_at: Instant,
    pub retry_count: u8,
}

type ProxyStateKey = [u8; 16];  // Unique correlation ID
```

**`crates/radius-server/src/proxy/handler.rs`** (~500 lines)
- `ProxyHandler` - Core forwarding logic
- `forward_request()` - Add Proxy-State, send to home server
- `handle_response()` - Validate and route response back to NAS
- Authenticator recalculation (with home server secret → client secret)
- Proxy loop detection (count Proxy-State attributes, limit to 5)

```rust
pub struct ProxyHandler {
    cache: Arc<ProxyCache>,
    socket: Arc<UdpSocket>,  // Proxy's socket for home server comms
}

impl ProxyHandler {
    /// Forward a request to a home server
    ///
    /// 1. Generates unique Proxy-State attribute
    /// 2. Stores request in cache for correlation
    /// 3. Sends modified request to home server
    /// 4. Returns proxy state ID for response matching
    pub async fn forward_request(
        &self,
        request: Packet,
        source: SocketAddr,
        home_server: Arc<HomeServer>,
    ) -> Result<ProxyStateKey, ProxyError>;

    /// Handle a response from a home server
    ///
    /// 1. Extracts Proxy-State from response
    /// 2. Looks up original request in cache
    /// 3. Validates response authenticator
    /// 4. Recalculates authenticator with client secret
    /// 5. Forwards to original NAS
    pub async fn handle_response(
        &self,
        response: Packet,
        home_server_addr: SocketAddr,
    ) -> Result<(), ProxyError>;
}
```

**Tests**: 25 unit tests
- ProxyCache insertion/lookup/expiry
- Proxy-State attribute generation (uniqueness)
- Authenticator recalculation
- Proxy loop detection
- HomeServer state transitions

#### Configuration Schema

```json
{
  "proxy": {
    "enabled": true,
    "cache_ttl": 30,
    "max_outstanding": 1000,
    "proxy_timeout": 30
  }
}
```

**Deliverable**: Basic proxy forwarding works (static single home server, no routing yet)

---

### Phase 2: Realm-Based Routing (Week 3)

#### Files to Create

**`crates/radius-server/src/proxy/realm.rs`** (~300 lines)
- `Realm` struct - Routing configuration for a realm
- `RealmMatcher` - Match logic (exact, suffix, regex)
- `extract_realm()` - Parse username for realm (@domain or \domain)

```rust
pub struct Realm {
    pub name: String,
    pub matcher: RealmMatcher,
    pub pool: Arc<HomeServerPool>,  // Target servers
    pub strip_realm: bool,  // Remove @domain before forwarding
}

pub enum RealmMatcher {
    Exact(String),           // Exact match: user@example.com
    Suffix(String),          // Suffix match: *.example.com
    Regex(regex::Regex),     // Regex match: custom patterns
}

pub fn extract_realm(username: &str) -> Option<String> {
    // Support @domain (suffix) and DOMAIN\user (prefix)
    // Examples:
    //   "user@example.com" → "example.com"
    //   "CORPORATE\user" → "CORPORATE"
    //   "plainuser" → None (no realm)
}
```

**`crates/radius-server/src/proxy/router.rs`** (~400 lines)
- `Router` - Main routing engine
- `route_request()` - Determine target home server
- Realm lookup and matching
- Fallback to local auth if no route found

```rust
pub struct Router {
    realms: Vec<Realm>,
    default_realm: Option<Arc<Realm>>,  // Fallback route
}

impl Router {
    /// Route a request based on User-Name realm
    ///
    /// 1. Extract User-Name attribute
    /// 2. Parse realm from username
    /// 3. Find matching Realm configuration
    /// 4. Select home server from pool
    /// 5. Return RoutingDecision
    pub fn route_request(&self, request: &Packet) -> RoutingDecision;
}

pub enum RoutingDecision {
    Proxy {
        home_server: Arc<HomeServer>,
        strip_realm: bool,
    },
    Local,  // Authenticate locally
    Reject, // No route, reject immediately
}
```

**Tests**: 20 unit tests
- Realm extraction (@domain, DOMAIN\, plain)
- Realm matching (exact, suffix, regex)
- Router selection logic
- Realm stripping
- Fallback to local auth

#### Configuration Schema

```json
{
  "proxy": {
    "realms": [
      {
        "name": "example.com",
        "match": {
          "type": "suffix",
          "pattern": "@example.com"
        },
        "pool": "pool_example",
        "strip_realm": true
      },
      {
        "name": "corporate",
        "match": {
          "type": "exact",
          "pattern": "CORPORATE"
        },
        "pool": "pool_ad",
        "strip_realm": true
      }
    ],
    "default_realm": "local"  // "local" = authenticate locally
  }
}
```

**Deliverable**: Routing works based on username realm

---

### Phase 3: Home Server Pools & Load Balancing (Week 4)

#### Files to Create

**`crates/radius-server/src/proxy/pool.rs`** (~500 lines)
- `HomeServerPool` - Group of home servers
- Load balancing strategies (round-robin, least-outstanding, failover)
- `select_server()` - Choose next server based on strategy
- Health tracking and automatic failover

```rust
pub struct HomeServerPool {
    pub name: String,
    pub servers: Vec<Arc<HomeServer>>,
    pub strategy: LoadBalanceStrategy,
    next_index: AtomicUsize,  // For round-robin
}

pub enum LoadBalanceStrategy {
    RoundRobin,          // Cycle through servers
    LeastOutstanding,    // Server with fewest pending requests
    Failover,            // Primary + backups (only use backup if primary down)
    Random,              // Random selection
}

impl HomeServerPool {
    /// Select next home server based on strategy
    ///
    /// Returns None if all servers are down
    pub fn select_server(&self) -> Option<Arc<HomeServer>>;

    /// Check if any server is available
    pub fn is_available(&self) -> bool;
}
```

**`crates/radius-server/src/proxy/health.rs`** (~350 lines)
- Health check implementation
- Periodic Status-Server requests to home servers
- Automatic state transitions (Up → Down, Down → Testing → Up)
- Dead server detection and retry logic

```rust
pub struct HealthChecker {
    interval: Duration,
    timeout: Duration,
    retries: u8,
}

impl HealthChecker {
    /// Start background health check task for a pool
    ///
    /// Sends Status-Server requests every interval
    /// Marks server Down after N consecutive failures
    /// Marks server Up after successful response
    pub fn start_checking(
        &self,
        pool: Arc<HomeServerPool>,
    ) -> JoinHandle<()>;
}
```

**Tests**: 25 unit tests
- Round-robin selection
- Least-outstanding selection
- Failover selection (primary → backup)
- Health state transitions
- Pool availability checks

#### Configuration Schema

```json
{
  "proxy": {
    "pools": [
      {
        "name": "pool_example",
        "strategy": "round_robin",
        "servers": [
          {
            "address": "192.168.1.10:1812",
            "secret": "server1_secret",
            "timeout": 30,
            "max_outstanding": 100
          },
          {
            "address": "192.168.1.11:1812",
            "secret": "server2_secret",
            "timeout": 30,
            "max_outstanding": 100
          }
        ]
      },
      {
        "name": "pool_ad",
        "strategy": "failover",
        "servers": [
          {
            "address": "10.0.0.1:1812",
            "secret": "ad_primary_secret",
            "timeout": 30
          },
          {
            "address": "10.0.0.2:1812",
            "secret": "ad_backup_secret",
            "timeout": 30
          }
        ]
      }
    ],
    "health_check": {
      "enabled": true,
      "interval": 30,
      "timeout": 10,
      "retries": 3
    }
  }
}
```

**Deliverable**: Load balancing and failover work correctly

---

### Phase 4: Retry & Timeout Handling (Week 5)

#### Files to Create

**`crates/radius-server/src/proxy/retry.rs`** (~300 lines)
- `RetryManager` - Timeout and retry orchestration
- Background task to check for timed-out requests
- Automatic retry with exponential backoff
- Max retries configuration

```rust
pub struct RetryManager {
    cache: Arc<ProxyCache>,
    handler: Arc<ProxyHandler>,
    router: Arc<Router>,
    max_retries: u8,
    retry_interval: Duration,
}

impl RetryManager {
    /// Start background retry task
    ///
    /// 1. Periodically scans ProxyCache for timed-out requests
    /// 2. Retries with same or different home server
    /// 3. Sends Access-Reject to NAS after max retries
    pub fn start_retry_task(&self) -> JoinHandle<()>;

    /// Handle a timeout for a specific request
    async fn handle_timeout(&self, entry: &ProxyCacheEntry);
}
```

**Tests**: 15 unit tests
- Timeout detection
- Retry logic (same server, different server)
- Max retries enforcement
- Access-Reject on exhaustion

#### Configuration Schema

```json
{
  "proxy": {
    "retry": {
      "max_retries": 3,
      "retry_interval": 5,
      "failover_on_timeout": true
    }
  }
}
```

**Deliverable**: Timeouts trigger retries, failover, and eventual reject

---

### Phase 5: Integration & Testing (Week 6)

#### Integration Work

**Modify `crates/radius-server/src/server.rs`**:
- Add `ProxyHandler` to `RadiusServer`
- Add `Router` to server state
- Modify `handle_access_request()`:
  1. Check Router for routing decision
  2. If Proxy: forward via ProxyHandler
  3. If Local: authenticate locally (existing code)
  4. If Reject: send Access-Reject immediately
- Add response handling task (listen for home server responses)

**Modify `crates/radius-server/src/config.rs`**:
- Add `ProxyConfig` struct
- Add pools, realms, health check config
- Validation for proxy configuration

**Integration Tests** (~15 tests):
- End-to-end proxy forwarding
- Realm-based routing
- Load balancing verification
- Failover on server down
- Timeout and retry
- Accounting request proxying
- Proxy-State preservation
- Loop detection

#### Example Scenario Test

```rust
#[tokio::test]
async fn test_realm_based_routing_with_failover() {
    // 1. Start two mock home servers
    // 2. Configure proxy with failover pool
    // 3. Send Access-Request with user@example.com
    // 4. Verify routed to primary server
    // 5. Shut down primary server
    // 6. Send another request
    // 7. Verify routed to backup server
    // 8. Verify Access-Accept received
}
```

**Deliverable**: Fully working proxy with routing, failover, retry

---

### Phase 6: Documentation & Examples (Week 7)

#### Documentation

**`docs/docs/proxy/README.md`** (~800 lines)
- Architecture overview
- Configuration guide
- Realm routing examples
- Load balancing strategies
- Health check tuning
- Security considerations
- Troubleshooting guide

**`examples/proxy_server.rs`** (~300 lines)
- Complete proxy server example
- Multi-realm routing configuration
- Two home server pools

**`examples/proxy_config.json`** (~100 lines)
- Production-ready proxy configuration
- Comments explaining each setting

#### Testing

- [ ] 60+ unit tests across all modules
- [ ] 15 integration tests
- [ ] Performance test (1000 req/s proxying)
- [ ] Stress test (failover under load)

**Deliverable**: Production-ready documentation and examples

---

## File Structure

```
crates/radius-server/src/proxy/
├── mod.rs                 # Module declarations, public API
├── home_server.rs         # HomeServer config and state
├── cache.rs               # ProxyCache for request tracking
├── handler.rs             # ProxyHandler for forwarding
├── realm.rs               # Realm matching and extraction
├── router.rs              # Router for routing decisions
├── pool.rs                # HomeServerPool and load balancing
├── health.rs              # Health checking background task
├── retry.rs               # RetryManager for timeouts
└── error.rs               # ProxyError types

examples/
├── proxy_server.rs        # Complete proxy example
└── proxy_config.json      # Example configuration

docs/docs/proxy/
└── README.md              # Comprehensive proxy guide
```

## Key Data Structures

### ProxyConfig

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub cache_ttl: u64,                    // Seconds
    pub max_outstanding: usize,            // Max in-flight requests
    pub proxy_timeout: u64,                // Seconds
    pub pools: Vec<HomeServerPoolConfig>,
    pub realms: Vec<RealmConfig>,
    pub default_realm: Option<String>,     // Fallback realm
    pub health_check: HealthCheckConfig,
    pub retry: RetryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeServerPoolConfig {
    pub name: String,
    pub strategy: String,  // "round_robin", "least_outstanding", "failover"
    pub servers: Vec<HomeServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeServerConfig {
    pub address: String,    // "host:port"
    pub secret: String,
    pub timeout: u64,       // Seconds
    pub max_outstanding: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmConfig {
    pub name: String,
    pub match_config: RealmMatchConfig,
    pub pool: String,       // Pool name reference
    pub strip_realm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmMatchConfig {
    pub match_type: String,  // "exact", "suffix", "regex"
    pub pattern: String,
}
```

## Testing Strategy

### Unit Tests (~60 total)

**proxy/cache.rs** (10 tests)
- Insert/lookup/remove
- TTL expiry
- Concurrent access
- Cleanup task

**proxy/home_server.rs** (10 tests)
- State transitions
- Statistics tracking
- Connection management

**proxy/realm.rs** (15 tests)
- Realm extraction (@, \, plain)
- Matcher types (exact, suffix, regex)
- Match failures

**proxy/router.rs** (10 tests)
- Routing decision logic
- Realm stripping
- Default realm fallback

**proxy/pool.rs** (15 tests)
- Round-robin selection
- Least-outstanding selection
- Failover selection
- Health state impact on selection

### Integration Tests (~15 total)

1. Basic proxy forwarding (single home server)
2. Realm-based routing (multiple realms)
3. Round-robin load balancing
4. Failover on server down
5. Health check recovery
6. Timeout and retry
7. Max retries exceeded → Reject
8. Proxy loop detection
9. Realm stripping
10. Accounting request proxying
11. Multiple Proxy-State preservation
12. Authenticator validation
13. Concurrent requests to pool
14. Pool exhaustion (all servers down)
15. Configuration validation

### Performance Benchmarks

- Proxy forwarding overhead (compare to local auth)
- Pool selection speed (1M selections)
- Realm matching speed (regex vs exact)
- Cache lookup performance

## Dependencies

**New dependencies** (add to `Cargo.toml`):

```toml
[dependencies]
# Existing dependencies...
regex = "1.10"  # For regex realm matching
```

**No new dependencies needed** - reuse existing:
- `dashmap` - Already used for RequestCache
- `tokio` - Already used for async runtime
- `serde` - Already used for config

## RFC Compliance

### RFC 2865 Proxy Requirements

- ✅ Section 5.33: Proxy-State attribute preservation
- ✅ Section 5: Response Authenticator recalculation
- ✅ Proxy loop prevention (limit Proxy-State attributes)

### RFC 2866 Accounting Proxy

- ✅ Forward Accounting-Request to home server
- ✅ Validate Request Authenticator with home server secret
- ✅ Recalculate Response Authenticator with client secret

## Security Considerations

1. **Proxy Loop Prevention**: Limit Proxy-State attributes to 5 (configurable)
2. **Authenticator Validation**: Verify response authenticator from home server
3. **Authenticator Recalculation**: Use client secret for response to NAS
4. **Secret Isolation**: Each home server has its own secret
5. **Timeout Limits**: Prevent resource exhaustion from slow home servers
6. **Cache Cleanup**: Automatic cleanup of timed-out requests
7. **DOS Protection**: Max outstanding requests per home server

## Performance Characteristics

**Expected Overhead**:
- Proxy cache lookup: < 1ms
- Realm extraction/matching: < 0.1ms
- Pool selection: < 0.1ms
- Network round-trip to home server: 1-50ms (depends on network)
- Total proxy overhead: ~2-5ms (excluding network)

**Memory Usage**:
- ProxyCache: ~1KB per in-flight request
- 1000 concurrent requests: ~1MB
- HomeServer state: ~1KB per server
- Realm configuration: ~1KB per realm

**Scalability**:
- Max outstanding requests: Configurable (default 1000)
- Max home servers: Unlimited (practical limit ~100 per pool)
- Max realms: Unlimited (practical limit ~1000)

## Risk Mitigation

**Complexity Risk**: Proxy state machine is complex
- Mitigation: Comprehensive unit tests, state diagram documentation

**Network Reliability**: Home servers may be unreliable
- Mitigation: Health checks, automatic failover, retry logic

**Performance Risk**: Proxy adds latency
- Mitigation: Efficient cache, minimal overhead, benchmarking

**Configuration Errors**: Complex configuration
- Mitigation: Validation on startup, example configs, documentation

## Timeline Summary

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Phase 1 | 2 weeks | Core proxy forwarding |
| Phase 2 | 1 week  | Realm-based routing |
| Phase 3 | 1 week  | Pools & load balancing |
| Phase 4 | 1 week  | Retry & timeout |
| Phase 5 | 1 week  | Integration & testing |
| Phase 6 | 1 week  | Documentation & examples |
| **Total** | **7 weeks** | **Production-ready proxy** |

## Success Criteria

### Phase 1 (MVP)
✅ Single home server forwarding works
✅ Proxy-State correlation works
✅ Authenticator recalculation correct
✅ 25 unit tests passing

### Phase 3 (Feature Complete)
✅ Realm-based routing works
✅ Load balancing works (all strategies)
✅ Failover works (auto + manual)
✅ 60 unit tests passing

### Phase 6 (Production Ready)
✅ All integration tests passing
✅ Documentation complete
✅ Example configurations work
✅ Performance meets targets (<5ms overhead)
✅ No memory leaks (stress test 1M requests)

## Next Steps

1. Begin Phase 1: Create `proxy/` module structure
2. Implement HomeServer and ProxyCache (core data structures)
3. Implement ProxyHandler forwarding logic
4. Write unit tests as we go (TDD approach)
5. Integration test with FreeRADIUS as home server

## Open Questions

1. **Accounting Proxy**: Should we proxy Accounting-Request packets?
   - Answer: YES - proxy both Auth and Acct (RFC 2866 supports it)

2. **CoA Proxy**: Should we proxy CoA-Request?
   - Answer: DEFER to v0.9.0 (CoA support)

3. **Proxy Chaining**: Should we support multi-hop proxying?
   - Answer: YES - Proxy-State stacking supports it (RFC 2865)

4. **Dynamic Configuration**: Should we support hot-reload of proxy config?
   - Answer: DEFER to future enhancement (start with startup-only config)

## References

- RFC 2865: RADIUS (Proxy-State, Section 5.33)
- RFC 2866: RADIUS Accounting (Accounting proxy)
- RFC 5997: Status-Server (Health checks)
- FreeRADIUS Proxy Documentation (Implementation reference)
