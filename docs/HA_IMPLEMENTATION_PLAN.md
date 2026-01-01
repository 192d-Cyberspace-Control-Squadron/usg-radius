# High Availability Implementation Plan - Phase 3

## Overview

Implement High Availability (HA) support for the USG RADIUS server to enable multi-server deployments with shared state, health monitoring, and seamless failover.

**Version**: v0.7.4 Phase 3
**Estimated Effort**: 3 weeks
**Priority**: HIGH (Required for production deployments)

**State Backend**: Valkey (open-source Redis fork, Linux Foundation)
**Why Valkey**: Better licensing (BSD), active community development, Redis-compatible protocol

## Goals

1. **Multi-Server Deployment**: Support N+1 active-active RADIUS server clusters
2. **Shared Session State**: Replicate EAP and accounting sessions across servers
3. **Health Monitoring**: Expose health check endpoints for load balancers
4. **Seamless Failover**: Continue authentication when individual servers fail
5. **Zero Downtime Updates**: Enable rolling updates without service interruption

## Architecture

### Current State (In-Memory, Single Server)

```
┌─────────────────────────────┐
│   RADIUS Server (Port 1812) │
│  ┌───────────────────────┐  │
│  │  EAP Sessions         │  │  HashMap<String, EapSession>
│  │  (In-Memory)          │  │
│  ├───────────────────────┤  │
│  │  Accounting Sessions  │  │  DashMap<String, Session>
│  │  (In-Memory)          │  │
│  ├───────────────────────┤  │
│  │  Request Cache        │  │  DashMap<Fingerprint, Entry>
│  │  (In-Memory)          │  │
│  ├───────────────────────┤  │
│  │  Rate Limit Buckets   │  │  DashMap<IpAddr, Bucket>
│  │  (In-Memory)          │  │
│  └───────────────────────┘  │
└─────────────────────────────┘
```

**Problem**: Sessions lost on server restart/failure. No redundancy.

### Target State (Shared State, HA Cluster)

```
                      Load Balancer (Active-Active)
                              │
                ┌─────────────┼─────────────┐
                │             │             │
         ┌──────▼─────┐  ┌───▼──────┐  ┌──▼───────┐
         │  RADIUS 1  │  │ RADIUS 2 │  │ RADIUS 3 │
         │ :1812      │  │ :1812    │  │ :1812    │
         └──────┬─────┘  └───┬──────┘  └──┬───────┘
                │            │            │
                └────────────┼────────────┘
                             │
                    ┌────────▼────────┐
                    │ Valkey Cluster  │
                    │  (Shared State) │
                    │                 │
                    │  - EAP Sessions │
                    │  - Accounting   │
                    │  - Rate Limits  │
                    │  - Req Cache    │
                    └─────────────────┘
```

**Benefits**:

- Session continuity across server failures
- Horizontal scaling (add servers as needed)
- Rolling updates without downtime
- Shared rate limiting across cluster

## Implementation Phases

### Phase 3A: Valkey Integration (Week 1)

**Goal**: Add Valkey backend for shared state storage

**Note**: Valkey uses the Redis protocol, so we use the `redis` Rust crate for compatibility.

#### Dependencies

Add to `crates/radius-server/Cargo.toml`:

```toml
[dependencies]
redis = { version = "0.24", features = ["tokio-comp", "connection-manager"] }
serde_json = "1.0"  # For session serialization

[features]
ha = ["redis"]  # New feature flag for HA support
```

#### New Modules

**1. `crates/radius-server/src/state/mod.rs`** (~100 lines)

Public API for state management:

```rust
pub trait StateBackend: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StateError>;
    async fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<(), StateError>;
    async fn delete(&self, key: &str) -> Result<(), StateError>;
    async fn exists(&self, key: &str) -> Result<bool, StateError>;
    async fn keys(&self, pattern: &str) -> Result<Vec<String>, StateError>;
}

pub enum StateBackendType {
    InMemory,   // Existing HashMap-based (default)
    Valkey,     // New Valkey-backed (Redis protocol)
}
```

**2. `crates/radius-server/src/state/valkey.rs`** (~400 lines)

Valkey backend implementation (uses Redis protocol via `redis` crate):

```rust
pub struct ValkeyStateBackend {
    client: redis::Client,
    connection_pool: redis::aio::ConnectionManager,
    key_prefix: String,  // e.g., "usg-radius:server1:"
}

impl ValkeyStateBackend {
    pub async fn new(config: ValkeyConfig) -> Result<Self, StateError>;

    // Implement StateBackend trait
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StateError>;
    async fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<(), StateError>;

    // Health checking
    pub async fn ping(&self) -> Result<(), StateError>;
}

pub struct ValkeyConfig {
    pub url: String,  // valkey://localhost:6379 (or redis:// for compatibility)
    pub key_prefix: String,
    pub connection_timeout: Duration,
    pub command_timeout: Duration,
    pub max_retries: u32,
}
```

**3. `crates/radius-server/src/state/memory.rs`** (~200 lines)

Wrap existing in-memory implementation to match `StateBackend` trait:

```rust
pub struct MemoryStateBackend {
    store: Arc<DashMap<String, (Vec<u8>, Option<Instant>)>>,
}

impl StateBackend for MemoryStateBackend {
    // Implement trait methods using DashMap
}
```

**4. `crates/radius-server/src/state/config.rs`** (~100 lines)

Configuration structures:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateConfig {
    pub backend: StateBackendType,
    pub valkey: Option<ValkeyConfig>,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            backend: StateBackendType::InMemory,
            valkey: None,
        }
    }
}
```

#### Modified Files

**1. Update `crates/radius-proto/src/eap.rs`** (+50 lines)

Add serialization to EapSession:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]  // Add Serialize/Deserialize
pub struct EapSession {
    pub session_id: String,
    pub state: EapState,
    pub current_identifier: u8,
    // ... existing fields
}

impl EapSession {
    // Add serialization helpers
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}
```

**Challenge**: EapTlsServer and EapTeapServer contain `rustls::ServerConnection` which is NOT serializable. Need alternative approach (see "Challenges" section below).

**2. Update `crates/radius-server/src/accounting.rs`** (+30 lines)

Add serialization to Session:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]  // Add Serialize/Deserialize
pub struct Session {
    pub session_id: String,
    pub username: String,
    // ... existing fields
}
```

**3. Update `crates/radius-server/src/server.rs`** (+20 lines)

Add state backend to ServerConfig:

```rust
pub struct ServerConfig {
    // ... existing fields
    pub state_backend: Arc<dyn StateBackend>,  // NEW
}
```

### Phase 3B: Shared Session State (Week 2)

**Goal**: Migrate session storage to use shared state backend

#### New Session Manager

**1. `crates/radius-server/src/session/shared_session_manager.rs`** (~500 lines)

Replace in-memory session manager:

```rust
pub struct SharedSessionManager {
    backend: Arc<dyn StateBackend>,
    local_cache: Arc<DashMap<String, CachedSession>>,  // Write-through cache
    cache_ttl: Duration,
}

impl SharedSessionManager {
    pub async fn get_eap_session(&self, session_id: &str) -> Result<Option<EapSession>, StateError> {
        // 1. Check local cache first (fast path)
        if let Some(cached) = self.local_cache.get(session_id) {
            if !cached.is_expired() {
                return Ok(Some(cached.session.clone()));
            }
        }

        // 2. Fetch from backend (Valkey/memory)
        let key = format!("eap_session:{}", session_id);
        if let Some(bytes) = self.backend.get(&key).await? {
            let session = EapSession::from_bytes(&bytes)?;

            // 3. Update local cache
            self.local_cache.insert(session_id.to_string(), CachedSession {
                session: session.clone(),
                cached_at: Instant::now(),
            });

            return Ok(Some(session));
        }

        Ok(None)
    }

    pub async fn save_eap_session(&self, session: &EapSession) -> Result<(), StateError> {
        let key = format!("eap_session:{}", session.session_id);
        let bytes = session.to_bytes()?;
        let ttl = Some(Duration::from_secs(300));  // 5 minutes default

        // 1. Save to backend
        self.backend.set(&key, &bytes, ttl).await?;

        // 2. Update local cache
        self.local_cache.insert(session.session_id.clone(), CachedSession {
            session: session.clone(),
            cached_at: Instant::now(),
        });

        Ok(())
    }

    pub async fn delete_eap_session(&self, session_id: &str) -> Result<(), StateError> {
        let key = format!("eap_session:{}", session_id);
        self.backend.delete(&key).await?;
        self.local_cache.remove(session_id);
        Ok(())
    }

    // Similar methods for accounting sessions
}
```

#### Modified Files

**1. Update `crates/radius-server/src/eap_auth.rs`** (+100 lines, -50 lines)

Replace HashMap-based session storage with SharedSessionManager:

```rust
pub struct EapAuthHandler {
    inner_handler: Arc<dyn AuthHandler>,
    // OLD: session_manager: Arc<RwLock<EapSessionManager>>,
    session_manager: Arc<SharedSessionManager>,  // NEW
    tls_configs: Arc<RwLock<HashMap<String, StdArc<rustls::ServerConfig>>>>,
    // ... other fields
}

impl EapAuthHandler {
    pub async fn start_eap_authentication(&mut self, username: &str, ...) {
        // ... existing logic

        // OLD: let mut mgr = self.session_manager.write().await;
        // OLD: mgr.insert(session_id.clone(), session);

        // NEW: Save to shared backend
        self.session_manager.save_eap_session(&session).await?;
    }

    pub async fn continue_eap_authentication(&mut self, session_id: &str, ...) {
        // OLD: let mgr = self.session_manager.read().await;
        // OLD: let session = mgr.get(session_id)?;

        // NEW: Load from shared backend
        let session = self.session_manager.get_eap_session(session_id).await?;
    }
}
```

**2. Update `crates/radius-server/src/accounting.rs`** (+80 lines)

Integrate shared backend for accounting sessions:

```rust
pub struct SessionTracker {
    // OLD: sessions: Arc<DashMap<String, Session>>,
    session_manager: Arc<SharedSessionManager>,  // NEW
}

impl SessionTracker {
    pub async fn start_session(&self, session_id: String, ...) {
        let session = Session { ... };
        self.session_manager.save_accounting_session(&session).await?;
    }

    pub async fn get_session(&self, session_id: &str) -> Option<Session> {
        self.session_manager.get_accounting_session(session_id).await.ok().flatten()
    }
}
```

### Phase 3C: Health Checks & Monitoring (Week 2)

**Goal**: Add HTTP health check endpoints for load balancers

#### Dependencies

Add to `crates/radius-server/Cargo.toml`:

```toml
[dependencies]
axum = { version = "0.7", optional = true }  # HTTP framework
tower = { version = "0.4", optional = true }
tower-http = { version = "0.5", features = ["trace"], optional = true }

[features]
ha = ["redis", "axum", "tower", "tower-http"]
```

#### New Modules

**1. `crates/radius-server/src/health/mod.rs`** (~300 lines)

Health check HTTP server:

```rust
use axum::{Router, routing::get, Json};
use serde::{Serialize, Deserialize};

pub struct HealthServer {
    config: HealthConfig,
    server_state: Arc<RadiusServerState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    pub enabled: bool,
    pub bind_address: SocketAddr,  // e.g., 0.0.0.0:8080
    pub auth_token: Option<String>,  // Optional bearer token
}

impl HealthServer {
    pub async fn new(config: HealthConfig, server_state: Arc<RadiusServerState>) -> Self;

    pub async fn run(self) -> Result<(), HealthError> {
        let app = Router::new()
            .route("/health", get(health_check))
            .route("/health/liveness", get(liveness_probe))
            .route("/health/readiness", get(readiness_probe))
            .route("/metrics", get(prometheus_metrics))
            .with_state(self.server_state);

        let listener = tokio::net::TcpListener::bind(&self.config.bind_address).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

// Health check handlers
async fn health_check(State(state): State<Arc<RadiusServerState>>) -> Json<HealthResponse> {
    // Check all subsystems
    let redis_ok = state.state_backend.ping().await.is_ok();
    let auth_ok = true;  // Check if auth handler is responsive

    Json(HealthResponse {
        status: if redis_ok && auth_ok { "healthy" } else { "degraded" },
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.uptime(),
        checks: vec![
            HealthCheck { name: "redis", status: redis_ok },
            HealthCheck { name: "auth", status: auth_ok },
        ],
    })
}

async fn liveness_probe() -> Json<ProbeResponse> {
    // Simple: Is the process alive?
    Json(ProbeResponse { status: "ok" })
}

async fn readiness_probe(State(state): State<Arc<RadiusServerState>>) -> Json<ProbeResponse> {
    // Is the server ready to accept traffic?
    // Check: Valkey connected, auth handler initialized, etc.
    let ready = state.is_ready().await;

    Json(ProbeResponse {
        status: if ready { "ready" } else { "not_ready" }
    })
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    uptime_seconds: u64,
    checks: Vec<HealthCheck>,
}

#[derive(Serialize)]
struct HealthCheck {
    name: &'static str,
    status: bool,
}

#[derive(Serialize)]
struct ProbeResponse {
    status: &'static str,
}
```

**2. `crates/radius-server/src/health/metrics.rs`** (~200 lines)

Prometheus-compatible metrics:

```rust
async fn prometheus_metrics(State(state): State<Arc<RadiusServerState>>) -> String {
    let stats = state.get_statistics().await;

    format!(r#"
# HELP radius_requests_total Total RADIUS requests processed
# TYPE radius_requests_total counter
radius_requests_total{{type="access"}} {}
radius_requests_total{{type="accounting"}} {}

# HELP radius_sessions_active Currently active sessions
# TYPE radius_sessions_active gauge
radius_sessions_active{{type="eap"}} {}
radius_sessions_active{{type="accounting"}} {}

# HELP radius_backend_latency_seconds Backend operation latency
# TYPE radius_backend_latency_seconds histogram
radius_backend_latency_seconds_bucket{{operation="get",le="0.001"}} {}
radius_backend_latency_seconds_bucket{{operation="get",le="0.01"}} {}
radius_backend_latency_seconds_bucket{{operation="get",le="0.1"}} {}
"#,
        stats.access_requests,
        stats.accounting_requests,
        stats.active_eap_sessions,
        stats.active_accounting_sessions,
        stats.backend_latency_1ms,
        stats.backend_latency_10ms,
        stats.backend_latency_100ms,
    )
}
```

#### Modified Files

**1. Update `crates/radius-server/src/server.rs`** (+50 lines)

Integrate health server:

```rust
pub struct RadiusServer {
    // ... existing fields
    health_server: Option<HealthServer>,  // NEW
}

impl RadiusServer {
    pub async fn run(self) -> Result<(), ServerError> {
        // Start health check server if enabled
        if let Some(health_server) = self.health_server {
            tokio::spawn(async move {
                if let Err(e) = health_server.run().await {
                    eprintln!("Health server error: {}", e);
                }
            });
        }

        // ... existing server loop
    }
}
```

### Phase 3D: Documentation & Examples (Week 3)

**Goal**: Comprehensive HA deployment documentation

#### New Documentation Files

**1. `docs/HA_DEPLOYMENT.md`** (~800 lines)

Complete HA deployment guide:

- Valkey cluster setup (3+ node quorum)
- Load balancer configuration (HAProxy, nginx)
- Multi-server RADIUS setup
- Health check integration
- Monitoring with Prometheus/Grafana
- Troubleshooting guide

**2. `examples/ha_cluster/`**

Production-ready HA deployment examples:

```
examples/ha_cluster/
├── README.md                    # Setup instructions
├── docker-compose.yml           # 3-node RADIUS + Valkey cluster
├── haproxy.cfg                  # Load balancer config
├── prometheus.yml               # Metrics collection
├── grafana_dashboard.json       # Monitoring dashboard
├── radius_server_1.json         # RADIUS server 1 config
├── radius_server_2.json         # RADIUS server 2 config
├── radius_server_3.json         # RADIUS server 3 config
└── kubernetes/                  # Kubernetes manifests
    ├── deployment.yaml          # RADIUS deployment
    ├── service.yaml             # LoadBalancer service
    ├── valkey-cluster.yaml      # Valkey StatefulSet
    └── configmap.yaml           # Configuration
```

**3. Update `README.md`** (+50 lines)

Add HA deployment section:

```markdown
## High Availability Deployment

USG RADIUS supports active-active clustering for high availability:

- **Shared State**: EAP and accounting sessions shared via Valkey
- **Health Checks**: HTTP endpoints for load balancer integration
- **Horizontal Scaling**: Add servers as needed
- **Zero Downtime**: Rolling updates without service interruption

See [HA Deployment Guide](docs/HA_DEPLOYMENT.md) for complete setup instructions.
```

## Challenges & Solutions

### Challenge 1: TLS Session Serialization

**Problem**: `EapTlsServer` contains `rustls::ServerConnection` which is NOT serializable.

**Solution**: Two-tier approach:

1. **Serialize EAP state** (identity, state machine, metadata)
2. **Do NOT serialize TLS connection** (stateless TLS handshake)

TLS is designed to be stateless at the handshake level. If a server fails mid-handshake:

- Client will retry from beginning (normal TLS behavior)
- New server starts fresh TLS handshake
- Session state (identity, method) is preserved

```rust
// Only serialize this minimal state
#[derive(Serialize, Deserialize)]
struct EapTlsSessionState {
    session_id: String,
    identity: Option<String>,
    state: EapState,
    // TLS connection is NOT serialized - will be recreated on retry
}
```

### Challenge 2: Request Cache Consistency

**Problem**: Request cache (duplicate detection) must be cluster-aware to prevent replay attacks.

**Solution**: Use Valkey SET with NX (not exists) for atomic deduplication:

```rust
async fn check_duplicate(&self, fingerprint: &RequestFingerprint) -> bool {
    let key = format!("req_cache:{}", fingerprint);

    // Atomic SET NX (only set if not exists)
    let result: bool = self.valkey.set_nx(&key, b"1", Some(Duration::from_secs(30))).await?;

    // result == true means key was created (not duplicate)
    // result == false means key already existed (duplicate!)
    !result
}
```

### Challenge 3: Rate Limit Coordination

**Problem**: Rate limiting must be coordinated across cluster to prevent bypass.

**Solution**: Use Valkey INCR for atomic counter increments:

```rust
async fn check_rate_limit(&self, client_ip: &IpAddr) -> bool {
    let key = format!("ratelimit:{}:count", client_ip);
    let window_key = format!("ratelimit:{}:window", client_ip);

    // Atomic increment
    let count: u32 = self.valkey.incr(&key).await?;

    if count == 1 {
        // First request in window - set TTL
        self.valkey.expire(&key, Duration::from_secs(60)).await?;
    }

    count <= self.config.max_requests_per_minute
}
```

## Testing Strategy

### Unit Tests (~20 tests)

**1. State Backend Tests** (`state/valkey.rs`)

- Valkey connection pooling
- GET/SET/DELETE operations
- TTL expiration
- Key prefix isolation
- Error handling (connection loss)

**2. Session Manager Tests** (`session/shared_session_manager.rs`)

- Session create/read/update/delete
- Local cache hit/miss
- Cache invalidation
- Concurrent access

### Integration Tests (~15 tests)

**1. Multi-Server Session Tests** (`tests/ha_session.rs`)

- Create session on server1, read from server2
- Update session on server2, verify on server1
- Delete session on server1, verify gone on server2
- Session TTL expiration across cluster

**2. Health Check Tests** (`tests/ha_health.rs`)

- Health endpoint returns 200 when healthy
- Readiness endpoint fails when Valkey down
- Metrics endpoint returns Prometheus format
- Liveness always returns 200

**3. Load Balancer Tests** (`tests/ha_failover.rs`)

- Client starts EAP on server1
- Server1 fails (simulated)
- Client retries, routed to server2
- Authentication completes successfully

### Performance Tests

**1. Latency Overhead**

- Measure Valkey GET/SET latency (target < 5ms p95)
- Measure total auth latency increase (target < 10ms)
- Local cache hit rate (target > 95%)

**2. Throughput**

- Single server: 5000 req/s (baseline)
- 3-server cluster: 15000 req/s (linear scaling)

## Success Criteria

### Functional Requirements

- ✅ EAP sessions survive individual server failures
- ✅ Accounting sessions persist across cluster
- ✅ Load balancer can detect unhealthy servers (health checks)
- ✅ Request deduplication works cluster-wide
- ✅ Rate limiting enforced across cluster
- ✅ Zero configuration changes for non-HA deployments (backward compatible)

### Non-Functional Requirements

- ✅ p95 latency increase < 10ms with Valkey backend
- ✅ Local cache hit rate > 95%
- ✅ Valkey connection pool management (no connection leaks)
- ✅ Graceful degradation (continue with degraded service if Valkey fails, based on config)
- ✅ 25+ tests passing (20 unit + 5 integration)

### Documentation Requirements

- ✅ Complete HA deployment guide
- ✅ Docker Compose example (3-node cluster)
- ✅ Kubernetes manifests
- ✅ Load balancer configuration examples (HAProxy, nginx)
- ✅ Monitoring setup (Prometheus + Grafana)
- ✅ Troubleshooting guide

## Timeline

| Week | Phase | Deliverables |
|------|-------|--------------|
| 1 | Phase 3A | Valkey integration, StateBackend trait, ValkeyStateBackend implementation |
| 2 | Phase 3B | SharedSessionManager, migrate EAP/accounting sessions, health checks |
| 3 | Phase 3C/3D | Documentation, examples, testing, final integration |

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Valkey adds significant latency | HIGH | Local write-through cache (target 95%+ hit rate) |
| TLS session cannot serialize | HIGH | Don't serialize - rely on stateless TLS retry |
| Valkey single point of failure | MEDIUM | Use Valkey cluster (3+ nodes), document failover |
| Backward compatibility breaks | MEDIUM | Feature flag (`ha`), default to in-memory |
| Complex testing scenarios | MEDIUM | Start with unit tests, build up to integration |

## Dependencies

### New Cargo Dependencies

```toml
[dependencies]
# Redis crate is Valkey-compatible (same protocol)
redis = { version = "0.24", features = ["tokio-comp", "connection-manager"], optional = true }
axum = { version = "0.7", optional = true }
tower = { version = "0.4", optional = true }
tower-http = { version = "0.5", features = ["trace"], optional = true }

[features]
ha = ["redis", "axum", "tower", "tower-http"]
```

### Infrastructure Dependencies

- Valkey 7.2+ (or Valkey Cluster, Redis-compatible)
- Load Balancer (HAProxy 2.0+, nginx 1.18+, or cloud LB)
- Docker (for examples)
- Kubernetes 1.20+ (optional, for k8s examples)

## Next Steps

1. Begin with Week 1: Valkey integration and StateBackend abstraction
2. Create `state/` module with trait definition
3. Implement `ValkeyStateBackend` with connection pooling
4. Write comprehensive unit tests for state operations
5. Update `EapSession` and `Session` with serialization
6. Integrate with existing session managers in Week 2

---

**Status**: Ready to begin implementation
**Approval**: Awaiting user confirmation to proceed
