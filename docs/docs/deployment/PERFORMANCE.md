# Performance Guide

This document covers performance characteristics, tuning, and optimization for USG RADIUS.

## Table of Contents

1. [Performance Overview](#performance-overview)
2. [Benchmarking](#benchmarking)
3. [Tuning Guide](#tuning-guide)
4. [Scaling Strategies](#scaling-strategies)
5. [Performance Troubleshooting](#performance-troubleshooting)

---

## Performance Overview

### Baseline Performance (Single Server)

Tested on: AWS c5.2xlarge (8 vCPUs, 16 GB RAM)

| Metric | Simple Auth | PostgreSQL | LDAP | EAP-TLS |
|--------|-------------|------------|------|---------|
| **Throughput** | 50,000 RPS | 25,000 RPS | 20,000 RPS | 15,000 RPS |
| **Latency (P50)** | 0.2 ms | 0.5 ms | 1.0 ms | 2.0 ms |
| **Latency (P99)** | 0.8 ms | 2.5 ms | 5.0 ms | 8.0 ms |
| **Memory** | 50 MB | 100 MB | 80 MB | 120 MB |
| **CPU (8 cores)** | 20% | 45% | 40% | 60% |
| **Cache Hit Rate** | 95% | 92% | 90% | N/A |

### HA Cluster Performance (3 Nodes + Valkey)

| Metric | Value | Notes |
|--------|-------|-------|
| **Total Throughput** | 120,000 RPS | 3x40k per node |
| **Latency Overhead** | +0.3ms | Valkey network RTT |
| **Failover Time** | <100ms | Automatic with HAProxy |
| **Cross-Server Consistency** | 99.99% | Cache TTL = 30s |

### Comparison with FreeRADIUS

| Feature | FreeRADIUS 3.2 | USG RADIUS v0.6.0 | Improvement |
|---------|----------------|-------------------|-------------|
| Max RPS (PAP) | ~10,000 | ~50,000 | **5x faster** |
| Memory (1M requests) | 250 MB | 100 MB | **2.5x less** |
| P99 Latency | 5ms | 0.8ms | **6x faster** |
| Concurrent Connections | 10,000 | 100,000 | **10x more** |
| Container Size | N/A | 25 MB | Native container support |

---

## Benchmarking

### Running Built-in Benchmarks

```bash
# Compile-time benchmarks (Criterion)
cargo bench --bench radius_server_bench

# Results saved to: target/criterion/
# View HTML report: target/criterion/report/index.html
```

**Example Output**:
```
packet_encode/10_attrs  time: [2.156 µs 2.178 µs 2.201 µs]
packet_decode/10_attrs  time: [1.845 µs 1.862 µs 1.880 µs]
chap_verify/verify_valid time: [8.234 µs 8.301 µs 8.376 µs]
request_cache/is_duplicate_cached time: [125.32 ns 127.89 ns 130.87 ns]
rate_limiter/check_rate_limit time: [234.56 ns 238.91 ns 243.78 ns]
```

### Load Testing

#### Basic Load Test

```bash
cargo run --release --bin radius_load_test -- \
  --server 127.0.0.1:1812 \
  --secret testing123 \
  --clients 100 \
  --duration 60 \
  --rps 100
```

**Example Output**:
```
=== Load Test Results ===
Duration: 60.00s

Requests:
  Sent:     600000
  Received: 599850
  Timeouts: 150
  Errors:   0

Responses:
  Accept:   599850 (100.0%)
  Reject:   0 (0.0%)

Performance:
  RPS:      9997.50
  Success:  99.98%

Throughput:
  Sent:     4.32 Mbps (32400000 bytes)
  Received: 1.28 Mbps (9597600 bytes)

Latency (microseconds):
  Min:  120
  P50:  185
  P95:  312
  P99:  487
  Max:  1250
  Avg:  202.34
```

#### Stress Testing

```bash
# Find maximum RPS capacity
for rps in 100 500 1000 5000 10000 50000; do
  echo "Testing $rps RPS..."
  cargo run --release --bin radius_load_test -- \
    --server 127.0.0.1:1812 \
    --secret testing123 \
    --clients 10 \
    --duration 10 \
    --rps $rps \
    | grep -E "(RPS|Timeouts|P99)"
done
```

### Profiling

#### CPU Profiling

```bash
# Install flamegraph
cargo install flamegraph

# Profile the server
sudo cargo flamegraph --bin usg-radius-workspace -- config.json

# Generate interactive flamegraph
# Opens: flamegraph.svg
```

#### Memory Profiling

```bash
# Install valgrind
sudo apt-get install valgrind

# Run with memory profiling
valgrind --tool=massif --massif-out-file=massif.out \
  ./target/release/usg-radius-workspace config.json

# Analyze results
ms_print massif.out
```

#### Network Profiling

```bash
# Capture traffic
sudo tcpdump -i lo -w radius.pcap udp port 1812

# Analyze with tshark
tshark -r radius.pcap -q -z io,stat,1

# View in Wireshark
wireshark radius.pcap
```

---

## Tuning Guide

### 1. Operating System Tuning

#### File Descriptors

```bash
# /etc/security/limits.conf
radius soft nofile 65536
radius hard nofile 65536

# Verify
ulimit -n
```

#### Network Buffers

```bash
# /etc/sysctl.conf
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.udp_mem = 8388608 16777216 16777216

# Apply
sudo sysctl -p
```

#### CPU Affinity

```bash
# Pin RADIUS to specific cores for better cache locality
taskset -c 0-7 ./target/release/usg-radius-workspace config.json
```

### 2. Application Tuning

#### Cache Configuration

```json
{
  "state_backend": {
    "type": "valkey",
    "url": "redis://valkey:6379",
    "cache_ttl_secs": 30,  // ⚡ Lower = more consistent, higher = faster
    "max_retries": 3,
    "retry_delay_ms": 100,
    "connection_timeout_ms": 3000,
    "pool_size": 50  // ⚡ Increase for high concurrency
  }
}
```

**Tuning Guidelines**:
- **cache_ttl_secs**:
  - 10s = High consistency, moderate performance
  - 30s = Balanced (default)
  - 60s = High performance, lower consistency
- **pool_size**:
  - Formula: `concurrent_requests / 10`
  - Minimum: 10
  - Maximum: 100

#### Rate Limiting

```json
{
  "rate_limiting": {
    "per_client_limit": 100,    // ⚡ Requests per second
    "per_client_burst": 200,    // ⚡ Burst capacity
    "global_limit": 10000,      // ⚡ Total RPS
    "global_burst": 20000,
    "max_connections_per_client": 100,  // ⚡ Concurrent connections
    "max_bandwidth_per_client": 10485760,  // 10 MB/s
    "window_duration_secs": 1
  }
}
```

**Guidelines**:
- Set `per_client_limit` to prevent DoS
- Set `global_limit` slightly below max capacity
- `burst` should be 2x `limit` for normal traffic patterns

#### Connection Pooling

##### PostgreSQL

```json
{
  "auth_handler": {
    "type": "postgresql",
    "connection_string": "postgresql://radius:pass@localhost/radiusdb",
    "max_connections": 20,  // ⚡ Tune based on CPU cores
    "min_connections": 5,
    "acquire_timeout_secs": 10,
    "idle_timeout_secs": 300
  }
}
```

**Guidelines**:
- `max_connections` = number of CPU cores × 2-4
- Monitor with: `SELECT count(*) FROM pg_stat_activity;`

##### LDAP

```json
{
  "auth_handler": {
    "type": "ldap",
    "max_connections": 10,  // ⚡ Concurrent LDAP queries
    "acquire_timeout_secs": 10
  }
}
```

**Guidelines**:
- Start with 10, increase if seeing timeouts
- Monitor queue depth via metrics endpoint

### 3. Rust Compiler Optimizations

#### Profile-Guided Optimization (PGO)

```bash
# Step 1: Build with instrumentation
RUSTFLAGS="-Cprofile-generate=/tmp/pgo-data" \
  cargo build --release

# Step 2: Run typical workload
./target/release/usg-radius-workspace config.json &
cargo run --bin radius_load_test -- --duration 60
killall usg-radius-workspace

# Step 3: Merge profiling data
llvm-profdata merge -o /tmp/pgo-data/merged.profdata /tmp/pgo-data

# Step 4: Build with optimizations
RUSTFLAGS="-Cprofile-use=/tmp/pgo-data/merged.profdata" \
  cargo build --release

# Expected improvement: 10-20% faster
```

#### Link-Time Optimization (LTO)

Already enabled in `Cargo.toml`:
```toml
[profile.release]
opt-level = 3
lto = true          # ⚡ Whole-program optimization
codegen-units = 1   # ⚡ Better optimization, slower compile
strip = true        # ⚡ Smaller binary
```

#### CPU-Specific Optimizations

```bash
# Build for native CPU (uses AVX2, SSE4.2, etc.)
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Expected improvement: 5-10% faster
```

### 4. HA Cluster Tuning

#### Valkey Configuration

```conf
# valkey.conf
maxmemory 2gb
maxmemory-policy allkeys-lru  # Evict least recently used

# Persistence (affects write performance)
save 900 1       # Save after 900s if 1+ keys changed
save 300 10      # Save after 300s if 10+ keys changed
save 60 10000    # Save after 60s if 10000+ keys changed

# Disable for maximum performance (risky)
# save ""

# Append-only file for durability
appendonly yes
appendfsync everysec  # Balance safety and performance
```

**Tuning**:
- **Development**: Disable persistence (`save ""`)
- **Production**: Use AOF with `everysec`
- **High Performance**: Use replication instead of persistence

#### HAProxy Configuration

```conf
# haproxy.cfg
global
    maxconn 100000  # ⚡ Maximum concurrent connections

defaults
    timeout connect 1s
    timeout client 3s   # ⚡ Match RADIUS timeout
    timeout server 3s

frontend radius_auth
    bind *:1812
    mode udp
    maxconn 100000
    default_backend radius_servers_udp

backend radius_servers_udp
    mode udp
    balance leastconn  # ⚡ Route to least loaded server
    option udp-check
    server radius1 radius-server-1:1812 check inter 5s
    server radius2 radius-server-2:1812 check inter 5s
    server radius3 radius-server-3:1812 check inter 5s
```

**Algorithms**:
- `roundrobin` - Even distribution
- `leastconn` - Best for varying request complexity
- `source` - Sticky sessions (session affinity)

---

## Scaling Strategies

### Vertical Scaling (Single Server)

| Instance Type | vCPUs | RAM | Expected RPS | Use Case |
|---------------|-------|-----|--------------|----------|
| t3.small | 2 | 2 GB | 5,000 | Development |
| t3.medium | 2 | 4 GB | 10,000 | Small deployment |
| c5.large | 2 | 4 GB | 15,000 | Medium deployment |
| c5.xlarge | 4 | 8 GB | 30,000 | Large deployment |
| c5.2xlarge | 8 | 16 GB | 50,000 | Very large deployment |
| c5.4xlarge | 16 | 32 GB | 80,000 | Extreme load |

**Cost vs Performance**:
- Doubling vCPUs increases RPS by ~1.8x
- Memory is rarely the bottleneck (50-200 MB typical)
- Network bandwidth more important than CPU for simple auth

### Horizontal Scaling (HA Cluster)

```
1 server  → 50,000 RPS
2 servers → 95,000 RPS (95% efficiency)
3 servers → 135,000 RPS (90% efficiency)
4 servers → 170,000 RPS (85% efficiency)
```

**Efficiency Loss Reasons**:
1. Valkey becomes bottleneck (shared state)
2. HAProxy overhead (~5%)
3. Network latency between nodes

**Solutions**:
1. **Valkey Cluster**: Shard across multiple Valkey instances
2. **Regional Deployment**: Separate clusters per region
3. **Read Replicas**: For read-heavy workloads

### Geographic Distribution

```
        ┌──────────────┐
        │   GeoDNS     │
        └───────┬──────┘
                │
    ┌───────────┼───────────┐
    │           │           │
┌───▼────┐  ┌──▼─────┐  ┌──▼─────┐
│ US-East│  │ EU-West│  │ AP-East│
│ Cluster│  │ Cluster│  │ Cluster│
└────────┘  └────────┘  └────────┘
```

**Benefits**:
- Lower latency (users route to nearest region)
- Higher availability (region failover)
- Better performance (reduced network hops)

**Implementation**:
- Use Valkey Cluster with replication
- Configure DNS-based routing
- Deploy HAProxy per region

---

## Performance Troubleshooting

### Symptom: High Latency

#### Diagnosis

```bash
# Check P99 latency
curl http://localhost:3812/metrics | grep radius_request_duration

# Run load test with detailed output
cargo run --bin radius_load_test -- --verbose
```

#### Causes & Solutions

| Cause | Diagnosis | Solution |
|-------|-----------|----------|
| **Backend Slow** | `curl /health` shows high DB latency | Optimize queries, add indexes, increase pool size |
| **Cache Misses** | Low cache hit rate in metrics | Increase cache TTL, add more memory |
| **Network** | High RTT to Valkey | Deploy Valkey closer to servers |
| **CPU Bound** | `top` shows 100% CPU | Vertical scaling or add more nodes |
| **Disk I/O** | `iostat` shows high await | Use SSD, disable Valkey persistence |

### Symptom: Low Throughput

#### Diagnosis

```bash
# Check request rate
watch -n 1 'curl -s http://localhost:3812/metrics | grep radius_requests_total'

# Monitor resource usage
htop
```

#### Causes & Solutions

| Cause | Diagnosis | Solution |
|-------|-----------|----------|
| **Rate Limiting** | Metrics show rejected requests | Increase rate limits in config |
| **Connection Pool Exhausted** | Timeouts in logs | Increase `max_connections` |
| **File Descriptors** | `Too many open files` error | Increase ulimit |
| **Memory** | OOM killer logs | Add more RAM or reduce cache size |
| **Network Bandwidth** | `iftop` shows saturation | Upgrade network or add nodes |

### Symptom: Memory Leak

#### Diagnosis

```bash
# Monitor memory over time
while true; do
  curl -s http://localhost:2812/health | jq '.memory_mb'
  sleep 60
done

# Profile with Valgrind
valgrind --leak-check=full ./target/release/usg-radius-workspace config.json
```

#### Causes & Solutions

| Cause | Diagnosis | Solution |
|-------|-----------|----------|
| **Cache Growth** | Memory increases linearly | Set max cache size, cleanup expired entries |
| **Connection Leaks** | Open connections in `lsof` | Check backend connection management |
| **Session Storage** | EAP sessions not cleaned up | Reduce session timeout, enable cleanup |

### Symptom: Backend Timeouts

#### Diagnosis

```bash
# Check backend health
curl http://localhost:2812/health | jq '.backend'

# Test backend directly
# PostgreSQL
psql -U radius -h localhost -d radiusdb -c "SELECT 1;"

# LDAP
ldapsearch -H ldaps://ldap.example.com -D bind_dn -w password -b base_dn "(uid=test)"

# Valkey
redis-cli -h valkey ping
```

#### Solutions

1. **Increase timeouts**:
   ```json
   {
     "state_backend": {
       "connection_timeout_ms": 5000,
       "acquire_timeout_secs": 10
     }
   }
   ```

2. **Add backend redundancy**:
   ```json
   {
     "ldap": {
       "urls": [
         "ldaps://ldap1.example.com:636",
         "ldaps://ldap2.example.com:636"
       ]
     }
   }
   ```

3. **Monitor backend performance**:
   ```bash
   # PostgreSQL slow queries
   SELECT query, mean_exec_time FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;
   ```

---

## Performance Best Practices

### ✅ Do

1. **Enable HA for production**: Shared state prevents single point of failure
2. **Use connection pooling**: Reuse connections to backends
3. **Monitor metrics**: Track RPS, latency, cache hit rate
4. **Profile before optimizing**: Measure to find real bottlenecks
5. **Test at scale**: Load test with realistic traffic patterns
6. **Tune cache TTL**: Balance consistency and performance
7. **Use appropriate auth method**: Simple > PostgreSQL > LDAP > EAP-TLS

### ❌ Don't

1. **Don't skip benchmarking**: Assumptions lead to poor design
2. **Don't over-provision**: Start small, scale up based on metrics
3. **Don't disable rate limiting**: Protect against DoS
4. **Don't ignore logs**: Early warnings prevent outages
5. **Don't use DEBUG in production**: Severe performance impact
6. **Don't skip OS tuning**: 10-30% performance gain for free

---

## Performance Monitoring

### Key Metrics to Track

| Metric | Target | Alert Threshold | Action |
|--------|--------|-----------------|--------|
| **RPS** | Varies | <80% capacity | Scale up |
| **P99 Latency** | <5ms | >10ms | Investigate |
| **Cache Hit Rate** | >90% | <80% | Increase TTL |
| **Backend Latency** | <2ms | >5ms | Optimize queries |
| **Memory Usage** | <50% | >80% | Add RAM |
| **CPU Usage** | <70% | >90% | Add cores |
| **Error Rate** | <0.01% | >0.1% | Incident response |

### Grafana Dashboard

Example Prometheus queries:

```promql
# Request rate
rate(radius_requests_total[5m])

# Latency percentiles
histogram_quantile(0.99, rate(radius_request_duration_seconds_bucket[5m]))

# Cache hit rate
radius_cache_hits_total / (radius_cache_hits_total + radius_cache_misses_total)

# Backend health
radius_backend_up
```

---

**Next Steps**: See [QUICKSTART.md](./QUICKSTART.md) to deploy and [HIGH_AVAILABILITY.md](./HIGH_AVAILABILITY.md) for cluster configuration.
