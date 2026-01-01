# Performance Optimization Guide

This document describes performance optimizations implemented in the USG RADIUS server and how to profile and benchmark your deployment.

## Memory Optimizations

### Buffer Pooling (v0.7.4)

The server implements a buffer pool to reduce memory allocations in hot paths. Instead of allocating a new 4096-byte buffer for each UDP packet reception, buffers are reused from a thread-safe pool.

**Key Features:**
- Zero-allocation packet reception (after pool warmup)
- Automatic buffer return on drop
- Configurable pool size (default: 1000 buffers max)
- Thread-safe concurrent access
- Automatic capacity management (shrinks oversized buffers)

**Implementation:**
```rust
// Buffer pool is created automatically in ServerConfig
let buffer_pool = BufferPool::new(4096, 1000);

// Buffers are acquired from pool in main server loop
let mut pooled_buf = self.config.buffer_pool.acquire().await;
let (len, addr) = self.socket.recv_from(pooled_buf.as_mut()).await?;

// Buffer automatically returns to pool when dropped
```

**Memory Savings:**
- Before: ~4KB allocation per packet (2+ allocations per request/response cycle)
- After: Pool reuse - zero allocations for steady-state traffic
- Typical savings: 8-16KB per authentication (request + response buffers)

**Monitoring:**
```rust
// Get current pool size
let pool_size = server.config.buffer_pool.size().await;
```

### Future Optimizations

Planned for future releases:
- String interning for repeated attribute values
- Packet struct pooling for high-throughput scenarios
- Zero-copy packet parsing where possible

## CPU Optimizations

### Current Optimizations

1. **Async I/O**: All network operations use Tokio async I/O
2. **Password hashing offload**: CPU-intensive hashing in `spawn_blocking`
3. **Connection pooling**: LDAP and PostgreSQL connection reuse
4. **Early validation**: Rate limiting and client validation before expensive operations

### Profiling Tools

#### CPU Profiling with flamegraph

```bash
# Install flamegraph
cargo install flamegraph

# Run benchmark with CPU profiling
cargo flamegraph --example perf_bench

# Open flamegraph.svg in browser to analyze
```

#### Memory Profiling with heaptrack (Linux)

```bash
# Install heaptrack
sudo apt install heaptrack

# Build release binary
cargo build --example perf_bench --release

# Profile memory
heaptrack ./target/release/examples/perf_bench

# Analyze results
heaptrack_gui heaptrack.perf_bench.*.zst
```

#### Memory Profiling with Instruments (macOS)

```bash
# Build release binary
cargo build --example perf_bench --release

# Profile with Instruments
instruments -t "Allocations" ./target/release/examples/perf_bench
```

## Benchmarking

### Built-in Benchmark

The `perf_bench` example provides load testing:

```bash
# Build
cargo build --example perf_bench --release

# Run benchmark
./target/release/examples/perf_bench
```

**Sample Output:**
```
RADIUS Server Performance Benchmark
===================================

Server started on 127.0.0.1:35891
Benchmark configuration:
  Workers: 10
  Requests per worker: 1000
  Total requests: 10000

Starting benchmark...

Benchmark Results:
==================
Total elapsed time: 2.15s
Requests sent: 10000
Responses received: 10000

Throughput: 4651 requests/second
Average latency: 0.21 ms
Per-worker average: 2.15 ms
```

### Custom Benchmarking

For production-like load testing, use `radperf` or `eapol_test`:

```bash
# Install radperf
git clone https://github.com/FreeRADIUS/freeradius-server
cd freeradius-server/src/tests/radperf
make

# Run load test
./radperf -s 127.0.0.1 -x \
  -c 100 \      # 100 concurrent clients
  -r 10000 \    # 10,000 total requests
  -t pap \      # PAP authentication
  -u testuser \ # Username
  -p testpass   # Password
```

## Performance Tuning

### Server Configuration

```json
{
  "request_cache_ttl": 60,
  "request_cache_max_entries": 10000,
  "rate_limit_per_client_rps": 100,
  "rate_limit_global_rps": 1000,
  "max_concurrent_connections": 100
}
```

### Buffer Pool Tuning

The buffer pool is configured in `ServerConfig`:

```rust
// Default: 4096 byte buffers, 1000 max pooled
let buffer_pool = BufferPool::new(4096, 1000);
```

Adjust based on your traffic:
- **Low traffic** (< 100 req/s): `max_pool_size = 100`
- **Medium traffic** (100-1000 req/s): `max_pool_size = 1000` (default)
- **High traffic** (> 1000 req/s): `max_pool_size = 5000`

### System Tuning (Linux)

```bash
# Increase UDP buffer sizes
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400

# Increase connection tracking
sudo sysctl -w net.netfilter.nf_conntrack_max=1000000

# Increase file descriptors
ulimit -n 65536
```

## Monitoring

### Metrics to Track

1. **Request Rate**: Requests per second
2. **Latency**: p50, p95, p99 response times
3. **Memory Usage**: RSS, heap allocations
4. **Buffer Pool**: Pool size, hit rate
5. **Connection Pools**: Active connections, wait times
6. **Cache Hit Rate**: Request deduplication effectiveness

### Integration with Prometheus

```rust
// TODO: Prometheus metrics endpoint (future release)
```

## Performance Targets

Based on internal testing (Apple M1 Pro, 16GB RAM):

| Metric | Target | Notes |
|--------|--------|-------|
| Throughput | 5,000+ req/s | PAP authentication, simple handler |
| Latency (p50) | < 1 ms | Local network |
| Latency (p95) | < 5 ms | Local network |
| Latency (p99) | < 10 ms | Local network |
| Memory (idle) | < 50 MB | Minimal configuration |
| Memory (10K req/s) | < 200 MB | With buffer pool |

Real-world performance will vary based on:
- Authentication backend (PostgreSQL, LDAP latency)
- Network latency
- Hardware specifications
- Concurrent client count

## Troubleshooting

### High Memory Usage

1. **Check buffer pool size**: May need to reduce `max_pool_size`
2. **Monitor connection pools**: LDAP/PostgreSQL pool leaks
3. **Check request cache**: May need smaller `max_entries`

### Low Throughput

1. **Check authentication backend**: LDAP/PostgreSQL may be bottleneck
2. **Profile CPU usage**: Identify hot paths with flamegraph
3. **Check rate limits**: May be throttling legitimate traffic
4. **System limits**: UDP buffers, file descriptors

### High Latency

1. **Network latency**: Check RTT to authentication backends
2. **Connection pool exhaustion**: Increase pool sizes
3. **CPU saturation**: Scale horizontally or optimize hot paths
4. **Lock contention**: Profile with perf/instruments

## Further Reading

- [Tokio Performance Tuning](https://tokio.rs/tokio/topics/performance)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [RADIUS RFC 2865](https://tools.ietf.org/html/rfc2865)
