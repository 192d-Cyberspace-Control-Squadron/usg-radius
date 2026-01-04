# High Availability Deployment Guide

This guide covers deploying usg-radius in a High Availability (HA) configuration with multiple RADIUS servers sharing state through Valkey.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Valkey Setup](#valkey-setup)
4. [Server Configuration](#server-configuration)
5. [Health Checks & Monitoring](#health-checks--monitoring)
6. [Load Balancer Configuration](#load-balancer-configuration)
7. [Kubernetes Deployment](#kubernetes-deployment)
8. [Docker Compose Example](#docker-compose-example)
9. [Troubleshooting](#troubleshooting)

## Architecture Overview

```
                     ┌─────────────────┐
                     │  Load Balancer  │
                     │  (HAProxy/nginx)│
                     └────────┬────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
    ┌─────▼─────┐       ┌─────▼─────┐       ┌─────▼─────┐
    │  RADIUS   │       │  RADIUS   │       │  RADIUS   │
    │  Server 1 │       │  Server 2 │       │  Server 3 │
    │  :1812    │       │  :1812    │       │  :1812    │
    └─────┬─────┘       └─────┬─────┘       └─────┬─────┘
          │                   │                   │
          └───────────────────┼───────────────────┘
                              │
                     ┌────────▼────────┐
                     │     Valkey      │
                     │  (Shared State) │
                     └─────────────────┘
```

### Key Components

- **RADIUS Servers**: Multiple instances sharing state
- **Valkey**: Distributed state backend for sessions, cache, and rate limiting
- **Load Balancer**: Distributes requests across servers
- **Health Endpoints**: Kubernetes-compatible health checks
- **Metrics Endpoint**: Prometheus-compatible metrics

### Shared State

All servers share:
- **EAP Sessions**: Multi-round authentication state
- **Accounting Sessions**: Session tracking for billing
- **Request Cache**: Duplicate request detection (60s TTL)
- **Rate Limits**: Global and per-client rate limiting

## Prerequisites

- Valkey server (or Redis-compatible server)
- 3+ RADIUS server instances for production HA
- Load balancer (HAProxy, nginx, or hardware load balancer)
- Monitoring system (Prometheus + Grafana recommended)

## Valkey Setup

### Installation

```bash
# Using Docker
docker run -d \
  --name valkey \
  -p 6379:6379 \
  valkey/valkey:latest

# Using Docker with persistence
docker run -d \
  --name valkey \
  -p 6379:6379 \
  -v valkey-data:/data \
  valkey/valkey:latest --save 60 1 --loglevel warning
```

### Production Configuration

For production, use Valkey with:
- **Persistence**: AOF or RDB snapshots
- **Replication**: Master-replica setup
- **Sentinel**: Automatic failover
- **Security**: Password authentication, TLS

Example `valkey.conf`:
```
# Network
bind 0.0.0.0
protected-mode yes
port 6379

# Persistence
save 900 1
save 300 10
save 60 10000
appendonly yes
appendfsync everysec

# Security
requirepass your_strong_password_here

# Memory
maxmemory 2gb
maxmemory-policy allkeys-lru
```

### Valkey Sentinel Setup (Recommended)

```bash
# Start Valkey master
docker run -d --name valkey-master \
  -p 6379:6379 \
  valkey/valkey:latest

# Start Valkey replicas
docker run -d --name valkey-replica-1 \
  -p 6380:6379 \
  valkey/valkey:latest --replicaof valkey-master 6379

# Start Sentinel instances
docker run -d --name valkey-sentinel-1 \
  -p 26379:26379 \
  valkey/valkey:latest --sentinel
```

## Server Configuration

### Environment Variables

```bash
# RADIUS configuration
RADIUS_PORT=1812
RADIUS_SECRET=your_shared_secret

# Valkey configuration
VALKEY_URL=redis://localhost:6379
# With authentication:
# VALKEY_URL=redis://:password@localhost:6379
# With TLS:
# VALKEY_URL=rediss://localhost:6379

# Health/Metrics ports (automatic)
# HEALTH_PORT = RADIUS_PORT + 1000 (e.g., 2812)
# METRICS_PORT = RADIUS_PORT + 2000 (e.g., 3812)
```

### Starting Servers

```bash
# Server 1
RADIUS_PORT=1812 \
VALKEY_URL=redis://valkey:6379 \
cargo run --example ha_cluster_server --features ha

# Server 2 (different host or port)
RADIUS_PORT=1813 \
VALKEY_URL=redis://valkey:6379 \
cargo run --example ha_cluster_server --features ha

# Server 3
RADIUS_PORT=1814 \
VALKEY_URL=redis://valkey:6379 \
cargo run --example ha_cluster_server --features ha
```

### Configuration File

Create `config.toml`:
```toml
[server]
address = "0.0.0.0:1812"
secret = "testing123"

[ha]
enabled = true
valkey_url = "redis://valkey:6379"
key_prefix = "usg-radius:"
max_retries = 3
retry_delay_ms = 100

[rate_limiting]
per_client_limit = 100  # requests per second per client
global_limit = 1000     # requests per second globally
window_duration_secs = 1

[request_cache]
ttl_secs = 60  # duplicate detection window
```

## Health Checks & Monitoring

### Health Check Endpoints

Each server exposes three health check endpoints:

```bash
# Overall health (JSON response)
curl http://server:2812/health
# Response: {"status":"healthy","backend":{"backend_type":"valkey","status":"up"},"cache":{"entries":42}}

# Readiness probe (Kubernetes)
curl http://server:2812/health/ready
# Returns 200 if backend is accessible, 503 otherwise

# Liveness probe (Kubernetes)
curl http://server:2812/health/live
# Returns 200 if server is running
```

### Metrics Endpoint

Prometheus-compatible metrics:

```bash
curl http://server:3812/metrics
```

Available metrics:
- `radius_backend_up` - Backend connectivity (1=up, 0=down)
- `radius_cache_entries` - Local cache size
- `radius_ratelimit_per_client_limit` - Per-client rate limit
- `radius_ratelimit_global_limit` - Global rate limit
- `radius_ratelimit_window_duration_seconds` - Rate limit window
- `radius_ratelimit_current_global_count` - Current request count
- `radius_uptime_seconds` - Server uptime

### Prometheus Configuration

`prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'radius-servers'
    static_configs:
      - targets:
        - 'radius-1:3812'
        - 'radius-2:3812'
        - 'radius-3:3812'
    scrape_interval: 15s
```

## Load Balancer Configuration

### HAProxy

`haproxy.cfg`:
```
global
    log stdout local0
    maxconn 4096

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend radius_auth
    bind *:1812
    mode udp
    default_backend radius_servers

backend radius_servers
    mode udp
    balance roundrobin
    option tcp-check
    server radius1 radius-server-1:1812 check inter 10s rise 2 fall 3
    server radius2 radius-server-2:1812 check inter 10s rise 2 fall 3
    server radius3 radius-server-3:1812 check inter 10s rise 2 fall 3

# Health check endpoint
frontend radius_health
    bind *:8080
    mode http
    default_backend radius_health_servers

backend radius_health_servers
    mode http
    balance roundrobin
    option httpchk GET /health/ready
    server radius1 radius-server-1:2812 check
    server radius2 radius-server-2:2812 check
    server radius3 radius-server-3:2812 check
```

### nginx (Stream Module)

`nginx.conf`:
```nginx
stream {
    upstream radius_servers {
        hash $remote_addr consistent;
        server radius-server-1:1812 max_fails=3 fail_timeout=30s;
        server radius-server-2:1812 max_fails=3 fail_timeout=30s;
        server radius-server-3:1812 max_fails=3 fail_timeout=30s;
    }

    server {
        listen 1812 udp;
        proxy_pass radius_servers;
        proxy_timeout 10s;
        proxy_responses 1;
    }
}

http {
    upstream radius_health {
        server radius-server-1:2812;
        server radius-server-2:2812;
        server radius-server-3:2812;
    }

    server {
        listen 8080;

        location /health {
            proxy_pass http://radius_health;
        }
    }
}
```

## Kubernetes Deployment

See [Kubernetes Deployment Example](./kubernetes/README.md) for full manifests.

### Quick Start

```bash
# Apply all manifests
kubectl apply -f k8s/

# Check status
kubectl get pods -n radius
kubectl get svc -n radius

# View logs
kubectl logs -f deployment/radius-server -n radius
```

### Key Features

- **StatefulSet**: Stable network identities for servers
- **Service**: Load balancing across pods
- **ConfigMap**: Centralized configuration
- **Secret**: Valkey credentials
- **Health Probes**: Automatic restart on failure
- **HPA**: Horizontal Pod Autoscaler support
- **NetworkPolicy**: Security isolation

## Docker Compose Example

See [docker-compose.yml](./docker-compose.yml) for full example.

```bash
# Start cluster
docker-compose up -d

# Scale servers
docker-compose up -d --scale radius-server=5

# View logs
docker-compose logs -f radius-server

# Stop cluster
docker-compose down
```

## Troubleshooting

### Backend Connection Issues

**Symptom**: Health checks failing, 503 errors

**Check**:
```bash
# Test Valkey connectivity
redis-cli -h valkey -p 6379 PING

# Check logs
docker logs radius-server-1 | grep -i valkey

# Verify backend status
curl http://server:2812/health | jq .backend
```

**Fix**:
- Verify `VALKEY_URL` is correct
- Check Valkey is running and accessible
- Verify network connectivity
- Check firewall rules

### Rate Limiting Issues

**Symptom**: Requests being blocked unexpectedly

**Check**:
```bash
# View current rate limit counts
curl http://server:3812/metrics | grep ratelimit

# Check configuration
echo $RATE_LIMIT_CONFIG
```

**Fix**:
- Increase `per_client_limit` or `global_limit`
- Adjust `window_duration`
- Check if limits are being shared correctly across cluster

### Session State Not Shared

**Symptom**: EAP authentication fails when switching servers

**Check**:
```bash
# Verify Valkey has session data
redis-cli -h valkey KEYS "usg-radius:eap_session:*"

# Check session manager stats
curl http://server:2812/health | jq .cache
```

**Fix**:
- Verify all servers using same `VALKEY_URL`
- Check `key_prefix` matches across servers
- Verify Valkey persistence is enabled

### Performance Issues

**Symptom**: High latency, timeouts

**Check**:
```bash
# Check Valkey performance
redis-cli --latency -h valkey

# Monitor metrics
curl http://server:3812/metrics | grep cache_entries

# Check backend stats
redis-cli -h valkey INFO stats
```

**Fix**:
- Increase Valkey memory: `maxmemory` setting
- Enable Valkey clustering for horizontal scaling
- Adjust local cache TTL: longer TTL = fewer backend queries
- Add more RADIUS server instances

### Cache Inconsistency

**Symptom**: Stale data being served

**Check**:
```bash
# Check cache TTL settings
grep cache_ttl config.toml

# Monitor cache size
watch -n 1 'curl -s http://server:3812/metrics | grep cache_entries'
```

**Fix**:
- Decrease local cache TTL (default: 30s)
- Ensure Valkey TTLs are appropriate
- Force cache clear: restart servers

## Best Practices

1. **Minimum 3 Servers**: Provides redundancy during maintenance
2. **Monitor Everything**: Use Prometheus + Grafana dashboards
3. **Set Alerts**: Backend down, high error rate, high latency
4. **Use Valkey Sentinel**: Automatic failover for Valkey
5. **Enable Persistence**: AOF + RDB for Valkey
6. **Test Failover**: Regularly test server and backend failures
7. **Capacity Planning**: Monitor request rates and scale accordingly
8. **Security**: Use TLS for Valkey connections in production
9. **Backup Strategy**: Regular Valkey snapshots
10. **Documentation**: Keep runbooks for common issues

## Production Checklist

- [ ] Valkey running with persistence enabled
- [ ] Valkey Sentinel configured for failover
- [ ] 3+ RADIUS server instances deployed
- [ ] Load balancer configured with health checks
- [ ] Prometheus scraping all servers
- [ ] Grafana dashboards created
- [ ] Alerts configured (backend down, high latency)
- [ ] TLS enabled for Valkey connections
- [ ] Firewall rules configured
- [ ] Backup/restore tested
- [ ] Failover scenarios tested
- [ ] Documentation updated
- [ ] Monitoring playbooks created

## Additional Resources

- [Valkey Documentation](https://valkey.io/docs/)
- [HAProxy UDP Load Balancing](https://www.haproxy.com/documentation/)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/cluster-administration/manage-deployment/)
- [Prometheus Monitoring](https://prometheus.io/docs/introduction/overview/)
