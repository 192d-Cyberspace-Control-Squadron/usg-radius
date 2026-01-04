# Quick Start Guide

This guide will get you running a production-ready RADIUS server in under 15 minutes.

## Table of Contents

1. [Single Server Setup](#single-server-setup) (5 minutes)
2. [High Availability Cluster](#high-availability-cluster) (10 minutes)
3. [Authentication Backends](#authentication-backends)
4. [Testing Your Setup](#testing-your-setup)
5. [Next Steps](#next-steps)

---

## Prerequisites

- **Rust 1.75+** (install from [rustup.rs](https://rustup.rs))
- **Linux, macOS, or Windows** (WSL2 recommended for Windows)
- **Optional**: Docker & Docker Compose for HA deployment

---

## Single Server Setup

Perfect for testing, development, or small deployments (<1000 users).

### 1. Clone and Build

```bash
git clone https://github.com/192d-Cyberspace-Control-Squadron/usg-radius.git
cd usg-radius
cargo build --release --features tls
```

### 2. Create Configuration

Create `config.json`:

```json
{
  "bind_address": "0.0.0.0:1812",
  "clients": [
    {
      "name": "test-nas",
      "address": "127.0.0.1",
      "secret": "testing123",
      "enabled": true
    }
  ],
  "auth_handler": {
    "type": "simple",
    "users": {
      "alice": "password123",
      "bob": "securepass"
    }
  },
  "rate_limiting": {
    "per_client_limit": 100,
    "per_client_burst": 200,
    "global_limit": 1000,
    "global_burst": 2000
  }
}
```

### 3. Run the Server

```bash
./target/release/usg-radius-workspace config.json
```

### 4. Test Authentication

```bash
# Using radtest (from freeradius-utils)
radtest alice password123 127.0.0.1:1812 0 testing123

# Expected output:
# Sent Access-Request Id 123 from 0.0.0.0:xxxxx to 127.0.0.1:1812 length 73
# Received Access-Accept Id 123 from 127.0.0.1:1812 to 0.0.0.0:xxxxx length 20
```

✅ **Done!** You now have a working RADIUS server.

---

## High Availability Cluster

Production-grade 3-node cluster with shared state and automatic failover.

### Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  RADIUS-1   │     │  RADIUS-2   │     │  RADIUS-3   │
│  :1812      │     │  :1812      │     │  :1812      │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┴───────────────────┘
                           │
                    ┌──────┴──────┐
                    │   Valkey    │
                    │  (State DB) │
                    └─────────────┘
```

### Quick Deploy with Docker Compose

1. **Create `docker-compose-ha.yml`**:

```yaml
version: '3.8'

services:
  valkey:
    image: valkey/valkey:latest
    ports:
      - "6379:6379"
    volumes:
      - valkey-data:/data
    command: valkey-server --save 60 1000 --appendonly yes

  radius-1:
    build: .
    environment:
      - RADIUS_PORT=1812
      - VALKEY_URL=redis://valkey:6379
      - RADIUS_SECRET=testing123
    ports:
      - "1812:1812/udp"
      - "2812:2812"  # Health checks
      - "3812:3812"  # Metrics
    depends_on:
      - valkey

  radius-2:
    build: .
    environment:
      - RADIUS_PORT=1812
      - VALKEY_URL=redis://valkey:6379
      - RADIUS_SECRET=testing123
    ports:
      - "1813:1812/udp"
      - "2813:2812"
      - "3813:3812"
    depends_on:
      - valkey

  radius-3:
    build: .
    environment:
      - RADIUS_PORT=1812
      - VALKEY_URL=redis://valkey:6379
      - RADIUS_SECRET=testing123
    ports:
      - "1814:1812/udp"
      - "2814:2812"
      - "3814:3812"
    depends_on:
      - valkey

  haproxy:
    image: haproxy:latest
    ports:
      - "1812:1812/udp"
    volumes:
      - ./examples/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    depends_on:
      - radius-1
      - radius-2
      - radius-3

volumes:
  valkey-data:
```

2. **Start the Cluster**:

```bash
docker-compose -f docker-compose-ha.yml up -d
```

3. **Verify Health**:

```bash
# Check all servers are healthy
curl http://localhost:2812/health
curl http://localhost:2813/health
curl http://localhost:2814/health

# Check metrics
curl http://localhost:3812/metrics
```

4. **Test Load Balancing**:

```bash
# Send 1000 requests through HAProxy
for i in {1..1000}; do
  radtest alice password123 127.0.0.1:1812 0 testing123
done
```

✅ **Production-ready HA cluster running!**

---

## Authentication Backends

### PostgreSQL

Best for: Large user bases, integration with existing systems

```json
{
  "auth_handler": {
    "type": "postgresql",
    "connection_string": "postgresql://radius:password@localhost/radiusdb",
    "users_query": "SELECT password, attributes FROM radius_users WHERE username = $1 AND enabled = true",
    "password_column": "password",
    "password_type": "bcrypt"
  }
}
```

**Schema**:

```sql
CREATE TABLE radius_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    attributes JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Example user with bcrypt
INSERT INTO radius_users (username, password)
VALUES ('alice', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeGGH6i.0VSO.aJIm');
```

### LDAP/Active Directory

Best for: Enterprise environments, Windows integration

```json
{
  "auth_handler": {
    "type": "ldap",
    "urls": ["ldaps://dc1.example.com:636", "ldaps://dc2.example.com:636"],
    "base_dn": "DC=example,DC=com",
    "bind_dn": "CN=radius,CN=Users,DC=example,DC=com",
    "bind_password": "service_account_password",
    "search_filter": "(&(objectClass=user)(sAMAccountName={username}))",
    "group_attribute": "memberOf",
    "group_mappings": {
      "CN=VPN Users,OU=Groups,DC=example,DC=com": {
        "Framed-IP-Netmask": "255.255.255.0",
        "Service-Type": "Framed-User"
      }
    },
    "max_connections": 10
  }
}
```

### EAP-TLS (Certificate-Based)

Best for: Highest security, 802.1X, Wi-Fi authentication

```json
{
  "auth_handler": {
    "type": "eap",
    "eap_methods": ["TLS"],
    "tls_config": {
      "ca_cert_path": "/etc/radius/certs/ca.pem",
      "server_cert_path": "/etc/radius/certs/server.pem",
      "server_key_path": "/etc/radius/certs/server-key.pem",
      "client_cert_required": true,
      "crl_check_enabled": true,
      "crl_path": "/etc/radius/certs/crl.pem"
    }
  }
}
```

**Generate Test Certificates**:

```bash
# CA certificate
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=RADIUS CA"

# Server certificate
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=radius.example.com"
openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out server.pem
```

---

## Testing Your Setup

### 1. Basic Connectivity Test

```bash
# Status-Server (RFC 5997)
radtest -t status-server test test 127.0.0.1:1812 0 testing123
```

### 2. Load Testing

```bash
# Run built-in load tester
cargo run --release --bin radius_load_test -- \
  --server 127.0.0.1:1812 \
  --secret testing123 \
  --clients 10 \
  --duration 60 \
  --rps 100
```

### 3. Monitor Performance

```bash
# Prometheus metrics
curl http://localhost:3812/metrics | grep radius_

# Example output:
# radius_requests_total{type="access"} 10250
# radius_request_duration_seconds_sum 0.523
# radius_cache_hit_rate 0.95
# radius_backend_up 1
```

### 4. Health Checks

```bash
# Liveness probe (is the server running?)
curl http://localhost:2812/health/live

# Readiness probe (can it accept traffic?)
curl http://localhost:2812/health/ready

# Example output:
# {"status":"healthy","backend":"connected","cache_entries":42}
```

---

## Next Steps

### Security Hardening

1. **Change default secrets**:
   ```bash
   # Generate strong secret
   openssl rand -base64 32
   ```

2. **Enable TLS for management**:
   - Require HTTPS for health/metrics endpoints
   - Use client certificates for authentication

3. **Restrict client access**:
   ```json
   {
     "clients": [
       {
         "name": "wifi-controller",
         "address": "10.0.1.0/24",
         "secret": "use-a-strong-secret-here",
         "enabled": true
       }
     ]
   }
   ```

### Monitoring & Observability

1. **Prometheus + Grafana**:
   ```bash
   # Add to docker-compose.yml
   prometheus:
     image: prom/prometheus
     volumes:
       - ./examples/prometheus.yml:/etc/prometheus/prometheus.yml
     ports:
       - "9090:9090"

   grafana:
     image: grafana/grafana
     ports:
       - "3000:3000"
   ```

2. **Structured Logging**:
   ```bash
   # JSON logs for log aggregation
   export RUST_LOG=radius_server=info
   export RUST_LOG_FORMAT=json
   ```

### High Availability Improvements

1. **Kubernetes Deployment**:
   ```bash
   kubectl apply -f examples/kubernetes/
   ```

2. **Geographic Distribution**:
   - Deploy clusters in multiple regions
   - Use GeoDNS for routing
   - Replicate Valkey across regions

### Performance Tuning

1. **Increase file limits**:
   ```bash
   # /etc/security/limits.conf
   radius soft nofile 65536
   radius hard nofile 65536
   ```

2. **Optimize cache TTL**:
   ```json
   {
     "state_backend": {
       "type": "valkey",
       "url": "redis://valkey:6379",
       "cache_ttl_secs": 30,  // Tune based on your workload
       "max_retries": 3
     }
   }
   ```

3. **Connection pooling**:
   ```json
   {
     "ldap": {
       "max_connections": 20,  // Increase for high load
       "acquire_timeout_secs": 10
     }
   }
   ```

---

## Common Issues

### Port 1812 already in use

```bash
# Check what's using the port
sudo lsof -i :1812

# Stop FreeRADIUS if running
sudo systemctl stop freeradius
```

### Cannot connect to Valkey

```bash
# Test Valkey connectivity
redis-cli -h valkey ping
# Should return: PONG

# Check Valkey logs
docker logs radius-valkey-1
```

### High latency

```bash
# Check backend health
curl http://localhost:2812/health

# Profile with load test
cargo run --release --bin radius_load_test -- \
  --server 127.0.0.1:1812 \
  --secret testing123 \
  --clients 1 \
  --duration 10 \
  --rps 10 \
  --verbose
```

---

## Getting Help

- **Documentation**: `/docs`
- **Examples**: `/examples`
- **GitHub Issues**: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/issues
- **RFC Compliance**: See `docs/RFC-COMPLIANCE.md`

---

## Migration from FreeRADIUS

See [FREERADIUS_MIGRATION.md](./FREERADIUS_MIGRATION.md) for a detailed migration guide.

Quick comparison:

| Feature | FreeRADIUS | USG RADIUS |
|---------|-----------|------------|
| Language | C | Rust |
| Memory Safety | Manual | Guaranteed |
| Config Format | Custom DSL | JSON |
| HA Built-in | No (requires external) | Yes (Valkey) |
| EAP Methods | 10+ | EAP-MD5, EAP-TLS, EAP-TEAP |
| Performance | ~10k rps | ~50k+ rps (benchmarked) |
| Container-Native | No | Yes |

---

**🎉 Congratulations! You're now running a production-grade RADIUS server.**

For advanced configurations, see the full documentation in `/docs`.
