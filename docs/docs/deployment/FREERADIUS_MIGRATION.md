# Migrating from FreeRADIUS to USG RADIUS

This guide helps you migrate from FreeRADIUS 3.x to USG RADIUS with minimal downtime.

## Table of Contents

1. [Why Migrate?](#why-migrate)
2. [Feature Comparison](#feature-comparison)
3. [Migration Strategy](#migration-strategy)
4. [Configuration Mapping](#configuration-mapping)
5. [User Database Migration](#user-database-migration)
6. [Testing & Validation](#testing--validation)
7. [Deployment Strategies](#deployment-strategies)
8. [Troubleshooting](#troubleshooting)

---

## Why Migrate?

### USG RADIUS Advantages

| Benefit | Description |
|---------|-------------|
| **Memory Safety** | Rust guarantees eliminate buffer overflows, use-after-free, and data races |
| **Performance** | 5-10x faster throughput (50k+ RPS vs FreeRADIUS ~10k RPS) |
| **Built-in HA** | Native Valkey/Redis support for multi-server clusters |
| **Container-Native** | Docker/Kubernetes-ready with health checks and metrics |
| **Modern Config** | JSON configuration instead of custom DSL |
| **Type Safety** | Compile-time checking prevents configuration errors |
| **Observability** | Prometheus metrics and structured JSON logging built-in |

### When to Stay with FreeRADIUS

- You need **EAP-TTLS** or **PEAP** (not yet supported)
- You heavily customize with **unlang** scripts
- You use exotic VSAs not yet implemented
- You need **RadSec** (RADIUS over TLS) - coming in v0.8.0

---

## Feature Comparison

### Protocol Support

| Feature | FreeRADIUS 3.x | USG RADIUS v0.6.0 |
|---------|----------------|-------------------|
| **Authentication** |
| PAP | ✅ | ✅ |
| CHAP | ✅ | ✅ |
| MS-CHAP v2 | ✅ | ⚠️ Via EAP-MSCHAPv2 |
| EAP-MD5 | ✅ | ✅ |
| EAP-TLS | ✅ | ✅ (TLS 1.2/1.3) |
| EAP-TTLS | ✅ | ❌ (planned v0.9.0) |
| PEAP | ✅ | ❌ (use EAP-TEAP) |
| EAP-TEAP | ❌ | ✅ (RFC 7170) |
| **Accounting** |
| Start/Stop/Interim | ✅ | ✅ |
| File logging | ✅ | ✅ |
| SQL accounting | ✅ | ✅ (PostgreSQL) |
| **Backends** |
| Files | ✅ | ✅ (JSON config) |
| LDAP | ✅ | ✅ (LDAPS, failover) |
| SQL | ✅ | ✅ (PostgreSQL) |
| PAM | ✅ | ❌ |
| **Proxy** |
| Realm routing | ✅ | ✅ |
| Load balancing | ✅ | ✅ (4 algorithms) |
| Failover | ✅ | ✅ (automatic) |
| **High Availability** |
| Multiple servers | ⚠️ Manual | ✅ Built-in |
| Shared state | ❌ | ✅ Valkey/Redis |
| Session failover | ❌ | ✅ |

### Configuration Format

#### FreeRADIUS (`radiusd.conf`)

```conf
# FreeRADIUS uses custom DSL
clients.conf:
client 192.168.1.1 {
    secret = testing123
    shortname = wifi-controller
    nas_type = other
}

users:
alice Cleartext-Password := "password123"
    Reply-Message = "Welcome Alice",
    Framed-IP-Netmask = 255.255.255.0
```

#### USG RADIUS (`config.json`)

```json
{
  "clients": [
    {
      "name": "wifi-controller",
      "address": "192.168.1.1",
      "secret": "testing123",
      "enabled": true
    }
  ],
  "auth_handler": {
    "type": "simple",
    "users": {
      "alice": "password123"
    }
  }
}
```

**Benefits**: JSON is validated at compile-time, easier to programmatically generate, and familiar to DevOps teams.

---

## Migration Strategy

### Recommended Approach: Blue-Green Deployment

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: Parallel Run (1 week)                              │
│                                                              │
│  ┌─────────────┐       ┌─────────────┐                     │
│  │ FreeRADIUS  │  50%  │ USG RADIUS  │  50%                │
│  │ (existing)  │◄──────┤ (new)       │                     │
│  └─────────────┘       └─────────────┘                     │
│         │                      │                             │
│         └──────────┬───────────┘                             │
│                    │                                          │
│            ┌───────▼────────┐                                │
│            │  Load Balancer  │                                │
│            └────────────────┘                                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Phase 2: Gradual Shift (2 weeks)                            │
│                                                              │
│  ┌─────────────┐       ┌─────────────┐                     │
│  │ FreeRADIUS  │  10%  │ USG RADIUS  │  90%                │
│  │ (legacy)    │◄──────┤ (primary)   │                     │
│  └─────────────┘       └─────────────┘                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Phase 3: Complete Migration                                 │
│                                                              │
│                    ┌─────────────┐                          │
│                    │ USG RADIUS  │  100%                    │
│                    │ (HA Cluster)│                          │
│                    └─────────────┘                          │
│  (FreeRADIUS decommissioned)                                │
└─────────────────────────────────────────────────────────────┘
```

### Timeline

| Week | Activity | Validation |
|------|----------|------------|
| **Week 0** | Assessment | Inventory current config, identify dependencies |
| **Week 1** | Test environment | Deploy USG RADIUS in staging, run tests |
| **Week 2** | Parallel production | 50/50 split, monitor metrics |
| **Week 3** | Gradual shift | 90/10 split, validate edge cases |
| **Week 4** | Complete migration | 100% USG RADIUS, decommission FreeRADIUS |
| **Week 5+** | Monitoring | Optimize performance, fine-tune |

---

## Configuration Mapping

### 1. Client Configuration

**FreeRADIUS** (`clients.conf`):
```conf
client wifi_controller {
    ipaddr = 192.168.1.0/24
    secret = super-secret-key
    shortname = wifi
    nas_type = cisco
}
```

**USG RADIUS** (`config.json`):
```json
{
  "clients": [
    {
      "name": "wifi",
      "address": "192.168.1.0/24",
      "secret": "super-secret-key",
      "enabled": true
    }
  ]
}
```

### 2. User Authentication

**FreeRADIUS** (`users` file):
```conf
alice Cleartext-Password := "password123"
    Reply-Message = "Welcome",
    Framed-IP-Address = 10.0.1.100,
    Framed-IP-Netmask = 255.255.255.0,
    Service-Type = Framed-User

DEFAULT Auth-Type := Reject
    Reply-Message = "Access denied"
```

**USG RADIUS** (Simple):
```json
{
  "auth_handler": {
    "type": "simple",
    "users": {
      "alice": "password123"
    }
  }
}
```

**USG RADIUS** (PostgreSQL with attributes):
```json
{
  "auth_handler": {
    "type": "postgresql",
    "connection_string": "postgresql://radius:pass@localhost/radiusdb",
    "users_query": "SELECT password, attributes FROM radius_users WHERE username = $1",
    "password_column": "password",
    "password_type": "bcrypt",
    "attributes_column": "attributes"
  }
}
```

### 3. LDAP Configuration

**FreeRADIUS** (`mods-available/ldap`):
```conf
ldap {
    server = 'ldap.example.com'
    port = 389
    identity = 'cn=admin,dc=example,dc=com'
    password = admin_pass
    base_dn = 'ou=users,dc=example,dc=com'
    filter = "(uid=%{%{Stripped-User-Name}:-%{User-Name}})"

    update {
        control:Password-With-Header    += 'userPassword'
        reply:Reply-Message := 'radiusReplyMessage'
    }
}
```

**USG RADIUS**:
```json
{
  "auth_handler": {
    "type": "ldap",
    "urls": [
      "ldaps://ldap1.example.com:636",
      "ldaps://ldap2.example.com:636"
    ],
    "base_dn": "ou=users,dc=example,dc=com",
    "bind_dn": "cn=admin,dc=example,dc=com",
    "bind_password": "admin_pass",
    "search_filter": "(uid={username})",
    "group_attribute": "memberOf",
    "group_mappings": {
      "cn=vpn_users,ou=groups,dc=example,dc=com": {
        "Reply-Message": "Welcome VPN user",
        "Framed-IP-Netmask": "255.255.255.0"
      }
    },
    "max_connections": 10,
    "acquire_timeout_secs": 10
  }
}
```

**Key Improvements**:
- Native LDAPS support (no separate TLS config)
- Automatic failover between multiple URLs
- Connection pooling built-in
- Group-based attribute mapping

### 4. EAP Configuration

**FreeRADIUS** (`mods-available/eap`):
```conf
eap {
    default_eap_type = tls
    timer_expire = 60
    ignore_unknown_eap_types = no

    tls-config tls-common {
        private_key_password = whatever
        private_key_file = /etc/raddb/certs/server.pem
        certificate_file = /etc/raddb/certs/server.pem
        CA_file = /etc/raddb/certs/ca.pem
        dh_file = /etc/raddb/certs/dh
        fragment_size = 1024
        check_crl = yes
    }

    tls {
        tls = tls-common
    }
}
```

**USG RADIUS**:
```json
{
  "auth_handler": {
    "type": "eap",
    "eap_methods": ["TLS", "TEAP"],
    "session_timeout_secs": 60,
    "tls_config": {
      "ca_cert_path": "/etc/radius/certs/ca.pem",
      "server_cert_path": "/etc/radius/certs/server.pem",
      "server_key_path": "/etc/radius/certs/server-key.pem",
      "client_cert_required": true,
      "crl_check_enabled": true,
      "crl_path": "/etc/radius/certs/crl.pem",
      "fragment_size": 1020
    }
  }
}
```

**Key Differences**:
- TLS 1.2/1.3 only (TLS 1.0/1.1 deprecated)
- No DH file needed (modern cipher suites)
- EAP-TEAP replaces EAP-TTLS/PEAP

### 5. Accounting

**FreeRADIUS** (`radiusd.conf`):
```conf
accounting {
    detail
    sql

    # Custom file logging
    unix  # /var/log/radacct/%{Client-IP-Address}/detail-%Y%m%d
}
```

**USG RADIUS**:
```json
{
  "accounting_handler": {
    "type": "postgresql",
    "connection_string": "postgresql://radius:pass@localhost/radiusdb",
    "table": "radacct",
    "start_query": "INSERT INTO radacct (...) VALUES (...)",
    "stop_query": "UPDATE radacct SET ... WHERE acct_session_id = $1",
    "interim_query": "UPDATE radacct SET ... WHERE acct_session_id = $1"
  }
}
```

Alternatively, file-based:
```json
{
  "accounting_handler": {
    "type": "file",
    "directory": "/var/log/radius/acct",
    "rotation": {
      "max_size_mb": 100,
      "max_age_days": 30
    }
  }
}
```

### 6. Proxy Configuration

**FreeRADIUS** (`proxy.conf`):
```conf
home_server home1 {
    type = auth
    ipaddr = 10.0.1.50
    port = 1812
    secret = proxy_secret
    response_window = 20
    zombie_period = 40
    status_check = status-server
}

home_server_pool failover_pool {
    type = fail-over
    home_server = home1
    home_server = home2
}

realm example.com {
    auth_pool = failover_pool
    nostrip
}
```

**USG RADIUS**:
```json
{
  "proxy": {
    "enabled": true,
    "home_servers": [
      {
        "name": "home1",
        "address": "10.0.1.50:1812",
        "secret": "proxy_secret",
        "timeout_secs": 3,
        "max_outstanding": 65536
      },
      {
        "name": "home2",
        "address": "10.0.1.51:1812",
        "secret": "proxy_secret"
      }
    ],
    "pools": [
      {
        "name": "failover_pool",
        "servers": ["home1", "home2"],
        "load_balance_strategy": "failover"
      }
    ],
    "realms": [
      {
        "name": "example.com",
        "pool": "failover_pool",
        "type": "suffix",
        "strip_realm": false
      }
    ],
    "health_check": {
      "enabled": true,
      "interval_secs": 30,
      "failure_threshold": 3,
      "recovery_threshold": 2
    }
  }
}
```

**Load balance strategies**:
- `round_robin` - Distribute evenly
- `random` - Random selection
- `failover` - Primary + backup
- `least_outstanding` - Least busy server

---

## User Database Migration

### From Files to PostgreSQL

1. **Export FreeRADIUS users**:

```bash
# Parse users file to SQL
cat /etc/raddb/users | grep -v '^#' | grep Cleartext-Password | \
  awk '{print "INSERT INTO radius_users (username, password) VALUES (" \
       "'"'"'" $1 "'"'"', '"'"'" $4 "'"'"');"}' > users.sql
```

2. **Hash passwords**:

```python
import bcrypt

with open('users.sql', 'r') as f:
    for line in f:
        # Extract plaintext password
        password = extract_password(line)
        # Hash with bcrypt
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        # Update SQL with hashed version
```

3. **Import to PostgreSQL**:

```bash
psql -U radius -d radiusdb < users_hashed.sql
```

### From LDAP to LDAP (Config Migration)

No user migration needed - just update configuration as shown above.

### Maintaining Both Systems

During transition:

```bash
# Sync changes to both systems
cat > sync_users.sh <<'EOF'
#!/bin/bash
# When user added to FreeRADIUS, also add to USG RADIUS DB
USER=$1
PASS=$2
HASHED=$(python3 -c "import bcrypt; print(bcrypt.hashpw('$PASS'.encode(), bcrypt.gensalt()).decode())")
psql -U radius -d radiusdb -c "INSERT INTO radius_users (username, password) VALUES ('$USER', '$HASHED');"
EOF
```

---

## Testing & Validation

### 1. Unit Testing with radtest

```bash
# Test against both servers
radtest alice password123 freeradius.example.com:1812 0 testing123
radtest alice password123 usg-radius.example.com:1812 0 testing123

# Compare responses - should be identical
```

### 2. Load Testing

```bash
# FreeRADIUS baseline
radperf -f users.txt -s freeradius.example.com:1812 -c 100 -n 10000

# USG RADIUS comparison
cargo run --release --bin radius_load_test -- \
  --server usg-radius.example.com:1812 \
  --secret testing123 \
  --clients 100 \
  --duration 60 \
  --rps 100
```

### 3. Functional Testing

Create test scenarios:

```bash
cat > test_scenarios.sh <<'EOF'
#!/bin/bash
# Test 1: Valid credentials
radtest alice password123 $SERVER 0 $SECRET
# Expected: Access-Accept

# Test 2: Invalid password
radtest alice wrongpass $SERVER 0 $SECRET
# Expected: Access-Reject

# Test 3: Unknown user
radtest nobody nopass $SERVER 0 $SECRET
# Expected: Access-Reject

# Test 4: CHAP authentication
echo "User-Name=alice,CHAP-Password=password123" | radclient $SERVER auth $SECRET
# Expected: Access-Accept

# Test 5: Accounting
echo "User-Name=alice,Acct-Status-Type=Start" | radclient $SERVER acct $SECRET
# Expected: Accounting-Response
EOF
```

### 4. Monitoring Comparison

| Metric | FreeRADIUS | USG RADIUS |
|--------|-----------|------------|
| Latency P99 | `radmin -e "stats client 192.168.1.1 auth"` | `curl localhost:3812/metrics \| grep p99` |
| Requests/sec | Parse detail files | `radius_requests_total` counter |
| Memory usage | `ps aux \| grep radiusd` | `curl localhost:2812/health` |
| Cache hit rate | N/A | `radius_cache_hit_rate` gauge |

---

## Deployment Strategies

### Strategy 1: Phased Rollout

```bash
# Week 1: Deploy USG RADIUS alongside FreeRADIUS
docker-compose up -d usg-radius

# Configure HAProxy to split traffic
# haproxy.cfg:
backend radius_servers
    mode udp
    balance roundrobin
    server freeradius 10.0.1.10:1812 weight 50
    server usg-radius 10.0.1.20:1812 weight 50

# Week 2: Shift to 90/10
    server freeradius 10.0.1.10:1812 weight 10
    server usg-radius 10.0.1.20:1812 weight 90

# Week 3: Complete migration
    server usg-radius-1 10.0.1.20:1812
    server usg-radius-2 10.0.1.21:1812
    server usg-radius-3 10.0.1.22:1812
```

### Strategy 2: Shadow Mode

```bash
# Configure FreeRADIUS to log all requests
# Then replay against USG RADIUS for validation

# Capture traffic
tcpdump -i eth0 -w radius_traffic.pcap udp port 1812

# Replay against USG RADIUS
tcpreplay --intf=eth1 --multiplier=1.0 radius_traffic.pcap

# Compare logs
diff freeradius.log usg-radius.log
```

### Strategy 3: Canary Deployment

```bash
# Route 1% of traffic to USG RADIUS
# Kubernetes Ingress with weighted routing
apiVersion: v1
kind: Service
metadata:
  name: radius
spec:
  selector:
    app: radius
  ports:
  - port: 1812
    targetPort: 1812
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/canary: "true"
    nginx.ingress.kubernetes.io/canary-weight: "1"
spec:
  rules:
  - host: radius.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: usg-radius
            port:
              number: 1812
```

---

## Troubleshooting

### Issue: Performance Degradation

**Symptom**: USG RADIUS slower than FreeRADIUS

**Diagnosis**:
```bash
# Check metrics
curl localhost:3812/metrics | grep duration

# Profile with load test
cargo run --bin radius_load_test -- --verbose

# Check backend connectivity
curl localhost:2812/health
```

**Solutions**:
1. Increase cache TTL
2. Tune connection pools (LDAP/PostgreSQL)
3. Enable HA mode with Valkey for distributed caching
4. Check network latency to backends

### Issue: Authentication Failures

**Symptom**: Users authenticated by FreeRADIUS fail with USG RADIUS

**Diagnosis**:
```bash
# Enable debug logging
export RUST_LOG=radius_server=debug

# Compare request/response
# FreeRADIUS:
radiusd -X

# USG RADIUS:
./usg-radius config.json
```

**Common Causes**:
1. **Password hashing mismatch**: FreeRADIUS uses plaintext, USG expects bcrypt
   - Solution: Hash passwords during migration
2. **Attribute differences**: Check returned attributes match
   - Solution: Configure accept_attributes in auth_handler
3. **CHAP implementation**: Verify challenge generation
   - Solution: Ensure authenticator is properly randomized

### Issue: LDAP Bind Failures

**Symptom**: LDAP authentication works in FreeRADIUS but not USG RADIUS

**Diagnosis**:
```bash
# Test LDAP connectivity
ldapsearch -H ldaps://ldap.example.com:636 \
  -D "cn=admin,dc=example,dc=com" \
  -w password \
  -b "ou=users,dc=example,dc=com" \
  "(uid=alice)"
```

**Solutions**:
1. Verify TLS certificates for LDAPS
2. Check bind DN and password
3. Confirm search filter syntax (USG uses `{username}` not `%{User-Name}`)
4. Ensure connection pool not exhausted

### Issue: EAP Negotiation Failures

**Symptom**: EAP-TLS works in FreeRADIUS but fails in USG RADIUS

**Diagnosis**:
```bash
# Check certificate chain
openssl verify -CAfile ca.pem server.pem

# Test with eapol_test
wpa_supplicant -c eapol_test.conf -i eth0 -D wired
```

**Common Causes**:
1. **TLS version mismatch**: USG RADIUS requires TLS 1.2+
   - Solution: Update client to support TLS 1.2
2. **Certificate validation**: USG RADIUS enforces strict validation
   - Solution: Ensure certificate SAN matches server hostname
3. **CRL issues**: CRL check may fail if unreachable
   - Solution: Disable CRL or ensure CRL URL accessible

---

## Rollback Plan

If issues arise, rollback quickly:

```bash
# Immediate rollback (HAProxy)
# Edit haproxy.cfg:
backend radius_servers
    server freeradius 10.0.1.10:1812 weight 100
    server usg-radius 10.0.1.20:1812 weight 0 backup

# Kubernetes rollback
kubectl rollout undo deployment/radius-server

# Docker Compose rollback
docker-compose down usg-radius
docker-compose up -d freeradius
```

**Post-Rollback**:
1. Capture logs for analysis
2. Test in staging environment
3. File GitHub issue with details
4. Re-attempt after fix

---

## Success Criteria

Before decommissioning FreeRADIUS:

- [ ] All authentication methods working (PAP, CHAP, EAP)
- [ ] Accounting data correctly logged
- [ ] Performance meets or exceeds baseline (latency, throughput)
- [ ] Zero authentication failures for known-good users
- [ ] Monitoring dashboards showing healthy metrics
- [ ] Backend integrations functional (LDAP, PostgreSQL)
- [ ] Proxy routing working as expected
- [ ] HA failover tested and validated
- [ ] Team trained on new system
- [ ] Documentation updated

---

## Getting Help

- **Pre-Migration Assessment**: Review ROADMAP.md and RFC-COMPLIANCE.md
- **Migration Support**: Open GitHub issue with "migration" label
- **Community**: Share your experience to help others

---

**Next Steps**: See [QUICKSTART.md](./QUICKSTART.md) to begin your USG RADIUS deployment.
