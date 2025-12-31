# Backend Integration Guide

USG RADIUS supports multiple authentication backends, allowing you to choose the best option for your infrastructure.

## Available Backends

1. **[File-Based](#file-based-authentication)** - Simple JSON configuration
2. **[LDAP/Active Directory](#ldap-active-directory)** - Enterprise directory services
3. **[PostgreSQL](#postgresql)** - Database-backed authentication

---

## Quick Comparison

| Feature | File-Based | LDAP/AD | PostgreSQL |
|---------|------------|---------|------------|
| **Ease of Setup** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Scalability** | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Central Management** | ❌ | ✅ | ✅ |
| **Dynamic Updates** | ❌ | ✅ | ✅ |
| **Group Support** | ❌ | ✅ | ✅ (custom) |
| **SSO Integration** | ❌ | ✅ | ❌ |
| **Custom Attributes** | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Best For** | Testing, small deployments | Enterprise, AD environments | Custom schemas, large scale |

---

## File-Based Authentication

### Overview

Store user credentials directly in the configuration file. Best for:
- Development and testing
- Small deployments (< 50 users)
- Static user lists

### Configuration

```json
{
  "listen_address": "::",
  "listen_port": 1812,
  "secret": "testing123",

  "users": [
    {
      "username": "alice",
      "password": "password123"
    },
    {
      "username": "bob",
      "password": "secret456"
    }
  ]
}
```

### Limitations

- Requires server restart to add/remove users
- Passwords stored in config file (use environment variables)
- Not suitable for large user bases
- No centralized management

### Use Cases

✅ Development environments
✅ POC/testing
✅ Small offices (< 50 users)
✅ Static service accounts

❌ Enterprise deployments
❌ Dynamic user provisioning
❌ Environments requiring audit trails

---

## LDAP / Active Directory

### Overview

Authenticate against LDAP or Active Directory servers. Best for:
- Enterprise environments
- Centralized user management
- Single Sign-On (SSO) integration
- Existing AD infrastructure

### Configuration

**OpenLDAP:**
```json
{
  "ldap": {
    "url": "ldaps://ldap.example.com:636",
    "base_dn": "dc=example,dc=com",
    "bind_dn": "cn=radius-service,ou=service-accounts,dc=example,dc=com",
    "bind_password": "${LDAP_BIND_PASSWORD}",
    "search_filter": "(uid={username})",
    "attributes": ["dn", "cn", "uid", "memberOf"],
    "timeout": 10,
    "verify_tls": true
  }
}
```

**Active Directory:**
```json
{
  "ldap": {
    "url": "ldaps://dc1.corp.example.com:636",
    "base_dn": "dc=corp,dc=example,dc=com",
    "bind_dn": "CN=RADIUS Service,OU=Service Accounts,DC=corp,DC=example,DC=com",
    "bind_password": "${AD_BIND_PASSWORD}",
    "search_filter": "(sAMAccountName={username})",
    "attributes": ["dn", "cn", "sAMAccountName", "memberOf"],
    "timeout": 15,
    "verify_tls": true
  }
}
```

### Features

✅ Central user management
✅ Dynamic user updates
✅ Group membership support
✅ Password policy enforcement
✅ Integration with AD/LDAP infrastructure
✅ Secure LDAPS support

### Use Cases

✅ Enterprise deployments
✅ Organizations with existing AD
✅ Environments requiring SSO
✅ Large user bases (1000+ users)

❌ No LDAP infrastructure
❌ Require custom user attributes
❌ Need offline authentication

### Documentation

See [LDAP_INTEGRATION.md](LDAP_INTEGRATION.md) for detailed configuration and troubleshooting.

---

## PostgreSQL

### Overview

Store user credentials in a PostgreSQL database. Best for:
- Custom user schemas
- Complex attribute requirements
- Integration with existing databases
- Large-scale deployments

### Configuration

```json
{
  "postgres": {
    "url": "postgresql://radius:${DB_PASSWORD}@localhost:5432/radius",
    "max_connections": 10,
    "timeout": 10,
    "query": "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true",
    "password_hash": "bcrypt",
    "attributes_query": "SELECT attribute_type, attribute_value FROM user_attributes WHERE username = $1"
  }
}
```

### Features

✅ Flexible schema design
✅ Custom SQL queries
✅ Dynamic user provisioning
✅ Per-user RADIUS attributes
✅ Connection pooling
✅ Bcrypt password hashing
✅ Audit logging support

### Use Cases

✅ Custom user schemas
✅ Integration with existing databases
✅ Require flexible attributes
✅ Large deployments needing scalability
✅ Multi-tenant environments

❌ Simple deployments
❌ No database infrastructure
❌ Require LDAP integration

### Documentation

See [POSTGRES_INTEGRATION.md](POSTGRES_INTEGRATION.md) for detailed setup, schema design, and optimization.

---

## Choosing a Backend

### Decision Tree

```
Do you have < 50 static users?
├─ Yes → File-Based
└─ No → Continue

Do you use Active Directory or LDAP?
├─ Yes → LDAP/AD
└─ No → Continue

Do you need custom schemas or attributes?
├─ Yes → PostgreSQL
└─ No → PostgreSQL or LDAP/AD
```

### By Environment Type

**Development/Testing:**
- **Recommended**: File-Based
- **Alternative**: PostgreSQL (for testing DB integration)

**Small Business (< 100 users):**
- **Recommended**: File-Based or LDAP (if already using AD)
- **Alternative**: PostgreSQL

**Enterprise (100-1000 users):**
- **Recommended**: LDAP/Active Directory
- **Alternative**: PostgreSQL

**Large Scale (1000+ users):**
- **Recommended**: LDAP/AD or PostgreSQL
- **Alternative**: Hybrid (LDAP + PostgreSQL)

**SaaS/Multi-Tenant:**
- **Recommended**: PostgreSQL
- **Alternative**: Multiple LDAP instances

---

## Combining Multiple Backends

USG RADIUS currently supports one backend at a time. To use multiple backends:

### Option 1: Multiple Server Instances

Run separate USG RADIUS instances for different backends:

```bash
# LDAP instance for corporate users
usg-radius --config ldap-config.json --port 1812

# PostgreSQL instance for contractors
usg-radius --config postgres-config.json --port 1813
```

### Option 2: Proxy/Load Balancer

Use a RADIUS proxy to route requests to different backends based on criteria.

### Future: Native Multi-Backend Support

Future versions may support multiple authentication backends in a single instance with fallback chains.

---

## Migration Guides

### File-Based → LDAP

1. Ensure users exist in LDAP with same usernames
2. Test LDAP authentication with a few users
3. Update configuration to use LDAP backend
4. Remove `users` section from config
5. Restart server

### File-Based → PostgreSQL

1. Set up PostgreSQL database (see [POSTGRES_INTEGRATION.md](POSTGRES_INTEGRATION.md))
2. Hash existing passwords with bcrypt
3. Import users into database
4. Update configuration to use PostgreSQL backend
5. Remove `users` section from config
6. Test authentication
7. Restart server

### LDAP → PostgreSQL

Consider if you need to migrate or can keep LDAP. If migrating:

1. Export users from LDAP
2. Set up PostgreSQL database
3. Import users with new password hashes
4. Update configuration
5. Test thoroughly before switching

---

## Performance Considerations

### File-Based
- **Pros**: No external dependencies, instant lookups
- **Cons**: Config reloads required, limited scalability
- **Best for**: < 100 users

### LDAP/AD
- **Pros**: Centralized, efficient for large user bases
- **Cons**: Network latency, LDAP server dependency
- **Considerations**:
  - Connection pooling helps performance
  - Timeout tuning important
  - LDAPS encryption overhead
- **Best for**: 100-10,000+ users

### PostgreSQL
- **Pros**: Scalable, connection pooling, query optimization
- **Cons**: Database dependency, query complexity
- **Considerations**:
  - Index username columns
  - Tune connection pool size
  - Monitor query performance
  - Use read replicas for high load
- **Best for**: 1,000-1,000,000+ users

---

## Security Comparison

| Security Feature | File-Based | LDAP/AD | PostgreSQL |
|-----------------|------------|---------|------------|
| **Password Hashing** | ❌ Plain | ✅ LDAP | ✅ bcrypt |
| **Encrypted Transport** | N/A | ✅ LDAPS | ✅ SSL/TLS |
| **Account Lockout** | ❌ | ✅ | ✅ (custom) |
| **Password Expiry** | ❌ | ✅ | ✅ (custom) |
| **2FA Support** | ❌ | ✅ (via AD) | ⚠️ (external) |
| **Audit Logging** | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

---

## Example Configurations

### Hybrid: File + LDAP Fallback (Not Currently Supported)

Future feature - example of desired functionality:

```json
{
  "auth_backends": [
    {
      "type": "ldap",
      "priority": 1,
      "config": { ... }
    },
    {
      "type": "file",
      "priority": 2,
      "users": [ ... ]
    }
  ]
}
```

### Current Best Practice: Primary Backend Only

```json
{
  "ldap": { ... }  // Use ONE backend
}
```

---

## Troubleshooting

### General Issues

**Problem**: Authentication fails with all backends
**Solution**:
- Check RADIUS secret matches
- Verify client IP is authorized
- Enable debug logging: `"log_level": "debug"`

### File-Based Issues

**Problem**: User not found
**Solution**: Check username spelling in config

**Problem**: Password incorrect
**Solution**: Passwords are case-sensitive, check for typos

### LDAP Issues

See [LDAP_INTEGRATION.md](LDAP_INTEGRATION.md#troubleshooting)

### PostgreSQL Issues

See [POSTGRES_INTEGRATION.md](POSTGRES_INTEGRATION.md#troubleshooting)

---

## Support & Documentation

- **Main Documentation**: [README.md](../../../README.md)
- **LDAP Guide**: [LDAP_INTEGRATION.md](LDAP_INTEGRATION.md)
- **PostgreSQL Guide**: [POSTGRES_INTEGRATION.md](POSTGRES_INTEGRATION.md)
- **Configuration Examples**: [examples/configs/](../../../examples/configs/)
- **Issue Tracker**: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/issues

---

## Future Backend Support

Planned backends for future releases:

- **MySQL/MariaDB**: Similar to PostgreSQL
- **Redis**: High-performance caching backend
- **REST API**: Authenticate via HTTP API
- **Multi-Backend**: Chain multiple backends with fallback
- **Custom Plugins**: Write custom authentication handlers

Vote on or request backends: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/issues
