# PostgreSQL Integration Guide

This guide covers integrating USG RADIUS with PostgreSQL for database-backed user authentication.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Database Setup](#database-setup)
- [Configuration](#configuration)
- [Password Hashing](#password-hashing)
- [RADIUS Attributes](#radius-attributes)
- [Testing](#testing)
- [Performance Tuning](#performance-tuning)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

---

## Overview

USG RADIUS supports authentication against PostgreSQL databases, enabling:

- **Centralized User Management**: Store user credentials in a database
- **Dynamic User Provisioning**: Add/remove users without restarting the server
- **Custom Attributes**: Return user-specific RADIUS attributes from the database
- **Connection Pooling**: Efficient connection reuse for better performance
- **Flexible Queries**: Customize SQL queries to match your schema
- **Multiple Hash Algorithms**: Support for bcrypt and plain text (not recommended for production)

---

## Quick Start

### 1. Set Up PostgreSQL Database

```bash
# Create database and user
sudo -u postgres psql <<EOF
CREATE DATABASE radius;
CREATE USER radius WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE radius TO radius;
\c radius
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO radius;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO radius;
EOF

# Load schema
sudo -u postgres psql -d radius -f examples/postgres-schema.sql
```

### 2. Configure USG RADIUS

Create `config.json`:

```json
{
  "listen_address": "::",
  "listen_port": 1812,
  "secret": "testing123",

  "postgres": {
    "url": "postgresql://radius:your_secure_password@localhost:5432/radius",
    "max_connections": 10,
    "timeout": 10,
    "query": "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true",
    "password_hash": "bcrypt"
  }
}
```

### 3. Add a Test User

```bash
# Generate bcrypt hash (using Python)
python3 -c "import bcrypt; print(bcrypt.hashpw(b'password123', bcrypt.gensalt()).decode())"

# Insert user
psql -U radius -d radius <<EOF
INSERT INTO users (username, password_hash, enabled) VALUES
    ('testuser', '$2b$12$YOUR_BCRYPT_HASH_HERE', true);
EOF
```

### 4. Start the Server

```bash
usg-radius --config config.json
```

---

## Database Setup

### Schema Overview

The default schema includes three tables:

1. **users**: Store user credentials and status
2. **user_attributes**: Store per-user RADIUS attributes
3. **auth_attempts**: Log authentication attempts (optional)

### Creating the Database

```sql
-- Create database
CREATE DATABASE radius;
CREATE USER radius WITH PASSWORD 'changeme';
GRANT ALL PRIVILEGES ON DATABASE radius TO radius;
```

### Loading the Schema

```bash
psql -U radius -d radius -f examples/postgres-schema.sql
```

The schema file (`examples/postgres-schema.sql`) includes:
- Table definitions
- Indexes for performance
- Sample data
- Triggers for auto-updating timestamps
- Useful views for administration

---

## Configuration

### Basic Configuration

```json
{
  "postgres": {
    "url": "postgresql://radius:password@localhost:5432/radius",
    "max_connections": 10,
    "timeout": 10,
    "query": "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true",
    "password_hash": "bcrypt"
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `url` | string | required | PostgreSQL connection URL |
| `max_connections` | integer | 10 | Maximum connections in pool |
| `timeout` | integer | 10 | Connection timeout in seconds |
| `query` | string | see below | SQL query to retrieve user credentials |
| `password_hash` | string | "bcrypt" | Password hashing algorithm |
| `attributes_query` | string | null | Optional query for RADIUS attributes |

### Default Query

```sql
SELECT username, password_hash
FROM users
WHERE username = $1 AND enabled = true
```

The query must:
- Accept username as parameter `$1`
- Return columns: `username`, `password_hash`
- Return exactly one row for valid users

### Custom Queries

You can customize queries to match your schema:

```json
{
  "postgres": {
    "query": "SELECT u.username, u.password_hash FROM users u JOIN departments d ON u.dept_id = d.id WHERE u.username = $1 AND u.enabled = true AND d.active = true"
  }
}
```

### RADIUS Attributes Query

Optionally return per-user RADIUS attributes:

```json
{
  "postgres": {
    "attributes_query": "SELECT attribute_type, attribute_value FROM user_attributes WHERE username = $1"
  }
}
```

The attributes query must:
- Accept username as parameter `$1`
- Return columns: `attribute_type` (integer), `attribute_value` (string)

---

## Password Hashing

### Bcrypt (Recommended)

Bcrypt is the recommended algorithm for production use.

**Generate hash (Python):**
```python
import bcrypt
password = b'your_password'
hash = bcrypt.hashpw(password, bcrypt.gensalt())
print(hash.decode())
```

**Generate hash (Node.js):**
```javascript
const bcrypt = require('bcrypt');
bcrypt.hash('your_password', 10, function(err, hash) {
    console.log(hash);
});
```

**Configuration:**
```json
{
  "postgres": {
    "password_hash": "bcrypt"
  }
}
```

### Plain Text (NOT Recommended)

Plain text passwords are **not recommended** for production.

**Configuration:**
```json
{
  "postgres": {
    "password_hash": "plain"
  }
}
```

**Note**: Using plain text passwords will generate warnings in logs.

---

## RADIUS Attributes

### Common RADIUS Attributes

| Type | Attribute | Description |
|------|-----------|-------------|
| 1 | User-Name | Username |
| 6 | Service-Type | Service type (1=Login, 2=Framed, etc.) |
| 7 | Framed-Protocol | Framed protocol (1=PPP, etc.) |
| 8 | Framed-IP-Address | IP address to assign |
| 11 | Filter-Id | Filter to apply |
| 25 | Class | User class |
| 27 | Session-Timeout | Session timeout in seconds |
| 28 | Idle-Timeout | Idle timeout in seconds |

### Adding Attributes to Users

```sql
INSERT INTO user_attributes (username, attribute_type, attribute_value) VALUES
    ('john', 6, '2'),        -- Service-Type: Framed
    ('john', 27, '3600'),    -- Session-Timeout: 1 hour
    ('john', 8, '10.1.1.100'); -- Framed-IP-Address
```

### Querying Attributes

Configure the attributes query:

```json
{
  "postgres": {
    "attributes_query": "SELECT attribute_type, attribute_value FROM user_attributes WHERE username = $1"
  }
}
```

---

## Testing

### Unit Tests

Run the PostgreSQL tests:

```bash
cargo test --test postgres_tests
```

### Integration Testing

Integration tests require a real PostgreSQL server. See commented tests in `tests/postgres_tests.rs` for examples.

**Setup test database:**
```bash
sudo -u postgres psql <<EOF
CREATE DATABASE radius_test;
CREATE USER radius WITH PASSWORD 'testpass';
GRANT ALL PRIVILEGES ON DATABASE radius_test TO radius;
EOF

psql -U radius -d radius_test -f examples/postgres-schema.sql
```

**Run integration tests:**
```bash
cargo test --test postgres_tests -- --ignored
```

### Manual Testing

Test authentication with `radtest`:

```bash
# Install freeradius-utils
sudo apt-get install freeradius-utils  # Debian/Ubuntu
sudo yum install freeradius-utils      # RHEL/CentOS

# Test authentication
radtest testuser password123 localhost:1812 0 testing123
```

Expected output for successful auth:
```
Sent Access-Request Id 123 from 0.0.0.0:54321 to 127.0.0.1:1812 length 73
Received Access-Accept Id 123 from 127.0.0.1:1812 to 0.0.0.0:54321 length 20
```

---

## Performance Tuning

### Connection Pool Sizing

The `max_connections` parameter controls the connection pool size:

```json
{
  "postgres": {
    "max_connections": 20
  }
}
```

**Guidelines:**
- Start with 10 connections for low traffic
- Increase to 20-50 for medium traffic
- Use 50-100 for high traffic scenarios
- Monitor PostgreSQL connections: `SELECT count(*) FROM pg_stat_activity WHERE datname = 'radius';`

### Query Optimization

**Use indexes** on frequently queried columns:

```sql
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_enabled ON users(enabled);
CREATE INDEX idx_user_attributes_username ON user_attributes(username);
```

**Analyze query performance:**

```sql
EXPLAIN ANALYZE
SELECT username, password_hash
FROM users
WHERE username = 'testuser' AND enabled = true;
```

### Connection Timeout

Adjust timeout for slow networks or high latency:

```json
{
  "postgres": {
    "timeout": 30
  }
}
```

---

## Security Best Practices

### 1. Use Strong Passwords

```bash
# Generate secure database password
openssl rand -base64 32
```

### 2. Limit Database Permissions

```sql
-- Revoke unnecessary permissions
REVOKE ALL ON DATABASE radius FROM radius;

-- Grant only required permissions
GRANT CONNECT ON DATABASE radius TO radius;
GRANT SELECT, INSERT ON users TO radius;
GRANT SELECT ON user_attributes TO radius;
GRANT INSERT ON auth_attempts TO radius;
```

### 3. Use SSL/TLS Connections

```json
{
  "postgres": {
    "url": "postgresql://radius:password@localhost:5432/radius?sslmode=require"
  }
}
```

SSL modes:
- `disable`: No SSL
- `require`: SSL required, no verification
- `verify-ca`: Verify server certificate
- `verify-full`: Full verification (recommended)

### 4. Use Environment Variables for Secrets

```json
{
  "postgres": {
    "url": "postgresql://radius:${DB_PASSWORD}@localhost:5432/radius"
  }
}
```

```bash
export DB_PASSWORD="your_secure_password"
usg-radius --config config.json
```

### 5. Regular Password Rotation

```sql
-- Update database password
ALTER USER radius WITH PASSWORD 'new_secure_password';
```

### 6. Audit Logging

Enable authentication attempt logging:

```sql
-- Query to review auth attempts
SELECT
    username,
    source_ip,
    success,
    timestamp
FROM auth_attempts
WHERE timestamp > NOW() - INTERVAL '24 hours'
ORDER BY timestamp DESC;
```

### 7. Network Security

- Bind PostgreSQL to localhost if RADIUS server is on the same host
- Use firewall rules to restrict database access
- Use VPN or SSH tunnels for remote connections

---

## Troubleshooting

### Connection Issues

**Error: "Connection refused"**

Check PostgreSQL is running:
```bash
sudo systemctl status postgresql
```

Check PostgreSQL is listening:
```bash
sudo netstat -tlnp | grep 5432
```

**Error: "Authentication failed"**

Verify credentials:
```bash
psql -U radius -d radius -h localhost
```

Check `pg_hba.conf`:
```bash
sudo vi /etc/postgresql/*/main/pg_hba.conf
```

Add/modify line:
```
host    radius    radius    127.0.0.1/32    md5
```

Reload PostgreSQL:
```bash
sudo systemctl reload postgresql
```

### Query Issues

**Error: "User not found"**

Verify user exists:
```sql
SELECT * FROM users WHERE username = 'testuser';
```

**Error: "Query error"**

Test query manually:
```sql
SELECT username, password_hash
FROM users
WHERE username = 'testuser' AND enabled = true;
```

Enable verbose logging:
```json
{
  "log_level": "debug"
}
```

### Performance Issues

**Slow authentication:**

1. Check database performance:
```sql
SELECT * FROM pg_stat_statements
ORDER BY total_time DESC
LIMIT 10;
```

2. Verify indexes exist:
```sql
SELECT * FROM pg_indexes WHERE tablename = 'users';
```

3. Increase connection pool:
```json
{
  "postgres": {
    "max_connections": 50
  }
}
```

### Password Verification Issues

**Bcrypt error:**

Verify bcrypt hash format:
```python
import bcrypt
# Should start with $2a$, $2b$, or $2y$
hash = '$2b$12$...'
```

**Plain text not working:**

Verify password_hash setting:
```json
{
  "postgres": {
    "password_hash": "plain"
  }
}
```

---

## Example Configurations

### Minimal Configuration

```json
{
  "listen_address": "::",
  "listen_port": 1812,
  "secret": "testing123",

  "postgres": {
    "url": "postgresql://radius:password@localhost:5432/radius"
  }
}
```

### Production Configuration

```json
{
  "listen_address": "::",
  "listen_port": 1812,
  "secret": "${RADIUS_SECRET}",
  "strict_rfc_compliance": true,

  "log_level": "info",
  "audit_log_path": "/var/log/radius/audit.log",

  "clients": [
    {
      "name": "Access Points",
      "address": "192.168.10.0/24",
      "secret": "${AP_SECRET}",
      "enabled": true
    }
  ],

  "postgres": {
    "url": "postgresql://radius:${DB_PASSWORD}@db.internal:5432/radius?sslmode=verify-full",
    "max_connections": 50,
    "timeout": 15,
    "query": "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true",
    "password_hash": "bcrypt",
    "attributes_query": "SELECT attribute_type, attribute_value FROM user_attributes WHERE username = $1"
  },

  "request_cache_ttl": 300,
  "request_cache_max_entries": 50000,

  "rate_limit_per_client_rps": 500,
  "rate_limit_per_client_burst": 1000,
  "rate_limit_global_rps": 5000,
  "rate_limit_global_burst": 10000
}
```

---

## Migration from File-Based Users

If migrating from file-based user configuration:

### 1. Export existing users

```bash
# Extract users from config.json
jq -r '.users[] | "\(.username),\(.password)"' config.json > users.csv
```

### 2. Hash passwords

```python
import csv
import bcrypt

with open('users.csv', 'r') as f:
    reader = csv.reader(f)
    for username, password in reader:
        hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        print(f"INSERT INTO users (username, password_hash, enabled) VALUES ('{username}', '{hash}', true);")
```

### 3. Import into PostgreSQL

```bash
python3 hash_passwords.py | psql -U radius -d radius
```

### 4. Update configuration

Remove `users` section and add `postgres` configuration.

---

## Support

- **Documentation**: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius
- **Issues**: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/issues
- **Schema Reference**: `examples/postgres-schema.sql`
- **Example Config**: `examples/configs/postgres.json`
