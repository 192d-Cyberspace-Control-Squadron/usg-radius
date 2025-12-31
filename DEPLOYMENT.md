# USG RADIUS Deployment Guide

This guide covers deploying USG RADIUS in various environments.

## Table of Contents

- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
- [Systemd Deployment](#systemd-deployment)
- [Production Checklist](#production-checklist)
- [Security Hardening](#security-hardening)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites

- Rust 1.70+ (for building from source)
- Linux system (production deployments)
- Network access to RADIUS clients (NAS devices)

### Build from Source

```bash
# Clone repository
git clone https://github.com/192d-Cyberspace-Control-Squadron/usg-radius.git
cd usg-radius

# Build release binary
cargo build --release

# Binary location
./target/release/usg_radius
```

### Test Configuration

```bash
# Copy example config
cp config.example.json config.json

# Edit configuration
vim config.json

# Test configuration (doesn't start server)
cargo run --release -- --validate config.json

# Run server
cargo run --release
```

---

## Docker Deployment

### Option 1: Docker Compose (Recommended)

**Step 1: Create environment file**

```bash
cp examples/docker/.env.example .env
vim .env  # Edit secrets
```

**Step 2: Start service**

```bash
docker-compose up -d
```

**Step 3: View logs**

```bash
docker-compose logs -f radius
```

**Step 4: Stop service**

```bash
docker-compose down
```

### Option 2: Docker Run

```bash
# Build image
docker build -t usg-radius .

# Run container
docker run -d \
  --name usg-radius \
  --network host \
  -v $(pwd)/config.json:/etc/radius/config.json:ro \
  -v radius-logs:/var/log/radius \
  -e RADIUS_SECRET=your_secret_here \
  usg-radius
```

### Docker Production Deployment

**Use Docker secrets:**

```bash
# Create secrets
echo "your_radius_secret" | docker secret create radius_secret -

# Update docker-compose.yml to use secrets
version: '3.8'
services:
  radius:
    secrets:
      - radius_secret
    environment:
      - RADIUS_SECRET_FILE=/run/secrets/radius_secret

secrets:
  radius_secret:
    external: true
```

**Health checks:**

Docker Compose includes health checks. Monitor with:

```bash
docker inspect --format='{{.State.Health.Status}}' usg-radius
```

---

## Systemd Deployment

### Installation

**Step 1: Build binary**

```bash
cargo build --release
sudo cp target/release/usg_radius /usr/local/bin/
sudo chmod 755 /usr/local/bin/usg_radius
```

**Step 2: Create user and directories**

```bash
sudo useradd -r -s /bin/false radius
sudo mkdir -p /etc/radius /var/lib/radius /var/log/radius
sudo chown radius:radius /etc/radius /var/lib/radius /var/log/radius
sudo chmod 750 /etc/radius /var/lib/radius /var/log/radius
```

**Step 3: Install configuration**

```bash
sudo cp config.json /etc/radius/config.json
sudo chown radius:radius /etc/radius/config.json
sudo chmod 600 /etc/radius/config.json
```

**Step 4: Install systemd service**

```bash
sudo cp examples/systemd/usg-radius.service /etc/systemd/system/
sudo systemctl daemon-reload
```

**Step 5: Enable and start**

```bash
sudo systemctl enable usg-radius
sudo systemctl start usg-radius
```

### Management

```bash
# Check status
sudo systemctl status usg-radius

# View logs
sudo journalctl -u usg-radius -f

# Restart service
sudo systemctl restart usg-radius

# Stop service
sudo systemctl stop usg-radius

# Disable service
sudo systemctl disable usg-radius
```

### Port Binding (<1024)

RADIUS uses port 1812 by default, which requires privileges. Options:

**Option 1: Use capabilities (recommended)**

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/usg_radius
```

**Option 2: Run as root (not recommended)**

Modify systemd service:
```ini
[Service]
User=root
Group=root
```

**Option 3: Use high port (>1024)**

Configure clients to use custom port:
```json
{
  "listen_port": 11812
}
```

---

## Production Checklist

### Pre-Deployment

- [ ] **Configuration validated**
  ```bash
  usg_radius --validate /etc/radius/config.json
  ```

- [ ] **Strong secrets generated**
  ```bash
  openssl rand -base64 32
  ```

- [ ] **Secrets stored securely**
  - Use environment variables
  - Never commit to version control
  - Use secret management (Vault, AWS Secrets Manager)

- [ ] **File permissions configured**
  ```bash
  chmod 600 /etc/radius/config.json
  chown radius:radius /etc/radius/config.json
  ```

- [ ] **Firewall rules configured**
  ```bash
  # UFW example
  sudo ufw allow from 192.168.1.0/24 to any port 1812 proto udp

  # iptables example
  sudo iptables -A INPUT -s 192.168.1.0/24 -p udp --dport 1812 -j ACCEPT
  sudo iptables -A INPUT -p udp --dport 1812 -j DROP
  ```

- [ ] **Logging configured**
  - Audit log path set
  - Log rotation configured (logrotate)
  - Log aggregation setup

- [ ] **Monitoring configured**
  - Health checks
  - Alert on failures
  - Metrics collection

### Post-Deployment

- [ ] **Test authentication**
  ```bash
  # Using radtest (from freeradius-utils package)
  radtest username password localhost 1812 testing123
  ```

- [ ] **Verify audit logs**
  ```bash
  tail -f /var/log/radius/audit.log
  ```

- [ ] **Check resource usage**
  ```bash
  # CPU and memory
  top -p $(pgrep usg_radius)

  # Network connections
  sudo ss -ulnp | grep 1812
  ```

- [ ] **Verify client connectivity**
  - Test from each RADIUS client network
  - Verify source IP validation
  - Test rate limiting

- [ ] **Document deployment**
  - Record configuration decisions
  - Document network topology
  - List all RADIUS clients
  - Create runbook for common issues

---

## Security Hardening

### Network Security

**1. Firewall Configuration**

Only allow RADIUS clients:

```bash
# Example: Allow specific networks
sudo ufw allow from 192.168.1.0/24 to any port 1812 proto udp
sudo ufw allow from 10.0.0.0/8 to any port 1812 proto udp
sudo ufw deny 1812/udp
```

**2. Network Isolation**

- Deploy RADIUS server in management VLAN
- Use VPN for remote RADIUS clients
- Never expose to public internet

**3. IPsec/TLS**

For future RadSec support (RADIUS over TLS).

### Application Security

**1. Configuration Security**

```json
{
  "strict_rfc_compliance": true,
  "request_cache_ttl": 60,
  "audit_log_path": "/var/log/radius/audit.log"
}
```

**2. Rate Limiting**

Tune based on your needs:

```json
{
  "rate_limit_per_client_rps": 100,
  "rate_limit_per_client_burst": 200,
  "rate_limit_global_rps": 1000,
  "rate_limit_global_burst": 2000
}
```

**3. Secret Management**

```bash
# Generate strong secrets
openssl rand -base64 32

# Use environment variables
export RADIUS_SECRET=$(openssl rand -base64 32)

# Or use secret management
vault kv get -field=radius_secret secret/radius
```

### System Security

**1. SELinux/AppArmor**

Consider creating custom policies for additional isolation.

**2. File Permissions**

```bash
# Config file (secrets inside)
chmod 600 /etc/radius/config.json
chown radius:radius /etc/radius/config.json

# Log directory
chmod 750 /var/log/radius
chown radius:radius /var/log/radius

# Binary
chmod 755 /usr/local/bin/usg_radius
chown root:root /usr/local/bin/usg_radius
```

**3. Resource Limits**

Systemd service includes resource limits. For manual deployment:

```bash
# /etc/security/limits.conf
radius soft nofile 65536
radius hard nofile 65536
radius soft nproc 512
radius hard nproc 512
```

---

## Monitoring

### Log Monitoring

**Structured logs:**

```bash
# View all logs
sudo journalctl -u usg-radius -f

# Filter by level
sudo journalctl -u usg-radius -p warning -f

# View audit log
tail -f /var/log/radius/audit.log | jq
```

**Log rotation:**

```bash
# /etc/logrotate.d/radius
/var/log/radius/audit.log {
    daily
    rotate 90
    compress
    delaycompress
    notifempty
    create 0640 radius radius
    sharedscripts
    postrotate
        systemctl reload usg-radius
    endscript
}
```

### Health Checks

**Systemd:**

```bash
# Check service status
systemctl is-active usg-radius

# Check for crashes
journalctl -u usg-radius --since "1 hour ago" | grep -i error
```

**Docker:**

```bash
# Health status
docker inspect --format='{{.State.Health.Status}}' usg-radius

# Container logs
docker logs -f usg-radius
```

### Metrics

Monitor these key metrics:

- Authentication success rate
- Authentication failures (potential attacks)
- Rate limit violations
- Request latency
- Memory usage
- CPU usage
- Network throughput

**Future:** Prometheus metrics endpoint planned for v1.0.

---

## Troubleshooting

### Server Won't Start

**Problem:** Port permission denied

```
Error: Permission denied (os error 13)
```

**Solution:** Use capabilities or run as root (port <1024)

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/usg_radius
```

---

**Problem:** Port already in use

```
Error: Address already in use (os error 98)
```

**Solution:** Check for other RADIUS servers

```bash
sudo lsof -i :1812
sudo ss -ulnp | grep 1812
```

---

**Problem:** Config file not found

```
Error: No such file or directory
```

**Solution:** Specify full path

```bash
usg_radius /etc/radius/config.json
```

### Authentication Failures

**Problem:** All auth requests fail

**Check:**

1. Client IP authorized in config
2. Correct shared secret
3. User exists in config
4. Firewall allows client

```bash
# View audit log
tail -f /var/log/radius/audit.log

# Check client authorization
grep "unauthorized_client" /var/log/radius/audit.log
```

---

**Problem:** Rate limiting

```
Rate limit exceeded for client X.X.X.X
```

**Solution:** Adjust rate limits or investigate DoS attack

```json
{
  "rate_limit_per_client_rps": 200
}
```

### Performance Issues

**Problem:** High CPU usage

**Check:**

- Too many authentication requests (DoS attack?)
- Rate limiting configured?
- Request cache working?

```bash
# Monitor CPU
top -p $(pgrep usg_radius)

# Check request rate
grep "auth_attempt" /var/log/radius/audit.log | wc -l
```

---

**Problem:** High memory usage

**Check:**

- Request cache size
- Number of clients/users

```json
{
  "request_cache_max_entries": 10000
}
```

### Network Issues

**Problem:** Clients can't reach server

**Check:**

1. Firewall rules
2. Network routing
3. Listen address correct

```bash
# Verify listening
sudo ss -ulnp | grep 1812

# Test network
sudo tcpdump -i any -n port 1812

# Check routes
ip route
```

### Configuration Issues

**Problem:** Environment variables not expanding

```
Error: Environment variable not found: RADIUS_SECRET
```

**Solution:** Export variables before starting

```bash
export RADIUS_SECRET="your_secret"
usg_radius /etc/radius/config.json
```

For systemd, use EnvironmentFile:

```ini
[Service]
EnvironmentFile=/etc/radius/environment
```

---

## Support

- **Documentation**: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius
- **Issues**: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/issues
- **RFC 2865**: https://tools.ietf.org/html/rfc2865

---

## Next Steps

After successful deployment:

1. Integrate with authentication backend (LDAP/AD) - future feature
2. Set up monitoring and alerting
3. Configure log aggregation
4. Implement backup and disaster recovery
5. Document operational procedures
6. Train operations team
7. Schedule regular security audits
8. Plan for high availability deployment
