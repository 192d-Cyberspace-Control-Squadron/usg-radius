# USG RADIUS Examples

This directory contains example configurations and deployment files for various use cases.

## Directory Structure

```
examples/
├── configs/          # Example configuration files
│   ├── basic-homelab.json      # Minimal config for testing
│   ├── small-business.json     # SMB production config
│   ├── enterprise.json         # Enterprise/high-scale config
│   └── docker.json             # Docker/container config
├── docker/           # Docker-related files
│   └── .env.example            # Environment variables template
└── systemd/          # Systemd service files
    └── usg-radius.service      # Systemd unit file
```

## Configuration Examples

### Basic Home Lab (`configs/basic-homelab.json`)

**Use case:** Home lab testing, development, learning

**Features:**

- Localhost-only binding
- Debug logging
- Minimal rate limits
- No audit logging
- Weak secrets (NOT for production)

**Start:**

```bash
usg_radius examples/configs/basic-homelab.json
```

### Small Business (`configs/small-business.json`)

**Use case:** Small business (10-100 users)

**Features:**

- Dual-stack IPv4/IPv6
- Environment variable secrets
- Audit logging enabled
- Moderate rate limits
- Multiple client networks (wireless, VPN, switches)

**Setup:**

```bash
# Set environment variables
export RADIUS_DEFAULT_SECRET=$(openssl rand -base64 32)
export RADIUS_WIRELESS_SECRET=$(openssl rand -base64 32)
export RADIUS_VPN_SECRET=$(openssl rand -base64 32)
export RADIUS_SWITCH_SECRET=$(openssl rand -base64 32)
export RADIUS_ADMIN_PASSWORD=$(openssl rand -base64 32)

# Start server
usg_radius examples/configs/small-business.json
```

### Enterprise (`configs/enterprise.json`)

**Use case:** Enterprise deployment (1000+ users)

**Features:**

- High-performance settings
- Large request cache
- High rate limits
- IPv6 support
- No users array (expects external auth backend)
- Multiple security zones

**Recommendations:**

- Deploy behind load balancer
- Use external authentication (LDAP/AD)
- Configure monitoring and alerting
- Implement log aggregation
- Regular secret rotation

### Docker (`configs/docker.json`)

**Use case:** Container deployments (Docker, Kubernetes)

**Features:**

- All secrets via environment variables
- Configurable via env vars
- Designed for immutable infrastructure
- Works with Docker secrets/Kubernetes secrets

**Usage:** See [Docker deployment guide](../../DEPLOYMENT.md#docker-deployment)

## Docker Deployment

### Quick Start

**1. Copy environment template:**

```bash
cp examples/docker/.env.example .env
```

**2. Edit secrets:**

```bash
vim .env  # Set strong secrets
```

**3. Start with Docker Compose:**

```bash
docker-compose up -d
```

**4. View logs:**

```bash
docker-compose logs -f
```

### Environment Variables

See `docker/.env.example` for all available variables.

**Required variables:**

- `RADIUS_SECRET` - Default shared secret
- `CLIENT_1_SECRET` - Client network 1 secret
- `CLIENT_2_SECRET` - Client network 2 secret
- `ADMIN_PASSWORD` - Admin user password

**Optional variables:**

- `CLIENT_1_NETWORK` - Client 1 network CIDR (default: 192.168.1.0/24)
- `CLIENT_2_NETWORK` - Client 2 network CIDR (default: 10.0.0.0/8)
- `LOG_LEVEL` - Logging level (default: info)
- `ADMIN_USERNAME` - Admin username (default: admin)

## Systemd Deployment

### Installation

**1. Copy service file:**

```bash
sudo cp examples/systemd/usg-radius.service /etc/systemd/system/
```

**2. Reload systemd:**

```bash
sudo systemctl daemon-reload
```

**3. Enable and start:**

```bash
sudo systemctl enable usg-radius
sudo systemctl start usg-radius
```

### Service Management

```bash
# Status
sudo systemctl status usg-radius

# Logs
sudo journalctl -u usg-radius -f

# Restart
sudo systemctl restart usg-radius

# Stop
sudo systemctl stop usg-radius
```

## Security Best Practices

### Secrets

**Generate strong secrets:**

```bash
# Linux/macOS
openssl rand -base64 32

# Or
head -c 32 /dev/urandom | base64
```

**Requirements:**

- Minimum 16 characters
- Include uppercase, lowercase, numbers, symbols
- Unique secret per client
- Never commit to version control
- Rotate regularly (quarterly recommended)

### File Permissions

**Configuration file:**

```bash
chmod 600 /etc/radius/config.json
chown radius:radius /etc/radius/config.json
```

**Log directory:**

```bash
chmod 750 /var/log/radius
chown radius:radius /var/log/radius
```

### Firewall

**Only allow RADIUS clients:**

```bash
# UFW
sudo ufw allow from 192.168.1.0/24 to any port 1812 proto udp
sudo ufw deny 1812/udp

# iptables
sudo iptables -A INPUT -s 192.168.1.0/24 -p udp --dport 1812 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 1812 -j DROP
```

## Testing

### Using radtest

Install FreeRADIUS utils:

```bash
# Debian/Ubuntu
sudo apt install freeradius-utils

# RHEL/CentOS
sudo yum install freeradius-utils
```

Test authentication:

```bash
radtest username password server_ip 1812 shared_secret
```

Example:

```bash
radtest admin admin123 localhost 1812 testing123
```

Expected output (success):

```
Sent Access-Request Id 123 from 0.0.0.0:12345 to 127.0.0.1:1812 length 77
Received Access-Accept Id 123 from 127.0.0.1:1812 to 127.0.0.1:12345 length 20
```

### Using Docker

Test Docker deployment:

```bash
# Build image
docker build -t usg-radius .

# Run with example config
docker run --rm \
  -v $(pwd)/examples/configs/basic-homelab.json:/etc/radius/config.json:ro \
  --network host \
  usg-radius

# In another terminal, test with radtest
radtest admin admin123 localhost 1812 testing123
```

## Troubleshooting

### Configuration Validation

Validate config before starting:

```bash
usg_radius --validate config.json
```

### Common Issues

**Port permission denied:**

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/usg_radius
```

**Environment variable not found:**

```bash
# Make sure to export variables
export RADIUS_SECRET="your_secret"
```

**Firewall blocking:**

```bash
# Check firewall status
sudo ufw status
sudo iptables -L -n | grep 1812

# Test network connectivity
sudo tcpdump -i any -n port 1812
```

## More Information

- [Full Deployment Guide](../../DEPLOYMENT.md)
- [Server Configuration Docs](../../docs/docs/configuration/server.md)
- [Security Best Practices](../../docs/docs/security/overview.md)
- [Project README](../../README.md)

## Contributing

Found an issue or have a suggestion for improving these examples?

Open an issue: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/issues
