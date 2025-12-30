# Server Configuration

This guide covers the configuration of the USG RADIUS server.

## Configuration File

USG RADIUS uses JSON for configuration. The default configuration file is `config.json` in the working directory.

### Specify Custom Config File

```bash
cargo run -- /path/to/custom-config.json
# or
usg_radius /path/to/custom-config.json
```

## Configuration Structure

```json
{
  "listen_address": "0.0.0.0",
  "listen_port": 1812,
  "secret": "testing123",
  "clients": [],
  "users": [],
  "verbose": false
}
```

## Server Settings

### listen_address

The IP address the server binds to.

- **Type**: String (IP address)
- **Default**: `"0.0.0.0"`
- **Valid values**:
  - `"0.0.0.0"` - Listen on all interfaces
  - `"127.0.0.1"` - Listen on localhost only
  - `"192.168.1.10"` - Listen on specific interface

**Example:**

```json
{
  "listen_address": "192.168.1.10"
}
```

!!! tip
    Use `"127.0.0.1"` for testing, `"0.0.0.0"` for production.

### listen_port

The UDP port the server listens on.

- **Type**: Integer
- **Default**: `1812`
- **Valid range**: 1-65535
- **Standard ports**:
  - 1812: RADIUS authentication (RFC 2865)
  - 1813: RADIUS accounting (RFC 2866)
  - 1645/1646: Legacy RADIUS ports

**Example:**

```json
{
  "listen_port": 1812
}
```

!!! warning
    Changing from standard port 1812 requires configuring all clients to use the custom port.

### secret

The default shared secret for client authentication.

- **Type**: String
- **Default**: `"testing123"`
- **Minimum length**: 1 character
- **Recommended length**: 16+ characters

**Example:**

```json
{
  "secret": "MyVerySecureSecret2024!"
}
```

!!! danger "Security Critical"
    - Use a strong, random secret (16+ characters)
    - Include uppercase, lowercase, numbers, and symbols
    - Never use default secrets in production
    - Rotate secrets regularly
    - Use different secrets per client (see Clients configuration)

### verbose

Enable verbose logging.

- **Type**: Boolean
- **Default**: `false`

**Example:**

```json
{
  "verbose": true
}
```

When enabled, logs include:

- All packet details
- Attribute contents
- Authentication decisions
- Cryptographic operations

!!! warning
    Verbose mode may log sensitive information. Use only for debugging.

## Complete Configuration Example

### Basic Configuration

```json
{
  "listen_address": "0.0.0.0",
  "listen_port": 1812,
  "secret": "SecureSharedSecret2024!",
  "clients": [
    {
      "address": "192.168.1.0/24",
      "secret": "NetworkSecret123!",
      "name": "Internal Network"
    },
    {
      "address": "10.0.0.1",
      "secret": "VPNSecret456!",
      "name": "VPN Gateway"
    }
  ],
  "users": [
    {
      "username": "admin",
      "password": "Admin!Pass123",
      "attributes": {}
    },
    {
      "username": "john.doe",
      "password": "UserPass456!",
      "attributes": {}
    }
  ],
  "verbose": false
}
```

### Production Configuration

```json
{
  "listen_address": "0.0.0.0",
  "listen_port": 1812,
  "secret": "ProductionDefaultSecret2024!Change",
  "clients": [
    {
      "address": "192.168.100.0/24",
      "secret": "WirelessAPSecret!2024",
      "name": "Wireless Access Points"
    },
    {
      "address": "10.20.30.40",
      "secret": "VPNGatewaySecret!2024",
      "name": "Primary VPN Gateway"
    },
    {
      "address": "10.20.30.41",
      "secret": "VPNGatewaySecret!2024",
      "name": "Backup VPN Gateway"
    },
    {
      "address": "172.16.0.0/16",
      "secret": "InternalNASSecret!2024",
      "name": "Internal Network Access Servers"
    }
  ],
  "users": [],
  "verbose": false
}
```

!!! note
    Production systems should integrate with external authentication backends (LDAP, AD, database) rather than storing users in config.

## Configuration Validation

The server validates configuration on startup:

### Valid Configuration

```plain
✓ Valid listen address: 0.0.0.0
✓ Valid port: 1812
✓ Valid secret (16+ characters)
✓ All clients have valid addresses
✓ All clients have valid secrets
✓ All users have usernames
```

### Invalid Examples

**Empty Secret:**

```json
{
  "secret": ""
}
```

```plain
Error: Secret cannot be empty
```

**Invalid Port:**

```json
{
  "listen_port": 0
}
```

```plain
Error: Port cannot be 0
```

**Invalid IP Address:**

```json
{
  "listen_address": "999.999.999.999"
}
```

```plain
Error: Invalid listen address: 999.999.999.999
```

## Environment Variables

!!! info "Future Feature"
    Environment variable support for secrets is planned for a future release.

Planned syntax:

```json
{
  "secret": "${RADIUS_SECRET}"
}
```

## Reloading Configuration

Currently, configuration changes require a server restart:

```bash
# Stop server (Ctrl+C)
# Edit config.json
# Start server
cargo run --release
```

!!! info "Future Feature"
    Hot reloading of configuration (SIGHUP) is planned for a future release.

## Configuration Best Practices

### Security

1. **File Permissions**: Restrict access to config file

   ```bash
   chmod 600 config.json
   chown radius:radius config.json
   ```

2. **Secret Management**:
   - Generate secrets using cryptographic random generators
   - Never commit config files with real secrets to version control
   - Use `.gitignore` to exclude `config.json`

3. **Separate Secrets**: Use different secrets for each client

4. **Regular Rotation**: Change secrets periodically

### Reliability

1. **Backup**: Keep backups of configuration

   ```bash
   cp config.json config.json.backup
   ```

2. **Version Control**: Track config structure (not secrets) in Git

   ```bash
   cp config.json config.example.json
   # Remove real secrets from config.example.json
   git add config.example.json
   ```

3. **Validation**: Test config changes before deploying

   ```bash
   # Dry-run validation (future feature)
   usg_radius --validate config.json
   ```

### Performance

1. **Specific Binding**: Bind to specific interface when possible
2. **Client Networks**: Use CIDR notation for client networks
3. **Minimal Verbosity**: Disable verbose logging in production

## Troubleshooting

### Server Won't Start

**Problem**: `Error: Permission denied`

**Solution**: Port below 1024 requires elevated privileges

```bash
sudo cargo run --release
# or use capabilities
sudo setcap 'cap_net_bind_service=+ep' target/release/usg_radius
```

---

**Problem**: `Error: Address already in use`

**Solution**: Another process is using port 1812

```bash
sudo lsof -i :1812
# Stop conflicting process or change port
```

### Configuration Errors

**Problem**: `Error: Could not load config file`

**Solution**: Check file path and permissions

```bash
ls -l config.json
# Ensure file exists and is readable
```

---

**Problem**: `Error: Invalid configuration`

**Solution**: Validate JSON syntax

```bash
# Use a JSON validator
cat config.json | python -m json.tool
```

## Next Steps

- [Client Configuration](clients.md)
- [User Management](users.md)
- [Security Best Practices](../security/overview.md)
