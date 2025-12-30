# Client Configuration

RADIUS clients are devices (NAS, VPN gateways, WiFi access points) that send authentication requests to the RADIUS server.

## Client Structure

Clients are defined in the `clients` array in `config.json`:

```json
{
  "clients": [
    {
      "address": "192.168.1.1",
      "secret": "ClientSecret123!",
      "name": "Main WiFi AP"
    }
  ]
}
```

## Client Fields

### address

The IP address or network of the client.

- **Type**: String
- **Required**: Yes
- **Formats**:
  - Single IP: `"192.168.1.1"`
  - CIDR network: `"192.168.1.0/24"`
  - Hostname: Not currently supported

**Examples:**

```json
"address": "10.0.0.1"           // Single IP
"address": "192.168.1.0/24"     // /24 network
"address": "10.20.0.0/16"       // /16 network
```

!!! warning
    The server currently accepts requests from any IP address. Client validation is planned for a future release.

### secret

The shared secret for this client.

- **Type**: String
- **Required**: Yes
- **Minimum length**: 1 character
- **Recommended length**: 16+ characters

**Example:**

```json
"secret": "ThisIsASecureSecret123!"
```

!!! tip
    Use a different secret for each client or client network for better security.

### name

A descriptive name for the client.

- **Type**: String
- **Required**: No
- **Purpose**: Documentation/logging

**Example:**

```json
"name": "Building A WiFi Access Points"
```

## Client Examples

### Single Client

```json
{
  "clients": [
    {
      "address": "192.168.1.10",
      "secret": "WiFiAPSecret!2024",
      "name": "Main Office WiFi AP"
    }
  ]
}
```

### Multiple Clients

```json
{
  "clients": [
    {
      "address": "192.168.1.10",
      "secret": "AP1Secret!2024",
      "name": "Building A - Floor 1 AP"
    },
    {
      "address": "192.168.1.11",
      "secret": "AP2Secret!2024",
      "name": "Building A - Floor 2 AP"
    },
    {
      "address": "192.168.1.12",
      "secret": "AP3Secret!2024",
      "name": "Building A - Floor 3 AP"
    }
  ]
}
```

### Network-based Clients

For multiple devices in a network:

```json
{
  "clients": [
    {
      "address": "192.168.100.0/24",
      "secret": "WiFiNetworkSecret!2024",
      "name": "All WiFi Access Points"
    },
    {
      "address": "10.20.30.0/24",
      "secret": "VPNNetworkSecret!2024",
      "name": "VPN Gateway Network"
    }
  ]
}
```

### Mixed Configuration

```json
{
  "clients": [
    {
      "address": "192.168.1.0/24",
      "secret": "InternalSecret!2024",
      "name": "Internal Network"
    },
    {
      "address": "10.0.0.1",
      "secret": "PrimaryVPNSecret!2024",
      "name": "Primary VPN Gateway"
    },
    {
      "address": "10.0.0.2",
      "secret": "BackupVPNSecret!2024",
      "name": "Backup VPN Gateway"
    }
  ]
}
```

## Client Types

### WiFi Access Points

Configure your access point with:

- **RADIUS Server IP**: Your server's IP
- **RADIUS Port**: 1812
- **Shared Secret**: Matching the config

**Cisco WLC Example:**

```plain
radius auth add 192.168.1.100 1812 ascii WiFiAPSecret!2024
```

**Ubiquiti UniFi Example:**

```plain
Settings → Profiles → RADIUS
  - IP Address: 192.168.1.100
  - Port: 1812
  - Shared Secret: WiFiAPSecret!2024
```

### VPN Gateways

#### OpenVPN

Add to server config:

```plain
plugin /usr/lib/openvpn/radiusplugin.so /etc/openvpn/radius.conf
```

Create `/etc/openvpn/radius.conf`:

```plain
NAS-IP-Address=10.0.0.1
OpenVPNConfig=/etc/openvpn/server.conf
subnet=10.8.0.0/255.255.255.0

server
{
    acctport=1813
    authport=1812
    name=192.168.1.100
    retry=1
    wait=1
    sharedsecret=VPNSecret!2024
}
```

#### strongSwan (IPsec)

Edit `/etc/strongswan.conf`:

```plain
charon {
    plugins {
        eap-radius {
            server {
                address = 192.168.1.100
                port = 1812
                secret = IPsecSecret!2024
            }
        }
    }
}
```

### Network Access Servers

#### Cisco IOS

```plain
aaa new-model
aaa authentication login default group radius local
aaa authorization exec default group radius local

radius server RADIUS1
 address ipv4 192.168.1.100 auth-port 1812
 key NASSecret!2024
```

#### MikroTik

```plain
/radius
add address=192.168.1.100 secret=MikroTikSecret!2024 service=login
/user aaa
set use-radius=yes
```

## Shared Secret Guidelines

### Generating Secrets

Use cryptographically secure random generators:

```bash
# Linux/macOS
openssl rand -base64 32

# Or
head -c 32 /dev/urandom | base64
```

**Example output:**

```plain
vK3mNx8Qq7RzPtW5YhU2jLdF9GbSaE4c
```

### Secret Requirements

- **Minimum**: 16 characters
- **Recommended**: 24-32 characters
- **Character types**: Mix of uppercase, lowercase, numbers, symbols
- **Uniqueness**: Different secret per client/network

**Good Secrets:**

```plain
✓ vK3mNx8Qq7RzPtW5YhU2jLdF9GbSaE4c
✓ MyCompany!WiFi!Secret!2024!Building!A
✓ Tr0ub4dor&3!VPN!Gateway!Production
```

**Bad Secrets:**

```plain
✗ password
✗ 123456
✗ secret
✗ testing123
```

### Secret Rotation

Rotate secrets periodically:

1. **Choose rotation period**: 90-180 days
2. **Update server config**: Add new secret
3. **Update client config**: Change to new secret
4. **Remove old secret**: After grace period

## Managing Clients

### Adding Clients

1. Edit `config.json`
2. Add client to `clients` array
3. Restart server
4. Configure client device with server IP and secret

### Removing Clients

1. Edit `config.json`
2. Remove client from `clients` array
3. Restart server

### Updating Secrets

1. Generate new secret
2. Update server config
3. Restart server
4. Update client device
5. Test authentication

## Network Design

### Centralized RADIUS

Single RADIUS server for all clients:

```plain
┌─────────────┐
│ WiFi APs    │───┐
└─────────────┘   │
                  │      ┌──────────────┐
┌─────────────┐   ├─────>│    RADIUS    │
│ VPN Gateway │───┤      │    Server    │
└─────────────┘   │      └──────────────┘
                  │
┌─────────────┐   │
│ NAS Devices │───┘
└─────────────┘
```

**Pros:**

- Simple configuration
- Single point of management
- Consistent policies

**Cons:**

- Single point of failure
- Performance bottleneck
- No geographic distribution

### Distributed RADIUS

Multiple RADIUS servers (future feature: proxy support):

```plain
┌─────────────┐     ┌──────────────┐
│ Site A      │────>│   RADIUS A   │
│ Clients     │     └──────────────┘
└─────────────┘             │
                            │
                    ┌──────────────┐
                    │    Central   │
                    │   Database   │
                    └──────────────┘
                            │
┌─────────────┐     ┌──────────────┐
│ Site B      │────>│   RADIUS B   │
│ Clients     │     └──────────────┘
└─────────────┘
```

## Testing Clients

### Test with radtest

```bash
radtest alice password123 <server-ip> 1812 <client-secret>
```

### Test from Client Device

Most client devices have RADIUS test utilities:

**Cisco:**

```plain
test aaa group radius alice password123 new-code
```

**MikroTik:**

```plain
/radius incoming
monitor 0
```

### Debugging

Enable verbose mode:

```json
{
  "verbose": true
}
```

Server will log:

```plain
Received Access-Request from 192.168.1.10 (ID: 42)
  User-Name: alice
  NAS-IP-Address: 192.168.1.10
  NAS-Port: 0
Authentication successful for user: alice
Sent Access-Accept to 192.168.1.10 (ID: 42)
```

## Firewall Configuration

Ensure RADIUS traffic can reach the server:

### Server-side Firewall

```bash
# Allow from specific client
sudo ufw allow from 192.168.1.10 to any port 1812 proto udp

# Allow from client network
sudo ufw allow from 192.168.1.0/24 to any port 1812 proto udp

# Allow from anywhere (not recommended)
sudo ufw allow 1812/udp
```

### Client-side Firewall

Ensure client can send to server:

```bash
# Allow outbound to RADIUS server
sudo ufw allow out to 192.168.1.100 port 1812 proto udp
```

## Troubleshooting

### Client Cannot Connect

**Problem**: No response from RADIUS server

**Debug steps:**

1. **Verify network connectivity**:

   ```bash
   ping <server-ip>
   ```

2. **Verify port is open**:

   ```bash
   nc -u -v <server-ip> 1812
   ```

3. **Check firewall**:

   ```bash
   sudo ufw status
   sudo iptables -L -n
   ```

4. **Verify server is listening**:

   ```bash
   sudo netstat -ulpn | grep 1812
   ```

### Authentication Fails

**Problem**: Server responds but rejects authentication

**Debug steps:**

1. **Verify shared secret matches**:
   - Check server config
   - Check client config
   - Secrets are case-sensitive

2. **Test with radtest**:

   ```bash
   radtest alice password123 <server-ip> 1812 <secret>
   ```

3. **Enable verbose logging**:

   ```json
   { "verbose": true }
   ```

### Wrong Client IP

**Problem**: Server receives requests from unexpected IP

**Solution**:

1. Check NAT configuration
2. Configure client to use correct source IP
3. Update server config with actual source IP

## Security Best Practices

1. **Unique Secrets**: Different secret per client or network
2. **Strong Secrets**: 16+ characters, random, complex
3. **Regular Rotation**: Change secrets every 90-180 days
4. **Network Isolation**: Keep RADIUS on isolated management network
5. **IP Restrictions**: Use firewall rules to limit client IPs
6. **Monitoring**: Log all authentication attempts
7. **Encryption**: Use IPsec or VPN for RADIUS traffic over untrusted networks

## Next Steps

- [User Configuration](users.md)
- [Server Configuration](server.md)
- [Security Best Practices](../security/overview.md)
