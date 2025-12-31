# Security Overview

RADIUS was designed in 1997, and while widely used, it has known security limitations. This guide explains the security considerations when deploying USG RADIUS.

## RADIUS Security Model

### What RADIUS Protects

✅ **User passwords** - Encrypted in transit using MD5
✅ **Message integrity** - Response Authenticator prevents tampering
✅ **Replay protection** - Request Authenticator is random
✅ **Server authentication** - Shared secret proves server identity

### What RADIUS Does NOT Protect

❌ **Usernames** - Sent in cleartext
❌ **Attributes** - Sent in cleartext (except User-Password)
❌ **Eavesdropping** - No end-to-end encryption
❌ **Client authentication** - Clients not cryptographically authenticated
❌ **Traffic analysis** - Packet metadata visible

## Cryptographic Weaknesses

### MD5 Hash Function

RADIUS uses MD5, which has known weaknesses:

- **Collision attacks**: MD5 collisions can be found in seconds
- **Pre-image attacks**: Theoretical weaknesses exist
- **Deprecated**: Considered cryptographically broken for many uses

**However**, for RADIUS:

- ✅ MD5 use is acceptable for password encryption (XOR with hash)
- ✅ Request/Response Authenticator use is acceptable
- ⚠️ Not suitable for password hashing (use bcrypt/argon2)

### Password Encryption

User-Password encryption process:

```
Encrypted = Password XOR MD5(Secret + Authenticator)
```

**Vulnerabilities:**

1. **Offline dictionary attacks** if:
   - Shared secret is weak
   - Attacker captures traffic
   - Attacker can try password guesses

2. **Known-plaintext attacks**:
   - If attacker knows some passwords
   - Can derive information about secret

**Mitigations:**

- Use strong shared secrets (16+ characters, random)
- Use network security (VPN, IPsec)
- Monitor for unusual traffic
- Implement account lockout policies

## Shared Secret Security

The shared secret is the foundation of RADIUS security.

### Secret Requirements

**Minimum:** 16 characters
**Recommended:** 24-32 characters
**Composition:** Random, high-entropy

### Generating Strong Secrets

```bash
# Linux/macOS - 32 random bytes, base64 encoded
openssl rand -base64 32

# Result:
vK3mNx8Qq7RzPtW5YhU2jLdF9GbSaE4c
```

```bash
# Alternative - hexadecimal
openssl rand -hex 24

# Result:
a3f9c2e1b5d8f0a6c9e4b2d7f1a5c8e3b6d9f2a5c8e1
```

### Secret Management

1. **Unique Secrets**: Different secret per client/network
2. **Secure Storage**:

   ```bash
   chmod 600 config.json
   chown radius:radius config.json
   ```

3. **No Version Control**: Add to `.gitignore`
4. **Regular Rotation**: Change every 90-180 days
5. **Secure Distribution**: Use encrypted channels
6. **Secure Deletion**: Overwrite when changing

### Secret Rotation Procedure

1. **Generate new secret**:

   ```bash
   NEW_SECRET=$(openssl rand -base64 32)
   echo "New secret: $NEW_SECRET"
   ```

2. **Update server** configuration with new secret

3. **Grace period**: Support both old and new secret (future feature)

4. **Update clients** one by one

5. **Verify** each client works with new secret

6. **Remove old secret** from server config

## Network Security

### Deployment Architectures

#### Insecure (Not Recommended)

```
[Client]──────Internet──────>[RADIUS Server]
          ❌ Cleartext
          ❌ No encryption
          ❌ Easily intercepted
```

**Problems:**

- Usernames visible
- Attributes visible
- Vulnerable to MITM
- Vulnerable to replay

#### Secure (Recommended)

```
[Client]──────VPN/IPsec──────>[RADIUS Server]
          ✓ Encrypted tunnel
          ✓ Authenticated
          ✓ Protected from eavesdropping
```

**Benefits:**

- All traffic encrypted
- Mutual authentication
- Perfect Forward Secrecy (with right config)

### VPN/IPsec for RADIUS

Wrap RADIUS in encrypted tunnel:

**IPsec Example:**

```bash
# Server-side
ipsec pki --gen > strongswanKey.pem
ipsec pki --pub --in strongswanKey.pem | ipsec pki --issue \
    --lifetime 3650 --cacert caCert.pem --cakey caKey.pem \
    --dn "C=US, O=Company, CN=radius.example.com" \
    --san radius.example.com > strongswanCert.pem
```

**OpenVPN Example:**

```
# Tunnel RADIUS through OpenVPN
server 10.8.0.0 255.255.255.0
push "route 192.168.1.100 255.255.255.255"
```

### Firewall Rules

Restrict RADIUS access:

```bash
# UFW - Allow only from specific network
sudo ufw allow from 192.168.1.0/24 to any port 1812 proto udp

# iptables - Allow only from specific IPs
sudo iptables -A INPUT -p udp --dport 1812 \
    -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 1812 -j DROP
```

### Network Isolation

```
┌─────────────────────────────────────┐
│     Management Network (Isolated)   │
│                                     │
│  ┌──────────┐      ┌─────────────┐ │
│  │  RADIUS  │      │  Auth DB    │ │
│  │  Server  │──────│             │ │
│  └────┬─────┘      └─────────────┘ │
│       │                             │
└───────┼─────────────────────────────┘
        │
   ┌────┴────┐
   │ Firewall│
   └────┬────┘
        │
┌───────┼─────────────────────────────┐
│  Production Network                 │
│                                     │
│  [NAS] [VPN] [WiFi APs]             │
└─────────────────────────────────────┘
```

## Authentication Security

### Password Policies

Enforce strong passwords:

```rust
struct PasswordPolicy {
    min_length: usize,
    require_uppercase: bool,
    require_lowercase: bool,
    require_numbers: bool,
    require_symbols: bool,
}

fn validate_password(password: &str, policy: &PasswordPolicy) -> bool {
    if password.len() < policy.min_length {
        return false;
    }

    if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return false;
    }

    // ... additional checks

    true
}
```

Recommended policy:

- Minimum 12 characters
- Mix of upper/lower/numbers/symbols
- No dictionary words
- No personal information

### Account Lockout

Prevent brute force attacks:

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct FailedAttempts {
    count: u32,
    last_attempt: Instant,
}

struct RateLimiter {
    attempts: HashMap<String, FailedAttempts>,
    max_attempts: u32,
    lockout_duration: Duration,
}

impl RateLimiter {
    fn check_attempt(&mut self, username: &str) -> bool {
        let now = Instant::now();

        let entry = self.attempts.entry(username.to_string())
            .or_insert(FailedAttempts {
                count: 0,
                last_attempt: now,
            });

        // Reset if lockout duration passed
        if now.duration_since(entry.last_attempt) > self.lockout_duration {
            entry.count = 0;
        }

        // Check if locked out
        if entry.count >= self.max_attempts {
            return false;
        }

        true
    }

    fn record_failure(&mut self, username: &str) {
        let entry = self.attempts.entry(username.to_string())
            .or_insert(FailedAttempts {
                count: 0,
                last_attempt: Instant::now(),
            });

        entry.count += 1;
        entry.last_attempt = Instant::now();
    }
}
```

### Multi-Factor Authentication

RADIUS supports MFA via Access-Challenge:

```
Client               Server
  │                    │
  │ Access-Request     │
  │ (username)         │
  │───────────────────>│
  │                    │
  │ Access-Challenge   │
  │ (OTP prompt)       │
  │<───────────────────│
  │                    │
  │ Access-Request     │
  │ (OTP code)         │
  │───────────────────>│
  │                    │
  │ Access-Accept      │
  │<───────────────────│
```

Implementation (future feature):

```rust
impl AuthHandler for MFAAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        // 1. Check password
        // 2. Send OTP
        // 3. Verify OTP
        // Return true only if both succeed
        todo!()
    }
}
```

## Operational Security

### Logging & Audit Trail

USG RADIUS provides comprehensive logging and JSON audit trail capabilities.

#### Structured Logging

All authentication attempts are logged using the `tracing` framework:

```rust
// Structured logging with fields
info!(
    username = %username,
    client_ip = %source_ip,
    request_id = request.identifier,
    "Authentication successful"
);

warn!(
    username = %username,
    client_ip = %source_ip,
    request_id = request.identifier,
    "Authentication failed"
);
```

**Log Levels:**

- `trace`: Extremely detailed debugging
- `debug`: Detailed debugging information
- `info`: Normal operational messages
- `warn`: Warning messages (failed auth, rate limits)
- `error`: Error messages

**Configuration:**

```json
{
  "log_level": "info"
}
```

Or use environment variable:

```bash
RUST_LOG=debug usg_radius
```

#### JSON Audit Trail

For compliance and forensic analysis, enable JSON audit logging:

```json
{
  "audit_log_path": "/var/log/radius/audit.log"
}
```

**Audit Events Logged:**

- `auth_attempt` - Every authentication request
- `auth_success` - Successful authentication
- `auth_failure` - Failed authentication
- `rate_limit_exceeded` - Rate limit violations
- `unauthorized_client` - Requests from unauthorized IPs
- `duplicate_request` - Replay attack attempts

**Audit Entry Format:**

```json
{
  "timestamp": 1735596000,
  "timestamp_iso": "2025-12-30T12:00:00Z",
  "event_type": "auth_success",
  "username": "admin",
  "client_ip": "192.168.1.50",
  "client_name": "Internal Network",
  "request_id": 42,
  "server_version": "0.1.0"
}
```

**What to log:**

- ✅ Username (success and failure)
- ✅ Source IP
- ✅ Client name (from config)
- ✅ Timestamp (Unix + ISO 8601)
- ✅ Event type
- ✅ Request ID
- ✅ Server version
- ❌ Passwords (never log passwords)

**Log Rotation:**

Use system tools like `logrotate` for audit log rotation:

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
        systemctl reload radius
    endscript
}
```

### Monitoring

Monitor for security events:

1. **Failed login patterns**:
   - Multiple failures for same user
   - Multiple users from same IP
   - Failures outside business hours

2. **Anomaly detection**:
   - Login from unusual location
   - Login at unusual time
   - Unusual number of requests

3. **Service availability**:
   - Server uptime
   - Response time
   - Request rate

### Incident Response

1. **Detection**: Automated alerting for suspicious activity

2. **Investigation**:

   ```bash
   # Check recent auth failures
   grep "REJECT" /var/log/radius.log | tail -100

   # Check specific user
   grep "user=alice" /var/log/radius.log
   ```

3. **Response**:
   - Lock compromised accounts
   - Block attacking IPs
   - Rotate shared secrets if compromised

4. **Recovery**:
   - Reset affected passwords
   - Review and update security policies
   - Document incident

## Compliance

### Regulatory Requirements

Different industries have different requirements:

**PCI DSS (Payment Card Industry):**

- Strong password policies
- Multi-factor authentication
- Encrypted transmission
- Access logging and monitoring
- Regular security audits

**HIPAA (Healthcare):**

- Access controls
- Audit logging
- Encryption in transit
- Risk assessments

**NIST Guidelines:**

- Follow NIST SP 800-63B for authentication
- Use strong cryptography
- Implement account lockout
- Monitor and log access

## Future Enhancements

Planned security improvements:

1. **RadSec (RADIUS over TLS/DTLS)**:
   - End-to-end encryption
   - Certificate-based authentication
   - Perfect Forward Secrecy

2. **Modern Crypto**:
   - Support for SHA-256
   - ChaCha20-Poly1305
   - Modern key derivation

3. **EAP Methods**:
   - EAP-TLS
   - EAP-TTLS
   - EAP-PEAP

## Security Checklist

Before deploying to production:

- [ ] Strong shared secrets (16+ characters)
- [ ] Unique secrets per client
- [ ] Firewall rules restricting access
- [ ] Network isolation or VPN
- [ ] File permissions on config (chmod 600)
- [ ] No secrets in version control
- [ ] Strong password policy
- [ ] Account lockout implemented
- [ ] Comprehensive logging enabled (`log_level: "info"`)
- [ ] JSON audit trail enabled (`audit_log_path` configured)
- [ ] Strict RFC compliance enabled (`strict_rfc_compliance: true`)
- [ ] Rate limiting configured appropriately
- [ ] Request deduplication cache enabled
- [ ] Monitoring and alerting configured
- [ ] Incident response plan documented
- [ ] Regular security audits scheduled
- [ ] Secret rotation procedure defined
- [ ] Backup and recovery tested
- [ ] Log rotation configured (logrotate)

## References

- [RFC 2865 - RADIUS](https://tools.ietf.org/html/rfc2865)
- [RFC 2866 - RADIUS Accounting](https://tools.ietf.org/html/rfc2866)
- [RFC 3579 - RADIUS EAP Support](https://tools.ietf.org/html/rfc3579)
- [RFC 6614 - RADIUS over TLS (RadSec)](https://tools.ietf.org/html/rfc6614)
- [NIST SP 800-63B - Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

## Next Steps

- [Server Configuration](../configuration/server.md)
- [Client Configuration](../configuration/clients.md)
- [Monitoring and Logging](monitoring.md) (future)
