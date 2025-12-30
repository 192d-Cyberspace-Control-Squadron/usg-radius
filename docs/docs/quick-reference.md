# Quick Reference

Fast reference for common tasks and commands.

## Installation

```bash
# Clone and build
git clone https://github.com/192d-Cyberspace-Control-Squadron/usg-radius.git
cd usg-radius
cargo build --release

# Run
cargo run --release
```

## Configuration

### Minimal Config

```json
{
  "listen_address": "0.0.0.0",
  "listen_port": 1812,
  "secret": "testing123",
  "users": [
    {
      "username": "alice",
      "password": "password123",
      "attributes": {}
    }
  ]
}
```

### Production Config

```json
{
  "listen_address": "0.0.0.0",
  "listen_port": 1812,
  "secret": "SecureSecret!2024",
  "clients": [
    {
      "address": "192.168.1.0/24",
      "secret": "ClientSecret!123",
      "name": "WiFi APs"
    }
  ],
  "users": [],
  "verbose": false
}
```

## Testing

### Using simple_client

```bash
cargo run --example simple_client USERNAME PASSWORD SECRET [SERVER]
```

### Using radtest

```bash
radtest USERNAME PASSWORD SERVER PORT SECRET
```

## Common Commands

### Start Server

```bash
cargo run --release
# or with custom config
cargo run --release -- /path/to/config.json
```

### Run Tests

```bash
cargo test
```

### Build Documentation

```bash
cargo doc --open
```

### Generate Secret

```bash
openssl rand -base64 32
```

## Packet Types

| Code | Name | Direction |
|------|------|-----------|
| 1 | Access-Request | Client → Server |
| 2 | Access-Accept | Server → Client |
| 3 | Access-Reject | Server → Client |
| 11 | Access-Challenge | Server → Client |
| 12 | Status-Server | Client → Server |

## Common Attributes

| Type | Name | Usage |
|------|------|-------|
| 1 | User-Name | Username |
| 2 | User-Password | Password (encrypted) |
| 4 | NAS-IP-Address | NAS IP |
| 6 | Service-Type | Service type |
| 8 | Framed-IP-Address | IP to assign |
| 18 | Reply-Message | Message to user |
| 27 | Session-Timeout | Session timeout |

## API Quick Start

### Create Packet

```rust
use usg_radius::{Packet, Code};

let packet = Packet::new(
    Code::AccessRequest,
    1,
    [0u8; 16]
);
```

### Add Attribute

```rust
use usg_radius::{Attribute, AttributeType};

packet.add_attribute(
    Attribute::string(1, "alice")?
);
```

### Encrypt Password

```rust
use usg_radius::auth::encrypt_user_password;

let encrypted = encrypt_user_password(
    "password",
    b"secret",
    &authenticator
);
```

### Custom Auth Handler

```rust
use usg_radius::AuthHandler;

struct MyHandler;

impl AuthHandler for MyHandler {
    fn authenticate(&self, user: &str, pass: &str) -> bool {
        // Your logic
        true
    }
}
```

## Troubleshooting

### Server Won't Start

```bash
# Check port
sudo lsof -i :1812

# Check permissions
ls -l config.json

# Check config
cat config.json | python -m json.tool
```

### Auth Fails

1. Check username/password (case-sensitive)
2. Check secret matches
3. Enable verbose: `"verbose": true`
4. Check server logs

### No Response

1. Check firewall rules
2. Verify server is running
3. Check client can reach server: `ping SERVER_IP`

## Security Checklist

- [ ] Strong secrets (16+ chars)
- [ ] Unique secrets per client
- [ ] File permissions (chmod 600)
- [ ] Firewall configured
- [ ] No secrets in git
- [ ] Logging enabled
- [ ] Regular secret rotation

## Port Reference

| Port | Protocol | Purpose |
|------|----------|---------|
| 1812 | UDP | RADIUS Authentication |
| 1813 | UDP | RADIUS Accounting |
| 1645 | UDP | Legacy RADIUS Auth |
| 1646 | UDP | Legacy RADIUS Acct |

## Error Codes

| Error | Meaning |
|-------|---------|
| Connection refused | Server not running |
| Permission denied | Need elevated privileges |
| Address in use | Port already used |
| Invalid config | Config syntax error |

## File Locations

```
usg-radius/
├── config.json           # Server configuration
├── Cargo.toml            # Project metadata
├── src/
│   ├── main.rs           # Server binary
│   ├── lib.rs            # Library exports
│   ├── packet/           # Packet handling
│   ├── attributes/       # Attribute handling
│   ├── auth.rs           # Cryptographic ops
│   ├── server.rs         # Server implementation
│   └── config.rs         # Config management
└── examples/
    └── simple_client.rs  # Example client
```

## Environment

```bash
# Rust version
rustc --version

# Cargo version
cargo --version

# Build profile
cargo build --release    # Production
cargo build              # Development

# Run with logging
RUST_LOG=debug cargo run
```

## Links

- [GitHub Repository](https://github.com/192d-Cyberspace-Control-Squadron/usg-radius)
- [RFC 2865 (RADIUS)](https://tools.ietf.org/html/rfc2865)
- [Full Documentation](index.md)
