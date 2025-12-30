# Basic Authentication Example

This example demonstrates basic RADIUS authentication using the USG RADIUS server.

## Scenario

Authenticate users against a RADIUS server for VPN access.

## Setup

### 1. Start the RADIUS Server

Create `config.json`:

```json
{
  "listen_address": "0.0.0.0",
  "listen_port": 1812,
  "secret": "MySecretKey123!",
  "clients": [
    {
      "address": "127.0.0.1",
      "secret": "MySecretKey123!",
      "name": "Test Client"
    }
  ],
  "users": [
    {
      "username": "alice",
      "password": "AlicePassword123!",
      "attributes": {}
    },
    {
      "username": "bob",
      "password": "BobPassword456!",
      "attributes": {}
    }
  ],
  "verbose": true
}
```

Start the server:

```bash
cargo run --release
```

Expected output:

```plain
USG RADIUS Server v0.1.0
Based on RFC 2865 (RADIUS)

Loaded configuration from: config.json
Added user: alice
Added user: bob
RADIUS server listening on 0.0.0.0:1812

Server started successfully!
Press Ctrl+C to stop
```

### 2. Test with Simple Client

Use the included test client:

```bash
cargo run --example simple_client alice AlicePassword123! MySecretKey123!
```

Expected output:

```plain
RADIUS Client Test
==================
Server: 127.0.0.1:1812
Username: alice
Secret: MySecretKey123!

Sending Access-Request (76 bytes)...
Received response (20 bytes)

✓ Authentication SUCCESSFUL!
  Response: Access-Accept

Response Details:
  Identifier: 1
  Attributes: 0
```

Server output:

```plain
Received AccessRequest from 127.0.0.1 (ID: 1)
Authentication request for user: alice
Authentication successful for user: alice
Sent AccessAccept to 127.0.0.1 (ID: 1)
```

### 3. Test Failed Authentication

Try with wrong password:

```bash
cargo run --example simple_client alice WrongPassword MySecretKey123!
```

Expected output:

```plain
✗ Authentication FAILED!
  Response: Access-Reject
  Message: Authentication failed
```

Server output:

```plain
Received AccessRequest from 127.0.0.1 (ID: 1)
Authentication request for user: alice
Authentication failed for user: alice
Sent AccessReject to 127.0.0.1 (ID: 1)
```

## Using radtest

Install FreeRADIUS utilities:

```bash
# Ubuntu/Debian
sudo apt-get install freeradius-utils

# macOS
brew install freeradius-server
```

Test authentication:

```bash
radtest alice AlicePassword123! 127.0.0.1 1812 MySecretKey123!
```

Expected output:

```plain
Sending Access-Request Id 147 from 0.0.0.0:52891 to 127.0.0.1:1812
 User-Name = "alice"
 User-Password = "AlicePassword123!"
 NAS-IP-Address = 127.0.0.1
 NAS-Port = 0
 Message-Authenticator = 0x00
Received Access-Accept Id 147 from 127.0.0.1:1812 to 0.0.0.0:52891 length 20
```

## Client Implementation

Here's the complete client code:

```rust
use std::net::UdpSocket;
use usg_radius::{
    auth::{encrypt_user_password, generate_request_authenticator},
    Attribute, AttributeType, Code, Packet,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configuration
    let server_addr = "127.0.0.1:1812";
    let secret = b"MySecretKey123!";
    let username = "alice";
    let password = "AlicePassword123!";

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server_addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    // Generate request authenticator
    let request_auth = generate_request_authenticator();

    // Create Access-Request packet
    let mut packet = Packet::new(Code::AccessRequest, 1, request_auth);

    // Add User-Name attribute
    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, username)?
    );

    // Add User-Password attribute (encrypted)
    let encrypted_password = encrypt_user_password(password, secret, &request_auth);
    packet.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_password)?
    );

    // Add NAS-IP-Address (optional)
    packet.add_attribute(
        Attribute::ipv4(AttributeType::NasIpAddress as u8, [127, 0, 0, 1])?
    );

    // Encode and send packet
    let request_data = packet.encode()?;
    println!("Sending Access-Request ({} bytes)...", request_data.len());
    socket.send(&request_data)?;

    // Receive response
    let mut buffer = vec![0u8; 4096];
    let len = socket.recv(&mut buffer)?;
    println!("Received response ({} bytes)", len);

    // Decode response
    let response = Packet::decode(&buffer[..len])?;

    // Handle response
    match response.code {
        Code::AccessAccept => {
            println!("\n✓ Authentication SUCCESSFUL!");
            println!("  Response: Access-Accept");

            // Show Reply-Message if present
            for attr in response.find_all_attributes(AttributeType::ReplyMessage as u8) {
                if let Ok(msg) = attr.as_string() {
                    println!("  Message: {}", msg);
                }
            }
        }
        Code::AccessReject => {
            println!("\n✗ Authentication FAILED!");
            println!("  Response: Access-Reject");

            // Show Reply-Message if present
            for attr in response.find_all_attributes(AttributeType::ReplyMessage as u8) {
                if let Ok(msg) = attr.as_string() {
                    println!("  Message: {}", msg);
                }
            }
        }
        _ => {
            println!("\n? Unexpected response: {:?}", response.code);
        }
    }

    Ok(())
}
```

## Packet Flow

### Successful Authentication

```plain
Client                                  Server
  │                                       │
  │  1. Generate Request Authenticator    │
  │     (16 random bytes)                 │
  │                                       │
  │  2. Encrypt password with:            │
  │     MD5(secret + request_auth)        │
  │                                       │
  │  3. Build Access-Request:             │
  │     - Code: 1                         │
  │     - ID: 1                           │
  │     - Authenticator: [random]         │
  │     - User-Name: "alice"              │
  │     - User-Password: [encrypted]      │
  │     - NAS-IP-Address: 127.0.0.1       │
  │                                       │
  │  Access-Request                       │
  │──────────────────────────────────────>│
  │                                       │
  │                                       │  4. Decrypt password
  │                                       │  5. Verify credentials
  │                                       │  6. Calculate Response Auth:
  │                                       │     MD5(Code+ID+Len+ReqAuth+
  │                                       │         Attrs+Secret)
  │                                       │
  │              Access-Accept            │
  │<──────────────────────────────────────│
  │     - Code: 2                         │
  │     - ID: 1                           │
  │     - Authenticator: [calculated]     │
  │                                       │
  │  7. Verify Response Authenticator     │
  │  8. Grant access                      │
```

### Failed Authentication

```plain
Client                                  Server
  │                                       │
  │  Access-Request                       │
  │  (username: alice, password: wrong)   │
  │──────────────────────────────────────>│
  │                                       │
  │                                       │  Decrypt password
  │                                       │  Verify credentials
  │                                       │  ✗ Password mismatch
  │                                       │
  │              Access-Reject            │
  │<──────────────────────────────────────│
  │     - Reply-Message: "Auth failed"    │
  │                                       │
  │  Deny access                          │
```

## Attributes in Request

The client sends these attributes in Access-Request:

| Type | Name | Value | Required |
|------|------|-------|----------|
| 1 | User-Name | "alice" | Yes |
| 2 | User-Password | [encrypted] | Yes |
| 4 | NAS-IP-Address | 127.0.0.1 | Recommended |

## Attributes in Response

The server may include these attributes in Access-Accept:

| Type | Name | Example | Purpose |
|------|------|---------|---------|
| 18 | Reply-Message | "Welcome!" | User message |
| 27 | Session-Timeout | 3600 | Max session time |
| 28 | Idle-Timeout | 900 | Max idle time |
| 8 | Framed-IP-Address | 10.0.0.100 | IP to assign |

## Common Issues

### Connection Refused

**Problem**: `Connection refused`

**Solution**:

1. Verify server is running
2. Check server is listening on correct port:

   ```bash
   netstat -ulpn | grep 1812
   ```

3. Check firewall rules

### No Response

**Problem**: Request sent but no response received

**Solution**:

1. Check secret matches on both sides
2. Enable verbose mode on server
3. Verify network connectivity:

   ```bash
   ping 127.0.0.1
   ```

### Authentication Always Fails

**Problem**: Server responds but always rejects

**Solution**:

1. Verify username/password exact match (case-sensitive)
2. Check server logs for reason
3. Enable verbose mode to see decrypted password

## Next Steps

- [WiFi Authentication Example](wifi-auth.md)
- [VPN Integration Example](vpn-integration.md)
- [Custom Client Example](custom-client.md)
