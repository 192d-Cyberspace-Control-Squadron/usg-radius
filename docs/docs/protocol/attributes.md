# RADIUS Attributes

This page provides a comprehensive reference of RADIUS attributes supported by USG RADIUS.

## Attribute Format

Each attribute has the following structure:

```
 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     |  Value ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Type**: 1 byte, identifies the attribute
- **Length**: 1 byte, total length including type and length (2-255)
- **Value**: 0-253 bytes, attribute-specific data

## Data Types

| Type | Description | Format |
|------|-------------|--------|
| **String** | UTF-8 text | 1-253 bytes |
| **Integer** | 32-bit unsigned | Big-endian, 4 bytes |
| **IPv4 Address** | IP address | 4 bytes |
| **Time** | Seconds since epoch | Big-endian, 4 bytes |

## Standard Attributes (RFC 2865)

### User Information

#### User-Name (1)

User's identity for authentication.

- **Type**: String
- **Length**: 3-255
- **Direction**: Request
- **Required**: Yes (in Access-Request)

```rust
let attr = Attribute::string(1, "alice@example.com")?;
```

#### User-Password (2)

User's password, encrypted using MD5.

- **Type**: String (encrypted)
- **Length**: 18-130 (minimum 16 bytes)
- **Direction**: Request
- **Required**: Yes (unless using CHAP/EAP)
- **Encryption**: MD5 with shared secret and Request Authenticator

!!! warning
    Never send unencrypted passwords. The library handles encryption automatically.

```rust
use usg_radius::auth::encrypt_user_password;

let encrypted = encrypt_user_password(
    "password123",
    secret,
    &authenticator
);
let attr = Attribute::new(2, encrypted)?;
```

#### CHAP-Password (3)

CHAP-encrypted password for stronger authentication.

- **Type**: String
- **Length**: 19 (1 byte CHAP ID + 16 bytes hash)
- **Direction**: Request

### NAS Information

#### NAS-IP-Address (4)

IP address of the Network Access Server.

- **Type**: IPv4 Address
- **Length**: 6
- **Direction**: Request
- **Required**: Yes (unless NAS-Identifier present)

```rust
let attr = Attribute::ipv4(4, [192, 168, 1, 1])?;
```

#### NAS-Port (5)

Physical port number of the NAS.

- **Type**: Integer
- **Length**: 6
- **Direction**: Request

```rust
let attr = Attribute::integer(5, 0)?;
```

#### NAS-Identifier (32)

String identifying the NAS.

- **Type**: String
- **Length**: 3-255
- **Direction**: Request
- **Required**: Yes (unless NAS-IP-Address present)

```rust
let attr = Attribute::string(32, "nas01.example.com")?;
```

#### NAS-Port-Type (61)

Type of port used by the NAS.

- **Type**: Integer (enumerated)
- **Length**: 6
- **Direction**: Request

**Values:**

| Value | Description |
|-------|-------------|
| 0 | Async |
| 1 | Sync |
| 2 | ISDN Sync |
| 3 | ISDN Async V.120 |
| 4 | ISDN Async V.110 |
| 5 | Virtual |
| 15 | Ethernet |
| 19 | Wireless - IEEE 802.11 |

### Service Parameters

#### Service-Type (6)

Type of service requested.

- **Type**: Integer (enumerated)
- **Length**: 6
- **Direction**: Request/Response

**Values:**

| Value | Description |
|-------|-------------|
| 1 | Login |
| 2 | Framed |
| 3 | Callback Login |
| 4 | Callback Framed |
| 5 | Outbound |
| 6 | Administrative |
| 7 | NAS Prompt |
| 8 | Authenticate Only |
| 9 | Callback NAS Prompt |

#### Framed-Protocol (7)

Framing protocol to use.

- **Type**: Integer (enumerated)
- **Length**: 6
- **Direction**: Response

**Values:**

| Value | Description |
|-------|-------------|
| 1 | PPP |
| 2 | SLIP |
| 3 | ARAP |
| 4 | Gandalf |
| 5 | Xylogics |

#### Framed-IP-Address (8)

IP address to assign to user.

- **Type**: IPv4 Address
- **Length**: 6
- **Direction**: Response

```rust
let attr = Attribute::ipv4(8, [10, 0, 0, 100])?;
```

#### Framed-IP-Netmask (9)

Netmask for user's IP address.

- **Type**: IPv4 Address
- **Length**: 6
- **Direction**: Response

```rust
let attr = Attribute::ipv4(9, [255, 255, 255, 0])?;
```

#### Framed-MTU (12)

Maximum Transmission Unit for framed connection.

- **Type**: Integer
- **Length**: 6
- **Direction**: Response
- **Range**: 64-65535

### Session Management

#### Session-Timeout (27)

Maximum session duration in seconds.

- **Type**: Integer
- **Length**: 6
- **Direction**: Response

```rust
// 1 hour session
let attr = Attribute::integer(27, 3600)?;
```

#### Idle-Timeout (28)

Maximum idle time before disconnect.

- **Type**: Integer
- **Length**: 6
- **Direction**: Response

```rust
// 15 minute idle timeout
let attr = Attribute::integer(28, 900)?;
```

#### Termination-Action (29)

Action to take when service completes.

- **Type**: Integer (enumerated)
- **Length**: 6
- **Direction**: Response

**Values:**

| Value | Description |
|-------|-------------|
| 0 | Default |
| 1 | RADIUS-Request |

### Messages and State

#### Reply-Message (18)

Message to display to user.

- **Type**: String
- **Length**: 3-255
- **Direction**: Response
- **Multiple**: Allowed

```rust
let attr = Attribute::string(18, "Welcome to the network!")?;
```

!!! tip
    Multiple Reply-Message attributes can be included. They should be displayed in order.

#### State (24)

State information for multi-round authentication.

- **Type**: String
- **Length**: 3-255
- **Direction**: Challenge/Response

Used with Access-Challenge for stateful authentication:

```rust
// Server sends challenge with state
let state = Attribute::new(24, session_state)?;

// Client includes state in next request
```

#### Class (25)

Arbitrary class information.

- **Type**: String
- **Length**: 3-255
- **Direction**: Response

### Station Identification

#### Called-Station-Id (30)

Phone number or identifier called by user.

- **Type**: String
- **Length**: 3-255
- **Direction**: Request

For WiFi: AP MAC address and SSID:

```
"00-11-22-33-44-55:MyNetwork"
```

#### Calling-Station-Id (31)

Phone number or identifier of user.

- **Type**: String
- **Length**: 3-255
- **Direction**: Request

For WiFi: Client MAC address:

```
"AA-BB-CC-DD-EE-FF"
```

### Advanced Features

#### Vendor-Specific (26)

Vendor-specific attributes.

- **Type**: Variable
- **Length**: 7-255
- **Direction**: Both

Format:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     |            Vendor-Id
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     Vendor-Id (cont)           |  Vendor-Specific...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Proxy-State (33)

State information for proxy servers.

- **Type**: String
- **Length**: 3-255
- **Direction**: Both
- **Usage**: Proxy chains

#### Message-Authenticator (80)

HMAC-MD5 message authentication (RFC 2869).

- **Type**: String
- **Length**: 18 (16 bytes hash + 2)
- **Direction**: Both
- **Purpose**: Stronger authentication than Response Authenticator

## Accounting Attributes (RFC 2866)

These attributes are used in Accounting-Request and Accounting-Response packets.

### Acct-Status-Type (40)

Type of accounting record.

- **Type**: Integer (enumerated)
- **Length**: 6

**Values:**

| Value | Description |
|-------|-------------|
| 1 | Start |
| 2 | Stop |
| 3 | Interim-Update |
| 7 | Accounting-On |
| 8 | Accounting-Off |

### Acct-Session-Id (44)

Unique session identifier.

- **Type**: String
- **Length**: 3-255
- **Required**: Yes (in accounting)

```rust
let attr = Attribute::string(44, "session-12345")?;
```

### Session Counters

#### Acct-Input-Octets (42)

Bytes received from user.

- **Type**: Integer
- **Length**: 6

#### Acct-Output-Octets (43)

Bytes sent to user.

- **Type**: Integer
- **Length**: 6

#### Acct-Input-Packets (47)

Packets received from user.

- **Type**: Integer
- **Length**: 6

#### Acct-Output-Packets (48)

Packets sent to user.

- **Type**: Integer
- **Length**: 6

#### Acct-Session-Time (46)

Session duration in seconds.

- **Type**: Integer
- **Length**: 6

## Usage Examples

### Creating Attributes

```rust
use usg_radius::{Attribute, AttributeType};

// String attribute
let username = Attribute::string(
    AttributeType::UserName as u8,
    "alice"
)?;

// Integer attribute
let timeout = Attribute::integer(
    AttributeType::SessionTimeout as u8,
    3600
)?;

// IPv4 attribute
let ip = Attribute::ipv4(
    AttributeType::FramedIpAddress as u8,
    [10, 0, 0, 100]
)?;
```

### Reading Attributes

```rust
// Find attribute by type
if let Some(attr) = packet.find_attribute(1) {
    let username = attr.as_string()?;
    println!("Username: {}", username);
}

// Find all attributes of a type
let messages = packet.find_all_attributes(18);
for msg in messages {
    if let Ok(text) = msg.as_string() {
        println!("Message: {}", text);
    }
}

// Access attribute value
match attr.as_integer() {
    Ok(value) => println!("Timeout: {} seconds", value),
    Err(e) => eprintln!("Not an integer: {}", e),
}
```

## Attribute Encoding

USG RADIUS handles attribute encoding automatically:

```rust
// Encoding
let bytes = attribute.encode()?;

// Decoding
let attribute = Attribute::decode(&bytes)?;
```

## Next Steps

- [Authentication Methods](authentication.md)
- [Packet Structure](overview.md#packet-structure)
- [API Reference](../api/attributes.md)
