# API Overview

USG RADIUS can be used as a Rust library to build custom RADIUS servers and clients.

## Adding to Your Project

Add to your `Cargo.toml`:

```toml
[dependencies]
usg_radius = "0.1.0"
```

## Core Modules

### Packets

Handle RADIUS packet encoding and decoding.

```rust
use usg_radius::{Packet, Code};

// Create a packet
let packet = Packet::new(
    Code::AccessRequest,
    identifier,
    authenticator
);

// Encode to bytes
let bytes = packet.encode()?;

// Decode from bytes
let decoded = Packet::decode(&bytes)?;
```

[Learn more →](packets.md)

### Attributes

Work with RADIUS attributes.

```rust
use usg_radius::{Attribute, AttributeType};

// Create string attribute
let username = Attribute::string(
    AttributeType::UserName as u8,
    "alice"
)?;

// Create integer attribute
let timeout = Attribute::integer(
    AttributeType::SessionTimeout as u8,
    3600
)?;
```

[Learn more →](attributes.md)

### Authentication

Cryptographic operations for RADIUS.

```rust
use usg_radius::auth::{
    generate_request_authenticator,
    encrypt_user_password,
    calculate_response_authenticator,
};

// Generate request authenticator
let req_auth = generate_request_authenticator();

// Encrypt password
let encrypted = encrypt_user_password(
    "password",
    secret,
    &req_auth
);

// Calculate response authenticator
let resp_auth = calculate_response_authenticator(
    &packet,
    &req_auth,
    secret
);
```

[Learn more →](authentication.md)

### Server

Build custom RADIUS servers.

```rust
use usg_radius::{RadiusServer, ServerConfig};
use std::sync::Arc;

// Create server config
let config = ServerConfig::new(
    bind_addr,
    secret,
    Arc::new(auth_handler)
);

// Create and run server
let server = RadiusServer::new(config).await?;
server.run().await?;
```

[Learn more →](server.md)

## Custom Authentication

Implement the `AuthHandler` trait for custom authentication logic:

```rust
use usg_radius::{AuthHandler, Attribute};

struct MyAuthHandler {
    // Your fields
}

impl AuthHandler for MyAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        // Your authentication logic
        true
    }

    fn get_accept_attributes(&self, username: &str) -> Vec<Attribute> {
        // Attributes for Access-Accept
        vec![]
    }

    fn get_reject_attributes(&self, username: &str) -> Vec<Attribute> {
        // Attributes for Access-Reject
        vec![]
    }
}
```

[Learn more →](custom-auth.md)

## Building a Client

Create a RADIUS client to test your server:

```rust
use usg_radius::{Packet, Code, Attribute, AttributeType};
use usg_radius::auth::{
    generate_request_authenticator,
    encrypt_user_password,
};
use std::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create socket
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("127.0.0.1:1812")?;

    // Generate request authenticator
    let req_auth = generate_request_authenticator();

    // Create Access-Request
    let mut packet = Packet::new(Code::AccessRequest, 1, req_auth);

    // Add attributes
    packet.add_attribute(
        Attribute::string(AttributeType::UserName as u8, "alice")?
    );

    let encrypted_pwd = encrypt_user_password(
        "password",
        b"secret",
        &req_auth
    );
    packet.add_attribute(
        Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd)?
    );

    // Send request
    let data = packet.encode()?;
    socket.send(&data)?;

    // Receive response
    let mut buffer = vec![0u8; 4096];
    let len = socket.recv(&mut buffer)?;

    // Decode response
    let response = Packet::decode(&buffer[..len])?;

    match response.code {
        Code::AccessAccept => println!("Authenticated!"),
        Code::AccessReject => println!("Failed!"),
        _ => println!("Unexpected response"),
    }

    Ok(())
}
```

[See full example →](../examples/basic-client.md)

## Error Handling

USG RADIUS uses the `thiserror` crate for error handling:

```rust
use usg_radius::{PacketError, ServerError};

// Packet errors
match Packet::decode(&data) {
    Ok(packet) => { /* ... */ },
    Err(PacketError::InvalidLength(len)) => {
        eprintln!("Invalid packet length: {}", len);
    },
    Err(PacketError::InvalidCode(code)) => {
        eprintln!("Invalid packet code: {}", code);
    },
    Err(e) => {
        eprintln!("Packet error: {}", e);
    }
}

// Server errors
match server.run().await {
    Ok(_) => {},
    Err(ServerError::AuthFailed) => {
        eprintln!("Authentication failed");
    },
    Err(ServerError::Io(e)) => {
        eprintln!("IO error: {}", e);
    },
    Err(e) => {
        eprintln!("Server error: {}", e);
    }
}
```

## Type Reference

### Core Types

- **`Code`**: RADIUS packet type enum
- **`Packet`**: RADIUS packet structure
- **`Attribute`**: RADIUS attribute
- **`AttributeType`**: Standard attribute types enum

### Server Types

- **`RadiusServer`**: RADIUS server
- **`ServerConfig`**: Server configuration
- **`AuthHandler`**: Authentication handler trait
- **`SimpleAuthHandler`**: In-memory authentication

### Error Types

- **`PacketError`**: Packet encoding/decoding errors
- **`ServerError`**: Server operation errors

## Example Projects

### Simple Server

```rust
use usg_radius::{
    RadiusServer, ServerConfig, SimpleAuthHandler,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create auth handler
    let mut handler = SimpleAuthHandler::new();
    handler.add_user("alice", "password");

    // Create server
    let config = ServerConfig::new(
        "0.0.0.0:1812".parse()?,
        b"secret",
        Arc::new(handler)
    );

    let server = RadiusServer::new(config).await?;
    server.run().await?;

    Ok(())
}
```

### Database-backed Server

```rust
use usg_radius::{AuthHandler, Attribute, AttributeType};
use sqlx::PgPool;

struct DatabaseAuthHandler {
    db: PgPool,
}

impl DatabaseAuthHandler {
    async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let db = PgPool::connect(database_url).await?;
        Ok(DatabaseAuthHandler { db })
    }
}

impl AuthHandler for DatabaseAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        // Query database in separate runtime
        let db = self.db.clone();
        let username = username.to_string();
        let password = password.to_string();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let result = sqlx::query!(
                    "SELECT password_hash FROM users WHERE username = $1",
                    username
                )
                .fetch_optional(&db)
                .await;

                match result {
                    Ok(Some(row)) => {
                        // Verify password hash
                        bcrypt::verify(&password, &row.password_hash)
                            .unwrap_or(false)
                    },
                    _ => false
                }
            })
        })
    }
}
```

## Testing

USG RADIUS includes comprehensive tests:

```bash
cargo test
```

### Unit Tests

Test individual components:

```rust
#[test]
fn test_packet_encode_decode() {
    let packet = Packet::new(Code::AccessRequest, 42, [1u8; 16]);
    let encoded = packet.encode().unwrap();
    let decoded = Packet::decode(&encoded).unwrap();
    assert_eq!(decoded.code, Code::AccessRequest);
}
```

### Integration Tests

Test complete flows:

```rust
#[tokio::test]
async fn test_authentication_flow() {
    // Start server
    // Send request
    // Verify response
}
```

## Documentation

Generate API documentation:

```bash
cargo doc --open
```

## Next Steps

- [Packet API](packets.md)
- [Attribute API](attributes.md)
- [Custom Authentication](custom-auth.md)
- [Examples](../examples/basic-client.md)
