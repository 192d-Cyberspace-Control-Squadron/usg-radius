# User Configuration

This guide explains how to configure users for RADIUS authentication.

## User Structure

Users are defined in the `users` array in `config.json`:

```json
{
  "users": [
    {
      "username": "alice",
      "password": "password123",
      "attributes": {}
    }
  ]
}
```

## User Fields

### username

The user's login name.

- **Type**: String
- **Required**: Yes
- **Constraints**: Cannot be empty
- **Case-sensitive**: Yes

**Examples:**

```json
"username": "alice"
"username": "alice@example.com"
"username": "DOMAIN\\alice"
```

### password

The user's password in plaintext.

- **Type**: String
- **Required**: Yes
- **Storage**: Plaintext in config file
- **Transmission**: Encrypted with MD5 over network

!!! danger "Security Warning"
    Passwords are stored in plaintext in the configuration file. In production:

    - Restrict file permissions: `chmod 600 config.json`
    - Consider external authentication backends
    - Never commit config files with real passwords to version control

**Examples:**

```json
"password": "SecurePass123!"
```

### attributes

Additional RADIUS attributes to include in Access-Accept responses.

- **Type**: Object (key-value pairs)
- **Required**: No
- **Default**: `{}`

!!! info "Future Feature"
    Attribute configuration is planned for a future release. Currently, this field must be an empty object.

## User Examples

### Basic User

```json
{
  "username": "john.doe",
  "password": "MyPassword123!",
  "attributes": {}
}
```

### Multiple Users

```json
{
  "users": [
    {
      "username": "admin",
      "password": "AdminPass!2024",
      "attributes": {}
    },
    {
      "username": "alice",
      "password": "AlicePass!2024",
      "attributes": {}
    },
    {
      "username": "bob",
      "password": "BobPass!2024",
      "attributes": {}
    }
  ]
}
```

### Email-based Usernames

```json
{
  "users": [
    {
      "username": "alice@example.com",
      "password": "Password123!",
      "attributes": {}
    },
    {
      "username": "bob@example.com",
      "password": "Password456!",
      "attributes": {}
    }
  ]
}
```

### Domain Users

```json
{
  "users": [
    {
      "username": "COMPANY\\alice",
      "password": "Password123!",
      "attributes": {}
    },
    {
      "username": "COMPANY\\bob",
      "password": "Password456!",
      "attributes": {}
    }
  ]
}
```

## Managing Users

### Adding Users

1. Edit `config.json`
2. Add user to `users` array
3. Restart server

```json
{
  "users": [
    {
      "username": "new.user",
      "password": "NewUserPass!",
      "attributes": {}
    }
  ]
}
```

### Removing Users

1. Edit `config.json`
2. Remove user from `users` array
3. Restart server

### Changing Passwords

1. Edit `config.json`
2. Update user's `password` field
3. Restart server

```json
{
  "username": "alice",
  "password": "NewPassword123!"
}
```

## Password Requirements

USG RADIUS does not enforce password policies in the current version. Implement your own policies:

### Recommended Password Policy

- **Minimum length**: 12 characters
- **Complexity**: Mix of uppercase, lowercase, numbers, symbols
- **No common passwords**: Avoid "password", "123456", etc.
- **No personal information**: Avoid names, birthdates, etc.

**Strong Password Examples:**

```plain
✓ MyS3cure!Pass2024
✓ Tr0ub4dor&3
✓ correct-horse-battery-staple
✓ P@ssw0rd!Complex123
```

**Weak Password Examples:**

```plain
✗ password
✗ 123456
✗ admin
✗ alice123
```

## User Limits

The current implementation has no hard limit on the number of users. However:

- **In-memory storage**: All users loaded into RAM at startup
- **Linear search**: Authentication is O(n) with number of users
- **Recommended maximum**: 1000 users for optimal performance

For larger deployments, consider:

- External authentication backend (LDAP, AD, database)
- Custom `AuthHandler` implementation

## Authentication Testing

### Test with simple_client

```bash
cargo run --example simple_client alice password123 testing123
```

Expected output:

```plain
RADIUS Client Test
==================
Server: 127.0.0.1:1812
Username: alice
Secret: testing123

Sending Access-Request (54 bytes)...
Received response (20 bytes)

✓ Authentication SUCCESSFUL!
  Response: Access-Accept
```

### Test with radtest

```bash
radtest alice password123 localhost 1812 testing123
```

Expected output:

```plain
Sending Access-Request...
Received Access-Accept
```

## External Authentication

For production deployments, integrate with external authentication systems instead of config-file users.

### Custom Authentication Handler

Implement the `AuthHandler` trait:

```rust
use usg_radius::{AuthHandler, Attribute};
use std::collections::HashMap;

struct LdapAuthHandler {
    ldap_url: String,
    // LDAP connection details
}

impl AuthHandler for LdapAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        // Connect to LDAP
        // Bind with username and password
        // Return true if successful
        todo!("Implement LDAP authentication")
    }

    fn get_accept_attributes(&self, username: &str) -> Vec<Attribute> {
        // Query LDAP for user attributes
        // Return RADIUS attributes
        vec![]
    }

    fn get_reject_attributes(&self, username: &str) -> Vec<Attribute> {
        vec![
            Attribute::string(18, "Authentication failed").unwrap()
        ]
    }
}
```

### Database Authentication

```rust
struct DatabaseAuthHandler {
    db_conn: DatabaseConnection,
}

impl AuthHandler for DatabaseAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        // Query database for user
        // Verify password hash
        // Return result
        match self.db_conn.query_user(username) {
            Some(user) => user.verify_password(password),
            None => false,
        }
    }
}
```

See [Custom Authentication](../api/custom-auth.md) for more details.

## Security Best Practices

### Configuration File Security

1. **Restrict permissions**:

   ```bash
   chmod 600 config.json
   chown radius:radius config.json
   ```

2. **Exclude from version control**:

   ```bash
   echo "config.json" >> .gitignore
   ```

3. **Use environment-specific configs**:

   ```plain
   config.dev.json
   config.staging.json
   config.prod.json
   ```

### Password Management

1. **Use strong passwords**: 12+ characters, mixed case, symbols
2. **Rotate regularly**: Change passwords every 90 days
3. **Unique passwords**: No password reuse across accounts
4. **Monitor failed attempts**: Log and alert on repeated failures

### Migration Strategy

For existing user databases:

1. **Export users**: From existing system
2. **Convert format**: To JSON config format
3. **Validate**: Test authentication for each user
4. **Deploy**: With proper rollback plan

## Troubleshooting

### Authentication Fails

**Problem**: User authentication always fails

**Debug steps:**

1. Verify username exactly matches (case-sensitive)
2. Verify password exactly matches
3. Check server logs for errors
4. Test with verbose mode:

   ```json
   { "verbose": true }
   ```

### User Not Found

**Problem**: `Authentication failed for user: alice`

**Solution**:

1. Verify user exists in config:

   ```bash
   cat config.json | jq '.users[] | select(.username=="alice")'
   ```

2. Verify server loaded config:

   ```plain
   Server output should show: "Added user: alice"
   ```

### Case Sensitivity Issues

**Problem**: "alice" works but "Alice" fails

**Solution**: Usernames are case-sensitive. Use exact case:

```json
{
  "username": "Alice",
  "password": "password"
}
```

## Next Steps

- [Client Configuration](clients.md)
- [Custom Authentication Handlers](../api/custom-auth.md)
- [Security Best Practices](../security/overview.md)
