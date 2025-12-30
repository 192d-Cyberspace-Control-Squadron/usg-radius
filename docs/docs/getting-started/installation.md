# Installation

This guide will help you install and set up the USG RADIUS server.

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Rust**: Version 1.70 or later
- **Memory**: Minimum 512MB RAM
- **Disk Space**: 100MB for installation
- **Network**: UDP port 1812 available (standard RADIUS authentication port)

### Installing Rust

If you don't have Rust installed, install it using rustup:

=== "Linux/macOS"

    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
    ```

=== "Windows"

    Download and run [rustup-init.exe](https://rustup.rs/) from the official Rust website.

Verify installation:

    ```bash
    rustc --version
    cargo --version
    ```

## Installation Methods

### From Source (Recommended)

1. **Clone the repository:**

    ```bash
    git clone https://github.com/192d-Cyberspace-Control-Squadron/usg-radius.git
    cd usg-radius
    ```

2. **Build the project:**

    ```bash
    cargo build --release
    ```

    The compiled binary will be at `target/release/usg_radius`.

3. **Optional: Install to system:**

    ```bash
    cargo install --path .
    ```

    This installs the binary to `~/.cargo/bin/usg_radius`.

### Pre-built Binaries

!!! info "Coming Soon"
    Pre-built binaries for common platforms will be available in future releases.

## Verification

Verify the installation by checking the version:

```bash
cargo run -- --version
# or if installed:
usg_radius --version
```

Expected output:

```
USG RADIUS Server v0.1.0
Based on RFC 2865 (RADIUS)
```

## First Run

On first run, the server will create an example configuration file:

```bash
cargo run --release
```

Expected output:

```
USG RADIUS Server v0.1.0
Based on RFC 2865 (RADIUS)

Warning: Could not load config file: No such file or directory (os error 2)
Creating example configuration at: config.json
Please edit config.json and restart the server
```

The server creates a default `config.json` file with example users and settings.

## Configuration

Edit the generated `config.json` file:

```json
{
  "listen_address": "0.0.0.0",
  "listen_port": 1812,
  "secret": "testing123",
  "clients": [
    {
      "address": "192.168.1.0/24",
      "secret": "client_secret_1",
      "name": "Internal Network"
    }
  ],
  "users": [
    {
      "username": "admin",
      "password": "admin123",
      "attributes": {}
    }
  ],
  "verbose": false
}
```

!!! warning "Security"
    Change the default secret and passwords before deploying to production!

## Starting the Server

After configuring, start the server:

```bash
cargo run --release
```

Expected output:

```
USG RADIUS Server v0.1.0
Based on RFC 2865 (RADIUS)

Loaded configuration from: config.json
Added user: admin
RADIUS server listening on 0.0.0.0:1812

Server started successfully!
Press Ctrl+C to stop
```

## Testing

Test the server using the included client:

```bash
cargo run --example simple_client admin admin123 testing123
```

Expected output:

```
RADIUS Client Test
==================
Server: 127.0.0.1:1812
Username: admin
Secret: testing123

Sending Access-Request (54 bytes)...
Received response (20 bytes)

✓ Authentication SUCCESSFUL!
  Response: Access-Accept
```

## Running as a Service

### Linux (systemd)

Create a systemd service file at `/etc/systemd/system/usg-radius.service`:

```ini
[Unit]
Description=USG RADIUS Server
After=network.target

[Service]
Type=simple
User=radius
Group=radius
WorkingDirectory=/opt/usg-radius
ExecStart=/opt/usg-radius/target/release/usg_radius
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable usg-radius
sudo systemctl start usg-radius
sudo systemctl status usg-radius
```

### Docker

!!! info "Coming Soon"
    Docker image and compose files will be available in future releases.

## Firewall Configuration

Ensure UDP port 1812 is open:

=== "UFW (Ubuntu)"

    ```bash
    sudo ufw allow 1812/udp
    ```

=== "firewalld (RHEL/CentOS)"

    ```bash
    sudo firewall-cmd --permanent --add-port=1812/udp
    sudo firewall-cmd --reload
    ```

=== "iptables"

    ```bash
    sudo iptables -A INPUT -p udp --dport 1812 -j ACCEPT
    ```

## Troubleshooting

### Port Already in Use

If port 1812 is already in use:

1. Check what's using the port:

   ```bash
   sudo lsof -i :1812
   # or
   sudo netstat -tulpn | grep 1812
   ```

2. Either stop the conflicting service or change the port in `config.json`

### Permission Denied

On Linux, binding to ports below 1024 requires root privileges. Port 1812 doesn't require root, but if you get permission errors:

```bash
# Run with sudo
sudo cargo run --release

# Or use capabilities
sudo setcap 'cap_net_bind_service=+ep' target/release/usg_radius
```

### Cannot Connect from Remote Host

1. Verify the server is listening on `0.0.0.0` (not `127.0.0.1`)
2. Check firewall rules
3. Verify the client secret matches the server configuration

## Next Steps

- [Configure Users and Clients](../configuration/users.md)
- [Test with RADIUS Clients](../examples/basic-auth.md)
- [Security Best Practices](../security/overview.md)
