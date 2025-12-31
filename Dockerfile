# USG RADIUS Server - Production Docker Image
# Multi-stage build for minimal image size

# Build stage
FROM rust:alpine as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build release binary
RUN cargo build --release --bin usg_radius

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 999 -s /bin/false radius

# Copy binary from builder
COPY --from=builder /build/target/release/usg_radius /usr/local/bin/usg_radius

# Create directories
RUN mkdir -p /etc/radius /var/log/radius \
    && chown radius:radius /etc/radius /var/log/radius

# Copy example config
COPY examples/configs/docker.json /etc/radius/config.example.json

# Set user
USER radius

# Expose RADIUS ports
EXPOSE 1812/udp 1813/udp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD /usr/local/bin/usg_radius --version || exit 1

# Default command
CMD ["/usr/local/bin/usg_radius", "/etc/radius/config.json"]
