use crate::audit::{AuditEntry, AuditEventType, AuditLogger};
use crate::cache::{RequestCache, RequestFingerprint};
use crate::config::Config;
use crate::ratelimit::{RateLimitConfig, RateLimiter};
use radius_proto::attributes::{Attribute, AttributeType};
use radius_proto::auth::{calculate_response_authenticator, decrypt_user_password};
use radius_proto::{validate_packet, Code, Packet, PacketError, ValidationMode};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Packet error: {0}")]
    Packet(#[from] PacketError),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Invalid client")]
    InvalidClient,
    #[error("Duplicate request")]
    DuplicateRequest,
    #[error("Rate limit exceeded")]
    RateLimited,
}

/// Authentication handler trait
///
/// Implement this trait to provide custom authentication logic.
pub trait AuthHandler: Send + Sync {
    /// Authenticate a user with username and password
    ///
    /// Returns true if authentication succeeds, false otherwise.
    fn authenticate(&self, username: &str, password: &str) -> bool;

    /// Get additional attributes to include in Access-Accept response
    fn get_accept_attributes(&self, _username: &str) -> Vec<Attribute> {
        vec![]
    }

    /// Get additional attributes to include in Access-Reject response
    fn get_reject_attributes(&self, _username: &str) -> Vec<Attribute> {
        vec![Attribute::string(
            AttributeType::ReplyMessage as u8,
            "Authentication failed",
        )
        .unwrap()]
    }
}

/// Simple in-memory authentication handler for testing
pub struct SimpleAuthHandler {
    users: std::collections::HashMap<String, String>,
}

impl SimpleAuthHandler {
    pub fn new() -> Self {
        SimpleAuthHandler {
            users: std::collections::HashMap::new(),
        }
    }

    pub fn add_user(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.users.insert(username.into(), password.into());
    }
}

impl AuthHandler for SimpleAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        self.users
            .get(username)
            .map(|p| p == password)
            .unwrap_or(false)
    }
}

/// RADIUS Server configuration
pub struct ServerConfig {
    /// Bind address for the server
    pub bind_addr: SocketAddr,
    /// Shared secret for authenticating clients (used if no client config provided)
    pub secret: Vec<u8>,
    /// Authentication handler
    pub auth_handler: Arc<dyn AuthHandler>,
    /// Optional full configuration with client validation
    pub config: Option<Arc<Config>>,
    /// Request deduplication cache
    pub request_cache: Arc<RequestCache>,
    /// Rate limiter
    pub rate_limiter: Arc<RateLimiter>,
    /// Audit logger
    pub audit_logger: Arc<AuditLogger>,
}

impl ServerConfig {
    pub fn new(
        bind_addr: SocketAddr,
        secret: impl Into<Vec<u8>>,
        auth_handler: Arc<dyn AuthHandler>,
    ) -> Self {
        // Default cache: 60 second TTL, 10000 max entries
        let request_cache = Arc::new(RequestCache::new(Duration::from_secs(60), 10000));

        // Default rate limiter
        let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));

        // No audit logging by default
        let audit_logger = Arc::new(AuditLogger::new(None).unwrap());

        ServerConfig {
            bind_addr,
            secret: secret.into(),
            auth_handler,
            config: None,
            request_cache,
            rate_limiter,
            audit_logger,
        }
    }

    /// Create server config from a full Config object
    pub fn from_config(config: Config, auth_handler: Arc<dyn AuthHandler>) -> Result<Self, ServerError> {
        let bind_addr = config.socket_addr().map_err(|e| {
            ServerError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        let secret = config.secret.clone().into_bytes();

        // Create cache with configured TTL and max entries
        let ttl = Duration::from_secs(config.request_cache_ttl.unwrap_or(60));
        let max_entries = config.request_cache_max_entries.unwrap_or(10000);
        let request_cache = Arc::new(RequestCache::new(ttl, max_entries));

        // Create rate limiter with configured limits
        let rate_limit_config = RateLimitConfig {
            per_client_rps: config.rate_limit_per_client_rps.unwrap_or(100),
            per_client_burst: config.rate_limit_per_client_burst.unwrap_or(200),
            global_rps: config.rate_limit_global_rps.unwrap_or(1000),
            global_burst: config.rate_limit_global_burst.unwrap_or(2000),
        };
        let rate_limiter = Arc::new(RateLimiter::new(rate_limit_config));

        // Create audit logger if configured
        let audit_logger = Arc::new(AuditLogger::new(config.audit_log_path.clone())?);

        Ok(ServerConfig {
            bind_addr,
            secret,
            auth_handler,
            config: Some(Arc::new(config)),
            request_cache,
            rate_limiter,
            audit_logger,
        })
    }

    /// Get the appropriate shared secret for a client IP address
    fn get_secret_for_client(&self, source_ip: std::net::IpAddr) -> &[u8] {
        if let Some(ref config) = self.config {
            config.get_secret_for_client(source_ip)
        } else {
            &self.secret
        }
    }

    /// Check if a client is authorized
    fn is_client_authorized(&self, source_ip: std::net::IpAddr) -> bool {
        // If no config is provided, allow all clients (backward compatibility)
        if let Some(ref config) = self.config {
            // If clients list is empty, allow all (backward compatibility)
            if config.clients.is_empty() {
                return true;
            }
            // Check if client is in the authorized list
            config.find_client(source_ip).is_some()
        } else {
            true
        }
    }
}

/// RADIUS Server
pub struct RadiusServer {
    config: Arc<ServerConfig>,
    socket: Arc<UdpSocket>,
}

impl RadiusServer {
    /// Create a new RADIUS server
    pub async fn new(config: ServerConfig) -> Result<Self, ServerError> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        info!("RADIUS server listening on {}", config.bind_addr);

        Ok(RadiusServer {
            config: Arc::new(config),
            socket: Arc::new(socket),
        })
    }

    /// Get the local address the server is listening on
    ///
    /// This is useful for testing when binding to port 0 (OS-assigned port)
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ServerError> {
        self.socket.local_addr().map_err(ServerError::from)
    }

    /// Start the server and handle incoming requests
    pub async fn run(&self) -> Result<(), ServerError> {
        let mut buf = vec![0u8; 4096];

        loop {
            let (len, addr) = self.socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();

            // Spawn a task to handle this request
            let config = Arc::clone(&self.config);
            let socket = Arc::clone(&self.socket);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_request(data, addr, config, socket).await {
                    debug!("Error handling request from {}: {}", addr, e);
                }
            });
        }
    }

    /// Handle a single RADIUS request
    async fn handle_request(
        data: Vec<u8>,
        addr: SocketAddr,
        config: Arc<ServerConfig>,
        socket: Arc<UdpSocket>,
    ) -> Result<(), ServerError> {
        // Check rate limit FIRST (before any expensive operations)
        if !config.rate_limiter.check_rate_limit(addr.ip()).await {
            let request_id = if data.len() >= 2 { data[1] } else { 0 };
            warn!(
                client_ip = %addr.ip(),
                request_id = request_id,
                "Rate limit exceeded"
            );

            // Audit log rate limit event
            config.audit_logger.log(
                AuditEntry::new(AuditEventType::RateLimitExceeded)
                    .with_client_ip(addr.ip())
                    .with_request_id(request_id)
            ).await;

            return Err(ServerError::RateLimited);
        }

        // RFC 2865 Section 3: Validate source IP address
        if !config.is_client_authorized(addr.ip()) {
            let request_id = if data.len() >= 2 { data[1] } else { 0 };
            warn!(
                client_ip = %addr.ip(),
                request_id = request_id,
                "Rejected request from unauthorized client"
            );

            // Audit log unauthorized client event
            config.audit_logger.log(
                AuditEntry::new(AuditEventType::UnauthorizedClient)
                    .with_client_ip(addr.ip())
                    .with_request_id(request_id)
            ).await;

            return Err(ServerError::InvalidClient);
        }

        // Decode the packet
        let request = Packet::decode(&data)?;

        // Validate the packet
        let validation_mode = if config
            .config
            .as_ref()
            .map(|c| c.strict_rfc_compliance)
            .unwrap_or(false)
        {
            ValidationMode::Strict
        } else {
            ValidationMode::Lenient
        };

        if let Err(e) = validate_packet(&request, validation_mode) {
            warn!(
                client_ip = %addr.ip(),
                request_id = request.identifier,
                error = %e,
                "Rejected malformed packet"
            );
            return Err(ServerError::Validation(e.to_string()));
        }

        // Check for duplicate request (replay attack prevention)
        let fingerprint = RequestFingerprint::new(addr.ip(), request.identifier, &request.authenticator);
        if config.request_cache.is_duplicate(fingerprint, request.authenticator) {
            warn!(
                client_ip = %addr.ip(),
                request_id = request.identifier,
                "Rejected duplicate request"
            );

            // Audit log duplicate request event
            config.audit_logger.log(
                AuditEntry::new(AuditEventType::DuplicateRequest)
                    .with_client_ip(addr.ip())
                    .with_request_id(request.identifier)
            ).await;

            return Err(ServerError::DuplicateRequest);
        }

        debug!(
            packet_type = ?request.code,
            client_addr = %addr,
            request_id = request.identifier,
            "Received RADIUS packet"
        );

        // Handle based on packet type
        let response = match request.code {
            Code::AccessRequest => Self::handle_access_request(&request, &config, addr.ip()).await?,
            Code::StatusServer => Self::handle_status_server(&request, &config, addr.ip())?,
            _ => {
                warn!(packet_type = ?request.code, "Unsupported packet type");
                return Ok(());
            }
        };

        // Send response
        let response_data = response.encode()?;
        socket.send_to(&response_data, addr).await?;

        debug!(
            response_type = ?response.code,
            client_addr = %addr,
            request_id = response.identifier,
            "Sent RADIUS response"
        );

        Ok(())
    }

    /// Handle Access-Request packet
    async fn handle_access_request(
        request: &Packet,
        config: &ServerConfig,
        source_ip: std::net::IpAddr,
    ) -> Result<Packet, ServerError> {
        // Get the appropriate shared secret for this client
        let secret = config.get_secret_for_client(source_ip);

        // Extract username
        let username = request
            .find_attribute(AttributeType::UserName as u8)
            .and_then(|attr| attr.as_string().ok())
            .ok_or(ServerError::AuthFailed)?;

        info!(
            username = %username,
            client_ip = %source_ip,
            request_id = request.identifier,
            "Authentication request received"
        );

        // Audit log authentication attempt
        let client_name = config.config.as_ref()
            .and_then(|c| c.find_client(source_ip))
            .and_then(|client| client.name.clone());

        config.audit_logger.log(
            AuditEntry::new(AuditEventType::AuthAttempt)
                .with_username(&username)
                .with_client_ip(source_ip)
                .with_request_id(request.identifier)
                .with_client_name(client_name.unwrap_or_else(|| "unknown".to_string()))
        ).await;

        // Extract and decrypt password using client-specific secret
        let password = request
            .find_attribute(AttributeType::UserPassword as u8)
            .map(|attr| {
                decrypt_user_password(&attr.value, secret, &request.authenticator)
            })
            .ok_or(ServerError::AuthFailed)?
            .map_err(|_| ServerError::AuthFailed)?;

        // Authenticate
        let authenticated = config.auth_handler.authenticate(&username, &password);

        if authenticated {
            info!(
                username = %username,
                client_ip = %source_ip,
                request_id = request.identifier,
                "Authentication successful"
            );

            // Audit log authentication success
            let client_name = config.config.as_ref()
                .and_then(|c| c.find_client(source_ip))
                .and_then(|client| client.name.clone());

            config.audit_logger.log(
                AuditEntry::new(AuditEventType::AuthSuccess)
                    .with_username(&username)
                    .with_client_ip(source_ip)
                    .with_request_id(request.identifier)
                    .with_client_name(client_name.unwrap_or_else(|| "unknown".to_string()))
            ).await;

            // Create Access-Accept response
            let mut response = Packet::new(Code::AccessAccept, request.identifier, [0u8; 16]);

            // Add attributes from auth handler
            for attr in config.auth_handler.get_accept_attributes(&username) {
                response.add_attribute(attr);
            }

            // Calculate and set Response Authenticator using client-specific secret
            let response_auth =
                calculate_response_authenticator(&response, &request.authenticator, secret);
            response.authenticator = response_auth;

            Ok(response)
        } else {
            warn!(
                username = %username,
                client_ip = %source_ip,
                request_id = request.identifier,
                "Authentication failed"
            );

            // Audit log authentication failure
            let client_name = config.config.as_ref()
                .and_then(|c| c.find_client(source_ip))
                .and_then(|client| client.name.clone());

            config.audit_logger.log(
                AuditEntry::new(AuditEventType::AuthFailure)
                    .with_username(&username)
                    .with_client_ip(source_ip)
                    .with_request_id(request.identifier)
                    .with_client_name(client_name.unwrap_or_else(|| "unknown".to_string()))
                    .with_details("Invalid credentials")
            ).await;

            // Create Access-Reject response
            let mut response = Packet::new(Code::AccessReject, request.identifier, [0u8; 16]);

            // Add attributes from auth handler
            for attr in config.auth_handler.get_reject_attributes(&username) {
                response.add_attribute(attr);
            }

            // Calculate and set Response Authenticator using client-specific secret
            let response_auth =
                calculate_response_authenticator(&response, &request.authenticator, secret);
            response.authenticator = response_auth;

            Ok(response)
        }
    }

    /// Handle Status-Server packet (RFC 5997)
    fn handle_status_server(
        request: &Packet,
        config: &ServerConfig,
        source_ip: std::net::IpAddr,
    ) -> Result<Packet, ServerError> {
        debug!(
            client_ip = %source_ip,
            request_id = request.identifier,
            "Status-Server request received"
        );

        // Get the appropriate shared secret for this client
        let secret = config.get_secret_for_client(source_ip);

        // Respond with Access-Accept to indicate server is alive
        let mut response = Packet::new(Code::AccessAccept, request.identifier, [0u8; 16]);

        // Calculate and set Response Authenticator using client-specific secret
        let response_auth =
            calculate_response_authenticator(&response, &request.authenticator, secret);
        response.authenticator = response_auth;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_auth_handler() {
        let mut handler = SimpleAuthHandler::new();
        handler.add_user("testuser", "testpass");

        assert!(handler.authenticate("testuser", "testpass"));
        assert!(!handler.authenticate("testuser", "wrongpass"));
        assert!(!handler.authenticate("wronguser", "testpass"));
    }
}
