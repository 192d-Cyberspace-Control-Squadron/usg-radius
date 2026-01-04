//! Proxy handler for request forwarding and response routing

use crate::proxy::cache::{ProxyCache, ProxyCacheEntry, ProxyStateKey, generate_proxy_state_key};
use crate::proxy::error::{ProxyError, ProxyResult};
use crate::proxy::home_server::HomeServer;
use radius_proto::Packet;
use radius_proto::attributes::{Attribute, AttributeType};
use radius_proto::auth::calculate_response_authenticator;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Maximum number of Proxy-State attributes allowed (loop detection)
const MAX_PROXY_STATE_ATTRIBUTES: usize = 5;

/// Proxy handler for forwarding requests and routing responses
pub struct ProxyHandler {
    /// Proxy cache for request correlation
    cache: Arc<ProxyCache>,
    /// UDP socket for communicating with home servers
    socket: Arc<UdpSocket>,
}

impl ProxyHandler {
    /// Create a new proxy handler
    ///
    /// # Arguments
    /// * `cache` - Proxy cache for request tracking
    /// * `bind_addr` - Address to bind the proxy socket to
    pub async fn new(cache: Arc<ProxyCache>, bind_addr: SocketAddr) -> ProxyResult<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        info!(bind_addr = %bind_addr, "Proxy handler socket bound");

        Ok(ProxyHandler {
            cache,
            socket: Arc::new(socket),
        })
    }

    /// Forward a request to a home server
    ///
    /// # Process
    /// 1. Check for proxy loops (count existing Proxy-State attributes)
    /// 2. Generate unique Proxy-State attribute
    /// 3. Add Proxy-State to request
    /// 4. Store request in cache for correlation
    /// 5. Send modified request to home server
    ///
    /// # Returns
    /// The Proxy-State key used for correlation
    pub async fn forward_request(
        &self,
        mut request: Packet,
        source: SocketAddr,
        home_server: Arc<HomeServer>,
        client_secret: Vec<u8>,
    ) -> ProxyResult<ProxyStateKey> {
        // Check for proxy loops (RFC 2865 Section 5.33)
        let proxy_state_count = request
            .attributes
            .iter()
            .filter(|attr| attr.attr_type == AttributeType::ProxyState as u8)
            .count();

        if proxy_state_count >= MAX_PROXY_STATE_ATTRIBUTES {
            warn!(
                source = %source,
                proxy_state_count = proxy_state_count,
                "Proxy loop detected - too many Proxy-State attributes"
            );
            return Err(ProxyError::ProxyLoop(
                proxy_state_count,
                MAX_PROXY_STATE_ATTRIBUTES,
            ));
        }

        // Generate unique Proxy-State
        let proxy_state = generate_proxy_state_key();

        // Add Proxy-State attribute to request
        request.add_attribute(
            Attribute::new(AttributeType::ProxyState as u8, proxy_state.to_vec()).map_err(|e| {
                ProxyError::Configuration(format!("Failed to create Proxy-State attribute: {}", e))
            })?,
        );

        // Create cache entry
        let entry = ProxyCacheEntry {
            original_request: request.clone(),
            original_source: source,
            home_server: home_server.clone(),
            sent_at: Instant::now(),
            retry_count: 0,
            proxy_state,
            client_secret,
        };

        // Store in cache (before sending to avoid race condition)
        self.cache.insert(entry)?;

        // Encode and send request to home server
        let request_data = request.encode()?;
        self.socket
            .send_to(&request_data, home_server.address)
            .await?;

        // Record statistics
        home_server.stats().record_request();

        debug!(
            source = %source,
            home_server = %home_server.name,
            identifier = request.identifier,
            proxy_state = ?proxy_state,
            "Request forwarded to home server"
        );

        Ok(proxy_state)
    }

    /// Handle a response from a home server
    ///
    /// # Process
    /// 1. Extract our Proxy-State attribute (last one added)
    /// 2. Look up original request in cache
    /// 3. Validate response authenticator (with home server secret)
    /// 4. Remove our Proxy-State attribute
    /// 5. Recalculate response authenticator (with client secret)
    /// 6. Forward to original NAS
    ///
    /// Note: This method should be called from a background task that listens
    /// for responses on the proxy socket.
    pub async fn handle_response(
        &self,
        mut response: Packet,
        home_server_addr: SocketAddr,
    ) -> ProxyResult<()> {
        // Extract the last Proxy-State attribute (the one we added)
        let proxy_state_attr = response
            .attributes
            .iter()
            .rfind(|attr| attr.attr_type == AttributeType::ProxyState as u8)
            .ok_or(ProxyError::CorrelationFailed)?;

        // Convert to ProxyStateKey
        if proxy_state_attr.value.len() != 16 {
            return Err(ProxyError::CorrelationFailed);
        }
        let mut proxy_state = [0u8; 16];
        proxy_state.copy_from_slice(&proxy_state_attr.value);

        // Look up original request
        let entry = self
            .cache
            .remove(&proxy_state)
            .ok_or(ProxyError::CorrelationFailed)?;

        // Verify this response is from the expected home server
        if home_server_addr != entry.home_server.address {
            warn!(
                expected = %entry.home_server.address,
                actual = %home_server_addr,
                "Response from unexpected home server"
            );
            return Err(ProxyError::CorrelationFailed);
        }

        // Record statistics
        entry.home_server.stats().record_response();

        // Remove our Proxy-State attribute from response
        response.attributes.retain(|attr| {
            !(attr.attr_type == AttributeType::ProxyState as u8 && attr.value == proxy_state)
        });

        // Recalculate Response-Authenticator with client secret
        // (response was calculated with home server secret, need to recalculate)
        let response_auth = calculate_response_authenticator(
            &response,
            &entry.original_request.authenticator,
            &entry.client_secret,
        );
        response.authenticator = response_auth;

        // Forward response to original NAS
        let response_data = response.encode()?;
        self.socket
            .send_to(&response_data, entry.original_source)
            .await?;

        info!(
            nas = %entry.original_source,
            home_server = %entry.home_server.name,
            code = ?response.code,
            identifier = response.identifier,
            "Response forwarded to NAS"
        );

        Ok(())
    }

    /// Get the proxy socket for listening to responses
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Get cache reference for statistics
    pub fn cache(&self) -> Arc<ProxyCache> {
        Arc::clone(&self.cache)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::home_server::HomeServerConfig;
    use radius_proto::Code;
    use std::time::Duration;

    fn create_test_home_server() -> Arc<HomeServer> {
        let config = HomeServerConfig {
            address: "127.0.0.1:11812".to_string(),
            secret: "home_secret".to_string(),
            timeout: 30,
            max_outstanding: 100,
            name: Some("Test Server".to_string()),
        };
        Arc::new(HomeServer::new(config).unwrap())
    }

    fn create_test_request() -> Packet {
        let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        packet.add_attribute(Attribute::string(AttributeType::UserName as u8, "testuser").unwrap());
        packet
    }

    #[tokio::test]
    async fn test_proxy_handler_creation() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap(); // OS-assigned port

        let handler = ProxyHandler::new(cache, bind_addr).await;
        assert!(handler.is_ok());
    }

    #[tokio::test]
    async fn test_forward_request_adds_proxy_state() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let request = create_test_request();
        let home_server = create_test_home_server();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        // Forward request
        let proxy_state = handler
            .forward_request(
                request.clone(),
                source,
                home_server,
                b"test_secret".to_vec(),
            )
            .await
            .unwrap();

        // Verify entry is in cache
        let entry = cache.get(&proxy_state);
        assert!(entry.is_some());

        let entry = entry.unwrap();
        assert_eq!(entry.original_source, source);
        assert_eq!(entry.retry_count, 0);
    }

    #[tokio::test]
    async fn test_proxy_loop_detection() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1000));
        let handler = ProxyHandler::new(cache, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // Create request with many Proxy-State attributes (simulating loop)
        let mut request = create_test_request();
        for _ in 0..MAX_PROXY_STATE_ATTRIBUTES {
            request.add_attribute(
                Attribute::new(AttributeType::ProxyState as u8, vec![0u8; 16]).unwrap(),
            );
        }

        let home_server = create_test_home_server();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        // Should detect loop
        let result = handler
            .forward_request(request, source, home_server, b"test_secret".to_vec())
            .await;
        assert!(result.is_err());
        match result {
            Err(ProxyError::ProxyLoop(count, limit)) => {
                assert_eq!(count, MAX_PROXY_STATE_ATTRIBUTES);
                assert_eq!(limit, MAX_PROXY_STATE_ATTRIBUTES);
            }
            _ => panic!("Expected ProxyLoop error"),
        }
    }

    #[tokio::test]
    async fn test_cache_full_error() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(60), 1)); // Max 1 entry
        let handler = ProxyHandler::new(cache, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let home_server = create_test_home_server();
        let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        // First request should succeed
        let result = handler
            .forward_request(
                create_test_request(),
                source,
                home_server.clone(),
                b"test_secret".to_vec(),
            )
            .await;
        assert!(result.is_ok());

        // Second request should fail (cache full)
        let result = handler
            .forward_request(
                create_test_request(),
                source,
                home_server,
                b"test_secret".to_vec(),
            )
            .await;
        assert!(result.is_err());
        match result {
            Err(ProxyError::CacheFull(_)) => {}
            _ => panic!("Expected CacheFull error"),
        }
    }
}
