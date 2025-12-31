//! EAP Authentication Handler
//!
//! This module provides authentication handlers for various EAP methods including
//! EAP-TLS, EAP-MD5, and potentially other methods in the future.
//!
//! The EAP handler integrates with the RADIUS server's AuthHandler trait and manages
//! multi-round EAP authentication sessions.

use radius_proto::eap::{EapPacket, EapSessionManager, EapState, EapType};
use radius_proto::{Attribute, Packet};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::server::{AuthHandler, AuthResult};

#[cfg(feature = "tls")]
use radius_proto::eap::eap_tls::{
    build_server_config, EapTlsPacket, EapTlsServer, TlsCertificateConfig,
};

#[cfg(feature = "tls")]
use std::sync::Arc as StdArc;

/// EAP Authentication Handler
///
/// Manages EAP authentication sessions and delegates to method-specific handlers.
///
/// # Example
///
/// ```no_run
/// use radius_server::eap_auth::EapAuthHandler;
/// use radius_server::server::SimpleAuthHandler;
/// use std::sync::Arc;
///
/// // Create inner handler for credential verification
/// let mut inner = SimpleAuthHandler::new();
/// inner.add_user("alice", "password123");
///
/// // Create EAP handler
/// let eap_handler = EapAuthHandler::new(Arc::new(inner));
///
/// // EAP handler can now be used as AuthHandler for RADIUS server
/// ```
pub struct EapAuthHandler {
    /// Session manager for tracking EAP authentication sessions
    session_manager: Arc<RwLock<EapSessionManager>>,

    /// Inner authentication handler for credential verification
    /// Used by EAP methods that require password validation (e.g., EAP-MD5)
    inner_handler: Arc<dyn AuthHandler>,

    /// EAP-TLS server configurations (if TLS feature is enabled)
    #[cfg(feature = "tls")]
    tls_configs: Arc<RwLock<HashMap<String, StdArc<rustls::ServerConfig>>>>,

    /// Active EAP-TLS sessions (if TLS feature is enabled)
    #[cfg(feature = "tls")]
    tls_sessions: Arc<RwLock<HashMap<String, EapTlsServer>>>,
}

impl EapAuthHandler {
    /// Create a new EAP authentication handler
    ///
    /// # Arguments
    ///
    /// * `inner_handler` - Handler for credential verification (used by password-based EAP methods)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use radius_server::eap_auth::EapAuthHandler;
    /// # use radius_server::server::SimpleAuthHandler;
    /// # use std::sync::Arc;
    /// let inner = SimpleAuthHandler::new();
    /// let eap_handler = EapAuthHandler::new(Arc::new(inner));
    /// ```
    pub fn new(inner_handler: Arc<dyn AuthHandler>) -> Self {
        EapAuthHandler {
            session_manager: Arc::new(RwLock::new(EapSessionManager::new())),
            inner_handler,
            #[cfg(feature = "tls")]
            tls_configs: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "tls")]
            tls_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure EAP-TLS for a specific realm or default
    ///
    /// # Arguments
    ///
    /// * `realm` - Realm identifier (use "" for default)
    /// * `cert_config` - TLS certificate configuration
    ///
    /// # Returns
    ///
    /// Result indicating success or error
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "tls")]
    /// # {
    /// # use radius_server::eap_auth::EapAuthHandler;
    /// # use radius_server::server::SimpleAuthHandler;
    /// # use radius_proto::eap::eap_tls::TlsCertificateConfig;
    /// # use std::sync::Arc;
    /// # let inner = SimpleAuthHandler::new();
    /// let mut eap_handler = EapAuthHandler::new(Arc::new(inner));
    ///
    /// let tls_config = TlsCertificateConfig::simple(
    ///     "certs/server.pem".to_string(),
    ///     "certs/server-key.pem".to_string(),
    /// );
    ///
    /// eap_handler.configure_tls("", tls_config).unwrap();
    /// # }
    /// ```
    #[cfg(feature = "tls")]
    pub fn configure_tls(
        &mut self,
        realm: &str,
        cert_config: TlsCertificateConfig,
    ) -> Result<(), String> {
        let server_config = build_server_config(&cert_config)
            .map_err(|e| format!("Failed to build TLS config: {:?}", e))?;

        let mut configs = self.tls_configs.write().unwrap();
        configs.insert(realm.to_string(), StdArc::new(server_config));

        Ok(())
    }

    /// Get or create an EAP session for a user
    fn get_or_create_session(&self, username: &str, state: Option<&[u8]>) -> String {
        let mut manager = self.session_manager.write().unwrap();

        // If state is provided, try to find existing session
        if let Some(state_bytes) = state {
            // State format: session_id encoded as string
            if let Ok(session_id) = String::from_utf8(state_bytes.to_vec()) {
                if manager.get_session(&session_id).is_some() {
                    return session_id;
                }
            }
        }

        // Create new session
        let session_id = format!("{}-{}", username, chrono::Utc::now().timestamp_millis());
        manager.create_session(session_id.clone());
        session_id
    }

    /// Handle EAP-Identity exchange
    fn handle_identity(
        &self,
        username: &str,
        session_id: &str,
    ) -> AuthResult {
        let mut manager = self.session_manager.write().unwrap();

        if let Some(session) = manager.get_session_mut(session_id) {
            session.identity = Some(username.to_string());
            let _ = session.transition(EapState::IdentityReceived);

            // Request EAP method
            let _ = session.transition(EapState::MethodRequested);

            // For now, default to EAP-TLS if available, otherwise EAP-MD5
            #[cfg(feature = "tls")]
            {
                session.eap_method = Some(EapType::Tls);
                return self.start_eap_tls(username, session_id);
            }

            #[cfg(not(feature = "tls"))]
            {
                session.eap_method = Some(EapType::Md5Challenge);
                return self.start_eap_md5(username, session_id);
            }
        }

        AuthResult::Reject
    }

    /// Start EAP-MD5 Challenge authentication
    fn start_eap_md5(&self, _username: &str, _session_id: &str) -> AuthResult {
        // EAP-MD5 implementation would go here
        // For now, not implemented
        AuthResult::Reject
    }

    /// Start EAP-TLS authentication
    #[cfg(feature = "tls")]
    fn start_eap_tls(&self, _username: &str, session_id: &str) -> AuthResult {
        // Get TLS config for user's realm (or default)
        let configs = self.tls_configs.read().unwrap();
        let tls_config = configs.get("").or_else(|| configs.values().next());

        if let Some(config) = tls_config {
            // Create EAP-TLS server for this session
            let mut tls_server = EapTlsServer::new(StdArc::clone(config));

            if tls_server.initialize_connection().is_ok() {
                // Store TLS session
                let mut tls_sessions = self.tls_sessions.write().unwrap();
                tls_sessions.insert(session_id.to_string(), tls_server);

                // Create EAP-TLS Start packet
                let start_packet = EapTlsPacket::start();
                let identifier = {
                    let mut manager = self.session_manager.write().unwrap();
                    if let Some(session) = manager.get_session_mut(session_id) {
                        session.next_identifier()
                    } else {
                        0
                    }
                };

                let eap_packet = start_packet.to_eap_request(identifier);

                // Convert EAP packet to RADIUS attributes
                if let Ok(eap_attrs) = radius_proto::eap::eap_to_radius_attributes(&eap_packet) {
                    return AuthResult::Challenge {
                        message: Some("EAP-TLS authentication".to_string()),
                        state: session_id.as_bytes().to_vec(),
                        attributes: eap_attrs,
                    };
                }
            }
        }

        AuthResult::Reject
    }

    /// Continue EAP-TLS authentication
    #[cfg(feature = "tls")]
    #[allow(unused_variables)]
    fn continue_eap_tls(
        &self,
        username: &str,
        session_id: &str,
        eap_response: &EapPacket,
    ) -> AuthResult {
        let mut tls_sessions = self.tls_sessions.write().unwrap();

        if let Some(tls_server) = tls_sessions.get_mut(session_id) {
            // Parse EAP-TLS packet from EAP data
            if let Ok(tls_packet) = EapTlsPacket::from_eap_data(&eap_response.data) {
                // Process client message
                match tls_server.process_client_message(&tls_packet) {
                    Ok(Some(ref response_data)) => {
                        // Create response packet
                        let identifier = {
                            let mut manager = self.session_manager.write().unwrap();
                            if let Some(session) = manager.get_session_mut(session_id) {
                                session.next_identifier()
                            } else {
                                eap_response.identifier.wrapping_add(1)
                            }
                        };

                        // Fragment if needed and create EAP-TLS packets
                        let fragments = radius_proto::eap::eap_tls::fragment_tls_message(&response_data, 1020);

                        if let Some(first_fragment) = fragments.first() {
                            let eap_packet = first_fragment.to_eap_request(identifier);

                            if let Ok(eap_attrs) = radius_proto::eap::eap_to_radius_attributes(&eap_packet) {
                                return AuthResult::Challenge {
                                    message: None,
                                    state: session_id.as_bytes().to_vec(),
                                    attributes: eap_attrs,
                                };
                            }
                        }
                    }
                    Ok(None) => {
                        // Check if handshake is complete
                        if tls_server.is_handshake_complete() {
                            // Extract keys
                            if tls_server.extract_keys().is_ok() {
                                // Verify client certificate if mutual TLS
                                let identity_verified = if let Some(_peer_certs) = tls_server.get_peer_certificates() {
                                    tls_server.verify_peer_identity(username).unwrap_or(false)
                                } else {
                                    true // Server-only auth
                                };

                                if identity_verified {
                                    // Success!
                                    let identifier = {
                                        let mut manager = self.session_manager.write().unwrap();
                                        if let Some(session) = manager.get_session_mut(session_id) {
                                            let _ = session.transition(EapState::Success);
                                            session.next_identifier()
                                        } else {
                                            eap_response.identifier.wrapping_add(1)
                                        }
                                    };

                                    let success_packet = EapPacket::success(identifier);

                                    if let Ok(_eap_attrs) = radius_proto::eap::eap_to_radius_attributes(&success_packet) {
                                        // Could add MS-MPPE keys here from MSK
                                        return AuthResult::Accept;
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // TLS error
                        return AuthResult::Reject;
                    }
                }
            }
        }

        AuthResult::Reject
    }
}

impl AuthHandler for EapAuthHandler {
    fn authenticate(&self, _username: &str, _password: &str) -> bool {
        // EAP doesn't use simple PAP authentication
        false
    }

    fn authenticate_with_challenge(
        &self,
        username: &str,
        _password: Option<&str>,
        state: Option<&[u8]>,
    ) -> AuthResult {
        // Get or create session
        let session_id = self.get_or_create_session(username, state);

        // Check if this is initial request or continuation
        if state.is_none() {
            // Initial request - start EAP-Identity
            return self.handle_identity(username, &session_id);
        }

        // This method doesn't have access to EAP-Message attributes
        // Use authenticate_request instead
        AuthResult::Reject
    }

    fn authenticate_request(
        &self,
        request: &Packet,
        _secret: &[u8],
    ) -> AuthResult {
        // Extract username
        let username = request
            .find_attribute(1) // UserName
            .and_then(|attr| attr.as_string().ok())
            .unwrap_or_default();

        // Extract state
        let state = request
            .find_attribute(24) // State
            .map(|attr| attr.value.as_slice());

        // Get or create session
        let session_id = self.get_or_create_session(&username, state);

        // Extract EAP-Message attributes
        let eap_messages: Vec<&Attribute> = request
            .attributes
            .iter()
            .filter(|attr| attr.attr_type == 79) // EAP-Message
            .collect();

        if eap_messages.is_empty() {
            // No EAP-Message - this is initial request, start EAP-Identity
            return self.handle_identity(&username, &session_id);
        }

        // Reassemble EAP packet from EAP-Message attributes
        let mut eap_data = Vec::new();
        for msg in eap_messages {
            eap_data.extend_from_slice(&msg.value);
        }

        // Parse EAP packet
        match EapPacket::from_bytes(&eap_data) {
            Ok(eap_packet) => {
                // Process EAP packet based on session state
                #[cfg(feature = "tls")]
                {
                    self.continue_eap_tls(&username, &session_id, &eap_packet)
                }
                #[cfg(not(feature = "tls"))]
                {
                    AuthResult::Reject
                }
            }
            Err(_) => AuthResult::Reject,
        }
    }

    fn get_user_password(&self, username: &str) -> Option<String> {
        // Delegate to inner handler
        self.inner_handler.get_user_password(username)
    }

    fn get_accept_attributes(&self, username: &str) -> Vec<Attribute> {
        // Could add MS-MPPE keys here from EAP-TLS MSK
        self.inner_handler.get_accept_attributes(username)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::SimpleAuthHandler;

    #[test]
    fn test_eap_auth_handler_creation() {
        let inner = SimpleAuthHandler::new();
        let eap_handler = EapAuthHandler::new(Arc::new(inner));

        // Handler should be created successfully
        // Verify no sessions exist by trying to get a non-existent session
        assert!(eap_handler.session_manager.read().unwrap().get_session("nonexistent").is_none());
    }

    #[test]
    fn test_session_creation() {
        let inner = SimpleAuthHandler::new();
        let eap_handler = EapAuthHandler::new(Arc::new(inner));

        let session_id = eap_handler.get_or_create_session("testuser", None);
        assert!(!session_id.is_empty());

        let sessions = eap_handler.session_manager.read().unwrap();
        assert!(sessions.get_session(&session_id).is_some());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_tls_configuration() {
        let inner = SimpleAuthHandler::new();
        let mut eap_handler = EapAuthHandler::new(Arc::new(inner));

        // Note: This test requires actual certificate files to work
        // For now, we just test that the method exists and has the right signature

        let result = eap_handler.configure_tls(
            "",
            TlsCertificateConfig::simple(
                "nonexistent.pem".to_string(),
                "nonexistent-key.pem".to_string(),
            ),
        );

        // Expected to fail since files don't exist
        assert!(result.is_err());
    }
}
