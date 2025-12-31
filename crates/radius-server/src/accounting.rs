//! RADIUS Accounting Handler and Session Management
//!
//! This module provides the trait and implementations for handling RADIUS
//! accounting requests and managing sessions.

use radius_proto::{AccountingError, Packet};
use std::net::IpAddr;
use std::sync::Arc;

/// Session information tracked by the accounting system
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session identifier (Acct-Session-Id)
    pub session_id: String,
    /// Username
    pub username: String,
    /// Client IP address (NAS IP)
    pub nas_ip: IpAddr,
    /// User's IP address (Framed-IP-Address)
    pub framed_ip: Option<IpAddr>,
    /// Session start time (Unix timestamp)
    pub start_time: u64,
    /// Last update time (Unix timestamp)
    pub last_update: u64,
    /// Input octets (bytes received)
    pub input_octets: u64,
    /// Output octets (bytes transmitted)
    pub output_octets: u64,
    /// Input packets
    pub input_packets: u64,
    /// Output packets
    pub output_packets: u64,
    /// Session time (seconds)
    pub session_time: u32,
    /// Termination cause (if stopped)
    pub terminate_cause: Option<u32>,
}

/// Result of processing an accounting request
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountingResult {
    /// Accounting request accepted
    Success,
    /// Accounting request rejected with reason
    Failure(String),
}

/// Trait for handling accounting requests
///
/// Implementations can store accounting data in various backends:
/// - In-memory (for testing/development)
/// - File-based logs
/// - Databases (PostgreSQL, MySQL)
/// - External systems
pub trait AccountingHandler: Send + Sync {
    /// Handle an accounting Start request
    ///
    /// Called when a new session begins
    fn handle_start(
        &self,
        session_id: &str,
        username: &str,
        nas_ip: IpAddr,
        packet: &Packet,
    ) -> impl std::future::Future<Output = Result<AccountingResult, AccountingError>> + Send;

    /// Handle an accounting Stop request
    ///
    /// Called when a session ends
    fn handle_stop(
        &self,
        session_id: &str,
        username: &str,
        nas_ip: IpAddr,
        packet: &Packet,
    ) -> impl std::future::Future<Output = Result<AccountingResult, AccountingError>> + Send;

    /// Handle an accounting Interim-Update request
    ///
    /// Called periodically during an active session
    fn handle_interim_update(
        &self,
        session_id: &str,
        username: &str,
        nas_ip: IpAddr,
        packet: &Packet,
    ) -> impl std::future::Future<Output = Result<AccountingResult, AccountingError>> + Send;

    /// Handle an Accounting-On request
    ///
    /// Called when NAS starts up and is ready to accept requests
    fn handle_accounting_on(
        &self,
        nas_ip: IpAddr,
        packet: &Packet,
    ) -> impl std::future::Future<Output = Result<AccountingResult, AccountingError>> + Send;

    /// Handle an Accounting-Off request
    ///
    /// Called when NAS is shutting down
    fn handle_accounting_off(
        &self,
        nas_ip: IpAddr,
        packet: &Packet,
    ) -> impl std::future::Future<Output = Result<AccountingResult, AccountingError>> + Send;

    /// Get active sessions (optional, for monitoring)
    fn get_active_sessions(
        &self,
    ) -> impl std::future::Future<Output = Vec<Session>> + Send {
        async { Vec::new() }
    }

    /// Get session by ID (optional, for queries)
    fn get_session(
        &self,
        session_id: &str,
    ) -> impl std::future::Future<Output = Option<Session>> + Send {
        let _session_id = session_id;
        async { None }
    }
}

/// Simple in-memory accounting handler for testing
///
/// This handler stores sessions in memory and provides basic
/// accounting functionality. Not recommended for production use.
pub struct SimpleAccountingHandler {
    sessions: Arc<dashmap::DashMap<String, Session>>,
}

impl SimpleAccountingHandler {
    /// Create a new simple accounting handler
    pub fn new() -> Self {
        SimpleAccountingHandler {
            sessions: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Get the number of active sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Clear all sessions (for testing)
    pub fn clear(&self) {
        self.sessions.clear();
    }
}

impl Default for SimpleAccountingHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountingHandler for SimpleAccountingHandler {
    async fn handle_start(
        &self,
        session_id: &str,
        username: &str,
        nas_ip: IpAddr,
        _packet: &Packet,
    ) -> Result<AccountingResult, AccountingError> {
        // Check for duplicate session
        if self.sessions.contains_key(session_id) {
            return Err(AccountingError::DuplicateSession(session_id.to_string()));
        }

        // Create new session
        let session = Session {
            session_id: session_id.to_string(),
            username: username.to_string(),
            nas_ip,
            framed_ip: None,
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_update: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            input_octets: 0,
            output_octets: 0,
            input_packets: 0,
            output_packets: 0,
            session_time: 0,
            terminate_cause: None,
        };

        self.sessions.insert(session_id.to_string(), session);
        Ok(AccountingResult::Success)
    }

    async fn handle_stop(
        &self,
        session_id: &str,
        _username: &str,
        _nas_ip: IpAddr,
        packet: &Packet,
    ) -> Result<AccountingResult, AccountingError> {
        // Get and remove session
        let mut session = self
            .sessions
            .remove(session_id)
            .ok_or_else(|| AccountingError::SessionNotFound(session_id.to_string()))?
            .1;

        // Update session with stop information
        use radius_proto::AttributeType;

        // Extract accounting attributes
        if let Some(attr) = packet.find_attribute(AttributeType::AcctSessionTime as u8) {
            if attr.value.len() >= 4 {
                session.session_time = u32::from_be_bytes([
                    attr.value[0],
                    attr.value[1],
                    attr.value[2],
                    attr.value[3],
                ]);
            }
        }

        if let Some(attr) = packet.find_attribute(AttributeType::AcctInputOctets as u8) {
            if attr.value.len() >= 4 {
                session.input_octets = u32::from_be_bytes([
                    attr.value[0],
                    attr.value[1],
                    attr.value[2],
                    attr.value[3],
                ]) as u64;
            }
        }

        if let Some(attr) = packet.find_attribute(AttributeType::AcctOutputOctets as u8) {
            if attr.value.len() >= 4 {
                session.output_octets = u32::from_be_bytes([
                    attr.value[0],
                    attr.value[1],
                    attr.value[2],
                    attr.value[3],
                ]) as u64;
            }
        }

        if let Some(attr) = packet.find_attribute(AttributeType::AcctTerminateCause as u8) {
            if attr.value.len() >= 4 {
                session.terminate_cause = Some(u32::from_be_bytes([
                    attr.value[0],
                    attr.value[1],
                    attr.value[2],
                    attr.value[3],
                ]));
            }
        }

        // Session is now removed and logged
        Ok(AccountingResult::Success)
    }

    async fn handle_interim_update(
        &self,
        session_id: &str,
        _username: &str,
        _nas_ip: IpAddr,
        packet: &Packet,
    ) -> Result<AccountingResult, AccountingError> {
        // Update existing session
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| AccountingError::SessionNotFound(session_id.to_string()))?;

        // Update last update time
        session.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Update usage statistics
        use radius_proto::AttributeType;

        if let Some(attr) = packet.find_attribute(AttributeType::AcctSessionTime as u8) {
            if attr.value.len() >= 4 {
                session.session_time = u32::from_be_bytes([
                    attr.value[0],
                    attr.value[1],
                    attr.value[2],
                    attr.value[3],
                ]);
            }
        }

        if let Some(attr) = packet.find_attribute(AttributeType::AcctInputOctets as u8) {
            if attr.value.len() >= 4 {
                session.input_octets = u32::from_be_bytes([
                    attr.value[0],
                    attr.value[1],
                    attr.value[2],
                    attr.value[3],
                ]) as u64;
            }
        }

        if let Some(attr) = packet.find_attribute(AttributeType::AcctOutputOctets as u8) {
            if attr.value.len() >= 4 {
                session.output_octets = u32::from_be_bytes([
                    attr.value[0],
                    attr.value[1],
                    attr.value[2],
                    attr.value[3],
                ]) as u64;
            }
        }

        Ok(AccountingResult::Success)
    }

    async fn handle_accounting_on(
        &self,
        _nas_ip: IpAddr,
        _packet: &Packet,
    ) -> Result<AccountingResult, AccountingError> {
        // NAS is starting up - could clear all sessions from this NAS
        Ok(AccountingResult::Success)
    }

    async fn handle_accounting_off(
        &self,
        nas_ip: IpAddr,
        _packet: &Packet,
    ) -> Result<AccountingResult, AccountingError> {
        // NAS is shutting down - terminate all sessions from this NAS
        self.sessions.retain(|_, session| session.nas_ip != nas_ip);
        Ok(AccountingResult::Success)
    }

    async fn get_active_sessions(&self) -> Vec<Session> {
        self.sessions
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    async fn get_session(&self, session_id: &str) -> Option<Session> {
        self.sessions.get(session_id).map(|entry| entry.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use radius_proto::{Attribute, AttributeType, Code};

    fn create_test_packet() -> Packet {
        Packet::new(Code::AccountingRequest, 1, [0u8; 16])
    }

    #[tokio::test]
    async fn test_simple_handler_session_start() {
        let handler = SimpleAccountingHandler::new();
        let packet = create_test_packet();

        let result = handler
            .handle_start("session123", "testuser", "192.168.1.1".parse().unwrap(), &packet)
            .await;

        assert!(result.is_ok());
        assert_eq!(handler.session_count(), 1);

        let session = handler.get_session("session123").await;
        assert!(session.is_some());
        let session = session.unwrap();
        assert_eq!(session.session_id, "session123");
        assert_eq!(session.username, "testuser");
    }

    #[tokio::test]
    async fn test_simple_handler_duplicate_session() {
        let handler = SimpleAccountingHandler::new();
        let packet = create_test_packet();

        // First start should succeed
        handler
            .handle_start("session123", "testuser", "192.168.1.1".parse().unwrap(), &packet)
            .await
            .unwrap();

        // Second start with same ID should fail
        let result = handler
            .handle_start("session123", "testuser", "192.168.1.1".parse().unwrap(), &packet)
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AccountingError::DuplicateSession(_)
        ));
    }

    #[tokio::test]
    async fn test_simple_handler_session_stop() {
        let handler = SimpleAccountingHandler::new();
        let mut packet = create_test_packet();

        // Start session
        handler
            .handle_start("session123", "testuser", "192.168.1.1".parse().unwrap(), &packet)
            .await
            .unwrap();

        // Add accounting attributes to stop packet
        packet
            .add_attribute(Attribute::new(AttributeType::AcctSessionTime as u8, vec![0, 0, 0, 100]).unwrap());
        packet
            .add_attribute(Attribute::new(AttributeType::AcctInputOctets as u8, vec![0, 0, 1, 0]).unwrap());

        // Stop session
        let result = handler
            .handle_stop("session123", "testuser", "192.168.1.1".parse().unwrap(), &packet)
            .await;

        assert!(result.is_ok());
        assert_eq!(handler.session_count(), 0);
    }

    #[tokio::test]
    async fn test_simple_handler_interim_update() {
        let handler = SimpleAccountingHandler::new();
        let mut packet = create_test_packet();

        // Start session
        handler
            .handle_start("session123", "testuser", "192.168.1.1".parse().unwrap(), &packet)
            .await
            .unwrap();

        // Add accounting attributes for interim update
        packet
            .add_attribute(Attribute::new(AttributeType::AcctSessionTime as u8, vec![0, 0, 0, 50]).unwrap());
        packet
            .add_attribute(Attribute::new(AttributeType::AcctInputOctets as u8, vec![0, 0, 0, 200]).unwrap());

        // Send interim update
        let result = handler
            .handle_interim_update("session123", "testuser", "192.168.1.1".parse().unwrap(), &packet)
            .await;

        assert!(result.is_ok());
        assert_eq!(handler.session_count(), 1);

        // Verify session was updated
        let session = handler.get_session("session123").await.unwrap();
        assert_eq!(session.session_time, 50);
        assert_eq!(session.input_octets, 200);
    }

    #[tokio::test]
    async fn test_simple_handler_accounting_off() {
        let handler = SimpleAccountingHandler::new();
        let packet = create_test_packet();

        // Start multiple sessions on same NAS
        handler
            .handle_start("session1", "user1", "192.168.1.1".parse().unwrap(), &packet)
            .await
            .unwrap();
        handler
            .handle_start("session2", "user2", "192.168.1.1".parse().unwrap(), &packet)
            .await
            .unwrap();
        handler
            .handle_start("session3", "user3", "192.168.1.2".parse().unwrap(), &packet)
            .await
            .unwrap();

        assert_eq!(handler.session_count(), 3);

        // Send Accounting-Off for first NAS
        handler
            .handle_accounting_off("192.168.1.1".parse().unwrap(), &packet)
            .await
            .unwrap();

        // Should only have session from second NAS
        assert_eq!(handler.session_count(), 1);
        assert!(handler.get_session("session3").await.is_some());
        assert!(handler.get_session("session1").await.is_none());
    }
}
