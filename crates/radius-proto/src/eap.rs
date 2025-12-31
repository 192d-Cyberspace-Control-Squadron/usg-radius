//! EAP (Extensible Authentication Protocol) Support
//!
//! This module implements EAP protocol structures as defined in RFC 3748
//! and EAP over RADIUS as defined in RFC 3579.
//!
//! # EAP Packet Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Code      |  Identifier   |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |  Type-Data ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::attributes::{Attribute, AttributeType};
use crate::packet::Packet;
use thiserror::Error;

/// EAP packet code (first byte of EAP packet)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EapCode {
    /// Request packet (Code 1)
    Request = 1,
    /// Response packet (Code 2)
    Response = 2,
    /// Success packet (Code 3)
    Success = 3,
    /// Failure packet (Code 4)
    Failure = 4,
}

impl EapCode {
    /// Convert from u8 to EapCode
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(EapCode::Request),
            2 => Some(EapCode::Response),
            3 => Some(EapCode::Success),
            4 => Some(EapCode::Failure),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// EAP method types (RFC 3748 and IANA registry)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EapType {
    /// Identity (Type 1) - RFC 3748
    Identity = 1,
    /// Notification (Type 2) - RFC 3748
    Notification = 2,
    /// Nak (Type 3) - RFC 3748
    /// Response only, sent in response to unacceptable authentication type
    Nak = 3,
    /// MD5-Challenge (Type 4) - RFC 3748
    Md5Challenge = 4,
    /// One-Time Password (Type 5) - RFC 2284 (deprecated)
    OneTimePassword = 5,
    /// Generic Token Card (Type 6) - RFC 2284 (deprecated)
    GenericTokenCard = 6,
    /// EAP-TLS (Type 13) - RFC 5216
    Tls = 13,
    /// EAP-TTLS (Type 21) - RFC 5281
    Ttls = 21,
    /// PEAP (Type 25) - draft-josefsson-pppext-eap-tls-eap
    Peap = 25,
    /// EAP-MSCHAPv2 (Type 26) - draft-kamath-pppext-eap-mschapv2
    MsChapV2 = 26,
    /// EAP-TEAP (Type 55) - RFC 7170
    Teap = 55,
}

impl EapType {
    /// Convert from u8 to EapType
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(EapType::Identity),
            2 => Some(EapType::Notification),
            3 => Some(EapType::Nak),
            4 => Some(EapType::Md5Challenge),
            5 => Some(EapType::OneTimePassword),
            6 => Some(EapType::GenericTokenCard),
            13 => Some(EapType::Tls),
            21 => Some(EapType::Ttls),
            25 => Some(EapType::Peap),
            26 => Some(EapType::MsChapV2),
            55 => Some(EapType::Teap),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// EAP packet structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket {
    /// EAP code (Request, Response, Success, Failure)
    pub code: EapCode,
    /// Identifier for matching requests and responses (0-255)
    pub identifier: u8,
    /// EAP type (only present for Request/Response)
    pub eap_type: Option<EapType>,
    /// Type-specific data
    pub data: Vec<u8>,
}

impl EapPacket {
    /// Create a new EAP packet
    pub fn new(code: EapCode, identifier: u8, eap_type: Option<EapType>, data: Vec<u8>) -> Self {
        EapPacket {
            code,
            identifier,
            eap_type,
            data,
        }
    }

    /// Create an EAP Identity Request
    pub fn identity_request(identifier: u8, message: &str) -> Self {
        EapPacket {
            code: EapCode::Request,
            identifier,
            eap_type: Some(EapType::Identity),
            data: message.as_bytes().to_vec(),
        }
    }

    /// Create an EAP Identity Response
    pub fn identity_response(identifier: u8, identity: &str) -> Self {
        EapPacket {
            code: EapCode::Response,
            identifier,
            eap_type: Some(EapType::Identity),
            data: identity.as_bytes().to_vec(),
        }
    }

    /// Create an EAP Success packet
    pub fn success(identifier: u8) -> Self {
        EapPacket {
            code: EapCode::Success,
            identifier,
            eap_type: None,
            data: Vec::new(),
        }
    }

    /// Create an EAP Failure packet
    pub fn failure(identifier: u8) -> Self {
        EapPacket {
            code: EapCode::Failure,
            identifier,
            eap_type: None,
            data: Vec::new(),
        }
    }

    /// Parse EAP packet from bytes
    ///
    /// # Packet Format
    /// - Code (1 byte)
    /// - Identifier (1 byte)
    /// - Length (2 bytes, network byte order)
    /// - Type (1 byte, only for Request/Response)
    /// - Type-Data (variable length)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EapError> {
        if bytes.len() < 4 {
            return Err(EapError::PacketTooShort {
                expected: 4,
                actual: bytes.len(),
            });
        }

        // Parse header
        let code = EapCode::from_u8(bytes[0]).ok_or(EapError::InvalidCode(bytes[0]))?;
        let identifier = bytes[1];
        let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;

        // Validate length
        if length < 4 {
            return Err(EapError::InvalidLength(length));
        }
        if bytes.len() < length {
            return Err(EapError::PacketTooShort {
                expected: length,
                actual: bytes.len(),
            });
        }

        // Parse type and data based on code
        let (eap_type, data) = match code {
            EapCode::Request | EapCode::Response => {
                if length < 5 {
                    return Err(EapError::InvalidLength(length));
                }
                let type_byte = bytes[4];
                let eap_type = EapType::from_u8(type_byte);
                let data = bytes[5..length].to_vec();
                (eap_type, data)
            }
            EapCode::Success | EapCode::Failure => {
                // Success and Failure packets have no Type field
                (None, Vec::new())
            }
        };

        Ok(EapPacket {
            code,
            identifier,
            eap_type,
            data,
        })
    }

    /// Encode EAP packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Add code and identifier
        bytes.push(self.code.as_u8());
        bytes.push(self.identifier);

        // Calculate length
        let length = match self.code {
            EapCode::Request | EapCode::Response => {
                4 + 1 + self.data.len() // header + type + data
            }
            EapCode::Success | EapCode::Failure => {
                4 // header only
            }
        };

        // Add length (network byte order)
        bytes.extend_from_slice(&(length as u16).to_be_bytes());

        // Add type and data for Request/Response
        if let Some(eap_type) = self.eap_type {
            bytes.push(eap_type.as_u8());
            bytes.extend_from_slice(&self.data);
        }

        bytes
    }

    /// Get the total length of the packet
    pub fn length(&self) -> usize {
        match self.code {
            EapCode::Request | EapCode::Response => 4 + 1 + self.data.len(),
            EapCode::Success | EapCode::Failure => 4,
        }
    }
}

/// EAP-related errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EapError {
    #[error("Packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    #[error("Invalid EAP code: {0}")]
    InvalidCode(u8),

    #[error("Invalid packet length: {0}")]
    InvalidLength(usize),

    #[error("Unknown EAP type: {0}")]
    UnknownType(u8),

    #[error("Fragmentation not supported")]
    FragmentationNotSupported,

    #[error("EAP session not found")]
    SessionNotFound,

    #[error("Invalid state for operation")]
    InvalidState,

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid challenge length: {0}")]
    InvalidChallengeLength(usize),

    #[error("Invalid response format")]
    InvalidResponseFormat,

    #[error("Encoding error: {0}")]
    EncodingError(String),
}

/// EAP-MD5 Challenge implementation (RFC 3748 Section 5.4)
///
/// EAP-MD5 provides a simple challenge-response authentication using MD5 hash.
/// It is primarily useful for testing and simple deployments.
///
/// Security Note: EAP-MD5 does not provide mutual authentication or key derivation,
/// and should not be used in production wireless environments. It's included here
/// for testing and compatibility with legacy systems.
pub mod eap_md5 {
    use super::*;

    /// EAP-MD5 Challenge value size (typically 16 bytes)
    pub const MD5_CHALLENGE_SIZE: usize = 16;

    /// EAP-MD5 Response value size (16 bytes MD5 hash)
    pub const MD5_RESPONSE_SIZE: usize = 16;

    /// Create an EAP-MD5 Challenge request
    ///
    /// # Arguments
    /// * `identifier` - EAP packet identifier
    /// * `challenge` - Challenge bytes (typically 16 bytes random)
    /// * `message` - Optional message to include after challenge
    ///
    /// # Format
    /// ```text
    /// 0                   1                   2                   3
    /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Value-Size    | Value (Challenge) ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Name (optional) ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    pub fn create_challenge(identifier: u8, challenge: &[u8], message: &str) -> EapPacket {
        let mut data = Vec::new();
        data.push(challenge.len() as u8); // Value-Size
        data.extend_from_slice(challenge); // Challenge value
        data.extend_from_slice(message.as_bytes()); // Optional name/message

        EapPacket::new(
            EapCode::Request,
            identifier,
            Some(EapType::Md5Challenge),
            data,
        )
    }

    /// Parse an EAP-MD5 Challenge from packet data
    ///
    /// Returns (challenge_bytes, optional_message)
    pub fn parse_challenge(packet: &EapPacket) -> Result<(Vec<u8>, String), EapError> {
        if packet.eap_type != Some(EapType::Md5Challenge) {
            return Err(EapError::InvalidResponseFormat);
        }

        if packet.data.is_empty() {
            return Err(EapError::InvalidChallengeLength(0));
        }

        let value_size = packet.data[0] as usize;
        if packet.data.len() < 1 + value_size {
            return Err(EapError::InvalidChallengeLength(packet.data.len()));
        }

        let challenge = packet.data[1..1 + value_size].to_vec();
        let message = if packet.data.len() > 1 + value_size {
            String::from_utf8_lossy(&packet.data[1 + value_size..]).to_string()
        } else {
            String::new()
        };

        Ok((challenge, message))
    }

    /// Create an EAP-MD5 Response
    ///
    /// # Arguments
    /// * `identifier` - EAP packet identifier (must match challenge)
    /// * `response_hash` - MD5 hash of (identifier + password + challenge)
    /// * `name` - Optional name/identity
    pub fn create_response(identifier: u8, response_hash: &[u8; 16], name: &str) -> EapPacket {
        let mut data = Vec::new();
        data.push(MD5_RESPONSE_SIZE as u8); // Value-Size
        data.extend_from_slice(response_hash); // MD5 hash
        data.extend_from_slice(name.as_bytes()); // Optional name

        EapPacket::new(
            EapCode::Response,
            identifier,
            Some(EapType::Md5Challenge),
            data,
        )
    }

    /// Parse an EAP-MD5 Response from packet data
    ///
    /// Returns (response_hash, optional_name)
    pub fn parse_response(packet: &EapPacket) -> Result<([u8; 16], String), EapError> {
        if packet.eap_type != Some(EapType::Md5Challenge) {
            return Err(EapError::InvalidResponseFormat);
        }

        if packet.data.is_empty() {
            return Err(EapError::InvalidChallengeLength(0));
        }

        let value_size = packet.data[0] as usize;
        if value_size != MD5_RESPONSE_SIZE {
            return Err(EapError::InvalidChallengeLength(value_size));
        }

        if packet.data.len() < 1 + MD5_RESPONSE_SIZE {
            return Err(EapError::PacketTooShort {
                expected: 1 + MD5_RESPONSE_SIZE,
                actual: packet.data.len(),
            });
        }

        let mut response_hash = [0u8; 16];
        response_hash.copy_from_slice(&packet.data[1..1 + MD5_RESPONSE_SIZE]);

        let name = if packet.data.len() > 1 + MD5_RESPONSE_SIZE {
            String::from_utf8_lossy(&packet.data[1 + MD5_RESPONSE_SIZE..]).to_string()
        } else {
            String::new()
        };

        Ok((response_hash, name))
    }

    /// Compute the expected EAP-MD5 response hash
    ///
    /// Hash = MD5(identifier + password + challenge)
    ///
    /// # Arguments
    /// * `identifier` - EAP packet identifier
    /// * `password` - User's password (plain text)
    /// * `challenge` - Challenge bytes from the request
    pub fn compute_response_hash(identifier: u8, password: &str, challenge: &[u8]) -> [u8; 16] {
        let mut data = Vec::new();
        data.push(identifier);
        data.extend_from_slice(password.as_bytes());
        data.extend_from_slice(challenge);

        let digest = md5::compute(&data);
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&digest.0);
        hash
    }

    /// Verify an EAP-MD5 response
    ///
    /// Returns true if the response hash matches the expected hash
    pub fn verify_response(
        identifier: u8,
        password: &str,
        challenge: &[u8],
        response_hash: &[u8; 16],
    ) -> bool {
        let expected = compute_response_hash(identifier, password, challenge);
        expected == *response_hash
    }
}

/// EAP authentication state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapState {
    /// Initial state - awaiting identity request
    Initialize,
    /// Identity request sent, awaiting response
    IdentityRequested,
    /// Identity received, selecting method
    IdentityReceived,
    /// Authentication method selected, awaiting challenge response
    MethodRequested,
    /// Challenge sent, awaiting response
    ChallengeRequested,
    /// Response received, validating
    ResponseReceived,
    /// Authentication succeeded
    Success,
    /// Authentication failed
    Failure,
    /// Timeout occurred
    Timeout,
}

impl EapState {
    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            EapState::Success | EapState::Failure | EapState::Timeout
        )
    }

    /// Check if this state can transition to another state
    pub fn can_transition_to(&self, next: &EapState) -> bool {
        match (self, next) {
            // From Initialize
            (EapState::Initialize, EapState::IdentityRequested) => true,

            // From IdentityRequested
            (EapState::IdentityRequested, EapState::IdentityReceived) => true,
            (EapState::IdentityRequested, EapState::Failure) => true,
            (EapState::IdentityRequested, EapState::Timeout) => true,

            // From IdentityReceived
            (EapState::IdentityReceived, EapState::MethodRequested) => true,
            (EapState::IdentityReceived, EapState::Failure) => true,

            // From MethodRequested
            (EapState::MethodRequested, EapState::ChallengeRequested) => true,
            (EapState::MethodRequested, EapState::Failure) => true,
            (EapState::MethodRequested, EapState::Timeout) => true,

            // From ChallengeRequested
            (EapState::ChallengeRequested, EapState::ResponseReceived) => true,
            (EapState::ChallengeRequested, EapState::Failure) => true,
            (EapState::ChallengeRequested, EapState::Timeout) => true,

            // From ResponseReceived
            (EapState::ResponseReceived, EapState::Success) => true,
            (EapState::ResponseReceived, EapState::Failure) => true,
            (EapState::ResponseReceived, EapState::ChallengeRequested) => true, // For multi-round auth

            // Terminal states can't transition
            _ if self.is_terminal() => false,

            // Default: no transition
            _ => false,
        }
    }
}

/// EAP session state for tracking authentication progress
#[derive(Debug, Clone)]
pub struct EapSession {
    /// Session identifier (typically username or session ID)
    pub session_id: String,
    /// Current authentication state
    pub state: EapState,
    /// Current EAP identifier (increments with each request)
    pub current_identifier: u8,
    /// Selected EAP method
    pub eap_method: Option<EapType>,
    /// User identity (from Identity response)
    pub identity: Option<String>,
    /// Last sent packet (for retransmission)
    pub last_request: Option<EapPacket>,
    /// Challenge data (method-specific)
    pub challenge: Option<Vec<u8>>,
    /// Session creation timestamp (Unix epoch seconds)
    pub created_at: u64,
    /// Last activity timestamp (Unix epoch seconds)
    pub last_activity: u64,
    /// Number of authentication attempts
    pub attempt_count: u32,
}

impl EapSession {
    /// Create a new EAP session
    pub fn new(session_id: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            session_id,
            state: EapState::Initialize,
            current_identifier: 0,
            eap_method: None,
            identity: None,
            last_request: None,
            challenge: None,
            created_at: now,
            last_activity: now,
            attempt_count: 0,
        }
    }

    /// Transition to a new state
    pub fn transition(&mut self, new_state: EapState) -> Result<(), EapError> {
        if !self.state.can_transition_to(&new_state) {
            return Err(EapError::InvalidState);
        }

        self.state = new_state;
        self.update_activity();
        Ok(())
    }

    /// Get next identifier and increment
    pub fn next_identifier(&mut self) -> u8 {
        let id = self.current_identifier;
        self.current_identifier = self.current_identifier.wrapping_add(1);
        self.update_activity();
        id
    }

    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Check if session has timed out
    pub fn is_timed_out(&self, timeout_seconds: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - self.last_activity > timeout_seconds
    }

    /// Get session age in seconds
    pub fn age(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - self.created_at
    }

    /// Increment attempt counter
    pub fn increment_attempts(&mut self) {
        self.attempt_count += 1;
        self.update_activity();
    }

    /// Check if maximum attempts exceeded
    pub fn is_max_attempts_exceeded(&self, max_attempts: u32) -> bool {
        self.attempt_count >= max_attempts
    }
}

/// EAP session manager for tracking multiple concurrent sessions
#[derive(Debug)]
pub struct EapSessionManager {
    /// Active sessions indexed by session ID
    sessions: std::collections::HashMap<String, EapSession>,
    /// Default session timeout in seconds
    default_timeout: u64,
    /// Maximum authentication attempts per session
    max_attempts: u32,
}

impl EapSessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            default_timeout: 300, // 5 minutes default
            max_attempts: 3,
        }
    }

    /// Create a new session manager with custom settings
    pub fn with_config(timeout_seconds: u64, max_attempts: u32) -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            default_timeout: timeout_seconds,
            max_attempts,
        }
    }

    /// Create a new session
    pub fn create_session(&mut self, session_id: String) -> &mut EapSession {
        let session = EapSession::new(session_id.clone());
        self.sessions.insert(session_id.clone(), session);
        self.sessions.get_mut(&session_id).unwrap()
    }

    /// Get an existing session
    pub fn get_session(&self, session_id: &str) -> Option<&EapSession> {
        self.sessions.get(session_id)
    }

    /// Get a mutable reference to an existing session
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut EapSession> {
        self.sessions.get_mut(session_id)
    }

    /// Remove a session
    pub fn remove_session(&mut self, session_id: &str) -> Option<EapSession> {
        self.sessions.remove(session_id)
    }

    /// Get or create a session
    pub fn get_or_create_session(&mut self, session_id: String) -> &mut EapSession {
        if !self.sessions.contains_key(&session_id) {
            self.create_session(session_id.clone());
        }
        self.sessions.get_mut(&session_id).unwrap()
    }

    /// Clean up timed out sessions
    pub fn cleanup_timed_out(&mut self) -> usize {
        let timeout = self.default_timeout;
        let before_count = self.sessions.len();

        self.sessions
            .retain(|_, session| !session.is_timed_out(timeout));

        before_count - self.sessions.len()
    }

    /// Clean up terminal sessions (success/failure/timeout)
    pub fn cleanup_terminal(&mut self) -> usize {
        let before_count = self.sessions.len();

        self.sessions
            .retain(|_, session| !session.state.is_terminal());

        before_count - self.sessions.len()
    }

    /// Get number of active sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get statistics about sessions
    pub fn stats(&self) -> SessionStats {
        let mut stats = SessionStats::default();

        for session in self.sessions.values() {
            stats.total += 1;

            match session.state {
                EapState::Initialize => stats.initialize += 1,
                EapState::IdentityRequested => stats.identity_requested += 1,
                EapState::IdentityReceived => stats.identity_received += 1,
                EapState::MethodRequested => stats.method_requested += 1,
                EapState::ChallengeRequested => stats.challenge_requested += 1,
                EapState::ResponseReceived => stats.response_received += 1,
                EapState::Success => stats.success += 1,
                EapState::Failure => stats.failure += 1,
                EapState::Timeout => stats.timeout += 1,
            }
        }

        stats
    }
}

impl Default for EapSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Session statistics
#[derive(Debug, Default, Clone)]
pub struct SessionStats {
    pub total: usize,
    pub initialize: usize,
    pub identity_requested: usize,
    pub identity_received: usize,
    pub method_requested: usize,
    pub challenge_requested: usize,
    pub response_received: usize,
    pub success: usize,
    pub failure: usize,
    pub timeout: usize,
}

// =============================================================================
// RADIUS Integration Helpers (RFC 3579)
// =============================================================================

/// Convert an EAP packet to RADIUS EAP-Message attribute(s)
///
/// Per RFC 3579, EAP packets are encapsulated in EAP-Message attributes (Type 79).
/// If the EAP packet is larger than 253 bytes, it MUST be split across multiple
/// EAP-Message attributes.
///
/// # Arguments
/// * `eap_packet` - The EAP packet to encapsulate
///
/// # Returns
/// Vector of EAP-Message attributes. May contain multiple attributes if the
/// EAP packet exceeds the maximum attribute value length (253 bytes).
///
/// # Example
/// ```
/// use radius_proto::eap::{EapPacket, EapCode, eap_to_radius_attributes};
///
/// let eap = EapPacket::new(EapCode::Request, 1, None, vec![]);
/// let attributes = eap_to_radius_attributes(&eap).unwrap();
/// assert_eq!(attributes.len(), 1);
/// assert_eq!(attributes[0].attr_type, 79); // EAP-Message
/// ```
pub fn eap_to_radius_attributes(eap_packet: &EapPacket) -> Result<Vec<Attribute>, EapError> {
    let eap_bytes = eap_packet.to_bytes();
    let mut attributes = Vec::new();

    // Maximum EAP-Message attribute value length is 253 bytes
    const MAX_ATTR_VALUE_LEN: usize = Attribute::MAX_VALUE_LENGTH;

    // Split EAP packet into chunks if necessary
    let mut offset = 0;
    while offset < eap_bytes.len() {
        let chunk_len = std::cmp::min(MAX_ATTR_VALUE_LEN, eap_bytes.len() - offset);
        let chunk = eap_bytes[offset..offset + chunk_len].to_vec();

        let attr = Attribute::new(AttributeType::EapMessage as u8, chunk)
            .map_err(|e| EapError::EncodingError(format!("Failed to create EAP-Message attribute: {}", e)))?;

        attributes.push(attr);
        offset += chunk_len;
    }

    Ok(attributes)
}

/// Extract EAP packet from RADIUS packet
///
/// Per RFC 3579, EAP packets may be fragmented across multiple EAP-Message
/// attributes. This function reassembles all EAP-Message attributes into a
/// single EAP packet.
///
/// # Arguments
/// * `radius_packet` - The RADIUS packet containing EAP-Message attribute(s)
///
/// # Returns
/// The reassembled EAP packet, or None if no EAP-Message attributes found
///
/// # Example
/// ```
/// use radius_proto::eap::eap_from_radius_packet;
/// use radius_proto::{Packet, Code, Attribute};
///
/// let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
/// // ... add EAP-Message attributes ...
///
/// if let Some(eap) = eap_from_radius_packet(&packet).unwrap() {
///     println!("EAP Code: {:?}", eap.code);
/// }
/// ```
pub fn eap_from_radius_packet(radius_packet: &Packet) -> Result<Option<EapPacket>, EapError> {
    // Collect all EAP-Message attributes (Type 79)
    let eap_message_type = AttributeType::EapMessage as u8;
    let mut eap_bytes = Vec::new();

    for attr in &radius_packet.attributes {
        if attr.attr_type == eap_message_type {
            eap_bytes.extend_from_slice(&attr.value);
        }
    }

    // No EAP-Message attributes found
    if eap_bytes.is_empty() {
        return Ok(None);
    }

    // Decode the reassembled EAP packet
    let eap_packet = EapPacket::from_bytes(&eap_bytes)?;
    Ok(Some(eap_packet))
}

/// Add an EAP packet to a RADIUS packet as EAP-Message attribute(s)
///
/// This is a convenience function that combines `eap_to_radius_attributes`
/// and adding the attributes to a RADIUS packet.
///
/// # Arguments
/// * `radius_packet` - The RADIUS packet to add EAP-Message attributes to
/// * `eap_packet` - The EAP packet to encapsulate
///
/// # Example
/// ```
/// use radius_proto::{Packet, Code};
/// use radius_proto::eap::{EapPacket, EapCode, add_eap_to_radius_packet};
///
/// let mut radius = Packet::new(Code::AccessChallenge, 1, [0u8; 16]);
/// let eap = EapPacket::new(EapCode::Request, 1, None, vec![]);
///
/// add_eap_to_radius_packet(&mut radius, &eap).unwrap();
/// ```
pub fn add_eap_to_radius_packet(
    radius_packet: &mut Packet,
    eap_packet: &EapPacket,
) -> Result<(), EapError> {
    let eap_attributes = eap_to_radius_attributes(eap_packet)?;

    for attr in eap_attributes {
        radius_packet.add_attribute(attr);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eap_code_conversion() {
        assert_eq!(EapCode::from_u8(1), Some(EapCode::Request));
        assert_eq!(EapCode::from_u8(2), Some(EapCode::Response));
        assert_eq!(EapCode::from_u8(3), Some(EapCode::Success));
        assert_eq!(EapCode::from_u8(4), Some(EapCode::Failure));
        assert_eq!(EapCode::from_u8(5), None);

        assert_eq!(EapCode::Request.as_u8(), 1);
        assert_eq!(EapCode::Response.as_u8(), 2);
        assert_eq!(EapCode::Success.as_u8(), 3);
        assert_eq!(EapCode::Failure.as_u8(), 4);
    }

    #[test]
    fn test_eap_type_conversion() {
        assert_eq!(EapType::from_u8(1), Some(EapType::Identity));
        assert_eq!(EapType::from_u8(4), Some(EapType::Md5Challenge));
        assert_eq!(EapType::from_u8(13), Some(EapType::Tls));
        assert_eq!(EapType::from_u8(255), None);

        assert_eq!(EapType::Identity.as_u8(), 1);
        assert_eq!(EapType::Md5Challenge.as_u8(), 4);
    }

    #[test]
    fn test_identity_request_encode_decode() {
        let packet = EapPacket::identity_request(42, "Enter your username");
        let bytes = packet.to_bytes();

        assert_eq!(bytes[0], 1); // Request code
        assert_eq!(bytes[1], 42); // Identifier
        assert_eq!(bytes[4], 1); // Identity type

        let decoded = EapPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.code, EapCode::Request);
        assert_eq!(decoded.identifier, 42);
        assert_eq!(decoded.eap_type, Some(EapType::Identity));
        assert_eq!(decoded.data, "Enter your username".as_bytes());
    }

    #[test]
    fn test_identity_response_encode_decode() {
        let packet = EapPacket::identity_response(42, "alice@example.com");
        let bytes = packet.to_bytes();

        let decoded = EapPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.code, EapCode::Response);
        assert_eq!(decoded.identifier, 42);
        assert_eq!(decoded.eap_type, Some(EapType::Identity));
        assert_eq!(decoded.data, "alice@example.com".as_bytes());
    }

    #[test]
    fn test_success_encode_decode() {
        let packet = EapPacket::success(99);
        let bytes = packet.to_bytes();

        assert_eq!(bytes.len(), 4); // Success has no type or data
        assert_eq!(bytes[0], 3); // Success code
        assert_eq!(bytes[1], 99); // Identifier

        let decoded = EapPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.code, EapCode::Success);
        assert_eq!(decoded.identifier, 99);
        assert_eq!(decoded.eap_type, None);
        assert_eq!(decoded.data.len(), 0);
    }

    #[test]
    fn test_failure_encode_decode() {
        let packet = EapPacket::failure(123);
        let bytes = packet.to_bytes();

        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0], 4); // Failure code

        let decoded = EapPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.code, EapCode::Failure);
        assert_eq!(decoded.identifier, 123);
        assert_eq!(decoded.eap_type, None);
    }

    #[test]
    fn test_packet_too_short() {
        let bytes = vec![1, 2]; // Only 2 bytes
        let result = EapPacket::from_bytes(&bytes);
        assert!(matches!(result, Err(EapError::PacketTooShort { .. })));
    }

    #[test]
    fn test_invalid_code() {
        let bytes = vec![99, 1, 0, 4]; // Invalid code 99
        let result = EapPacket::from_bytes(&bytes);
        assert!(matches!(result, Err(EapError::InvalidCode(99))));
    }

    #[test]
    fn test_packet_length_mismatch() {
        // Length says 10 bytes but only provide 4
        let bytes = vec![1, 1, 0, 10];
        let result = EapPacket::from_bytes(&bytes);
        assert!(matches!(result, Err(EapError::PacketTooShort { .. })));
    }

    #[test]
    fn test_eap_md5_challenge_create_parse() {
        use super::eap_md5;

        let challenge_bytes = b"0123456789abcdef"; // 16 bytes
        let packet = eap_md5::create_challenge(42, challenge_bytes, "Enter password");

        // Verify packet structure
        assert_eq!(packet.code, EapCode::Request);
        assert_eq!(packet.identifier, 42);
        assert_eq!(packet.eap_type, Some(EapType::Md5Challenge));

        // Parse it back
        let (parsed_challenge, message) = eap_md5::parse_challenge(&packet).unwrap();
        assert_eq!(parsed_challenge, challenge_bytes);
        assert_eq!(message, "Enter password");
    }

    #[test]
    fn test_eap_md5_response_create_parse() {
        use super::eap_md5;

        let response_hash = [1u8; 16];
        let packet = eap_md5::create_response(99, &response_hash, "alice");

        // Verify packet structure
        assert_eq!(packet.code, EapCode::Response);
        assert_eq!(packet.identifier, 99);
        assert_eq!(packet.eap_type, Some(EapType::Md5Challenge));

        // Parse it back
        let (parsed_hash, name) = eap_md5::parse_response(&packet).unwrap();
        assert_eq!(parsed_hash, response_hash);
        assert_eq!(name, "alice");
    }

    #[test]
    fn test_eap_md5_compute_and_verify() {
        use super::eap_md5;

        let identifier = 42;
        let password = "secret123";
        let challenge = b"random_challenge";

        // Compute response hash
        let response_hash = eap_md5::compute_response_hash(identifier, password, challenge);

        // Verify it
        assert!(eap_md5::verify_response(
            identifier,
            password,
            challenge,
            &response_hash
        ));

        // Verify wrong password fails
        assert!(!eap_md5::verify_response(
            identifier,
            "wrong_password",
            challenge,
            &response_hash
        ));

        // Verify wrong identifier fails
        assert!(!eap_md5::verify_response(
            99,
            password,
            challenge,
            &response_hash
        ));
    }

    #[test]
    fn test_eap_md5_full_flow() {
        use super::eap_md5;

        // Server creates challenge
        let challenge_bytes = b"1234567890abcdef";
        let challenge_packet = eap_md5::create_challenge(1, challenge_bytes, "");

        // Encode and decode challenge
        let challenge_bytes_encoded = challenge_packet.to_bytes();
        let challenge_decoded = EapPacket::from_bytes(&challenge_bytes_encoded).unwrap();

        // Client parses challenge
        let (received_challenge, _) = eap_md5::parse_challenge(&challenge_decoded).unwrap();

        // Client computes response
        let password = "my_password";
        let response_hash = eap_md5::compute_response_hash(
            challenge_decoded.identifier,
            password,
            &received_challenge,
        );

        // Client sends response
        let response_packet =
            eap_md5::create_response(challenge_decoded.identifier, &response_hash, "user123");

        // Encode and decode response
        let response_bytes = response_packet.to_bytes();
        let response_decoded = EapPacket::from_bytes(&response_bytes).unwrap();

        // Server verifies response
        let (received_hash, username) = eap_md5::parse_response(&response_decoded).unwrap();
        assert_eq!(username, "user123");

        let is_valid = eap_md5::verify_response(
            response_decoded.identifier,
            password,
            challenge_bytes,
            &received_hash,
        );

        assert!(is_valid);
    }

    // ===== State Machine Tests =====

    #[test]
    fn test_eap_state_transitions() {
        // Test valid transitions
        assert!(EapState::Initialize.can_transition_to(&EapState::IdentityRequested));
        assert!(EapState::IdentityRequested.can_transition_to(&EapState::IdentityReceived));
        assert!(EapState::IdentityReceived.can_transition_to(&EapState::MethodRequested));
        assert!(EapState::MethodRequested.can_transition_to(&EapState::ChallengeRequested));
        assert!(EapState::ChallengeRequested.can_transition_to(&EapState::ResponseReceived));
        assert!(EapState::ResponseReceived.can_transition_to(&EapState::Success));
        assert!(EapState::ResponseReceived.can_transition_to(&EapState::Failure));

        // Test invalid transitions
        assert!(!EapState::Initialize.can_transition_to(&EapState::Success));
        assert!(!EapState::IdentityRequested.can_transition_to(&EapState::Success));
        assert!(!EapState::Success.can_transition_to(&EapState::Failure));
        assert!(!EapState::Failure.can_transition_to(&EapState::Success));

        // Test terminal states
        assert!(EapState::Success.is_terminal());
        assert!(EapState::Failure.is_terminal());
        assert!(EapState::Timeout.is_terminal());
        assert!(!EapState::Initialize.is_terminal());
        assert!(!EapState::MethodRequested.is_terminal());
    }

    #[test]
    fn test_eap_state_multi_round_auth() {
        // Multi-round authentication: ResponseReceived -> ChallengeRequested
        assert!(EapState::ResponseReceived.can_transition_to(&EapState::ChallengeRequested));
    }

    #[test]
    fn test_eap_state_failure_from_any() {
        // Can fail from most states
        assert!(EapState::IdentityRequested.can_transition_to(&EapState::Failure));
        assert!(EapState::IdentityReceived.can_transition_to(&EapState::Failure));
        assert!(EapState::MethodRequested.can_transition_to(&EapState::Failure));
        assert!(EapState::ChallengeRequested.can_transition_to(&EapState::Failure));
        assert!(EapState::ResponseReceived.can_transition_to(&EapState::Failure));
    }

    #[test]
    fn test_eap_state_timeout_transitions() {
        // Can timeout from specific states
        assert!(EapState::IdentityRequested.can_transition_to(&EapState::Timeout));
        assert!(EapState::MethodRequested.can_transition_to(&EapState::Timeout));
        assert!(EapState::ChallengeRequested.can_transition_to(&EapState::Timeout));
    }

    // ===== Session Tests =====

    #[test]
    fn test_eap_session_creation() {
        let session = EapSession::new("test_session".to_string());

        assert_eq!(session.session_id, "test_session");
        assert_eq!(session.state, EapState::Initialize);
        assert_eq!(session.current_identifier, 0);
        assert_eq!(session.eap_method, None);
        assert_eq!(session.identity, None);
        assert_eq!(session.last_request, None);
        assert_eq!(session.challenge, None);
        assert_eq!(session.attempt_count, 0);
        assert!(session.created_at > 0);
        assert!(session.last_activity > 0);
    }

    #[test]
    fn test_eap_session_transition_valid() {
        let mut session = EapSession::new("test".to_string());

        // Valid transition
        assert!(session.transition(EapState::IdentityRequested).is_ok());
        assert_eq!(session.state, EapState::IdentityRequested);

        assert!(session.transition(EapState::IdentityReceived).is_ok());
        assert_eq!(session.state, EapState::IdentityReceived);
    }

    #[test]
    fn test_eap_session_transition_invalid() {
        let mut session = EapSession::new("test".to_string());

        // Invalid transition
        let result = session.transition(EapState::Success);
        assert!(result.is_err());
        assert_eq!(session.state, EapState::Initialize); // State unchanged
    }

    #[test]
    fn test_eap_session_identifier_increment() {
        let mut session = EapSession::new("test".to_string());

        assert_eq!(session.next_identifier(), 0);
        assert_eq!(session.next_identifier(), 1);
        assert_eq!(session.next_identifier(), 2);
        assert_eq!(session.current_identifier, 3);
    }

    #[test]
    fn test_eap_session_identifier_wrapping() {
        let mut session = EapSession::new("test".to_string());
        session.current_identifier = 255;

        assert_eq!(session.next_identifier(), 255);
        assert_eq!(session.current_identifier, 0); // Wrapped around
    }

    #[test]
    fn test_eap_session_timeout_check() {
        let mut session = EapSession::new("test".to_string());

        // Set last_activity to 400 seconds ago
        session.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 400;

        assert!(!session.is_timed_out(500)); // Not timed out
        assert!(session.is_timed_out(300)); // Timed out
    }

    #[test]
    fn test_eap_session_age() {
        let mut session = EapSession::new("test".to_string());

        // Set created_at to 100 seconds ago
        session.created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 100;

        let age = session.age();
        assert!(age >= 100 && age <= 102); // Allow small timing variations
    }

    #[test]
    fn test_eap_session_attempts() {
        let mut session = EapSession::new("test".to_string());

        assert_eq!(session.attempt_count, 0);
        assert!(!session.is_max_attempts_exceeded(3));

        session.increment_attempts();
        assert_eq!(session.attempt_count, 1);

        session.increment_attempts();
        session.increment_attempts();
        assert_eq!(session.attempt_count, 3);
        assert!(session.is_max_attempts_exceeded(3));
        assert!(!session.is_max_attempts_exceeded(5));
    }

    #[test]
    fn test_eap_session_activity_update() {
        let mut session = EapSession::new("test".to_string());
        let initial_activity = session.last_activity;

        // Sleep briefly to ensure time difference
        std::thread::sleep(std::time::Duration::from_millis(100));

        session.update_activity();
        assert!(session.last_activity >= initial_activity);
    }

    // ===== Session Manager Tests =====

    #[test]
    fn test_session_manager_creation() {
        let manager = EapSessionManager::new();
        assert_eq!(manager.session_count(), 0);
        assert_eq!(manager.default_timeout, 300);
        assert_eq!(manager.max_attempts, 3);
    }

    #[test]
    fn test_session_manager_with_config() {
        let manager = EapSessionManager::with_config(600, 5);
        assert_eq!(manager.default_timeout, 600);
        assert_eq!(manager.max_attempts, 5);
    }

    #[test]
    fn test_session_manager_create_session() {
        let mut manager = EapSessionManager::new();

        let session = manager.create_session("session1".to_string());
        assert_eq!(session.session_id, "session1");
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_manager_get_session() {
        let mut manager = EapSessionManager::new();
        manager.create_session("session1".to_string());

        let session = manager.get_session("session1");
        assert!(session.is_some());
        assert_eq!(session.unwrap().session_id, "session1");

        let missing = manager.get_session("nonexistent");
        assert!(missing.is_none());
    }

    #[test]
    fn test_session_manager_get_session_mut() {
        let mut manager = EapSessionManager::new();
        manager.create_session("session1".to_string());

        {
            let session = manager.get_session_mut("session1").unwrap();
            session.increment_attempts();
        }

        let session = manager.get_session("session1").unwrap();
        assert_eq!(session.attempt_count, 1);
    }

    #[test]
    fn test_session_manager_remove_session() {
        let mut manager = EapSessionManager::new();
        manager.create_session("session1".to_string());
        assert_eq!(manager.session_count(), 1);

        let removed = manager.remove_session("session1");
        assert!(removed.is_some());
        assert_eq!(manager.session_count(), 0);

        let missing = manager.remove_session("session1");
        assert!(missing.is_none());
    }

    #[test]
    fn test_session_manager_get_or_create() {
        let mut manager = EapSessionManager::new();

        // First call creates
        let session1 = manager.get_or_create_session("session1".to_string());
        assert_eq!(session1.session_id, "session1");
        assert_eq!(manager.session_count(), 1);

        // Second call returns existing
        let session1_again = manager.get_or_create_session("session1".to_string());
        assert_eq!(session1_again.session_id, "session1");
        assert_eq!(manager.session_count(), 1); // Still 1
    }

    #[test]
    fn test_session_manager_cleanup_timed_out() {
        let mut manager = EapSessionManager::with_config(300, 3);

        // Create sessions with different ages
        let mut session1 = EapSession::new("session1".to_string());
        session1.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 400; // 400 seconds ago - timed out

        let session2 = EapSession::new("session2".to_string());
        // session2 has current timestamp - not timed out

        manager.sessions.insert("session1".to_string(), session1);
        manager.sessions.insert("session2".to_string(), session2);

        assert_eq!(manager.session_count(), 2);

        let removed = manager.cleanup_timed_out();
        assert_eq!(removed, 1); // Removed 1 timed out session
        assert_eq!(manager.session_count(), 1); // 1 remaining
        assert!(manager.get_session("session2").is_some());
        assert!(manager.get_session("session1").is_none());
    }

    #[test]
    fn test_session_manager_cleanup_terminal() {
        let mut manager = EapSessionManager::new();

        // Create sessions with different states
        let mut session1 = EapSession::new("session1".to_string());
        session1.state = EapState::Success; // Terminal

        let mut session2 = EapSession::new("session2".to_string());
        session2.state = EapState::Failure; // Terminal

        let mut session3 = EapSession::new("session3".to_string());
        session3.state = EapState::ChallengeRequested; // Not terminal

        manager.sessions.insert("session1".to_string(), session1);
        manager.sessions.insert("session2".to_string(), session2);
        manager.sessions.insert("session3".to_string(), session3);

        assert_eq!(manager.session_count(), 3);

        let removed = manager.cleanup_terminal();
        assert_eq!(removed, 2); // Removed 2 terminal sessions
        assert_eq!(manager.session_count(), 1); // 1 remaining
        assert!(manager.get_session("session3").is_some());
    }

    #[test]
    fn test_session_manager_stats() {
        let mut manager = EapSessionManager::new();

        // Create sessions in various states
        let mut s1 = EapSession::new("s1".to_string());
        s1.state = EapState::Initialize;

        let mut s2 = EapSession::new("s2".to_string());
        s2.state = EapState::IdentityRequested;

        let mut s3 = EapSession::new("s3".to_string());
        s3.state = EapState::ChallengeRequested;

        let mut s4 = EapSession::new("s4".to_string());
        s4.state = EapState::Success;

        let mut s5 = EapSession::new("s5".to_string());
        s5.state = EapState::Failure;

        manager.sessions.insert("s1".to_string(), s1);
        manager.sessions.insert("s2".to_string(), s2);
        manager.sessions.insert("s3".to_string(), s3);
        manager.sessions.insert("s4".to_string(), s4);
        manager.sessions.insert("s5".to_string(), s5);

        let stats = manager.stats();
        assert_eq!(stats.total, 5);
        assert_eq!(stats.initialize, 1);
        assert_eq!(stats.identity_requested, 1);
        assert_eq!(stats.challenge_requested, 1);
        assert_eq!(stats.success, 1);
        assert_eq!(stats.failure, 1);
    }

    #[test]
    fn test_session_manager_multiple_sessions() {
        let mut manager = EapSessionManager::new();

        for i in 0..10 {
            manager.create_session(format!("session_{}", i));
        }

        assert_eq!(manager.session_count(), 10);

        // Verify all sessions exist
        for i in 0..10 {
            assert!(manager.get_session(&format!("session_{}", i)).is_some());
        }
    }

    #[test]
    fn test_session_full_authentication_flow() {
        let mut manager = EapSessionManager::new();
        let session = manager.create_session("user_session".to_string());

        // Initial state
        assert_eq!(session.state, EapState::Initialize);

        // Request identity
        assert!(session.transition(EapState::IdentityRequested).is_ok());
        let id1 = session.next_identifier();
        assert_eq!(id1, 0);

        // Receive identity
        assert!(session.transition(EapState::IdentityReceived).is_ok());
        session.identity = Some("alice@example.com".to_string());

        // Select method
        assert!(session.transition(EapState::MethodRequested).is_ok());
        session.eap_method = Some(EapType::Md5Challenge);

        // Send challenge
        assert!(session.transition(EapState::ChallengeRequested).is_ok());
        let id2 = session.next_identifier();
        assert_eq!(id2, 1);
        session.challenge = Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Receive response
        assert!(session.transition(EapState::ResponseReceived).is_ok());

        // Success
        assert!(session.transition(EapState::Success).is_ok());

        // Verify final state
        assert_eq!(session.state, EapState::Success);
        assert_eq!(session.identity, Some("alice@example.com".to_string()));
        assert_eq!(session.eap_method, Some(EapType::Md5Challenge));
        assert!(session.state.is_terminal());
    }

    // =========================================================================
    // RADIUS Integration Helper Tests
    // =========================================================================

    #[test]
    fn test_eap_to_radius_attributes_small_packet() {
        // Small EAP packet that fits in one attribute
        let eap = EapPacket::new(EapCode::Request, 1, Some(EapType::Identity), vec![]);
        let attributes = eap_to_radius_attributes(&eap).unwrap();

        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].attr_type, AttributeType::EapMessage as u8);

        // Verify the attribute contains the encoded EAP packet
        let expected_eap_bytes = eap.to_bytes();
        assert_eq!(attributes[0].value, expected_eap_bytes);
    }

    #[test]
    fn test_eap_to_radius_attributes_large_packet() {
        // Create a large EAP packet that requires multiple attributes
        // Each EAP-Message attribute can hold max 253 bytes
        let large_data = vec![0x42; 500]; // 500 bytes of data
        let eap = EapPacket::new(EapCode::Request, 1, Some(EapType::Md5Challenge), large_data);
        let attributes = eap_to_radius_attributes(&eap).unwrap();

        // Should be split across multiple attributes
        assert!(attributes.len() > 1);

        // All attributes should be EAP-Message type
        for attr in &attributes {
            assert_eq!(attr.attr_type, AttributeType::EapMessage as u8);
        }

        // Reassemble and verify
        let mut reassembled = Vec::new();
        for attr in &attributes {
            reassembled.extend_from_slice(&attr.value);
        }

        let expected_eap_bytes = eap.to_bytes();
        assert_eq!(reassembled, expected_eap_bytes);
    }

    #[test]
    fn test_eap_from_radius_packet_single_attribute() {
        use crate::packet::Code;

        let eap = EapPacket::new(EapCode::Response, 5, Some(EapType::Identity), b"alice".to_vec());
        let eap_bytes = eap.to_bytes();

        // Create RADIUS packet with EAP-Message attribute
        let mut radius = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        let eap_attr = Attribute::new(AttributeType::EapMessage as u8, eap_bytes.clone()).unwrap();
        radius.add_attribute(eap_attr);

        // Extract EAP packet
        let extracted = eap_from_radius_packet(&radius).unwrap();
        assert!(extracted.is_some());

        let extracted_eap = extracted.unwrap();
        assert_eq!(extracted_eap.code, EapCode::Response);
        assert_eq!(extracted_eap.identifier, 5);
        assert_eq!(extracted_eap.eap_type, Some(EapType::Identity));
        assert_eq!(extracted_eap.data, b"alice");
    }

    #[test]
    fn test_eap_from_radius_packet_multiple_attributes() {
        use crate::packet::Code;

        // Create a large EAP packet
        let large_data = vec![0xAA; 400];
        let eap = EapPacket::new(EapCode::Request, 10, Some(EapType::Md5Challenge), large_data.clone());

        // Convert to RADIUS attributes (will be split)
        let eap_attributes = eap_to_radius_attributes(&eap).unwrap();
        assert!(eap_attributes.len() > 1);

        // Create RADIUS packet with fragmented EAP-Message attributes
        let mut radius = Packet::new(Code::AccessChallenge, 10, [0u8; 16]);
        for attr in eap_attributes {
            radius.add_attribute(attr);
        }

        // Extract and verify
        let extracted = eap_from_radius_packet(&radius).unwrap();
        assert!(extracted.is_some());

        let extracted_eap = extracted.unwrap();
        assert_eq!(extracted_eap.code, EapCode::Request);
        assert_eq!(extracted_eap.identifier, 10);
        assert_eq!(extracted_eap.eap_type, Some(EapType::Md5Challenge));
        assert_eq!(extracted_eap.data, large_data);
    }

    #[test]
    fn test_eap_from_radius_packet_no_eap_message() {
        use crate::packet::Code;

        // RADIUS packet without EAP-Message attributes
        let mut radius = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        radius.add_attribute(Attribute::string(AttributeType::UserName as u8, "alice").unwrap());

        let extracted = eap_from_radius_packet(&radius).unwrap();
        assert!(extracted.is_none());
    }

    #[test]
    fn test_add_eap_to_radius_packet() {
        use crate::packet::Code;

        let mut radius = Packet::new(Code::AccessChallenge, 2, [0u8; 16]);
        let eap = EapPacket::new(EapCode::Request, 2, Some(EapType::Md5Challenge), vec![1, 2, 3, 4]);

        // Initially no attributes
        assert_eq!(radius.attributes.len(), 0);

        // Add EAP packet
        add_eap_to_radius_packet(&mut radius, &eap).unwrap();

        // Should have EAP-Message attribute(s)
        assert!(radius.attributes.len() > 0);

        // All added attributes should be EAP-Message
        for attr in &radius.attributes {
            assert_eq!(attr.attr_type, AttributeType::EapMessage as u8);
        }

        // Verify we can extract it back
        let extracted = eap_from_radius_packet(&radius).unwrap().unwrap();
        assert_eq!(extracted.code, eap.code);
        assert_eq!(extracted.identifier, eap.identifier);
        assert_eq!(extracted.eap_type, eap.eap_type);
        assert_eq!(extracted.data, eap.data);
    }

    #[test]
    fn test_radius_integration_round_trip() {
        use crate::packet::Code;

        // Test various EAP packet types
        let test_cases = vec![
            EapPacket::new(EapCode::Request, 1, Some(EapType::Identity), vec![]),
            EapPacket::new(EapCode::Response, 2, Some(EapType::Identity), b"user@example.com".to_vec()),
            EapPacket::new(EapCode::Request, 3, Some(EapType::Md5Challenge), vec![0x11; 16]),
            EapPacket::new(EapCode::Success, 4, None, vec![]),
            EapPacket::new(EapCode::Failure, 5, None, vec![]),
        ];

        for original_eap in test_cases {
            let mut radius = Packet::new(Code::AccessRequest, 1, [0u8; 16]);

            // Add EAP to RADIUS
            add_eap_to_radius_packet(&mut radius, &original_eap).unwrap();

            // Extract EAP from RADIUS
            let extracted_eap = eap_from_radius_packet(&radius).unwrap().unwrap();

            // Verify round-trip
            assert_eq!(extracted_eap.code, original_eap.code);
            assert_eq!(extracted_eap.identifier, original_eap.identifier);
            assert_eq!(extracted_eap.eap_type, original_eap.eap_type);
            assert_eq!(extracted_eap.data, original_eap.data);
        }
    }

    #[test]
    fn test_radius_integration_with_other_attributes() {
        use crate::packet::Code;

        // RADIUS packet with both EAP-Message and other attributes
        let mut radius = Packet::new(Code::AccessRequest, 7, [0u8; 16]);

        // Add non-EAP attributes
        radius.add_attribute(Attribute::string(AttributeType::UserName as u8, "bob").unwrap());
        radius.add_attribute(Attribute::string(AttributeType::NasIdentifier as u8, "nas1").unwrap());

        // Add EAP packet
        let eap = EapPacket::new(EapCode::Response, 7, Some(EapType::Identity), b"bob@example.com".to_vec());
        add_eap_to_radius_packet(&mut radius, &eap).unwrap();

        // Add more attributes after EAP
        radius.add_attribute(Attribute::integer(AttributeType::NasPort as u8, 1234).unwrap());

        // Should have all attributes (2 before + EAP + 1 after = at least 4)
        assert!(radius.attributes.len() >= 4);

        // Should still be able to extract EAP correctly
        let extracted = eap_from_radius_packet(&radius).unwrap().unwrap();
        assert_eq!(extracted.code, EapCode::Response);
        assert_eq!(extracted.identifier, 7);
        assert_eq!(extracted.data, b"bob@example.com");
    }
}
