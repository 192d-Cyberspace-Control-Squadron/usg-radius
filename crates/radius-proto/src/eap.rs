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
}
