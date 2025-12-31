//! EAP-TEAP (Tunneled Extensible Authentication Protocol)
//!
//! Implementation of RFC 7170 - Tunnel Extensible Authentication Protocol (TEAP) Version 1
//!
//! TEAP is a two-phase authentication protocol:
//! - Phase 1: TLS tunnel establishment (reuses EAP-TLS infrastructure)
//! - Phase 2: TLV-based inner authentication inside encrypted tunnel
//!
//! # Architecture
//!
//! ```text
//! Phase 1: TLS Handshake (using EapTlsServer)
//!     ↓
//! Phase 2: TLV Protocol
//!     - Identity-Type TLV
//!     - Inner Auth (EAP-Payload or Basic-Password-Auth)
//!     - Crypto-Binding TLV (optional, for security)
//!     - Result TLV (success/failure)
//! ```
//!
//! # Example
//!
//! ```no_run
//! # use radius_proto::eap::eap_teap::*;
//! # use radius_proto::eap::eap_tls::*;
//! # use std::sync::Arc;
//! # use rustls::ServerConfig;
//! # let config = Arc::new(ServerConfig::builder().with_no_client_auth().with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into())).unwrap());
//! // Create TEAP server
//! let mut server = EapTeapServer::new(config);
//!
//! // Initialize connection (Phase 1)
//! server.initialize_connection().unwrap();
//!
//! // Process client messages...
//! ```

use super::eap_tls::{EapTlsPacket, EapTlsServer};
use super::EapError;
use std::sync::Arc;

/// TEAP TLV Type (RFC 7170 Section 4.2)
///
/// Defines all TLV types used in TEAP Phase 2 authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TlvType {
    /// Authority-ID TLV (Type 1) - Used for PAC provisioning
    AuthorityId = 1,
    /// Identity-Type TLV (Type 2) - Negotiates identity type (User/Machine)
    IdentityType = 2,
    /// Result TLV (Type 3) - Indicates final authentication result
    Result = 3,
    /// NAK TLV (Type 4) - Rejects unsupported TLV
    Nak = 4,
    /// Error TLV (Type 5) - Indicates protocol errors
    Error = 5,
    /// Channel-Binding TLV (Type 6) - Binds to specific channel
    ChannelBinding = 6,
    /// Vendor-Specific TLV (Type 7) - Vendor extensions
    VendorSpecific = 7,
    /// Request-Action TLV (Type 8) - Requests specific actions
    RequestAction = 8,
    /// EAP-Payload TLV (Type 9) - Encapsulates inner EAP method
    EapPayload = 9,
    /// Intermediate-Result TLV (Type 10) - Result of intermediate authentication
    IntermediateResult = 10,
    /// PAC TLV (Type 11) - Protected Access Credential
    Pac = 11,
    /// Crypto-Binding TLV (Type 12) - Cryptographic binding
    CryptoBinding = 12,
    /// Basic-Password-Auth-Req TLV (Type 13) - Password request
    BasicPasswordAuthReq = 13,
    /// Basic-Password-Auth-Resp TLV (Type 14) - Password response
    BasicPasswordAuthResp = 14,
    /// PKCS#7 TLV (Type 15) - Certificate provisioning
    Pkcs7 = 15,
    /// PKCS#10 TLV (Type 16) - Certificate request
    Pkcs10 = 16,
    /// Trusted-Server-Root TLV (Type 17) - Trusted server certificate
    TrustedServerRoot = 17,
}

impl TlvType {
    /// Convert from u16 to TlvType
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::AuthorityId),
            2 => Some(Self::IdentityType),
            3 => Some(Self::Result),
            4 => Some(Self::Nak),
            5 => Some(Self::Error),
            6 => Some(Self::ChannelBinding),
            7 => Some(Self::VendorSpecific),
            8 => Some(Self::RequestAction),
            9 => Some(Self::EapPayload),
            10 => Some(Self::IntermediateResult),
            11 => Some(Self::Pac),
            12 => Some(Self::CryptoBinding),
            13 => Some(Self::BasicPasswordAuthReq),
            14 => Some(Self::BasicPasswordAuthResp),
            15 => Some(Self::Pkcs7),
            16 => Some(Self::Pkcs10),
            17 => Some(Self::TrustedServerRoot),
            _ => None,
        }
    }
}

/// TEAP TLV Structure (RFC 7170 Section 4.2)
///
/// TLV Format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |M|R|            TLV Type       |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              Value...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - M = Mandatory bit (0x8000): If set, TLV must be understood
/// - R = Reserved (0x4000): Must be zero
/// - TLV Type = 14 bits (0x3FFF mask)
/// - Length = Length of Value field (not including Type/Length header)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeapTlv {
    /// TLV type (14 bits)
    pub tlv_type: u16,
    /// Mandatory flag (M bit)
    pub mandatory: bool,
    /// TLV value (variable length)
    pub value: Vec<u8>,
}

impl TeapTlv {
    /// Mandatory flag mask (M bit)
    pub const MANDATORY_FLAG: u16 = 0x8000;

    /// Reserved flag mask (R bit, must be 0)
    pub const RESERVED_FLAG: u16 = 0x4000;

    /// Type mask (14 bits)
    pub const TYPE_MASK: u16 = 0x3FFF;

    /// Create a new TLV
    ///
    /// # Arguments
    ///
    /// * `tlv_type` - TLV type
    /// * `mandatory` - Whether this TLV is mandatory
    /// * `value` - TLV value bytes
    ///
    /// # Example
    ///
    /// ```
    /// # use radius_proto::eap::eap_teap::{TeapTlv, TlvType};
    /// let tlv = TeapTlv::new(TlvType::Result, true, vec![0x01]); // Success result
    /// ```
    pub fn new(tlv_type: TlvType, mandatory: bool, value: Vec<u8>) -> Self {
        Self {
            tlv_type: tlv_type as u16,
            mandatory,
            value,
        }
    }

    /// Create a TLV from raw type value
    pub fn new_raw(tlv_type: u16, mandatory: bool, value: Vec<u8>) -> Self {
        Self {
            tlv_type,
            mandatory,
            value,
        }
    }

    /// Parse a single TLV from bytes
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing TLV data
    ///
    /// # Returns
    ///
    /// Returns `Ok((tlv, bytes_consumed))` on success, or `Err` if parsing fails.
    ///
    /// # Errors
    ///
    /// Returns `EapError::InvalidPacket` if:
    /// - Data is too short (< 4 bytes for header)
    /// - Length field exceeds available data
    /// - Reserved flag is set
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), EapError> {
        if data.len() < 4 {
            return Err(EapError::PacketTooShort {
                expected: 4,
                actual: data.len(),
            });
        }

        // Parse Type field (2 bytes, big-endian)
        let type_field = u16::from_be_bytes([data[0], data[1]]);

        // Extract M bit
        let mandatory = (type_field & Self::MANDATORY_FLAG) != 0;

        // Check R bit (must be 0)
        if (type_field & Self::RESERVED_FLAG) != 0 {
            return Err(EapError::InvalidResponseFormat);
        }

        // Extract TLV type (14 bits)
        let tlv_type = type_field & Self::TYPE_MASK;

        // Parse Length field (2 bytes, big-endian)
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Validate length
        if data.len() < 4 + length {
            return Err(EapError::InvalidLength(length));
        }

        // Extract value
        let value = data[4..4 + length].to_vec();

        let tlv = Self {
            tlv_type,
            mandatory,
            value,
        };

        Ok((tlv, 4 + length))
    }

    /// Encode TLV to bytes
    ///
    /// # Returns
    ///
    /// Returns byte vector containing encoded TLV
    ///
    /// # Example
    ///
    /// ```
    /// # use radius_proto::eap::eap_teap::{TeapTlv, TlvType};
    /// let tlv = TeapTlv::new(TlvType::Result, true, vec![0x01]);
    /// let bytes = tlv.to_bytes();
    /// assert_eq!(bytes.len(), 5); // 4 byte header + 1 byte value
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.value.len());

        // Encode Type field (M bit | TLV type)
        let mut type_field = self.tlv_type & Self::TYPE_MASK;
        if self.mandatory {
            type_field |= Self::MANDATORY_FLAG;
        }
        bytes.extend_from_slice(&type_field.to_be_bytes());

        // Encode Length field
        let length = self.value.len() as u16;
        bytes.extend_from_slice(&length.to_be_bytes());

        // Encode Value
        bytes.extend_from_slice(&self.value);

        bytes
    }

    /// Parse multiple TLVs from data
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing multiple TLVs
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<TeapTlv>)` with all parsed TLVs, or `Err` if parsing fails.
    ///
    /// # Example
    ///
    /// ```
    /// # use radius_proto::eap::eap_teap::TeapTlv;
    /// let data = vec![
    ///     0x80, 0x03, 0x00, 0x02, 0x00, 0x01, // Result TLV (mandatory, success)
    /// ];
    /// let tlvs = TeapTlv::parse_tlvs(&data).unwrap();
    /// assert_eq!(tlvs.len(), 1);
    /// ```
    pub fn parse_tlvs(data: &[u8]) -> Result<Vec<Self>, EapError> {
        let mut tlvs = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let (tlv, consumed) = Self::from_bytes(&data[offset..])?;
            tlvs.push(tlv);
            offset += consumed;
        }

        Ok(tlvs)
    }

    /// Encode multiple TLVs to bytes
    ///
    /// # Arguments
    ///
    /// * `tlvs` - Slice of TLVs to encode
    ///
    /// # Returns
    ///
    /// Returns byte vector containing all encoded TLVs concatenated
    ///
    /// # Example
    ///
    /// ```
    /// # use radius_proto::eap::eap_teap::{TeapTlv, TlvType};
    /// let tlvs = vec![
    ///     TeapTlv::new(TlvType::Result, true, vec![0x01]),
    /// ];
    /// let bytes = TeapTlv::encode_tlvs(&tlvs);
    /// ```
    pub fn encode_tlvs(tlvs: &[Self]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for tlv in tlvs {
            bytes.extend_from_slice(&tlv.to_bytes());
        }
        bytes
    }

    /// Get the TLV type as enum (if known)
    pub fn get_type(&self) -> Option<TlvType> {
        TlvType::from_u16(self.tlv_type)
    }
}

/// TEAP Result values (for Result and Intermediate-Result TLVs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TeapResult {
    /// Success
    Success = 1,
    /// Failure
    Failure = 2,
}

impl TeapResult {
    /// Convert from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Success),
            2 => Some(Self::Failure),
            _ => None,
        }
    }

    /// Convert to Result TLV
    pub fn to_result_tlv(&self) -> TeapTlv {
        let mut value = vec![0u8; 2];
        value[0..2].copy_from_slice(&(*self as u16).to_be_bytes());
        TeapTlv::new(TlvType::Result, true, value)
    }

    /// Convert to Intermediate-Result TLV
    pub fn to_intermediate_result_tlv(&self) -> TeapTlv {
        let mut value = vec![0u8; 2];
        value[0..2].copy_from_slice(&(*self as u16).to_be_bytes());
        TeapTlv::new(TlvType::IntermediateResult, true, value)
    }

    /// Parse Result TLV value
    pub fn from_result_tlv(tlv: &TeapTlv) -> Result<Self, EapError> {
        if tlv.tlv_type != TlvType::Result as u16 {
            return Err(EapError::InvalidResponseFormat);
        }
        if tlv.value.len() < 2 {
            return Err(EapError::InvalidLength(tlv.value.len()));
        }
        let result_value = u16::from_be_bytes([tlv.value[0], tlv.value[1]]);
        Self::from_u16(result_value).ok_or(EapError::InvalidResponseFormat)
    }
}

/// Identity Type values (for Identity-Type TLV)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IdentityType {
    /// User identity
    User = 1,
    /// Machine identity
    Machine = 2,
}

impl IdentityType {
    /// Convert from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::User),
            2 => Some(Self::Machine),
            _ => None,
        }
    }

    /// Create Identity-Type TLV
    pub fn to_tlv(&self) -> TeapTlv {
        let mut value = vec![0u8; 2];
        value[0..2].copy_from_slice(&(*self as u16).to_be_bytes());
        TeapTlv::new(TlvType::IdentityType, true, value)
    }

    /// Parse Identity-Type TLV
    pub fn from_tlv(tlv: &TeapTlv) -> Result<Self, EapError> {
        if tlv.tlv_type != TlvType::IdentityType as u16 {
            return Err(EapError::InvalidResponseFormat);
        }
        if tlv.value.len() < 2 {
            return Err(EapError::InvalidLength(tlv.value.len()));
        }
        let identity_type = u16::from_be_bytes([tlv.value[0], tlv.value[1]]);
        Self::from_u16(identity_type).ok_or(EapError::InvalidResponseFormat)
    }
}

/// TEAP authentication phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeapPhase {
    /// Phase 1: TLS tunnel establishment
    Phase1TlsHandshake,
    /// Phase 2: Inner authentication
    Phase2InnerAuth,
    /// Authentication complete
    Complete,
}

/// EAP-TEAP Server
///
/// Manages TEAP authentication sessions, handling both Phase 1 (TLS tunnel)
/// and Phase 2 (inner authentication via TLVs).
///
/// # Example
///
/// ```no_run
/// # use radius_proto::eap::eap_teap::*;
/// # use std::sync::Arc;
/// # use rustls::ServerConfig;
/// # let config = Arc::new(ServerConfig::builder().with_no_client_auth().with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into())).unwrap());
/// let mut server = EapTeapServer::new(config);
/// server.initialize_connection().unwrap();
/// ```
pub struct EapTeapServer {
    /// Underlying TLS server (Phase 1)
    tls_server: EapTlsServer,

    /// Current TEAP phase
    phase: TeapPhase,

    /// Intermediate results from inner methods
    intermediate_results: Vec<TeapResult>,
}

impl EapTeapServer {
    /// Create new TEAP server
    ///
    /// # Arguments
    ///
    /// * `config` - rustls ServerConfig for TLS tunnel
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use radius_proto::eap::eap_teap::EapTeapServer;
    /// # use std::sync::Arc;
    /// # use rustls::ServerConfig;
    /// # let config = Arc::new(ServerConfig::builder().with_no_client_auth().with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into())).unwrap());
    /// let server = EapTeapServer::new(config);
    /// ```
    pub fn new(config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            tls_server: EapTlsServer::new(config),
            phase: TeapPhase::Phase1TlsHandshake,
            intermediate_results: Vec::new(),
        }
    }

    /// Initialize TLS connection (Phase 1)
    pub fn initialize_connection(&mut self) -> Result<(), EapError> {
        self.tls_server.initialize_connection()
    }

    /// Check if TLS handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        self.tls_server.is_handshake_complete()
    }

    /// Get current phase
    pub fn get_phase(&self) -> TeapPhase {
        self.phase
    }

    /// Process client message (Phase 1 - TLS handshake)
    ///
    /// This handles Phase 1 TLS tunnel establishment.
    pub fn process_client_message(
        &mut self,
        tls_packet: &EapTlsPacket,
    ) -> Result<Option<Vec<u8>>, EapError> {
        match self.phase {
            TeapPhase::Phase1TlsHandshake => {
                // Delegate to TLS server
                let response = self.tls_server.process_client_message(tls_packet)?;

                // Check if handshake complete
                if self.tls_server.is_handshake_complete() {
                    // Extract keys for future use
                    self.tls_server.extract_keys()?;
                    // Transition to Phase 2
                    self.phase = TeapPhase::Phase2InnerAuth;
                }

                Ok(response)
            }
            TeapPhase::Phase2InnerAuth => {
                // Phase 2 will be implemented in next iteration
                // For now, just return None
                Ok(None)
            }
            TeapPhase::Complete => Err(EapError::InvalidState),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_type_from_u16() {
        assert_eq!(TlvType::from_u16(1), Some(TlvType::AuthorityId));
        assert_eq!(TlvType::from_u16(3), Some(TlvType::Result));
        assert_eq!(TlvType::from_u16(9), Some(TlvType::EapPayload));
        assert_eq!(TlvType::from_u16(12), Some(TlvType::CryptoBinding));
        assert_eq!(TlvType::from_u16(17), Some(TlvType::TrustedServerRoot));
        assert_eq!(TlvType::from_u16(255), None);
    }

    #[test]
    fn test_tlv_new() {
        let tlv = TeapTlv::new(TlvType::Result, true, vec![0x00, 0x01]);
        assert_eq!(tlv.tlv_type, 3);
        assert_eq!(tlv.mandatory, true);
        assert_eq!(tlv.value, vec![0x00, 0x01]);
    }

    #[test]
    fn test_tlv_encode_decode_roundtrip() {
        let original = TeapTlv::new(TlvType::Result, true, vec![0x00, 0x01]);
        let bytes = original.to_bytes();
        let (decoded, consumed) = TeapTlv::from_bytes(&bytes).unwrap();

        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_tlv_mandatory_flag() {
        let mandatory_tlv = TeapTlv::new(TlvType::Result, true, vec![0x01]);
        let bytes = mandatory_tlv.to_bytes();
        assert_eq!(bytes[0] & 0x80, 0x80); // M bit set

        let optional_tlv = TeapTlv::new(TlvType::VendorSpecific, false, vec![0x01]);
        let bytes = optional_tlv.to_bytes();
        assert_eq!(bytes[0] & 0x80, 0x00); // M bit not set
    }

    #[test]
    fn test_tlv_parse_single() {
        // Result TLV (mandatory, success)
        let data = vec![
            0x80, 0x03, // Type: Mandatory | Result
            0x00, 0x02, // Length: 2
            0x00, 0x01, // Value: Success
        ];

        let (tlv, consumed) = TeapTlv::from_bytes(&data).unwrap();
        assert_eq!(consumed, 6);
        assert_eq!(tlv.tlv_type, 3);
        assert_eq!(tlv.mandatory, true);
        assert_eq!(tlv.value, vec![0x00, 0x01]);
    }

    #[test]
    fn test_tlv_parse_multiple() {
        let data = vec![
            0x80, 0x02, 0x00, 0x02, 0x00, 0x01, // Identity-Type TLV
            0x80, 0x03, 0x00, 0x02, 0x00, 0x01, // Result TLV
        ];

        let tlvs = TeapTlv::parse_tlvs(&data).unwrap();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].tlv_type, 2); // Identity-Type
        assert_eq!(tlvs[1].tlv_type, 3); // Result
    }

    #[test]
    fn test_tlv_encode_multiple() {
        let tlvs = vec![
            TeapTlv::new(TlvType::IdentityType, true, vec![0x00, 0x01]),
            TeapTlv::new(TlvType::Result, true, vec![0x00, 0x01]),
        ];

        let bytes = TeapTlv::encode_tlvs(&tlvs);
        let decoded = TeapTlv::parse_tlvs(&bytes).unwrap();

        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn test_tlv_invalid_length() {
        // Length says 10, but only 2 bytes available
        let data = vec![0x80, 0x03, 0x00, 0x0A, 0x00, 0x01];
        assert!(TeapTlv::from_bytes(&data).is_err());
    }

    #[test]
    fn test_tlv_too_short() {
        let data = vec![0x80, 0x03]; // Only 2 bytes, need at least 4
        assert!(TeapTlv::from_bytes(&data).is_err());
    }

    #[test]
    fn test_tlv_reserved_flag_set() {
        // Reserved bit (0x4000) should cause error
        let data = vec![
            0xC0, 0x03, // Type with both M and R bits set
            0x00, 0x02,
            0x00, 0x01,
        ];
        assert!(TeapTlv::from_bytes(&data).is_err());
    }

    #[test]
    fn test_result_tlv_success() {
        let result = TeapResult::Success;
        let tlv = result.to_result_tlv();

        assert_eq!(tlv.tlv_type, 3);
        assert_eq!(tlv.mandatory, true);
        assert_eq!(tlv.value, vec![0x00, 0x01]);

        let parsed = TeapResult::from_result_tlv(&tlv).unwrap();
        assert_eq!(parsed, TeapResult::Success);
    }

    #[test]
    fn test_result_tlv_failure() {
        let result = TeapResult::Failure;
        let tlv = result.to_result_tlv();

        assert_eq!(tlv.value, vec![0x00, 0x02]);

        let parsed = TeapResult::from_result_tlv(&tlv).unwrap();
        assert_eq!(parsed, TeapResult::Failure);
    }

    #[test]
    fn test_intermediate_result_tlv() {
        let result = TeapResult::Success;
        let tlv = result.to_intermediate_result_tlv();

        assert_eq!(tlv.tlv_type, 10); // Intermediate-Result
        assert_eq!(tlv.mandatory, true);
    }

    #[test]
    fn test_identity_type_user() {
        let identity = IdentityType::User;
        let tlv = identity.to_tlv();

        assert_eq!(tlv.tlv_type, 2); // Identity-Type
        assert_eq!(tlv.mandatory, true);
        assert_eq!(tlv.value, vec![0x00, 0x01]);

        let parsed = IdentityType::from_tlv(&tlv).unwrap();
        assert_eq!(parsed, IdentityType::User);
    }

    #[test]
    fn test_identity_type_machine() {
        let identity = IdentityType::Machine;
        let tlv = identity.to_tlv();

        assert_eq!(tlv.value, vec![0x00, 0x02]);

        let parsed = IdentityType::from_tlv(&tlv).unwrap();
        assert_eq!(parsed, IdentityType::Machine);
    }

    #[test]
    fn test_teap_phase_initial_state() {
        use std::sync::Arc as StdArc;
        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );
        let server = EapTeapServer::new(config);

        assert_eq!(server.get_phase(), TeapPhase::Phase1TlsHandshake);
    }

    #[test]
    fn test_tlv_get_type() {
        let tlv = TeapTlv::new(TlvType::Result, true, vec![0x01]);
        assert_eq!(tlv.get_type(), Some(TlvType::Result));

        let unknown_tlv = TeapTlv::new_raw(999, false, vec![]);
        assert_eq!(unknown_tlv.get_type(), None);
    }

    #[test]
    fn test_tlv_empty_value() {
        let tlv = TeapTlv::new(TlvType::Nak, true, vec![]);
        let bytes = tlv.to_bytes();

        assert_eq!(bytes.len(), 4); // Just header, no value

        let (decoded, _) = TeapTlv::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.value.len(), 0);
    }
}
