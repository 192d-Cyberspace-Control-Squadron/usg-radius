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

    /// Inner authentication method handler
    inner_method: Option<Box<dyn InnerMethodHandler>>,

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
            inner_method: None,
            intermediate_results: Vec::new(),
        }
    }

    /// Create new TEAP server with inner method handler
    ///
    /// # Arguments
    ///
    /// * `config` - rustls ServerConfig for TLS tunnel
    /// * `inner_method` - Inner authentication method handler
    pub fn with_inner_method(
        config: Arc<rustls::ServerConfig>,
        inner_method: Box<dyn InnerMethodHandler>,
    ) -> Self {
        Self {
            tls_server: EapTlsServer::new(config),
            phase: TeapPhase::Phase1TlsHandshake,
            inner_method: Some(inner_method),
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

    /// Check if TEAP authentication is complete
    pub fn is_complete(&self) -> bool {
        self.phase == TeapPhase::Complete
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
                // Decrypt TLS application data to get TLVs
                let tlv_data = self.decrypt_tls_data(tls_packet)?;

                // Parse TLVs from decrypted data
                let tlvs = TeapTlv::parse_tlvs(&tlv_data)?;

                // Process Phase 2 TLVs
                self.process_phase2_tlvs(&tlvs)
            }
            TeapPhase::Complete => Err(EapError::InvalidState),
        }
    }

    /// Decrypt TLS application data from EAP-TLS packet
    ///
    /// In Phase 2, the client sends TLVs encrypted in the TLS tunnel.
    /// We need to decrypt them using the established TLS connection.
    ///
    /// TODO: For MVP, this treats data as plaintext TLVs. In production, this must:
    /// 1. Use rustls::ServerConnection::read_tls() to feed encrypted records
    /// 2. Use rustls::ServerConnection::process_new_packets() to decrypt
    /// 3. Use rustls::ServerConnection::reader() to extract application data
    fn decrypt_tls_data(&mut self, tls_packet: &EapTlsPacket) -> Result<Vec<u8>, EapError> {
        // For MVP, treat the data as plaintext TLVs
        // In production, this would decrypt through the TLS connection
        Ok(tls_packet.tls_data.clone())
    }

    /// Process Phase 2 TLVs
    ///
    /// Handles the TLV exchange for inner authentication.
    fn process_phase2_tlvs(&mut self, tlvs: &[TeapTlv]) -> Result<Option<Vec<u8>>, EapError> {
        if tlvs.is_empty() {
            // No TLVs received, send Identity-Type request
            return self.send_identity_type_request();
        }

        // Process each TLV
        for tlv in tlvs {
            match tlv.get_type() {
                Some(TlvType::IdentityType) => {
                    // Identity-Type response received
                    // Send Basic-Password-Auth-Req
                    return self.send_password_auth_request();
                }
                Some(TlvType::BasicPasswordAuthResp) => {
                    // Password auth response received
                    if let Some(ref mut handler) = self.inner_method {
                        let result_tlv = handler.process_inner_request(tlv)?;

                        // Check if authentication is complete
                        if handler.is_complete() {
                            self.phase = TeapPhase::Complete;

                            // Encrypt and return result TLV
                            return self.encrypt_and_send_tlvs(&[result_tlv]);
                        }
                    }
                }
                Some(TlvType::Result) => {
                    // Final result TLV from client (acknowledgment)
                    self.phase = TeapPhase::Complete;
                    return Ok(None);
                }
                _ => {
                    // Unknown or unsupported TLV
                    continue;
                }
            }
        }

        Ok(None)
    }

    /// Send Identity-Type TLV request
    fn send_identity_type_request(&self) -> Result<Option<Vec<u8>>, EapError> {
        let identity_tlv = IdentityType::User.to_tlv();
        self.encrypt_and_send_tlvs(&[identity_tlv])
    }

    /// Send Basic-Password-Auth-Req TLV
    fn send_password_auth_request(&self) -> Result<Option<Vec<u8>>, EapError> {
        let request_tlv = BasicPasswordAuthHandler::create_password_request();
        self.encrypt_and_send_tlvs(&[request_tlv])
    }

    /// Encrypt TLVs and send in TLS tunnel
    ///
    /// This encrypts the TLVs using the established TLS connection
    /// and returns the encrypted data for transmission.
    ///
    /// TODO: For MVP, this returns plaintext TLVs. In production, this must:
    /// 1. Use rustls::ServerConnection::writer() to write application data
    /// 2. Use rustls::ServerConnection::write_tls() to get encrypted records
    /// 3. Properly handle mutable access to the TLS connection
    fn encrypt_and_send_tlvs(&self, tlvs: &[TeapTlv]) -> Result<Option<Vec<u8>>, EapError> {
        // Encode TLVs
        let tlv_data = TeapTlv::encode_tlvs(tlvs);

        // For MVP, return plaintext TLVs
        // In production, this would be encrypted through the TLS connection
        Ok(Some(tlv_data))
    }
}

/// Inner authentication method handler trait
///
/// Defines the interface for handling inner authentication methods within
/// the TEAP tunnel (Phase 2).
pub trait InnerMethodHandler: Send + Sync {
    /// Process inner authentication request
    ///
    /// # Arguments
    ///
    /// * `request_tlv` - TLV containing the inner auth request
    ///
    /// # Returns
    ///
    /// Returns response TLV or error
    fn process_inner_request(&mut self, request_tlv: &TeapTlv) -> Result<TeapTlv, EapError>;

    /// Check if authentication is complete
    fn is_complete(&self) -> bool;

    /// Get authentication result
    fn get_result(&self) -> TeapResult;

    /// Get authenticated identity (if successful)
    fn get_identity(&self) -> Option<String>;
}

/// Basic Password Authentication Handler
///
/// Implements simple username/password authentication inside TEAP tunnel.
/// This is the simplest inner method for MVP.
///
/// # Example
///
/// ```no_run
/// # use radius_proto::eap::eap_teap::*;
/// let handler = BasicPasswordAuthHandler::new();
/// // Process authentication TLVs...
/// ```
pub struct BasicPasswordAuthHandler {
    /// Expected username
    expected_username: Option<String>,
    /// Expected password
    expected_password: Option<String>,
    /// Received username
    username: Option<String>,
    /// Authentication complete flag
    complete: bool,
    /// Authentication result
    result: TeapResult,
}

impl BasicPasswordAuthHandler {
    /// Create new Basic Password Auth handler
    ///
    /// # Arguments
    ///
    /// * `expected_username` - Expected username for authentication
    /// * `expected_password` - Expected password for authentication
    pub fn new(expected_username: String, expected_password: String) -> Self {
        Self {
            expected_username: Some(expected_username),
            expected_password: Some(expected_password),
            username: None,
            complete: false,
            result: TeapResult::Failure,
        }
    }

    /// Create handler without pre-set credentials (for testing)
    pub fn new_empty() -> Self {
        Self {
            expected_username: None,
            expected_password: None,
            username: None,
            complete: false,
            result: TeapResult::Failure,
        }
    }

    /// Parse Basic-Password-Auth-Resp TLV
    ///
    /// Format (RFC 7170 Section 4.2.14):
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |            Username Length    |          Username...
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |            Password Length    |          Password...
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn parse_password_response(&mut self, tlv: &TeapTlv) -> Result<(), EapError> {
        if tlv.value.len() < 4 {
            return Err(EapError::InvalidLength(tlv.value.len()));
        }

        let mut offset = 0;

        // Parse username length (2 bytes)
        let username_len =
            u16::from_be_bytes([tlv.value[offset], tlv.value[offset + 1]]) as usize;
        offset += 2;

        if offset + username_len > tlv.value.len() {
            return Err(EapError::InvalidLength(username_len));
        }

        // Parse username
        let username = String::from_utf8(tlv.value[offset..offset + username_len].to_vec())
            .map_err(|_| EapError::InvalidResponseFormat)?;
        offset += username_len;

        if offset + 2 > tlv.value.len() {
            return Err(EapError::InvalidLength(tlv.value.len() - offset));
        }

        // Parse password length (2 bytes)
        let password_len =
            u16::from_be_bytes([tlv.value[offset], tlv.value[offset + 1]]) as usize;
        offset += 2;

        if offset + password_len > tlv.value.len() {
            return Err(EapError::InvalidLength(password_len));
        }

        // Parse password
        let password = String::from_utf8(tlv.value[offset..offset + password_len].to_vec())
            .map_err(|_| EapError::InvalidResponseFormat)?;

        // Verify credentials
        let auth_success = if let (Some(exp_user), Some(exp_pass)) =
            (&self.expected_username, &self.expected_password)
        {
            &username == exp_user && &password == exp_pass
        } else {
            false
        };

        self.username = Some(username);
        self.complete = true;
        self.result = if auth_success {
            TeapResult::Success
        } else {
            TeapResult::Failure
        };

        Ok(())
    }

    /// Create Basic-Password-Auth-Req TLV
    ///
    /// Simple request with no prompt (minimal implementation)
    fn create_password_request() -> TeapTlv {
        // Empty prompt for simplicity (MVP)
        TeapTlv::new(TlvType::BasicPasswordAuthReq, true, vec![])
    }
}

impl InnerMethodHandler for BasicPasswordAuthHandler {
    fn process_inner_request(&mut self, request_tlv: &TeapTlv) -> Result<TeapTlv, EapError> {
        match request_tlv.get_type() {
            Some(TlvType::BasicPasswordAuthResp) => {
                // Process password response
                self.parse_password_response(request_tlv)?;
                // Return result TLV
                Ok(self.result.to_result_tlv())
            }
            _ => {
                // Unknown TLV type, return NAK
                Err(EapError::InvalidResponseFormat)
            }
        }
    }

    fn is_complete(&self) -> bool {
        self.complete
    }

    fn get_result(&self) -> TeapResult {
        self.result
    }

    fn get_identity(&self) -> Option<String> {
        self.username.clone()
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

    // BasicPasswordAuthHandler tests
    #[test]
    fn test_basic_password_auth_handler_creation() {
        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        assert!(!handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Failure);
        assert_eq!(handler.get_identity(), None);
    }

    #[test]
    fn test_basic_password_auth_success() {
        let mut handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        // Create Basic-Password-Auth-Resp TLV
        // Format: username_len (2) | username | password_len (2) | password
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes()); // username length = 5
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&6u16.to_be_bytes()); // password length = 6
        value.extend_from_slice(b"secret");

        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        // Process the response
        let result_tlv = handler.process_inner_request(&response_tlv).unwrap();

        // Should be complete with success
        assert!(handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Success);
        assert_eq!(handler.get_identity(), Some("alice".to_string()));

        // Result TLV should indicate success
        assert_eq!(result_tlv.tlv_type, TlvType::Result as u16);
        assert_eq!(
            TeapResult::from_result_tlv(&result_tlv).unwrap(),
            TeapResult::Success
        );
    }

    #[test]
    fn test_basic_password_auth_failure_wrong_password() {
        let mut handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        // Create response with wrong password
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"wrong");

        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        let result_tlv = handler.process_inner_request(&response_tlv).unwrap();

        // Should be complete with failure
        assert!(handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Failure);
        assert_eq!(handler.get_identity(), Some("alice".to_string()));

        assert_eq!(
            TeapResult::from_result_tlv(&result_tlv).unwrap(),
            TeapResult::Failure
        );
    }

    #[test]
    fn test_basic_password_auth_failure_wrong_username() {
        let mut handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        // Create response with wrong username
        let mut value = Vec::new();
        value.extend_from_slice(&3u16.to_be_bytes());
        value.extend_from_slice(b"bob");
        value.extend_from_slice(&6u16.to_be_bytes());
        value.extend_from_slice(b"secret");

        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        let _result_tlv = handler.process_inner_request(&response_tlv).unwrap();

        assert!(handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Failure);
        assert_eq!(handler.get_identity(), Some("bob".to_string()));
    }

    #[test]
    fn test_basic_password_auth_invalid_tlv_too_short() {
        let mut handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        // TLV with insufficient data
        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, vec![0x00]);

        let result = handler.process_inner_request(&response_tlv);
        assert!(result.is_err());
    }

    #[test]
    fn test_basic_password_auth_invalid_username_length() {
        let mut handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        // Username length exceeds available data
        let mut value = Vec::new();
        value.extend_from_slice(&100u16.to_be_bytes()); // claims 100 bytes
        value.extend_from_slice(b"alice"); // only 5 bytes

        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        let result = handler.process_inner_request(&response_tlv);
        assert!(result.is_err());
    }

    #[test]
    fn test_basic_password_auth_empty_credentials() {
        let mut handler = BasicPasswordAuthHandler::new("".to_string(), "".to_string());

        // Empty username and password
        let mut value = Vec::new();
        value.extend_from_slice(&0u16.to_be_bytes());
        value.extend_from_slice(&0u16.to_be_bytes());

        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        let _result_tlv = handler.process_inner_request(&response_tlv).unwrap();

        assert!(handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Success);
        assert_eq!(handler.get_identity(), Some("".to_string()));
    }

    #[test]
    fn test_basic_password_auth_request_creation() {
        let request_tlv = BasicPasswordAuthHandler::create_password_request();

        assert_eq!(request_tlv.tlv_type, TlvType::BasicPasswordAuthReq as u16);
        assert!(request_tlv.mandatory);
        assert_eq!(request_tlv.value.len(), 0); // Empty prompt
    }

    #[test]
    fn test_inner_method_handler_trait() {
        let handler: Box<dyn InnerMethodHandler> =
            Box::new(BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string()));

        // Test trait methods
        assert!(!handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Failure);
        assert_eq!(handler.get_identity(), None);
    }

    // Phase 2 Integration Tests
    #[test]
    fn test_eap_teap_server_creation() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let server = EapTeapServer::new(config);
        assert_eq!(server.phase, TeapPhase::Phase1TlsHandshake);
    }

    #[test]
    fn test_eap_teap_server_with_inner_method() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let server = EapTeapServer::with_inner_method(config, Box::new(handler));

        assert_eq!(server.phase, TeapPhase::Phase1TlsHandshake);
        assert!(server.inner_method.is_some());
    }

    #[test]
    fn test_phase2_empty_tlvs_sends_identity_request() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        // Manually transition to Phase 2 (in real scenario, this happens after TLS handshake)
        server.phase = TeapPhase::Phase2InnerAuth;

        // Process empty TLVs should send Identity-Type request
        let result = server.process_phase2_tlvs(&[]);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.is_some());

        // Parse the response TLVs
        let tlvs = TeapTlv::parse_tlvs(&response.unwrap()).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].get_type(), Some(TlvType::IdentityType));
    }

    #[test]
    fn test_phase2_identity_response_sends_password_request() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        server.phase = TeapPhase::Phase2InnerAuth;

        // Simulate Identity-Type response
        let identity_response = IdentityType::User.to_tlv();

        // Process identity response should send password request
        let result = server.process_phase2_tlvs(&[identity_response]);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.is_some());

        // Parse the response TLVs
        let tlvs = TeapTlv::parse_tlvs(&response.unwrap()).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].get_type(), Some(TlvType::BasicPasswordAuthReq));
    }

    #[test]
    fn test_phase2_password_response_successful_auth() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        server.phase = TeapPhase::Phase2InnerAuth;

        // Create password response TLV
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes()); // username length = 5
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&6u16.to_be_bytes()); // password length = 6
        value.extend_from_slice(b"secret");

        let password_response = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        // Process password response
        let result = server.process_phase2_tlvs(&[password_response]);
        assert!(result.is_ok());

        // Server should transition to Complete
        assert_eq!(server.phase, TeapPhase::Complete);

        let response = result.unwrap();
        assert!(response.is_some());

        // Parse the response TLVs - should be Result TLV with Success
        let tlvs = TeapTlv::parse_tlvs(&response.unwrap()).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].get_type(), Some(TlvType::Result));

        // Parse Result TLV value
        let result_value = u16::from_be_bytes([tlvs[0].value[0], tlvs[0].value[1]]);
        assert_eq!(result_value, TeapResult::Success as u16);
    }

    #[test]
    fn test_phase2_password_response_failed_auth() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        server.phase = TeapPhase::Phase2InnerAuth;

        // Create password response TLV with WRONG password
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"wrong"); // Wrong password

        let password_response = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        // Process password response
        let result = server.process_phase2_tlvs(&[password_response]);
        assert!(result.is_ok());

        // Server should transition to Complete
        assert_eq!(server.phase, TeapPhase::Complete);

        let response = result.unwrap();
        assert!(response.is_some());

        // Parse the response TLVs - should be Result TLV with Failure
        let tlvs = TeapTlv::parse_tlvs(&response.unwrap()).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].get_type(), Some(TlvType::Result));

        let result_value = u16::from_be_bytes([tlvs[0].value[0], tlvs[0].value[1]]);
        assert_eq!(result_value, TeapResult::Failure as u16);
    }

    #[test]
    fn test_phase2_complete_flow_success() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        server.phase = TeapPhase::Phase2InnerAuth;

        // Step 1: Empty TLVs -> Identity request
        let result1 = server.process_phase2_tlvs(&[]).unwrap();
        assert!(result1.is_some());
        let tlvs1 = TeapTlv::parse_tlvs(&result1.unwrap()).unwrap();
        assert_eq!(tlvs1[0].get_type(), Some(TlvType::IdentityType));

        // Step 2: Identity response -> Password request
        let identity_response = IdentityType::User.to_tlv();
        let result2 = server.process_phase2_tlvs(&[identity_response]).unwrap();
        assert!(result2.is_some());
        let tlvs2 = TeapTlv::parse_tlvs(&result2.unwrap()).unwrap();
        assert_eq!(tlvs2[0].get_type(), Some(TlvType::BasicPasswordAuthReq));

        // Step 3: Password response -> Result (Success)
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&6u16.to_be_bytes());
        value.extend_from_slice(b"secret");
        let password_response = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        let result3 = server.process_phase2_tlvs(&[password_response]).unwrap();
        assert!(result3.is_some());
        assert_eq!(server.phase, TeapPhase::Complete);

        let tlvs3 = TeapTlv::parse_tlvs(&result3.unwrap()).unwrap();
        assert_eq!(tlvs3[0].get_type(), Some(TlvType::Result));
        let result_value = u16::from_be_bytes([tlvs3[0].value[0], tlvs3[0].value[1]]);
        assert_eq!(result_value, TeapResult::Success as u16);
    }

    #[test]
    fn test_phase2_result_acknowledgment() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        server.phase = TeapPhase::Phase2InnerAuth;

        // Simulate receiving Result TLV from client (acknowledgment)
        let result_tlv = TeapResult::Success.to_result_tlv();

        let response = server.process_phase2_tlvs(&[result_tlv]);
        assert!(response.is_ok());

        // Should transition to Complete and return None (no more data)
        assert_eq!(server.phase, TeapPhase::Complete);
        assert!(response.unwrap().is_none());
    }

    #[test]
    fn test_decrypt_tls_data_mvp() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let mut server = EapTeapServer::new(config);

        // Create test TLS packet with data
        let test_data = vec![1, 2, 3, 4, 5];
        let tls_packet = EapTlsPacket {
            flags: crate::eap::eap_tls::TlsFlags::new(false, false, false),
            tls_message_length: None,
            tls_data: test_data.clone(),
        };

        // For MVP, decrypt should return data as-is (plaintext)
        let decrypted = server.decrypt_tls_data(&tls_packet).unwrap();
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_encrypt_and_send_tlvs_mvp() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let server = EapTeapServer::new(config);

        // Create test TLVs
        let tlv = IdentityType::User.to_tlv();
        let encrypted = server.encrypt_and_send_tlvs(&[tlv.clone()]).unwrap();

        assert!(encrypted.is_some());

        // For MVP, encrypted data should be plaintext TLV encoding
        let expected = TeapTlv::encode_tlvs(&[tlv]);
        assert_eq!(encrypted.unwrap(), expected);
    }
}
