use super::Code;
use crate::attributes::Attribute;
use std::io::{self, Cursor, Read, Write};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PacketError {
    #[error("Invalid packet length: {0}")]
    InvalidLength(usize),
    #[error("Invalid packet code: {0}")]
    InvalidCode(u8),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Attribute error: {0}")]
    AttributeError(String),
    #[error("Packet too large: {0} bytes")]
    PacketTooLarge(usize),
}

/// RADIUS Packet structure as defined in RFC 2865 Section 3
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Code      |  Identifier   |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                         Authenticator                         |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Attributes ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-
/// ```
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet type (1 byte)
    pub code: Code,
    /// Packet identifier for matching requests/responses (1 byte)
    pub identifier: u8,
    /// Request Authenticator (16 bytes)
    pub authenticator: [u8; 16],
    /// List of attributes
    pub attributes: Vec<Attribute>,
}

impl Packet {
    /// Minimum RADIUS packet size (20 bytes: 1 code + 1 id + 2 length + 16 authenticator)
    pub const MIN_PACKET_SIZE: usize = 20;
    /// Maximum RADIUS packet size (4096 bytes as per RFC 2865)
    pub const MAX_PACKET_SIZE: usize = 4096;

    pub fn new(code: Code, identifier: u8, authenticator: [u8; 16]) -> Self {
        Packet {
            code,
            identifier,
            authenticator,
            attributes: Vec::new(),
        }
    }

    pub fn add_attribute(&mut self, attribute: Attribute) {
        self.attributes.push(attribute);
    }

    /// Encode packet to bytes
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        let mut buffer = Vec::new();

        // Write code (1 byte)
        buffer.write_all(&[self.code.as_u8()])?;

        // Write identifier (1 byte)
        buffer.write_all(&[self.identifier])?;

        // Reserve space for length (2 bytes) - will fill in later
        let length_pos = buffer.len();
        buffer.write_all(&[0, 0])?;

        // Write authenticator (16 bytes)
        buffer.write_all(&self.authenticator)?;

        // Write attributes
        for attr in &self.attributes {
            let attr_bytes = attr.encode()?;
            buffer.write_all(&attr_bytes)?;
        }

        // Calculate and write length
        let total_length = buffer.len();
        if total_length > Self::MAX_PACKET_SIZE {
            return Err(PacketError::PacketTooLarge(total_length));
        }

        buffer[length_pos] = (total_length >> 8) as u8;
        buffer[length_pos + 1] = (total_length & 0xff) as u8;

        Ok(buffer)
    }

    /// Decode packet from bytes
    pub fn decode(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < Self::MIN_PACKET_SIZE {
            return Err(PacketError::InvalidLength(data.len()));
        }

        let mut cursor = Cursor::new(data);

        // Read code
        let mut code_buf = [0u8; 1];
        cursor.read_exact(&mut code_buf)?;
        let code = Code::from_u8(code_buf[0]).ok_or(PacketError::InvalidCode(code_buf[0]))?;

        // Read identifier
        let mut id_buf = [0u8; 1];
        cursor.read_exact(&mut id_buf)?;
        let identifier = id_buf[0];

        // Read length
        let mut len_buf = [0u8; 2];
        cursor.read_exact(&mut len_buf)?;
        let length = u16::from_be_bytes(len_buf) as usize;

        if length < Self::MIN_PACKET_SIZE || length > Self::MAX_PACKET_SIZE {
            return Err(PacketError::InvalidLength(length));
        }

        if data.len() < length {
            return Err(PacketError::InvalidLength(data.len()));
        }

        // Read authenticator
        let mut authenticator = [0u8; 16];
        cursor.read_exact(&mut authenticator)?;

        // Read attributes
        let mut attributes = Vec::new();
        let position = cursor.position() as usize;
        let mut attr_data = &data[position..length];

        while !attr_data.is_empty() {
            let attr = Attribute::decode(attr_data)?;
            let attr_len = attr.encoded_length();
            attributes.push(attr);
            attr_data = &attr_data[attr_len..];
        }

        Ok(Packet {
            code,
            identifier,
            authenticator,
            attributes,
        })
    }

    /// Get the length of the encoded packet
    pub fn length(&self) -> usize {
        let mut len = Self::MIN_PACKET_SIZE;
        for attr in &self.attributes {
            len += attr.encoded_length();
        }
        len
    }

    /// Find first attribute by type
    pub fn find_attribute(&self, attr_type: u8) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.attr_type == attr_type)
    }

    /// Find all attributes by type
    pub fn find_all_attributes(&self, attr_type: u8) -> Vec<&Attribute> {
        self.attributes
            .iter()
            .filter(|a| a.attr_type == attr_type)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_encode_decode() {
        let packet = Packet::new(Code::AccessRequest, 42, [1u8; 16]);
        let encoded = packet.encode().unwrap();
        let decoded = Packet::decode(&encoded).unwrap();

        assert_eq!(decoded.code, Code::AccessRequest);
        assert_eq!(decoded.identifier, 42);
        assert_eq!(decoded.authenticator, [1u8; 16]);
    }

    #[test]
    fn test_packet_min_size() {
        let data = vec![0u8; 19]; // Less than minimum
        assert!(Packet::decode(&data).is_err());
    }
}
