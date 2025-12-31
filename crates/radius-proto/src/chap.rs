//! CHAP (Challenge-Handshake Authentication Protocol) Support
//!
//! This module implements CHAP authentication for RADIUS as defined in RFC 2865 Section 5.3.
//!
//! CHAP provides more security than PAP by not sending the password in clear text.
//! Instead, it sends a challenge and a hash of the challenge combined with the password.

/// CHAP response structure
///
/// A CHAP response consists of:
/// - CHAP Identifier (1 byte)
/// - CHAP Response (16 bytes MD5 hash)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChapResponse {
    /// CHAP identifier (must match the challenge)
    pub ident: u8,
    /// MD5 hash of (ident + password + challenge)
    pub response: [u8; 16],
}

impl ChapResponse {
    /// Create a new CHAP response from raw bytes
    ///
    /// The CHAP-Password attribute value must be exactly 17 bytes:
    /// - 1 byte: CHAP identifier
    /// - 16 bytes: MD5 hash
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChapError> {
        if bytes.len() != 17 {
            return Err(ChapError::InvalidLength(bytes.len()));
        }

        let ident = bytes[0];
        let mut response = [0u8; 16];
        response.copy_from_slice(&bytes[1..17]);

        Ok(ChapResponse { ident, response })
    }

    /// Convert CHAP response to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(17);
        bytes.push(self.ident);
        bytes.extend_from_slice(&self.response);
        bytes
    }
}

/// CHAP challenge
///
/// A CHAP challenge can come from either:
/// 1. The Request Authenticator (16 bytes)
/// 2. The CHAP-Challenge attribute (variable length, typically 16 bytes)
///
/// Per RFC 2865 Section 5.3: If the CHAP-Challenge attribute is present,
/// it should be used. Otherwise, use the Request Authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChapChallenge {
    /// The challenge bytes
    pub challenge: Vec<u8>,
}

impl ChapChallenge {
    /// Create a new CHAP challenge
    pub fn new(challenge: Vec<u8>) -> Self {
        ChapChallenge { challenge }
    }

    /// Create a CHAP challenge from the Request Authenticator
    pub fn from_authenticator(authenticator: &[u8; 16]) -> Self {
        ChapChallenge {
            challenge: authenticator.to_vec(),
        }
    }

    /// Get the challenge bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.challenge
    }
}

/// Compute the expected CHAP response
///
/// The CHAP response is computed as:
/// MD5(CHAP_Identifier + Password + Challenge)
///
/// # Arguments
/// * `ident` - CHAP identifier (from CHAP-Password attribute)
/// * `password` - User's password (plain text)
/// * `challenge` - CHAP challenge (from CHAP-Challenge attribute or Request Authenticator)
///
/// # Returns
/// The expected CHAP response (16 bytes MD5 hash)
pub fn compute_chap_response(ident: u8, password: &str, challenge: &[u8]) -> [u8; 16] {
    let mut data = Vec::new();
    data.push(ident);
    data.extend_from_slice(password.as_bytes());
    data.extend_from_slice(challenge);

    let digest = md5::compute(&data);
    let mut response = [0u8; 16];
    response.copy_from_slice(&digest.0);
    response
}

/// Verify a CHAP response
///
/// # Arguments
/// * `chap_response` - The CHAP response from the client (CHAP-Password attribute)
/// * `password` - User's password (plain text)
/// * `challenge` - CHAP challenge used
///
/// # Returns
/// `true` if the response is valid, `false` otherwise
pub fn verify_chap_response(
    chap_response: &ChapResponse,
    password: &str,
    challenge: &ChapChallenge,
) -> bool {
    let expected = compute_chap_response(chap_response.ident, password, challenge.as_bytes());
    chap_response.response == expected
}

/// CHAP-specific errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ChapError {
    #[error("Invalid CHAP-Password length: expected 17 bytes, got {0}")]
    InvalidLength(usize),
    #[error("CHAP-Challenge not found")]
    ChallengeNotFound,
    #[error("CHAP-Password not found")]
    PasswordNotFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chap_response_from_bytes() {
        let bytes = vec![0x01; 17]; // ident=1, response=all ones
        let response = ChapResponse::from_bytes(&bytes).unwrap();
        assert_eq!(response.ident, 0x01);
        assert_eq!(response.response, [0x01; 16]);
    }

    #[test]
    fn test_chap_response_invalid_length() {
        let bytes = vec![0x01; 16]; // Too short
        assert!(ChapResponse::from_bytes(&bytes).is_err());

        let bytes = vec![0x01; 18]; // Too long
        assert!(ChapResponse::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_chap_response_to_bytes() {
        let response = ChapResponse {
            ident: 0x42,
            response: [0xAB; 16],
        };
        let bytes = response.to_bytes();
        assert_eq!(bytes.len(), 17);
        assert_eq!(bytes[0], 0x42);
        assert_eq!(&bytes[1..17], &[0xAB; 16]);
    }

    #[test]
    fn test_compute_chap_response() {
        // Test with known values
        let ident = 0x01;
        let password = "password";
        let challenge = b"0123456789abcdef"; // 16 bytes

        let response = compute_chap_response(ident, password, challenge);

        // Response should be deterministic
        let response2 = compute_chap_response(ident, password, challenge);
        assert_eq!(response, response2);

        // Different password should give different response
        let response3 = compute_chap_response(ident, "different", challenge);
        assert_ne!(response, response3);

        // Different ident should give different response
        let response4 = compute_chap_response(0x02, password, challenge);
        assert_ne!(response, response4);

        // Different challenge should give different response
        let response5 = compute_chap_response(ident, password, b"fedcba9876543210");
        assert_ne!(response, response5);
    }

    #[test]
    fn test_verify_chap_response() {
        let ident = 0x10;
        let password = "secret123";
        let challenge = ChapChallenge::new(b"random_challenge_123".to_vec());

        // Compute valid response
        let expected = compute_chap_response(ident, password, challenge.as_bytes());
        let chap_response = ChapResponse {
            ident,
            response: expected,
        };

        // Should verify successfully
        assert!(verify_chap_response(&chap_response, password, &challenge));

        // Wrong password should fail
        assert!(!verify_chap_response(&chap_response, "wrongpassword", &challenge));

        // Wrong ident should fail
        let wrong_ident_response = ChapResponse {
            ident: 0x20,
            response: expected,
        };
        assert!(!verify_chap_response(&wrong_ident_response, password, &challenge));
    }

    #[test]
    fn test_chap_challenge_from_authenticator() {
        let authenticator: [u8; 16] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                                       0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let challenge = ChapChallenge::from_authenticator(&authenticator);
        assert_eq!(challenge.as_bytes(), &authenticator);
    }

    #[test]
    fn test_round_trip_response() {
        let original = ChapResponse {
            ident: 0x42,
            response: [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
                      0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44],
        };

        let bytes = original.to_bytes();
        let decoded = ChapResponse::from_bytes(&bytes).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_rfc_2865_example() {
        // This is a conceptual test based on RFC 2865 CHAP example
        let ident = 0x01;
        let password = "MyPassword";
        let challenge_bytes = b"0123456789ABCDEF"; // Example 16-byte challenge

        // Client computes response
        let response = compute_chap_response(ident, password, challenge_bytes);
        let chap_response = ChapResponse { ident, response };

        // Server verifies
        let challenge = ChapChallenge::new(challenge_bytes.to_vec());
        assert!(verify_chap_response(&chap_response, password, &challenge));
        assert!(!verify_chap_response(&chap_response, "WrongPassword", &challenge));
    }
}
