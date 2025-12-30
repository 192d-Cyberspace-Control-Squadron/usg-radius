/// RADIUS packet codes as defined in RFC 2865 Section 4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Code {
    /// Access-Request (1)
    AccessRequest = 1,
    /// Access-Accept (2)
    AccessAccept = 2,
    /// Access-Reject (3)
    AccessReject = 3,
    /// Accounting-Request (4) - RFC 2866
    AccountingRequest = 4,
    /// Accounting-Response (5) - RFC 2866
    AccountingResponse = 5,
    /// Access-Challenge (11)
    AccessChallenge = 11,
    /// Status-Server (12) - RFC 5997
    StatusServer = 12,
    /// Status-Client (13) - RFC 5997
    StatusClient = 13,
}

impl Code {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Code::AccessRequest),
            2 => Some(Code::AccessAccept),
            3 => Some(Code::AccessReject),
            4 => Some(Code::AccountingRequest),
            5 => Some(Code::AccountingResponse),
            11 => Some(Code::AccessChallenge),
            12 => Some(Code::StatusServer),
            13 => Some(Code::StatusClient),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}
