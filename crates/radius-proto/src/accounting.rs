//! RADIUS Accounting Protocol Support (RFC 2866)
//!
//! This module implements RADIUS accounting as defined in RFC 2866.
//! Accounting provides session tracking, usage monitoring, and billing support.
//!
//! # Accounting Status Types
//!
//! - **Start**: Session has started (e.g., user logged in)
//! - **Stop**: Session has ended (e.g., user logged out)
//! - **Interim-Update**: Periodic update during an active session
//! - **Accounting-On**: NAS is now ready to accept requests
//! - **Accounting-Off**: NAS is shutting down
//!
//! # Example
//!
//! ```rust
//! use radius_proto::accounting::{AcctStatusType, AcctTerminateCause};
//!
//! // Session start
//! let start = AcctStatusType::Start;
//! assert_eq!(start.as_u32(), 1);
//!
//! // Session stop with normal termination
//! let stop = AcctStatusType::Stop;
//! let cause = AcctTerminateCause::UserRequest;
//! assert_eq!(cause.as_u32(), 1);
//! ```

use thiserror::Error;

/// Accounting Status-Type values (RFC 2866 Section 5.1)
///
/// Indicates the type of accounting packet being sent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AcctStatusType {
    /// Start (1) - Session has begun
    Start = 1,
    /// Stop (2) - Session has ended
    Stop = 2,
    /// Interim-Update (3) - Periodic update during session
    InterimUpdate = 3,
    /// Accounting-On (7) - NAS is ready
    AccountingOn = 7,
    /// Accounting-Off (8) - NAS is shutting down
    AccountingOff = 8,
}

impl AcctStatusType {
    /// Convert from u32 value
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(AcctStatusType::Start),
            2 => Some(AcctStatusType::Stop),
            3 => Some(AcctStatusType::InterimUpdate),
            7 => Some(AcctStatusType::AccountingOn),
            8 => Some(AcctStatusType::AccountingOff),
            _ => None,
        }
    }

    /// Convert to u32 value
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// Check if this is a session-related status (Start, Stop, Interim-Update)
    pub fn is_session_status(self) -> bool {
        matches!(
            self,
            AcctStatusType::Start | AcctStatusType::Stop | AcctStatusType::InterimUpdate
        )
    }

    /// Check if this is a NAS status (Accounting-On, Accounting-Off)
    pub fn is_nas_status(self) -> bool {
        matches!(
            self,
            AcctStatusType::AccountingOn | AcctStatusType::AccountingOff
        )
    }
}

/// Acct-Terminate-Cause values (RFC 2866 Section 5.10)
///
/// Indicates how a session was terminated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AcctTerminateCause {
    /// User Request (1) - User initiated disconnect
    UserRequest = 1,
    /// Lost Carrier (2) - Connection lost
    LostCarrier = 2,
    /// Lost Service (3) - Service unavailable
    LostService = 3,
    /// Idle Timeout (4) - Session idle too long
    IdleTimeout = 4,
    /// Session Timeout (5) - Maximum session time exceeded
    SessionTimeout = 5,
    /// Admin Reset (6) - Administrator terminated session
    AdminReset = 6,
    /// Admin Reboot (7) - NAS rebooted
    AdminReboot = 7,
    /// Port Error (8) - Port experienced an error
    PortError = 8,
    /// NAS Error (9) - NAS experienced an error
    NasError = 9,
    /// NAS Request (10) - NAS requested termination
    NasRequest = 10,
    /// NAS Reboot (11) - NAS rebooting
    NasReboot = 11,
    /// Port Unneeded (12) - Port no longer needed
    PortUnneeded = 12,
    /// Port Preempted (13) - Port required for higher priority use
    PortPreempted = 13,
    /// Port Suspended (14) - Port administratively suspended
    PortSuspended = 14,
    /// Service Unavailable (15) - Service is unavailable
    ServiceUnavailable = 15,
    /// Callback (16) - Callback requested
    Callback = 16,
    /// User Error (17) - User error
    UserError = 17,
    /// Host Request (18) - Host requested termination
    HostRequest = 18,
}

impl AcctTerminateCause {
    /// Convert from u32 value
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(AcctTerminateCause::UserRequest),
            2 => Some(AcctTerminateCause::LostCarrier),
            3 => Some(AcctTerminateCause::LostService),
            4 => Some(AcctTerminateCause::IdleTimeout),
            5 => Some(AcctTerminateCause::SessionTimeout),
            6 => Some(AcctTerminateCause::AdminReset),
            7 => Some(AcctTerminateCause::AdminReboot),
            8 => Some(AcctTerminateCause::PortError),
            9 => Some(AcctTerminateCause::NasError),
            10 => Some(AcctTerminateCause::NasRequest),
            11 => Some(AcctTerminateCause::NasReboot),
            12 => Some(AcctTerminateCause::PortUnneeded),
            13 => Some(AcctTerminateCause::PortPreempted),
            14 => Some(AcctTerminateCause::PortSuspended),
            15 => Some(AcctTerminateCause::ServiceUnavailable),
            16 => Some(AcctTerminateCause::Callback),
            17 => Some(AcctTerminateCause::UserError),
            18 => Some(AcctTerminateCause::HostRequest),
            _ => None,
        }
    }

    /// Convert to u32 value
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Acct-Authentic values (RFC 2866 Section 5.6)
///
/// Indicates how the user was authenticated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AcctAuthentic {
    /// RADIUS (1) - Authenticated by RADIUS
    Radius = 1,
    /// Local (2) - Authenticated locally
    Local = 2,
    /// Remote (3) - Authenticated remotely
    Remote = 3,
}

impl AcctAuthentic {
    /// Convert from u32 value
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(AcctAuthentic::Radius),
            2 => Some(AcctAuthentic::Local),
            3 => Some(AcctAuthentic::Remote),
            _ => None,
        }
    }

    /// Convert to u32 value
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Accounting-related errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AccountingError {
    /// Missing required attribute
    #[error("Missing required attribute: {0}")]
    MissingAttribute(&'static str),

    /// Invalid attribute value
    #[error("Invalid attribute value for {attribute}: {reason}")]
    InvalidAttributeValue {
        attribute: &'static str,
        reason: String,
    },

    /// Invalid status type
    #[error("Invalid Acct-Status-Type value: {0}")]
    InvalidStatusType(u32),

    /// Invalid terminate cause
    #[error("Invalid Acct-Terminate-Cause value: {0}")]
    InvalidTerminateCause(u32),

    /// Session not found
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    /// Duplicate session start
    #[error("Duplicate session start: {0}")]
    DuplicateSession(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acct_status_type_conversion() {
        assert_eq!(AcctStatusType::Start.as_u32(), 1);
        assert_eq!(AcctStatusType::Stop.as_u32(), 2);
        assert_eq!(AcctStatusType::InterimUpdate.as_u32(), 3);
        assert_eq!(AcctStatusType::AccountingOn.as_u32(), 7);
        assert_eq!(AcctStatusType::AccountingOff.as_u32(), 8);

        assert_eq!(AcctStatusType::from_u32(1), Some(AcctStatusType::Start));
        assert_eq!(AcctStatusType::from_u32(2), Some(AcctStatusType::Stop));
        assert_eq!(
            AcctStatusType::from_u32(3),
            Some(AcctStatusType::InterimUpdate)
        );
        assert_eq!(
            AcctStatusType::from_u32(7),
            Some(AcctStatusType::AccountingOn)
        );
        assert_eq!(
            AcctStatusType::from_u32(8),
            Some(AcctStatusType::AccountingOff)
        );
        assert_eq!(AcctStatusType::from_u32(99), None);
    }

    #[test]
    fn test_acct_status_type_categories() {
        assert!(AcctStatusType::Start.is_session_status());
        assert!(AcctStatusType::Stop.is_session_status());
        assert!(AcctStatusType::InterimUpdate.is_session_status());
        assert!(!AcctStatusType::AccountingOn.is_session_status());
        assert!(!AcctStatusType::AccountingOff.is_session_status());

        assert!(AcctStatusType::AccountingOn.is_nas_status());
        assert!(AcctStatusType::AccountingOff.is_nas_status());
        assert!(!AcctStatusType::Start.is_nas_status());
    }

    #[test]
    fn test_acct_terminate_cause_conversion() {
        assert_eq!(AcctTerminateCause::UserRequest.as_u32(), 1);
        assert_eq!(AcctTerminateCause::IdleTimeout.as_u32(), 4);
        assert_eq!(AcctTerminateCause::SessionTimeout.as_u32(), 5);

        assert_eq!(
            AcctTerminateCause::from_u32(1),
            Some(AcctTerminateCause::UserRequest)
        );
        assert_eq!(
            AcctTerminateCause::from_u32(4),
            Some(AcctTerminateCause::IdleTimeout)
        );
        assert_eq!(AcctTerminateCause::from_u32(99), None);
    }

    #[test]
    fn test_acct_authentic_conversion() {
        assert_eq!(AcctAuthentic::Radius.as_u32(), 1);
        assert_eq!(AcctAuthentic::Local.as_u32(), 2);
        assert_eq!(AcctAuthentic::Remote.as_u32(), 3);

        assert_eq!(AcctAuthentic::from_u32(1), Some(AcctAuthentic::Radius));
        assert_eq!(AcctAuthentic::from_u32(2), Some(AcctAuthentic::Local));
        assert_eq!(AcctAuthentic::from_u32(3), Some(AcctAuthentic::Remote));
        assert_eq!(AcctAuthentic::from_u32(99), None);
    }
}
