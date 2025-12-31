//! File-based accounting handler
//!
//! This module provides a file-based implementation of the AccountingHandler trait
//! that writes accounting records to a file in JSON Lines format.

use super::{AccountingHandler, AccountingResult};
use radius_proto::{AccountingError, AttributeType, Packet};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// Accounting event types for file logging
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountingEvent {
    Start,
    Stop,
    InterimUpdate,
    AccountingOn,
    AccountingOff,
}

/// Accounting record written to file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountingRecord {
    /// Timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// Event type
    pub event: AccountingEvent,
    /// Session ID (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Username (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// NAS IP address
    pub nas_ip: IpAddr,
    /// Framed IP address (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framed_ip: Option<IpAddr>,
    /// Session duration in seconds (for Stop/Interim)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_time: Option<u32>,
    /// Input octets (bytes received)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_octets: Option<u64>,
    /// Output octets (bytes transmitted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_octets: Option<u64>,
    /// Input packets
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_packets: Option<u64>,
    /// Output packets
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_packets: Option<u64>,
    /// Termination cause (for Stop events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminate_cause: Option<u32>,
}

/// File-based accounting handler
///
/// Writes accounting records to a file in JSON Lines format (one JSON object per line).
/// This format is easy to parse and can be processed with standard tools like jq.
pub struct FileAccountingHandler {
    /// Path to accounting log file
    #[allow(dead_code)]
    file_path: PathBuf,
    /// File handle (protected by mutex for async writes)
    file: Arc<Mutex<Option<tokio::fs::File>>>,
}

impl FileAccountingHandler {
    /// Create a new file-based accounting handler
    pub async fn new(file_path: PathBuf) -> Result<Self, std::io::Error> {
        // Create parent directories if they don't exist
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Open file in append mode
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .await?;

        Ok(FileAccountingHandler {
            file_path,
            file: Arc::new(Mutex::new(Some(file))),
        })
    }

    /// Write an accounting record to the file
    async fn write_record(&self, record: AccountingRecord) -> Result<(), std::io::Error> {
        let json = serde_json::to_string(&record)?;
        let line = format!("{}\n", json);

        let mut file_guard = self.file.lock().await;
        if let Some(file) = file_guard.as_mut() {
            file.write_all(line.as_bytes()).await?;
            file.flush().await?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "File not open",
            ));
        }

        Ok(())
    }

    /// Extract accounting attributes from packet
    fn extract_accounting_attrs(packet: &Packet) -> (Option<u32>, Option<u64>, Option<u64>, Option<u32>) {
        let session_time = packet
            .find_attribute(AttributeType::AcctSessionTime as u8)
            .and_then(|attr| {
                if attr.value.len() >= 4 {
                    Some(u32::from_be_bytes([
                        attr.value[0],
                        attr.value[1],
                        attr.value[2],
                        attr.value[3],
                    ]))
                } else {
                    None
                }
            });

        let input_octets = packet
            .find_attribute(AttributeType::AcctInputOctets as u8)
            .and_then(|attr| {
                if attr.value.len() >= 4 {
                    Some(u32::from_be_bytes([
                        attr.value[0],
                        attr.value[1],
                        attr.value[2],
                        attr.value[3],
                    ]) as u64)
                } else {
                    None
                }
            });

        let output_octets = packet
            .find_attribute(AttributeType::AcctOutputOctets as u8)
            .and_then(|attr| {
                if attr.value.len() >= 4 {
                    Some(u32::from_be_bytes([
                        attr.value[0],
                        attr.value[1],
                        attr.value[2],
                        attr.value[3],
                    ]) as u64)
                } else {
                    None
                }
            });

        let terminate_cause = packet
            .find_attribute(AttributeType::AcctTerminateCause as u8)
            .and_then(|attr| {
                if attr.value.len() >= 4 {
                    Some(u32::from_be_bytes([
                        attr.value[0],
                        attr.value[1],
                        attr.value[2],
                        attr.value[3],
                    ]))
                } else {
                    None
                }
            });

        (session_time, input_octets, output_octets, terminate_cause)
    }
}

impl AccountingHandler for FileAccountingHandler {
    fn handle_start(
        &self,
        session_id: &str,
        username: &str,
        nas_ip: IpAddr,
        packet: &Packet,
    ) -> Pin<Box<dyn Future<Output = Result<AccountingResult, AccountingError>> + Send + '_>> {
        let session_id = session_id.to_string();
        let username = username.to_string();

        // Extract framed IP if present
        let framed_ip = packet
            .find_attribute(AttributeType::FramedIpAddress as u8)
            .and_then(|attr| {
                if attr.value.len() >= 4 {
                    Some(IpAddr::from([
                        attr.value[0],
                        attr.value[1],
                        attr.value[2],
                        attr.value[3],
                    ]))
                } else {
                    None
                }
            });

        Box::pin(async move {
            let record = AccountingRecord {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                event: AccountingEvent::Start,
                session_id: Some(session_id),
                username: Some(username),
                nas_ip,
                framed_ip,
                session_time: None,
                input_octets: None,
                output_octets: None,
                input_packets: None,
                output_packets: None,
                terminate_cause: None,
            };

            self.write_record(record)
                .await
                .map_err(|e| AccountingError::InvalidAttributeValue {
                    attribute: "file_write",
                    reason: e.to_string(),
                })?;

            Ok(AccountingResult::Success)
        })
    }

    fn handle_stop(
        &self,
        session_id: &str,
        username: &str,
        nas_ip: IpAddr,
        packet: &Packet,
    ) -> Pin<Box<dyn Future<Output = Result<AccountingResult, AccountingError>> + Send + '_>> {
        let session_id = session_id.to_string();
        let username = username.to_string();
        let packet = packet.clone();

        Box::pin(async move {
            let (session_time, input_octets, output_octets, terminate_cause) =
                Self::extract_accounting_attrs(&packet);

            let record = AccountingRecord {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                event: AccountingEvent::Stop,
                session_id: Some(session_id),
                username: Some(username),
                nas_ip,
                framed_ip: None,
                session_time,
                input_octets,
                output_octets,
                input_packets: None,
                output_packets: None,
                terminate_cause,
            };

            self.write_record(record)
                .await
                .map_err(|e| AccountingError::InvalidAttributeValue {
                    attribute: "file_write",
                    reason: e.to_string(),
                })?;

            Ok(AccountingResult::Success)
        })
    }

    fn handle_interim_update(
        &self,
        session_id: &str,
        username: &str,
        nas_ip: IpAddr,
        packet: &Packet,
    ) -> Pin<Box<dyn Future<Output = Result<AccountingResult, AccountingError>> + Send + '_>> {
        let session_id = session_id.to_string();
        let username = username.to_string();
        let packet = packet.clone();

        Box::pin(async move {
            let (session_time, input_octets, output_octets, _) =
                Self::extract_accounting_attrs(&packet);

            let record = AccountingRecord {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                event: AccountingEvent::InterimUpdate,
                session_id: Some(session_id),
                username: Some(username),
                nas_ip,
                framed_ip: None,
                session_time,
                input_octets,
                output_octets,
                input_packets: None,
                output_packets: None,
                terminate_cause: None,
            };

            self.write_record(record)
                .await
                .map_err(|e| AccountingError::InvalidAttributeValue {
                    attribute: "file_write",
                    reason: e.to_string(),
                })?;

            Ok(AccountingResult::Success)
        })
    }

    fn handle_accounting_on(
        &self,
        nas_ip: IpAddr,
        _packet: &Packet,
    ) -> Pin<Box<dyn Future<Output = Result<AccountingResult, AccountingError>> + Send + '_>> {
        Box::pin(async move {
            let record = AccountingRecord {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                event: AccountingEvent::AccountingOn,
                session_id: None,
                username: None,
                nas_ip,
                framed_ip: None,
                session_time: None,
                input_octets: None,
                output_octets: None,
                input_packets: None,
                output_packets: None,
                terminate_cause: None,
            };

            self.write_record(record)
                .await
                .map_err(|e| AccountingError::InvalidAttributeValue {
                    attribute: "file_write",
                    reason: e.to_string(),
                })?;

            Ok(AccountingResult::Success)
        })
    }

    fn handle_accounting_off(
        &self,
        nas_ip: IpAddr,
        _packet: &Packet,
    ) -> Pin<Box<dyn Future<Output = Result<AccountingResult, AccountingError>> + Send + '_>> {
        Box::pin(async move {
            let record = AccountingRecord {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                event: AccountingEvent::AccountingOff,
                session_id: None,
                username: None,
                nas_ip,
                framed_ip: None,
                session_time: None,
                input_octets: None,
                output_octets: None,
                input_packets: None,
                output_packets: None,
                terminate_cause: None,
            };

            self.write_record(record)
                .await
                .map_err(|e| AccountingError::InvalidAttributeValue {
                    attribute: "file_write",
                    reason: e.to_string(),
                })?;

            Ok(AccountingResult::Success)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use radius_proto::{Attribute, Code};
    use tempfile::TempDir;

    fn create_test_packet() -> Packet {
        Packet::new(Code::AccountingRequest, 1, [0u8; 16])
    }

    #[tokio::test]
    async fn test_file_handler_creates_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("accounting.log");

        let handler = FileAccountingHandler::new(file_path.clone())
            .await
            .expect("Failed to create handler");

        assert!(file_path.exists());

        // Write a start event
        let packet = create_test_packet();
        let result = handler
            .handle_start("session123", "testuser", "192.168.1.1".parse().unwrap(), &packet)
            .await;

        assert!(result.is_ok());

        // Read the file and verify content
        let content = tokio::fs::read_to_string(&file_path)
            .await
            .expect("Failed to read file");

        assert!(content.contains("\"event\":\"start\""));
        assert!(content.contains("\"session_id\":\"session123\""));
        assert!(content.contains("\"username\":\"testuser\""));
    }

    #[tokio::test]
    async fn test_file_handler_stop_event() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("accounting.log");

        let handler = FileAccountingHandler::new(file_path.clone())
            .await
            .expect("Failed to create handler");

        let mut packet = create_test_packet();
        packet.add_attribute(
            Attribute::new(AttributeType::AcctSessionTime as u8, vec![0, 0, 0, 100]).unwrap(),
        );
        packet.add_attribute(
            Attribute::new(AttributeType::AcctInputOctets as u8, vec![0, 0, 1, 0]).unwrap(),
        );

        let result = handler
            .handle_stop("session123", "testuser", "192.168.1.1".parse().unwrap(), &packet)
            .await;

        assert!(result.is_ok());

        let content = tokio::fs::read_to_string(&file_path)
            .await
            .expect("Failed to read file");

        assert!(content.contains("\"event\":\"stop\""));
        assert!(content.contains("\"session_time\":100"));
        assert!(content.contains("\"input_octets\":256"));
    }
}
