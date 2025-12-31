//! PostgreSQL accounting handler
//!
//! This module provides a PostgreSQL-based implementation of the AccountingHandler trait
//! that stores accounting records and active sessions in a PostgreSQL database.

use super::{AccountingHandler, AccountingResult, Session};
use radius_proto::{AccountingError, AttributeType, Packet};
use sqlx::{PgPool, Row};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

/// PostgreSQL accounting handler
///
/// Stores accounting data in a PostgreSQL database with two main tables:
/// - `radius_sessions`: Active and completed sessions
/// - `radius_accounting_events`: All accounting events for audit trail
pub struct PostgresAccountingHandler {
    pool: PgPool,
}

impl PostgresAccountingHandler {
    /// Create a new PostgreSQL accounting handler
    ///
    /// # Arguments
    /// * `pool` - PostgreSQL connection pool
    pub fn new(pool: PgPool) -> Self {
        PostgresAccountingHandler { pool }
    }

    /// Create a new handler from a database URL
    ///
    /// # Arguments
    /// * `database_url` - PostgreSQL connection URL (e.g., "postgresql://user:pass@localhost/radius")
    pub async fn from_url(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self::new(pool))
    }

    /// Run database migrations to create the required schema
    ///
    /// This creates the necessary tables if they don't exist:
    /// - radius_sessions
    /// - radius_accounting_events
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        // Create sessions table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS radius_sessions (
                session_id VARCHAR(255) PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                nas_ip INET NOT NULL,
                framed_ip INET,
                start_time BIGINT NOT NULL,
                last_update BIGINT NOT NULL,
                stop_time BIGINT,
                input_octets BIGINT NOT NULL DEFAULT 0,
                output_octets BIGINT NOT NULL DEFAULT 0,
                input_packets BIGINT NOT NULL DEFAULT 0,
                output_packets BIGINT NOT NULL DEFAULT 0,
                session_time INTEGER NOT NULL DEFAULT 0,
                terminate_cause INTEGER,
                is_active BOOLEAN NOT NULL DEFAULT true,
                created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMP NOT NULL DEFAULT NOW()
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes for sessions table
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_sessions_username ON radius_sessions(username);
            CREATE INDEX IF NOT EXISTS idx_sessions_nas_ip ON radius_sessions(nas_ip);
            CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON radius_sessions(is_active);
            CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON radius_sessions(start_time);
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create accounting events table for audit trail
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS radius_accounting_events (
                id BIGSERIAL PRIMARY KEY,
                timestamp BIGINT NOT NULL,
                event_type VARCHAR(50) NOT NULL,
                session_id VARCHAR(255),
                username VARCHAR(255),
                nas_ip INET NOT NULL,
                framed_ip INET,
                session_time INTEGER,
                input_octets BIGINT,
                output_octets BIGINT,
                input_packets BIGINT,
                output_packets BIGINT,
                terminate_cause INTEGER,
                created_at TIMESTAMP NOT NULL DEFAULT NOW()
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes for events table
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_events_session_id ON radius_accounting_events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_username ON radius_accounting_events(username);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON radius_accounting_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_event_type ON radius_accounting_events(event_type);
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Log an accounting event to the events table
    async fn log_event(
        &self,
        event_type: &str,
        session_id: Option<&str>,
        username: Option<&str>,
        nas_ip: IpAddr,
        framed_ip: Option<IpAddr>,
        session_time: Option<u32>,
        input_octets: Option<u64>,
        output_octets: Option<u64>,
        input_packets: Option<u64>,
        output_packets: Option<u64>,
        terminate_cause: Option<u32>,
    ) -> Result<(), sqlx::Error> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO radius_accounting_events (
                timestamp, event_type, session_id, username, nas_ip,
                framed_ip, session_time, input_octets, output_octets,
                input_packets, output_packets, terminate_cause
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(timestamp)
        .bind(event_type)
        .bind(session_id)
        .bind(username)
        .bind(nas_ip.to_string())
        .bind(framed_ip.map(|ip| ip.to_string()))
        .bind(session_time.map(|v| v as i32))
        .bind(input_octets.map(|v| v as i64))
        .bind(output_octets.map(|v| v as i64))
        .bind(input_packets.map(|v| v as i64))
        .bind(output_packets.map(|v| v as i64))
        .bind(terminate_cause.map(|v| v as i32))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Extract accounting attributes from packet
    fn extract_accounting_attrs(
        packet: &Packet,
    ) -> (Option<u32>, Option<u64>, Option<u64>, Option<u64>, Option<u64>, Option<u32>) {
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

        // Extract input octets with 64-bit support (RFC 2869)
        let input_octets_low = packet
            .find_attribute(AttributeType::AcctInputOctets as u8)
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

        let input_octets_high = packet
            .find_attribute(AttributeType::AcctInputGigawords as u8)
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

        let input_octets = input_octets_low.map(|low| {
            let high = input_octets_high.unwrap_or(0) as u64;
            (high << 32) | (low as u64)
        });

        // Extract output octets with 64-bit support (RFC 2869)
        let output_octets_low = packet
            .find_attribute(AttributeType::AcctOutputOctets as u8)
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

        let output_octets_high = packet
            .find_attribute(AttributeType::AcctOutputGigawords as u8)
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

        let output_octets = output_octets_low.map(|low| {
            let high = output_octets_high.unwrap_or(0) as u64;
            (high << 32) | (low as u64)
        });

        let input_packets = packet
            .find_attribute(AttributeType::AcctInputPackets as u8)
            .and_then(|attr| {
                if attr.value.len() >= 4 {
                    Some(
                        u32::from_be_bytes([
                            attr.value[0],
                            attr.value[1],
                            attr.value[2],
                            attr.value[3],
                        ]) as u64,
                    )
                } else {
                    None
                }
            });

        let output_packets = packet
            .find_attribute(AttributeType::AcctOutputPackets as u8)
            .and_then(|attr| {
                if attr.value.len() >= 4 {
                    Some(
                        u32::from_be_bytes([
                            attr.value[0],
                            attr.value[1],
                            attr.value[2],
                            attr.value[3],
                        ]) as u64,
                    )
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

        (session_time, input_octets, output_octets, input_packets, output_packets, terminate_cause)
    }
}

impl AccountingHandler for PostgresAccountingHandler {
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
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            // Insert new session
            sqlx::query(
                r#"
                INSERT INTO radius_sessions (
                    session_id, username, nas_ip, framed_ip,
                    start_time, last_update, is_active
                ) VALUES ($1, $2, $3, $4, $5, $6, true)
                ON CONFLICT (session_id) DO UPDATE SET
                    username = EXCLUDED.username,
                    nas_ip = EXCLUDED.nas_ip,
                    framed_ip = EXCLUDED.framed_ip,
                    start_time = EXCLUDED.start_time,
                    last_update = EXCLUDED.last_update,
                    is_active = true,
                    stop_time = NULL
                "#,
            )
            .bind(&session_id)
            .bind(&username)
            .bind(nas_ip.to_string())
            .bind(framed_ip.map(|ip| ip.to_string()))
            .bind(timestamp)
            .bind(timestamp)
            .execute(&self.pool)
            .await
            .map_err(|e| AccountingError::InvalidAttributeValue {
                attribute: "database_insert",
                reason: e.to_string(),
            })?;

            // Log event
            self.log_event(
                "start",
                Some(&session_id),
                Some(&username),
                nas_ip,
                framed_ip,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .map_err(|e| AccountingError::InvalidAttributeValue {
                attribute: "event_log",
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
            let (session_time, input_octets, output_octets, input_packets, output_packets, terminate_cause) =
                Self::extract_accounting_attrs(&packet);

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            // Update session as stopped
            sqlx::query(
                r#"
                UPDATE radius_sessions
                SET
                    is_active = false,
                    stop_time = $1,
                    last_update = $1,
                    session_time = COALESCE($2, session_time),
                    input_octets = COALESCE($3, input_octets),
                    output_octets = COALESCE($4, output_octets),
                    input_packets = COALESCE($5, input_packets),
                    output_packets = COALESCE($6, output_packets),
                    terminate_cause = $7,
                    updated_at = NOW()
                WHERE session_id = $8
                "#,
            )
            .bind(timestamp)
            .bind(session_time.map(|v| v as i32))
            .bind(input_octets.map(|v| v as i64))
            .bind(output_octets.map(|v| v as i64))
            .bind(input_packets.map(|v| v as i64))
            .bind(output_packets.map(|v| v as i64))
            .bind(terminate_cause.map(|v| v as i32))
            .bind(&session_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AccountingError::InvalidAttributeValue {
                attribute: "database_update",
                reason: e.to_string(),
            })?;

            // Log event
            self.log_event(
                "stop",
                Some(&session_id),
                Some(&username),
                nas_ip,
                None,
                session_time,
                input_octets,
                output_octets,
                input_packets,
                output_packets,
                terminate_cause,
            )
            .await
            .map_err(|e| AccountingError::InvalidAttributeValue {
                attribute: "event_log",
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
            let (session_time, input_octets, output_octets, input_packets, output_packets, _) =
                Self::extract_accounting_attrs(&packet);

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            // Update session with interim data
            sqlx::query(
                r#"
                UPDATE radius_sessions
                SET
                    last_update = $1,
                    session_time = COALESCE($2, session_time),
                    input_octets = COALESCE($3, input_octets),
                    output_octets = COALESCE($4, output_octets),
                    input_packets = COALESCE($5, input_packets),
                    output_packets = COALESCE($6, output_packets),
                    updated_at = NOW()
                WHERE session_id = $7 AND is_active = true
                "#,
            )
            .bind(timestamp)
            .bind(session_time.map(|v| v as i32))
            .bind(input_octets.map(|v| v as i64))
            .bind(output_octets.map(|v| v as i64))
            .bind(input_packets.map(|v| v as i64))
            .bind(output_packets.map(|v| v as i64))
            .bind(&session_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AccountingError::InvalidAttributeValue {
                attribute: "database_update",
                reason: e.to_string(),
            })?;

            // Log event
            self.log_event(
                "interim_update",
                Some(&session_id),
                Some(&username),
                nas_ip,
                None,
                session_time,
                input_octets,
                output_octets,
                input_packets,
                output_packets,
                None,
            )
            .await
            .map_err(|e| AccountingError::InvalidAttributeValue {
                attribute: "event_log",
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
            // Log the accounting-on event
            self.log_event(
                "accounting_on",
                None,
                None,
                nas_ip,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .map_err(|e| AccountingError::InvalidAttributeValue {
                attribute: "event_log",
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
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            // Mark all active sessions from this NAS as stopped
            sqlx::query(
                r#"
                UPDATE radius_sessions
                SET
                    is_active = false,
                    stop_time = $1,
                    last_update = $1,
                    updated_at = NOW()
                WHERE nas_ip = $2 AND is_active = true
                "#,
            )
            .bind(timestamp)
            .bind(nas_ip.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AccountingError::InvalidAttributeValue {
                attribute: "database_update",
                reason: e.to_string(),
            })?;

            // Log the accounting-off event
            self.log_event(
                "accounting_off",
                None,
                None,
                nas_ip,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .map_err(|e| AccountingError::InvalidAttributeValue {
                attribute: "event_log",
                reason: e.to_string(),
            })?;

            Ok(AccountingResult::Success)
        })
    }

    fn get_active_sessions(&self) -> Pin<Box<dyn Future<Output = Vec<Session>> + Send + '_>> {
        Box::pin(async move {
            let rows = sqlx::query(
                r#"
                SELECT
                    session_id, username, nas_ip, framed_ip,
                    start_time, last_update, input_octets, output_octets,
                    input_packets, output_packets, session_time, terminate_cause
                FROM radius_sessions
                WHERE is_active = true
                ORDER BY start_time DESC
                "#,
            )
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();

            rows.into_iter()
                .filter_map(|row| {
                    let nas_ip_str: String = row.get("nas_ip");
                    let nas_ip = nas_ip_str.parse::<IpAddr>().ok()?;
                    let framed_ip: Option<String> = row.get("framed_ip");
                    let framed_ip = framed_ip.and_then(|s| s.parse::<IpAddr>().ok());

                    Some(Session {
                        session_id: row.get("session_id"),
                        username: row.get("username"),
                        nas_ip,
                        framed_ip,
                        start_time: row.get::<i64, _>("start_time") as u64,
                        last_update: row.get::<i64, _>("last_update") as u64,
                        input_octets: row.get::<i64, _>("input_octets") as u64,
                        output_octets: row.get::<i64, _>("output_octets") as u64,
                        input_packets: row.get::<i64, _>("input_packets") as u64,
                        output_packets: row.get::<i64, _>("output_packets") as u64,
                        session_time: row.get::<Option<i32>, _>("session_time").unwrap_or(0) as u32,
                        terminate_cause: row.get::<Option<i32>, _>("terminate_cause").map(|v| v as u32),
                    })
                })
                .collect()
        })
    }

    fn get_session(
        &self,
        session_id: &str,
    ) -> Pin<Box<dyn Future<Output = Option<Session>> + Send + '_>> {
        let session_id = session_id.to_string();
        Box::pin(async move {
            let row = sqlx::query(
                r#"
                SELECT
                    session_id, username, nas_ip, framed_ip,
                    start_time, last_update, input_octets, output_octets,
                    input_packets, output_packets, session_time, terminate_cause
                FROM radius_sessions
                WHERE session_id = $1
                "#,
            )
            .bind(&session_id)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten()?;

            let nas_ip_str: String = row.get("nas_ip");
            let nas_ip = nas_ip_str.parse::<IpAddr>().ok()?;
            let framed_ip: Option<String> = row.get("framed_ip");
            let framed_ip = framed_ip.and_then(|s| s.parse::<IpAddr>().ok());

            Some(Session {
                session_id: row.get("session_id"),
                username: row.get("username"),
                nas_ip,
                framed_ip,
                start_time: row.get::<i64, _>("start_time") as u64,
                last_update: row.get::<i64, _>("last_update") as u64,
                input_octets: row.get::<i64, _>("input_octets") as u64,
                output_octets: row.get::<i64, _>("output_octets") as u64,
                input_packets: row.get::<i64, _>("input_packets") as u64,
                output_packets: row.get::<i64, _>("output_packets") as u64,
                session_time: row.get::<Option<i32>, _>("session_time").unwrap_or(0) as u32,
                terminate_cause: row.get::<Option<i32>, _>("terminate_cause").map(|v| v as u32),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use radius_proto::Code;

    fn create_test_packet() -> Packet {
        Packet::new(Code::AccountingRequest, 1, [0u8; 16])
    }

    #[tokio::test]
    #[ignore] // Requires running PostgreSQL instance
    async fn test_postgres_handler_basic() {
        // This test requires a running PostgreSQL instance
        // Set DATABASE_URL environment variable to test:
        // DATABASE_URL=postgresql://user:pass@localhost/test_radius cargo test --package radius-server -- --ignored

        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost/test_radius".to_string());

        let handler = PostgresAccountingHandler::from_url(&database_url)
            .await
            .expect("Failed to connect to database");

        handler.migrate().await.expect("Failed to run migrations");

        let packet = create_test_packet();
        let result = handler
            .handle_start("test_session", "testuser", "192.168.1.1".parse().unwrap(), &packet)
            .await;

        assert!(result.is_ok());

        // Verify session was created
        let session = handler.get_session("test_session").await;
        assert!(session.is_some());
        assert_eq!(session.unwrap().username, "testuser");
    }
}
