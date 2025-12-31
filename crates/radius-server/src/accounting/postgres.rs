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

    /// Clean up old accounting data based on retention period
    ///
    /// # Arguments
    /// * `retention_days` - Number of days to retain data (older data will be deleted)
    ///
    /// # Returns
    /// Tuple of (sessions_deleted, events_deleted)
    pub async fn cleanup_old_data(&self, retention_days: u32) -> Result<(u64, u64), sqlx::Error> {
        let cutoff_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - (retention_days as i64 * 86400); // days to seconds

        // Delete old completed sessions (not active, older than retention period)
        let sessions_result = sqlx::query(
            r#"
            DELETE FROM radius_sessions
            WHERE is_active = false AND stop_time < $1
            "#,
        )
        .bind(cutoff_timestamp)
        .execute(&self.pool)
        .await?;

        // Delete old accounting events (older than retention period)
        let events_result = sqlx::query(
            r#"
            DELETE FROM radius_accounting_events
            WHERE timestamp < $1
            "#,
        )
        .bind(cutoff_timestamp)
        .execute(&self.pool)
        .await?;

        Ok((
            sessions_result.rows_affected(),
            events_result.rows_affected(),
        ))
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

    /// Get total usage for a specific user within a time range
    ///
    /// Returns (total_input_octets, total_output_octets, total_session_time, session_count)
    pub async fn get_user_usage(
        &self,
        username: &str,
        start_timestamp: Option<i64>,
        end_timestamp: Option<i64>,
    ) -> Result<(i64, i64, i64, i64), sqlx::Error> {
        let start_ts = start_timestamp.unwrap_or(0);
        let end_ts = end_timestamp.unwrap_or(i64::MAX);

        let row = sqlx::query(
            r#"
            SELECT
                COALESCE(SUM(input_octets), 0) as total_input,
                COALESCE(SUM(output_octets), 0) as total_output,
                COALESCE(SUM(session_time), 0) as total_time,
                COUNT(*) as session_count
            FROM radius_sessions
            WHERE username = $1
                AND start_time >= $2
                AND start_time <= $3
            "#,
        )
        .bind(username)
        .bind(start_ts)
        .bind(end_ts)
        .fetch_one(&self.pool)
        .await?;

        Ok((
            row.get("total_input"),
            row.get("total_output"),
            row.get("total_time"),
            row.get("session_count"),
        ))
    }

    /// Get total usage for a specific NAS within a time range
    ///
    /// Returns (total_input_octets, total_output_octets, total_session_time, session_count)
    pub async fn get_nas_usage(
        &self,
        nas_ip: &str,
        start_timestamp: Option<i64>,
        end_timestamp: Option<i64>,
    ) -> Result<(i64, i64, i64, i64), sqlx::Error> {
        let start_ts = start_timestamp.unwrap_or(0);
        let end_ts = end_timestamp.unwrap_or(i64::MAX);

        let row = sqlx::query(
            r#"
            SELECT
                COALESCE(SUM(input_octets), 0) as total_input,
                COALESCE(SUM(output_octets), 0) as total_output,
                COALESCE(SUM(session_time), 0) as total_time,
                COUNT(*) as session_count
            FROM radius_sessions
            WHERE nas_ip = $1
                AND start_time >= $2
                AND start_time <= $3
            "#,
        )
        .bind(nas_ip)
        .bind(start_ts)
        .bind(end_ts)
        .fetch_one(&self.pool)
        .await?;

        Ok((
            row.get("total_input"),
            row.get("total_output"),
            row.get("total_time"),
            row.get("session_count"),
        ))
    }

    /// Get top users by bandwidth usage within a time range
    ///
    /// Returns a list of (username, total_input_octets, total_output_octets, total_octets, session_count)
    pub async fn get_top_users_by_bandwidth(
        &self,
        limit: i64,
        start_timestamp: Option<i64>,
        end_timestamp: Option<i64>,
    ) -> Result<Vec<(String, i64, i64, i64, i64)>, sqlx::Error> {
        let start_ts = start_timestamp.unwrap_or(0);
        let end_ts = end_timestamp.unwrap_or(i64::MAX);

        let rows = sqlx::query(
            r#"
            SELECT
                username,
                COALESCE(SUM(input_octets), 0) as total_input,
                COALESCE(SUM(output_octets), 0) as total_output,
                COALESCE(SUM(input_octets + output_octets), 0) as total_octets,
                COUNT(*) as session_count
            FROM radius_sessions
            WHERE start_time >= $1
                AND start_time <= $2
            GROUP BY username
            ORDER BY total_octets DESC
            LIMIT $3
            "#,
        )
        .bind(start_ts)
        .bind(end_ts)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| {
                (
                    row.get("username"),
                    row.get("total_input"),
                    row.get("total_output"),
                    row.get("total_octets"),
                    row.get("session_count"),
                )
            })
            .collect())
    }

    /// Get session duration statistics for a user within a time range
    ///
    /// Returns (avg_session_time, min_session_time, max_session_time, total_session_time)
    pub async fn get_user_session_stats(
        &self,
        username: &str,
        start_timestamp: Option<i64>,
        end_timestamp: Option<i64>,
    ) -> Result<(f64, i32, i32, i64), sqlx::Error> {
        let start_ts = start_timestamp.unwrap_or(0);
        let end_ts = end_timestamp.unwrap_or(i64::MAX);

        let row = sqlx::query(
            r#"
            SELECT
                COALESCE(AVG(session_time), 0) as avg_time,
                COALESCE(MIN(session_time), 0) as min_time,
                COALESCE(MAX(session_time), 0) as max_time,
                COALESCE(SUM(session_time), 0) as total_time
            FROM radius_sessions
            WHERE username = $1
                AND start_time >= $2
                AND start_time <= $3
                AND session_time > 0
            "#,
        )
        .bind(username)
        .bind(start_ts)
        .bind(end_ts)
        .fetch_one(&self.pool)
        .await?;

        Ok((
            row.get("avg_time"),
            row.get("min_time"),
            row.get("max_time"),
            row.get("total_time"),
        ))
    }

    /// Get daily usage aggregation for a user
    ///
    /// Returns a list of (date, total_input_octets, total_output_octets, session_count)
    /// Date is in YYYY-MM-DD format
    pub async fn get_daily_usage_by_user(
        &self,
        username: &str,
        start_timestamp: Option<i64>,
        end_timestamp: Option<i64>,
    ) -> Result<Vec<(String, i64, i64, i64)>, sqlx::Error> {
        let start_ts = start_timestamp.unwrap_or(0);
        let end_ts = end_timestamp.unwrap_or(i64::MAX);

        let rows = sqlx::query(
            r#"
            SELECT
                TO_CHAR(TO_TIMESTAMP(start_time), 'YYYY-MM-DD') as date,
                COALESCE(SUM(input_octets), 0) as total_input,
                COALESCE(SUM(output_octets), 0) as total_output,
                COUNT(*) as session_count
            FROM radius_sessions
            WHERE username = $1
                AND start_time >= $2
                AND start_time <= $3
            GROUP BY date
            ORDER BY date DESC
            "#,
        )
        .bind(username)
        .bind(start_ts)
        .bind(end_ts)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| {
                (
                    row.get("date"),
                    row.get("total_input"),
                    row.get("total_output"),
                    row.get("session_count"),
                )
            })
            .collect())
    }

    /// Get hourly usage aggregation for a specific date
    ///
    /// Returns a list of (hour, total_input_octets, total_output_octets, session_count)
    /// Hour is 0-23
    pub async fn get_hourly_usage(
        &self,
        start_timestamp: i64,
        end_timestamp: i64,
    ) -> Result<Vec<(i32, i64, i64, i64)>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT
                EXTRACT(HOUR FROM TO_TIMESTAMP(start_time))::INTEGER as hour,
                COALESCE(SUM(input_octets), 0) as total_input,
                COALESCE(SUM(output_octets), 0) as total_output,
                COUNT(*) as session_count
            FROM radius_sessions
            WHERE start_time >= $1
                AND start_time <= $2
            GROUP BY hour
            ORDER BY hour
            "#,
        )
        .bind(start_timestamp)
        .bind(end_timestamp)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| {
                (
                    row.get("hour"),
                    row.get("total_input"),
                    row.get("total_output"),
                    row.get("session_count"),
                )
            })
            .collect())
    }

    /// Get currently active sessions count
    pub async fn get_active_sessions_count(&self) -> Result<i64, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM radius_sessions
            WHERE is_active = true
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row.get("count"))
    }

    /// Get active sessions grouped by NAS
    ///
    /// Returns a list of (nas_ip, session_count)
    pub async fn get_active_sessions_by_nas(&self) -> Result<Vec<(String, i64)>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT
                nas_ip,
                COUNT(*) as session_count
            FROM radius_sessions
            WHERE is_active = true
            GROUP BY nas_ip
            ORDER BY session_count DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| (row.get("nas_ip"), row.get("session_count")))
            .collect())
    }

    /// Export user usage data to CSV format
    ///
    /// Returns CSV string with columns: username, total_input_mb, total_output_mb, total_mb, session_count, avg_session_minutes
    pub async fn export_user_usage_csv(
        &self,
        start_timestamp: Option<i64>,
        end_timestamp: Option<i64>,
    ) -> Result<String, sqlx::Error> {
        let start_ts = start_timestamp.unwrap_or(0);
        let end_ts = end_timestamp.unwrap_or(i64::MAX);

        let rows = sqlx::query(
            r#"
            SELECT
                username,
                COALESCE(SUM(input_octets), 0) as total_input,
                COALESCE(SUM(output_octets), 0) as total_output,
                COALESCE(SUM(input_octets + output_octets), 0) as total_octets,
                COUNT(*) as session_count,
                COALESCE(AVG(session_time), 0) as avg_session_time
            FROM radius_sessions
            WHERE start_time >= $1
                AND start_time <= $2
            GROUP BY username
            ORDER BY total_octets DESC
            "#,
        )
        .bind(start_ts)
        .bind(end_ts)
        .fetch_all(&self.pool)
        .await?;

        let mut csv = String::from(
            "username,total_input_mb,total_output_mb,total_mb,session_count,avg_session_minutes\n",
        );

        for row in rows {
            let username: String = row.get("username");
            let total_input: i64 = row.get("total_input");
            let total_output: i64 = row.get("total_output");
            let total_octets: i64 = row.get("total_octets");
            let session_count: i64 = row.get("session_count");
            let avg_session_time: f64 = row.get("avg_session_time");

            // Convert bytes to MB (1 MB = 1,048,576 bytes)
            let input_mb = total_input as f64 / 1_048_576.0;
            let output_mb = total_output as f64 / 1_048_576.0;
            let total_mb = total_octets as f64 / 1_048_576.0;
            let avg_minutes = avg_session_time / 60.0;

            csv.push_str(&format!(
                "\"{}\",{:.2},{:.2},{:.2},{},{:.2}\n",
                username.replace('"', "\"\""), // Escape quotes in username
                input_mb,
                output_mb,
                total_mb,
                session_count,
                avg_minutes
            ));
        }

        Ok(csv)
    }

    /// Export sessions data to CSV format
    ///
    /// Returns CSV string with session details
    pub async fn export_sessions_csv(
        &self,
        start_timestamp: Option<i64>,
        end_timestamp: Option<i64>,
        active_only: bool,
    ) -> Result<String, sqlx::Error> {
        let start_ts = start_timestamp.unwrap_or(0);
        let end_ts = end_timestamp.unwrap_or(i64::MAX);

        let query = if active_only {
            r#"
            SELECT
                session_id, username, nas_ip, framed_ip,
                start_time, stop_time, session_time,
                input_octets, output_octets, is_active
            FROM radius_sessions
            WHERE start_time >= $1
                AND start_time <= $2
                AND is_active = true
            ORDER BY start_time DESC
            "#
        } else {
            r#"
            SELECT
                session_id, username, nas_ip, framed_ip,
                start_time, stop_time, session_time,
                input_octets, output_octets, is_active
            FROM radius_sessions
            WHERE start_time >= $1
                AND start_time <= $2
            ORDER BY start_time DESC
            "#
        };

        let rows = sqlx::query(query)
            .bind(start_ts)
            .bind(end_ts)
            .fetch_all(&self.pool)
            .await?;

        let mut csv = String::from(
            "session_id,username,nas_ip,framed_ip,start_time,stop_time,duration_minutes,input_mb,output_mb,total_mb,status\n",
        );

        for row in rows {
            let session_id: String = row.get("session_id");
            let username: String = row.get("username");
            let nas_ip: String = row.get("nas_ip");
            let framed_ip: Option<String> = row.get("framed_ip");
            let start_time: i64 = row.get("start_time");
            let stop_time: Option<i64> = row.get("stop_time");
            let session_time: Option<i32> = row.get("session_time");
            let input_octets: i64 = row.get("input_octets");
            let output_octets: i64 = row.get("output_octets");
            let is_active: bool = row.get("is_active");

            let duration_minutes = session_time.unwrap_or(0) as f64 / 60.0;
            let input_mb = input_octets as f64 / 1_048_576.0;
            let output_mb = output_octets as f64 / 1_048_576.0;
            let total_mb = (input_octets + output_octets) as f64 / 1_048_576.0;
            let status = if is_active { "active" } else { "completed" };

            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",{},{},{:.2},{:.2},{:.2},{:.2},{}\n",
                session_id.replace('"', "\"\""),
                username.replace('"', "\"\""),
                nas_ip,
                framed_ip.unwrap_or_else(|| "".to_string()),
                start_time,
                stop_time
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "".to_string()),
                duration_minutes,
                input_mb,
                output_mb,
                total_mb,
                status
            ));
        }

        Ok(csv)
    }

    /// Generate a JSON usage report with summary statistics
    ///
    /// Returns a comprehensive JSON report with user usage, top users, and summary stats
    pub async fn generate_usage_report_json(
        &self,
        start_timestamp: Option<i64>,
        end_timestamp: Option<i64>,
    ) -> Result<String, sqlx::Error> {
        let start_ts = start_timestamp.unwrap_or(0);
        let end_ts = end_timestamp.unwrap_or(i64::MAX);

        // Get summary statistics
        let summary = sqlx::query(
            r#"
            SELECT
                COUNT(DISTINCT username) as total_users,
                COUNT(*) as total_sessions,
                COALESCE(SUM(input_octets), 0) as total_input,
                COALESCE(SUM(output_octets), 0) as total_output,
                COALESCE(SUM(session_time), 0) as total_time,
                COALESCE(AVG(session_time), 0) as avg_session_time
            FROM radius_sessions
            WHERE start_time >= $1
                AND start_time <= $2
            "#,
        )
        .bind(start_ts)
        .bind(end_ts)
        .fetch_one(&self.pool)
        .await?;

        let total_users: i64 = summary.get("total_users");
        let total_sessions: i64 = summary.get("total_sessions");
        let total_input: i64 = summary.get("total_input");
        let total_output: i64 = summary.get("total_output");
        let total_time: i64 = summary.get("total_time");
        let avg_session_time: f64 = summary.get("avg_session_time");

        // Get top 10 users by bandwidth
        let top_users_rows = sqlx::query(
            r#"
            SELECT
                username,
                COALESCE(SUM(input_octets), 0) as total_input,
                COALESCE(SUM(output_octets), 0) as total_output,
                COALESCE(SUM(input_octets + output_octets), 0) as total_octets,
                COUNT(*) as session_count
            FROM radius_sessions
            WHERE start_time >= $1
                AND start_time <= $2
            GROUP BY username
            ORDER BY total_octets DESC
            LIMIT 10
            "#,
        )
        .bind(start_ts)
        .bind(end_ts)
        .fetch_all(&self.pool)
        .await?;

        // Build JSON manually for better control
        let mut json = String::from("{\n");

        // Report metadata
        json.push_str("  \"report_type\": \"usage_summary\",\n");
        json.push_str(&format!(
            "  \"generated_at\": {},\n",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ));

        if start_timestamp.is_some() || end_timestamp.is_some() {
            json.push_str("  \"time_range\": {\n");
            if let Some(start) = start_timestamp {
                json.push_str(&format!("    \"start\": {},\n", start));
            }
            if let Some(end) = end_timestamp {
                json.push_str(&format!("    \"end\": {}\n", end));
            }
            json.push_str("  },\n");
        }

        // Summary statistics
        json.push_str("  \"summary\": {\n");
        json.push_str(&format!("    \"total_users\": {},\n", total_users));
        json.push_str(&format!("    \"total_sessions\": {},\n", total_sessions));
        json.push_str(&format!("    \"total_input_bytes\": {},\n", total_input));
        json.push_str(&format!("    \"total_output_bytes\": {},\n", total_output));
        json.push_str(&format!(
            "    \"total_bytes\": {},\n",
            total_input + total_output
        ));
        json.push_str(&format!(
            "    \"total_input_mb\": {:.2},\n",
            total_input as f64 / 1_048_576.0
        ));
        json.push_str(&format!(
            "    \"total_output_mb\": {:.2},\n",
            total_output as f64 / 1_048_576.0
        ));
        json.push_str(&format!(
            "    \"total_mb\": {:.2},\n",
            (total_input + total_output) as f64 / 1_048_576.0
        ));
        json.push_str(&format!(
            "    \"total_session_time_seconds\": {},\n",
            total_time
        ));
        json.push_str(&format!(
            "    \"avg_session_time_seconds\": {:.2}\n",
            avg_session_time
        ));
        json.push_str("  },\n");

        // Top users
        json.push_str("  \"top_users\": [\n");
        for (i, row) in top_users_rows.iter().enumerate() {
            let username: String = row.get("username");
            let total_input: i64 = row.get("total_input");
            let total_output: i64 = row.get("total_output");
            let total_octets: i64 = row.get("total_octets");
            let session_count: i64 = row.get("session_count");

            json.push_str("    {\n");
            json.push_str(&format!(
                "      \"username\": \"{}\",\n",
                username.replace('"', "\\\"")
            ));
            json.push_str(&format!("      \"total_input_bytes\": {},\n", total_input));
            json.push_str(&format!(
                "      \"total_output_bytes\": {},\n",
                total_output
            ));
            json.push_str(&format!("      \"total_bytes\": {},\n", total_octets));
            json.push_str(&format!(
                "      \"total_mb\": {:.2},\n",
                total_octets as f64 / 1_048_576.0
            ));
            json.push_str(&format!("      \"session_count\": {}\n", session_count));

            if i < top_users_rows.len() - 1 {
                json.push_str("    },\n");
            } else {
                json.push_str("    }\n");
            }
        }
        json.push_str("  ]\n");
        json.push_str("}");

        Ok(json)
    }

    /// Extract accounting attributes from packet
    fn extract_accounting_attrs(
        packet: &Packet,
    ) -> (
        Option<u32>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        Option<u32>,
    ) {
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

        let output_packets = packet
            .find_attribute(AttributeType::AcctOutputPackets as u8)
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

        (
            session_time,
            input_octets,
            output_octets,
            input_packets,
            output_packets,
            terminate_cause,
        )
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
            let (
                session_time,
                input_octets,
                output_octets,
                input_packets,
                output_packets,
                terminate_cause,
            ) = Self::extract_accounting_attrs(&packet);

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
                        terminate_cause: row
                            .get::<Option<i32>, _>("terminate_cause")
                            .map(|v| v as u32),
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
                terminate_cause: row
                    .get::<Option<i32>, _>("terminate_cause")
                    .map(|v| v as u32),
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
            .handle_start(
                "test_session",
                "testuser",
                "192.168.1.1".parse().unwrap(),
                &packet,
            )
            .await;

        assert!(result.is_ok());

        // Verify session was created
        let session = handler.get_session("test_session").await;
        assert!(session.is_some());
        assert_eq!(session.unwrap().username, "testuser");
    }

    #[tokio::test]
    #[ignore] // Requires running PostgreSQL instance
    async fn test_postgres_aggregation_queries() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost/test_radius".to_string());

        let handler = PostgresAccountingHandler::from_url(&database_url)
            .await
            .expect("Failed to connect to database");

        handler.migrate().await.expect("Failed to run migrations");

        // Clean up any existing test data
        sqlx::query("DELETE FROM radius_sessions WHERE username LIKE 'test_%'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");

        // Create test sessions with different users and timestamps
        let base_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // User 1: 3 sessions with varying usage
        for i in 0..3 {
            sqlx::query(
                r#"
                INSERT INTO radius_sessions (
                    session_id, username, nas_ip, start_time, last_update,
                    input_octets, output_octets, session_time, is_active
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(format!("session_user1_{}", i))
            .bind("test_user1")
            .bind("192.168.1.1")
            .bind(base_time - 3600 * i)
            .bind(base_time - 3600 * i)
            .bind((i + 1) * 1000000) // 1MB, 2MB, 3MB
            .bind((i + 1) * 500000) // 0.5MB, 1MB, 1.5MB
            .bind((i + 1) * 300) // 300s, 600s, 900s
            .bind(false)
            .execute(&handler.pool)
            .await
            .expect("Failed to insert test session");
        }

        // User 2: 2 sessions
        for i in 0..2 {
            sqlx::query(
                r#"
                INSERT INTO radius_sessions (
                    session_id, username, nas_ip, start_time, last_update,
                    input_octets, output_octets, session_time, is_active
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(format!("session_user2_{}", i))
            .bind("test_user2")
            .bind("192.168.1.2")
            .bind(base_time - 7200 * i)
            .bind(base_time - 7200 * i)
            .bind((i + 1) * 2000000) // 2MB, 4MB
            .bind((i + 1) * 1000000) // 1MB, 2MB
            .bind((i + 1) * 600) // 600s, 1200s
            .bind(i == 0) // First session is active
            .execute(&handler.pool)
            .await
            .expect("Failed to insert test session");
        }

        // Test get_user_usage
        let (input, output, time, count) = handler
            .get_user_usage("test_user1", None, None)
            .await
            .expect("Failed to get user usage");

        assert_eq!(count, 3, "Expected 3 sessions for test_user1");
        assert_eq!(input, 6000000, "Expected 6MB total input"); // 1+2+3 MB
        assert_eq!(output, 3000000, "Expected 3MB total output"); // 0.5+1+1.5 MB
        assert_eq!(time, 1800, "Expected 1800s total time"); // 300+600+900

        // Test get_nas_usage
        let (input, output, _time, count) = handler
            .get_nas_usage("192.168.1.2", None, None)
            .await
            .expect("Failed to get NAS usage");

        assert_eq!(count, 2, "Expected 2 sessions for NAS 192.168.1.2");
        assert_eq!(input, 6000000, "Expected 6MB total input"); // 2+4 MB
        assert_eq!(output, 3000000, "Expected 3MB total output"); // 1+2 MB

        // Test get_top_users_by_bandwidth
        let top_users = handler
            .get_top_users_by_bandwidth(10, None, None)
            .await
            .expect("Failed to get top users");

        assert!(top_users.len() >= 2, "Expected at least 2 users");

        // test_user1 should have more total bandwidth (9MB vs 9MB, but check ordering)
        let user1_entry = top_users.iter().find(|(u, _, _, _, _)| u == "test_user1");
        assert!(user1_entry.is_some(), "test_user1 should be in top users");

        let (_, input, output, total, count) = user1_entry.unwrap();
        assert_eq!(*input, 6000000);
        assert_eq!(*output, 3000000);
        assert_eq!(*total, 9000000);
        assert_eq!(*count, 3);

        // Test get_user_session_stats
        let (avg, min, max, total) = handler
            .get_user_session_stats("test_user1", None, None)
            .await
            .expect("Failed to get session stats");

        assert_eq!(avg, 600.0, "Expected average of 600s");
        assert_eq!(min, 300, "Expected min of 300s");
        assert_eq!(max, 900, "Expected max of 900s");
        assert_eq!(total, 1800, "Expected total of 1800s");

        // Test get_active_sessions_count
        let active_count = handler
            .get_active_sessions_count()
            .await
            .expect("Failed to get active sessions count");

        assert!(active_count >= 1, "Expected at least 1 active session");

        // Test get_active_sessions_by_nas
        let active_by_nas = handler
            .get_active_sessions_by_nas()
            .await
            .expect("Failed to get active sessions by NAS");

        assert!(
            !active_by_nas.is_empty(),
            "Expected at least one NAS with active sessions"
        );

        let nas_entry = active_by_nas.iter().find(|(nas, _)| nas == "192.168.1.2");
        assert!(
            nas_entry.is_some(),
            "Expected 192.168.1.2 to have active sessions"
        );
        assert_eq!(
            nas_entry.unwrap().1,
            1,
            "Expected 1 active session for 192.168.1.2"
        );

        // Test get_daily_usage_by_user
        let daily_usage = handler
            .get_daily_usage_by_user("test_user1", None, None)
            .await
            .expect("Failed to get daily usage");

        assert!(
            !daily_usage.is_empty(),
            "Expected at least one day of usage"
        );

        // Test get_hourly_usage
        let _hourly_usage = handler
            .get_hourly_usage(base_time - 86400, base_time)
            .await
            .expect("Failed to get hourly usage");

        // May or may not have hourly data depending on when test runs
        // Just verify it doesn't error

        // Clean up test data
        sqlx::query("DELETE FROM radius_sessions WHERE username LIKE 'test_%'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");
    }

    #[tokio::test]
    #[ignore] // Requires running PostgreSQL instance
    async fn test_postgres_cleanup_old_data() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost/test_radius".to_string());

        let handler = PostgresAccountingHandler::from_url(&database_url)
            .await
            .expect("Failed to connect to database");

        handler.migrate().await.expect("Failed to run migrations");

        // Clean up any existing test data
        sqlx::query("DELETE FROM radius_sessions WHERE username = 'test_cleanup_user'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");

        sqlx::query("DELETE FROM radius_accounting_events WHERE username = 'test_cleanup_user'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Create old session (100 days ago)
        let old_time = current_time - (100 * 86400);
        sqlx::query(
            r#"
            INSERT INTO radius_sessions (
                session_id, username, nas_ip, start_time, last_update,
                stop_time, is_active
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind("old_session")
        .bind("test_cleanup_user")
        .bind("192.168.1.1")
        .bind(old_time)
        .bind(old_time)
        .bind(old_time + 3600)
        .bind(false) // Not active
        .execute(&handler.pool)
        .await
        .expect("Failed to insert old session");

        // Create recent session (1 day ago)
        let recent_time = current_time - 86400;
        sqlx::query(
            r#"
            INSERT INTO radius_sessions (
                session_id, username, nas_ip, start_time, last_update,
                stop_time, is_active
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind("recent_session")
        .bind("test_cleanup_user")
        .bind("192.168.1.1")
        .bind(recent_time)
        .bind(recent_time)
        .bind(recent_time + 3600)
        .bind(false) // Not active
        .execute(&handler.pool)
        .await
        .expect("Failed to insert recent session");

        // Create old accounting event
        sqlx::query(
            r#"
            INSERT INTO radius_accounting_events (
                timestamp, event_type, session_id, username, nas_ip
            ) VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(old_time)
        .bind("start")
        .bind("old_session")
        .bind("test_cleanup_user")
        .bind("192.168.1.1")
        .execute(&handler.pool)
        .await
        .expect("Failed to insert old event");

        // Run cleanup with 90 day retention
        let (sessions_deleted, events_deleted) = handler
            .cleanup_old_data(90)
            .await
            .expect("Failed to cleanup old data");

        assert_eq!(sessions_deleted, 1, "Expected 1 old session to be deleted");
        assert_eq!(events_deleted, 1, "Expected 1 old event to be deleted");

        // Verify old session was deleted
        let old_session = handler.get_session("old_session").await;
        assert!(old_session.is_none(), "Old session should be deleted");

        // Verify recent session still exists
        let recent_session = handler.get_session("recent_session").await;
        assert!(
            recent_session.is_some(),
            "Recent session should still exist"
        );

        // Clean up test data
        sqlx::query("DELETE FROM radius_sessions WHERE username = 'test_cleanup_user'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");

        sqlx::query("DELETE FROM radius_accounting_events WHERE username = 'test_cleanup_user'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");
    }

    #[tokio::test]
    #[ignore] // Requires running PostgreSQL instance
    async fn test_export_user_usage_csv() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost/test_radius".to_string());

        let handler = PostgresAccountingHandler::from_url(&database_url)
            .await
            .expect("Failed to connect to database");

        handler.migrate().await.expect("Failed to run migrations");

        // Clean up any existing test data
        sqlx::query("DELETE FROM radius_sessions WHERE username LIKE 'export_test_%'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");

        let base_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Create test sessions
        for i in 0..3 {
            sqlx::query(
                r#"
                INSERT INTO radius_sessions (
                    session_id, username, nas_ip, start_time, last_update,
                    input_octets, output_octets, session_time, is_active
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(format!("export_session_{}", i))
            .bind(format!("export_test_user{}", i % 2)) // Two users
            .bind("192.168.1.1")
            .bind(base_time - 3600 * i)
            .bind(base_time - 3600 * i)
            .bind((i + 1) * 10_485_760) // 10MB, 20MB, 30MB
            .bind((i + 1) * 5_242_880) // 5MB, 10MB, 15MB
            .bind((i + 1) * 600) // 600s, 1200s, 1800s
            .bind(false)
            .execute(&handler.pool)
            .await
            .expect("Failed to insert test session");
        }

        // Export to CSV
        let csv = handler
            .export_user_usage_csv(None, None)
            .await
            .expect("Failed to export CSV");

        // Verify CSV format
        assert!(csv.contains(
            "username,total_input_mb,total_output_mb,total_mb,session_count,avg_session_minutes"
        ));
        assert!(csv.contains("export_test_user"));

        // Should have header + 2 users
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines.len() >= 3, "Expected at least header + 2 data rows");

        // Clean up test data
        sqlx::query("DELETE FROM radius_sessions WHERE username LIKE 'export_test_%'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");
    }

    #[tokio::test]
    #[ignore] // Requires running PostgreSQL instance
    async fn test_export_sessions_csv() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost/test_radius".to_string());

        let handler = PostgresAccountingHandler::from_url(&database_url)
            .await
            .expect("Failed to connect to database");

        handler.migrate().await.expect("Failed to run migrations");

        // Clean up any existing test data
        sqlx::query("DELETE FROM radius_sessions WHERE username = 'export_session_test'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");

        let base_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Create test sessions (one active, one completed)
        sqlx::query(
            r#"
            INSERT INTO radius_sessions (
                session_id, username, nas_ip, start_time, last_update,
                input_octets, output_octets, session_time, is_active
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind("active_session")
        .bind("export_session_test")
        .bind("192.168.1.1")
        .bind(base_time)
        .bind(base_time)
        .bind(10_485_760) // 10MB
        .bind(5_242_880) // 5MB
        .bind(600)
        .bind(true) // Active
        .execute(&handler.pool)
        .await
        .expect("Failed to insert active session");

        sqlx::query(
            r#"
            INSERT INTO radius_sessions (
                session_id, username, nas_ip, start_time, last_update, stop_time,
                input_octets, output_octets, session_time, is_active
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind("completed_session")
        .bind("export_session_test")
        .bind("192.168.1.1")
        .bind(base_time - 7200)
        .bind(base_time - 3600)
        .bind(base_time - 3600)
        .bind(20_971_520) // 20MB
        .bind(10_485_760) // 10MB
        .bind(1200)
        .bind(false) // Completed
        .execute(&handler.pool)
        .await
        .expect("Failed to insert completed session");

        // Export all sessions
        let csv_all = handler
            .export_sessions_csv(None, None, false)
            .await
            .expect("Failed to export all sessions CSV");

        assert!(csv_all.contains("session_id,username,nas_ip,framed_ip,start_time,stop_time,duration_minutes,input_mb,output_mb,total_mb,status"));
        assert!(csv_all.contains("active_session"));
        assert!(csv_all.contains("completed_session"));
        assert!(csv_all.contains("active"));
        assert!(csv_all.contains("completed"));

        // Export active sessions only
        let csv_active = handler
            .export_sessions_csv(None, None, true)
            .await
            .expect("Failed to export active sessions CSV");

        assert!(csv_active.contains("active_session"));
        assert!(!csv_active.contains("completed_session"));

        // Clean up test data
        sqlx::query("DELETE FROM radius_sessions WHERE username = 'export_session_test'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");
    }

    #[tokio::test]
    #[ignore] // Requires running PostgreSQL instance
    async fn test_generate_usage_report_json() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost/test_radius".to_string());

        let handler = PostgresAccountingHandler::from_url(&database_url)
            .await
            .expect("Failed to connect to database");

        handler.migrate().await.expect("Failed to run migrations");

        // Clean up any existing test data
        sqlx::query("DELETE FROM radius_sessions WHERE username LIKE 'report_test_%'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");

        let base_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Create test sessions for multiple users
        for user_id in 0..5 {
            for session_id in 0..2 {
                sqlx::query(
                    r#"
                    INSERT INTO radius_sessions (
                        session_id, username, nas_ip, start_time, last_update,
                        input_octets, output_octets, session_time, is_active
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    "#,
                )
                .bind(format!("report_session_{}_{}", user_id, session_id))
                .bind(format!("report_test_user{}", user_id))
                .bind("192.168.1.1")
                .bind(base_time - (user_id * 3600 + session_id * 1800))
                .bind(base_time - (user_id * 3600 + session_id * 1800))
                .bind((user_id + 1) * (session_id + 1) * 10_485_760) // Varying usage
                .bind((user_id + 1) * (session_id + 1) * 5_242_880)
                .bind((user_id + 1) * (session_id + 1) * 300)
                .bind(false)
                .execute(&handler.pool)
                .await
                .expect("Failed to insert test session");
            }
        }

        // Generate JSON report
        let json = handler
            .generate_usage_report_json(None, None)
            .await
            .expect("Failed to generate JSON report");

        // Verify JSON structure
        assert!(json.contains("\"report_type\": \"usage_summary\""));
        assert!(json.contains("\"generated_at\":"));
        assert!(json.contains("\"summary\":"));
        assert!(json.contains("\"total_users\":"));
        assert!(json.contains("\"total_sessions\":"));
        assert!(json.contains("\"total_input_bytes\":"));
        assert!(json.contains("\"total_output_bytes\":"));
        assert!(json.contains("\"total_mb\":"));
        assert!(json.contains("\"top_users\":"));
        assert!(json.contains("report_test_user"));

        // Verify it's valid JSON by attempting to parse (basic check)
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));

        // Clean up test data
        sqlx::query("DELETE FROM radius_sessions WHERE username LIKE 'report_test_%'")
            .execute(&handler.pool)
            .await
            .expect("Failed to clean up test data");
    }
}
