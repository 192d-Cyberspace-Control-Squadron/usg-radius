//! PostgreSQL authentication handler
//!
//! This module provides RADIUS authentication against a PostgreSQL database.

use crate::server::AuthHandler;
use radius_proto::attributes::Attribute;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, warn};

#[derive(Error, Debug)]
pub enum PostgresError {
    #[error("Database connection error: {0}")]
    Connection(String),
    #[error("Database query error: {0}")]
    Query(String),
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Password verification error: {0}")]
    PasswordVerification(String),
}

/// PostgreSQL authentication handler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConfig {
    /// PostgreSQL connection URL
    /// Format: postgresql://username:password@host:port/database
    /// Example: postgresql://radius:secret@localhost:5432/radius
    pub url: String,

    /// Maximum number of connections in the pool
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// SQL query to retrieve user credentials
    /// Must return columns: username, password_hash
    /// The {username} placeholder will be replaced with the actual username
    ///
    /// Example for bcrypt: "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true"
    #[serde(default = "default_query")]
    pub query: String,

    /// Password hashing algorithm
    /// Supported: "bcrypt", "argon2", "pbkdf2", "plain" (NOT recommended for production)
    #[serde(default = "default_password_hash")]
    pub password_hash: String,

    /// Optional query to retrieve RADIUS attributes for accepted users
    /// Should return columns: attribute_type, attribute_value
    /// Example: "SELECT attribute_type, attribute_value FROM user_attributes WHERE username = $1"
    #[serde(default)]
    pub attributes_query: Option<String>,
}

fn default_max_connections() -> u32 {
    10
}

fn default_timeout() -> u64 {
    10
}

fn default_query() -> String {
    "SELECT username, password_hash FROM users WHERE username = $1 AND enabled = true".to_string()
}

fn default_password_hash() -> String {
    "bcrypt".to_string()
}

impl Default for PostgresConfig {
    fn default() -> Self {
        PostgresConfig {
            url: "postgresql://radius:changeme@localhost:5432/radius".to_string(),
            max_connections: default_max_connections(),
            timeout: default_timeout(),
            query: default_query(),
            password_hash: default_password_hash(),
            attributes_query: None,
        }
    }
}

/// PostgreSQL authentication handler
pub struct PostgresAuthHandler {
    config: PostgresConfig,
    pool: Arc<PgPool>,
}

impl PostgresAuthHandler {
    /// Create a new PostgreSQL authentication handler
    ///
    /// This will establish a connection pool to the database.
    /// Returns an error if the database cannot be reached.
    pub async fn new(config: PostgresConfig) -> Result<Self, PostgresError> {
        debug!(
            "Creating PostgreSQL connection pool to {}",
            mask_url(&config.url)
        );

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(Duration::from_secs(config.timeout))
            .connect(&config.url)
            .await
            .map_err(|e| PostgresError::Connection(e.to_string()))?;

        info!(
            max_connections = config.max_connections,
            "PostgreSQL connection pool created successfully"
        );

        Ok(PostgresAuthHandler {
            config,
            pool: Arc::new(pool),
        })
    }

    /// Verify password against stored hash
    async fn verify_password(&self, password: &str, hash: &str) -> Result<bool, PostgresError> {
        match self.config.password_hash.as_str() {
            "bcrypt" => {
                // Use bcrypt to verify password
                tokio::task::spawn_blocking({
                    let password = password.to_string();
                    let hash = hash.to_string();
                    move || bcrypt::verify(&password, &hash)
                })
                .await
                .map_err(|e| PostgresError::PasswordVerification(e.to_string()))?
                .map_err(|e| PostgresError::PasswordVerification(e.to_string()))
            }
            "plain" => {
                // Plain text comparison (NOT recommended for production)
                warn!("Using plain text password comparison - NOT recommended for production");
                Ok(password == hash)
            }
            other => {
                error!(algorithm = %other, "Unsupported password hashing algorithm");
                Err(PostgresError::PasswordVerification(format!(
                    "Unsupported password algorithm: {}",
                    other
                )))
            }
        }
    }

    /// Retrieve user credentials from database
    async fn get_user_credentials(&self, username: &str) -> Result<String, PostgresError> {
        debug!(username = %username, "Querying database for user credentials");

        let row = sqlx::query(&self.config.query)
            .bind(username)
            .fetch_optional(&*self.pool)
            .await
            .map_err(|e| PostgresError::Query(e.to_string()))?;

        match row {
            Some(row) => {
                let password_hash: String = row
                    .try_get("password_hash")
                    .map_err(|e| PostgresError::Query(e.to_string()))?;

                debug!(username = %username, "User credentials retrieved from database");
                Ok(password_hash)
            }
            None => {
                warn!(username = %username, "User not found in database");
                Err(PostgresError::UserNotFound(username.to_string()))
            }
        }
    }

    /// Retrieve RADIUS attributes for user
    async fn get_user_attributes(&self, username: &str) -> Vec<Attribute> {
        if let Some(query) = &self.config.attributes_query {
            debug!(username = %username, "Querying database for user attributes");

            match sqlx::query(query)
                .bind(username)
                .fetch_all(&*self.pool)
                .await
            {
                Ok(rows) => {
                    let mut attributes = Vec::new();
                    for row in rows {
                        if let (Ok(attr_type), Ok(attr_value)) = (
                            row.try_get::<i32, _>("attribute_type"),
                            row.try_get::<String, _>("attribute_value"),
                        ) {
                            // Try to create attribute (string type for now)
                            if let Ok(attr) = Attribute::string(attr_type as u8, &attr_value) {
                                attributes.push(attr);
                            }
                        }
                    }
                    debug!(
                        username = %username,
                        count = attributes.len(),
                        "Retrieved user attributes from database"
                    );
                    attributes
                }
                Err(e) => {
                    warn!(
                        username = %username,
                        error = %e,
                        "Failed to retrieve user attributes"
                    );
                    vec![]
                }
            }
        } else {
            vec![]
        }
    }
}

impl AuthHandler for PostgresAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        // Database operations are async, so we need to use block_in_place
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                // Get user credentials from database
                let password_hash = match self.get_user_credentials(username).await {
                    Ok(hash) => hash,
                    Err(e) => {
                        debug!(username = %username, error = %e, "Failed to get user credentials");
                        return false;
                    }
                };

                // Verify password
                match self.verify_password(password, &password_hash).await {
                    Ok(valid) => {
                        if valid {
                            info!(username = %username, "PostgreSQL authentication successful");
                            true
                        } else {
                            warn!(username = %username, "PostgreSQL authentication failed - invalid password");
                            false
                        }
                    }
                    Err(e) => {
                        error!(username = %username, error = %e, "Password verification error");
                        false
                    }
                }
            })
        })
    }

    // CHAP authentication is not supported for PostgreSQL by default
    // PostgreSQL typically stores hashed passwords (bcrypt, etc.) which cannot be used for CHAP
    // CHAP requires access to plaintext passwords to compute the expected response
    // If you need CHAP support, you must store plaintext passwords (not recommended)
    // and implement get_user_password() to return them
    // The default implementation in AuthHandler will return false for CHAP

    fn get_accept_attributes(&self, username: &str) -> Vec<Attribute> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.get_user_attributes(username).await })
        })
    }

    fn get_reject_attributes(&self, _username: &str) -> Vec<Attribute> {
        vec![
            Attribute::string(
                radius_proto::attributes::AttributeType::ReplyMessage as u8,
                "PostgreSQL authentication failed",
            )
            .unwrap(),
        ]
    }
}

/// Mask sensitive parts of database URL for logging
fn mask_url(url: &str) -> String {
    if let Some(at_pos) = url.find('@') {
        if let Some(scheme_end) = url.find("://") {
            let scheme = &url[..=scheme_end + 2];
            let host_part = &url[at_pos..];
            format!("{}***:***{}", scheme, host_part)
        } else {
            "***:***@***".to_string()
        }
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgres_config_default() {
        let config = PostgresConfig::default();
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.timeout, 10);
        assert_eq!(config.password_hash, "bcrypt");
        assert!(config.query.contains("SELECT"));
    }

    #[test]
    fn test_mask_url() {
        let url = "postgresql://user:password@localhost:5432/database";
        let masked = mask_url(url);
        assert!(masked.contains("***:***"));
        assert!(!masked.contains("password"));
        assert!(masked.contains("@localhost:5432/database"));
    }

    #[test]
    fn test_mask_url_without_credentials() {
        let url = "postgresql://localhost:5432/database";
        let masked = mask_url(url);
        assert_eq!(masked, url);
    }
}
