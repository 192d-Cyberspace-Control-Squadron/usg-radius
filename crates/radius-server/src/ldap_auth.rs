//! LDAP/Active Directory authentication handler
//!
//! This module provides RADIUS authentication against LDAP/AD servers.

use crate::server::AuthHandler;
use ldap3::{LdapConn, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use radius_proto::attributes::Attribute;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Error, Debug)]
pub enum LdapError {
    #[error("LDAP connection error: {0}")]
    Connection(String),
    #[error("LDAP bind error: {0}")]
    Bind(String),
    #[error("LDAP search error: {0}")]
    Search(String),
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Authentication failed")]
    AuthFailed,
}

/// LDAP authentication handler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    /// LDAP server URL (e.g., "ldap://localhost:389" or "ldaps://ldap.example.com:636")
    pub url: String,

    /// Base DN for user searches (e.g., "dc=example,dc=com")
    pub base_dn: String,

    /// Bind DN for searching (e.g., "cn=admin,dc=example,dc=com")
    /// If None, anonymous bind will be used
    #[serde(default)]
    pub bind_dn: Option<String>,

    /// Bind password for searching
    #[serde(default)]
    pub bind_password: Option<String>,

    /// User search filter (e.g., "(uid={username})" or "(sAMAccountName={username})")
    /// {username} will be replaced with the actual username
    #[serde(default = "default_search_filter")]
    pub search_filter: String,

    /// Attributes to retrieve from LDAP
    #[serde(default = "default_attributes")]
    pub attributes: Vec<String>,

    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Require valid TLS certificate for LDAPS connections
    #[serde(default = "default_true")]
    pub verify_tls: bool,
}

fn default_search_filter() -> String {
    "(uid={username})".to_string()
}

fn default_attributes() -> Vec<String> {
    vec!["dn".to_string(), "cn".to_string(), "memberOf".to_string()]
}

fn default_timeout() -> u64 {
    10
}

fn default_true() -> bool {
    true
}

impl Default for LdapConfig {
    fn default() -> Self {
        LdapConfig {
            url: "ldap://localhost:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: None,
            bind_password: None,
            search_filter: default_search_filter(),
            attributes: default_attributes(),
            timeout: default_timeout(),
            verify_tls: true,
        }
    }
}

/// LDAP authentication handler with connection pooling
pub struct LdapAuthHandler {
    config: LdapConfig,
    /// Cached connection (single connection for now, can be expanded to pool)
    connection: Arc<RwLock<Option<LdapConn>>>,
}

impl LdapAuthHandler {
    /// Create a new LDAP authentication handler
    pub fn new(config: LdapConfig) -> Self {
        LdapAuthHandler {
            config,
            connection: Arc::new(RwLock::new(None)),
        }
    }

    /// Get or create LDAP connection
    async fn get_connection(&self) -> Result<LdapConn, LdapError> {
        // Try to reuse existing connection
        {
            let conn_guard = self.connection.read().await;
            if let Some(conn) = conn_guard.as_ref() {
                // Test if connection is still alive by doing a simple operation
                // If this fails, we'll create a new connection
                if let Ok(_) = conn.clone().simple_bind("", "") {
                    debug!("Reusing existing LDAP connection");
                    return Ok(conn.clone());
                }
            }
        }

        // Create new connection
        debug!("Creating new LDAP connection to {}", self.config.url);
        let settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(self.config.timeout));

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.config.url)
            .await
            .map_err(|e| LdapError::Connection(e.to_string()))?;

        // Start connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                error!("LDAP connection driver error: {}", e);
            }
        });

        // Bind with service account if configured
        if let (Some(bind_dn), Some(bind_password)) =
            (&self.config.bind_dn, &self.config.bind_password)
        {
            ldap.simple_bind(bind_dn, bind_password)
                .await
                .map_err(|e| LdapError::Bind(e.to_string()))?
                .success()
                .map_err(|e| LdapError::Bind(e.to_string()))?;
            debug!("Bound to LDAP as {}", bind_dn);
        } else {
            // Anonymous bind
            ldap.simple_bind("", "")
                .await
                .map_err(|e| LdapError::Bind(e.to_string()))?
                .success()
                .map_err(|e| LdapError::Bind(e.to_string()))?;
            debug!("Anonymous bind to LDAP");
        }

        // Convert async LDAP to sync for compatibility
        let sync_conn = ldap.into_sync();

        // Store connection for reuse
        {
            let mut conn_guard = self.connection.write().await;
            *conn_guard = Some(sync_conn.clone());
        }

        Ok(sync_conn)
    }

    /// Search for user in LDAP
    async fn find_user(&self, username: &str) -> Result<String, LdapError> {
        let mut ldap = self.get_connection().await?;

        // Build search filter by replacing {username}
        let filter = self.config.search_filter.replace("{username}", username);

        debug!(
            username = %username,
            base_dn = %self.config.base_dn,
            filter = %filter,
            "Searching for user in LDAP"
        );

        // Search for user
        let (rs, _res) = ldap
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &filter,
                &self.config.attributes,
            )
            .map_err(|e| LdapError::Search(e.to_string()))?
            .success()
            .map_err(|e| LdapError::Search(e.to_string()))?;

        if rs.is_empty() {
            warn!(username = %username, "User not found in LDAP");
            return Err(LdapError::UserNotFound(username.to_string()));
        }

        if rs.len() > 1 {
            warn!(
                username = %username,
                count = rs.len(),
                "Multiple users found in LDAP, using first result"
            );
        }

        // Get user DN
        let entry = SearchEntry::construct(rs[0].clone());
        let user_dn = entry.dn;

        debug!(
            username = %username,
            dn = %user_dn,
            "Found user in LDAP"
        );

        Ok(user_dn)
    }

    /// Authenticate user with LDAP bind
    async fn authenticate_ldap(&self, user_dn: &str, password: &str) -> Result<(), LdapError> {
        debug!(dn = %user_dn, "Attempting LDAP bind for user");

        let settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(self.config.timeout));

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.config.url)
            .await
            .map_err(|e| LdapError::Connection(e.to_string()))?;

        // Start connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                error!("LDAP connection driver error: {}", e);
            }
        });

        // Try to bind as the user
        let result = ldap.simple_bind(user_dn, password).await;

        match result {
            Ok(bind_result) => {
                match bind_result.success() {
                    Ok(_) => {
                        info!(dn = %user_dn, "LDAP authentication successful");
                        Ok(())
                    }
                    Err(e) => {
                        warn!(dn = %user_dn, error = %e, "LDAP bind failed");
                        Err(LdapError::AuthFailed)
                    }
                }
            }
            Err(e) => {
                warn!(dn = %user_dn, error = %e, "LDAP bind error");
                Err(LdapError::AuthFailed)
            }
        }
    }
}

impl AuthHandler for LdapAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        // LDAP operations are async, so we need to use block_in_place
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                // Find user DN
                let user_dn = match self.find_user(username).await {
                    Ok(dn) => dn,
                    Err(e) => {
                        debug!(username = %username, error = %e, "Failed to find user");
                        return false;
                    }
                };

                // Authenticate with user credentials
                match self.authenticate_ldap(&user_dn, password).await {
                    Ok(_) => true,
                    Err(e) => {
                        debug!(username = %username, error = %e, "Authentication failed");
                        false
                    }
                }
            })
        })
    }

    fn get_accept_attributes(&self, _username: &str) -> Vec<Attribute> {
        // Could retrieve group memberships or other attributes from LDAP
        // and convert them to RADIUS attributes
        vec![]
    }

    fn get_reject_attributes(&self, _username: &str) -> Vec<Attribute> {
        vec![Attribute::string(
            radius_proto::attributes::AttributeType::ReplyMessage as u8,
            "LDAP authentication failed",
        )
        .unwrap()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_config_default() {
        let config = LdapConfig::default();
        assert_eq!(config.url, "ldap://localhost:389");
        assert_eq!(config.base_dn, "dc=example,dc=com");
        assert_eq!(config.search_filter, "(uid={username})");
        assert_eq!(config.timeout, 10);
        assert!(config.verify_tls);
    }

    #[test]
    fn test_search_filter_replacement() {
        let filter = "(uid={username})";
        let result = filter.replace("{username}", "testuser");
        assert_eq!(result, "(uid=testuser)");

        let ad_filter = "(sAMAccountName={username})";
        let result = ad_filter.replace("{username}", "jdoe");
        assert_eq!(result, "(sAMAccountName=jdoe)");
    }
}
