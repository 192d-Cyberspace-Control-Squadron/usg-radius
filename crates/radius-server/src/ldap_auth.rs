//! LDAP/Active Directory authentication handler
//!
//! This module provides RADIUS authentication against LDAP/AD servers.

use crate::server::AuthHandler;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use radius_proto::attributes::Attribute;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Semaphore;
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
    /// For backward compatibility, this is still supported as primary server
    #[serde(default)]
    pub url: String,

    /// Multiple LDAP server URLs for failover support
    /// If specified, this takes precedence over `url`
    /// Servers are tried in order until one succeeds
    #[serde(default)]
    pub urls: Vec<String>,

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

    /// Maximum number of connections in the pool
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Connection acquire timeout in seconds
    #[serde(default = "default_acquire_timeout")]
    pub acquire_timeout: u64,

    /// Group attribute name (default: "memberOf")
    #[serde(default = "default_group_attribute")]
    pub group_attribute: String,

    /// Map LDAP groups to RADIUS attributes
    /// Format: { "CN=GroupName,OU=Groups,DC=example,DC=com": [{"type": 25, "value": "Framed-User"}] }
    #[serde(default)]
    pub group_attribute_mapping: std::collections::HashMap<String, Vec<GroupAttributeMapping>>,
}

/// Mapping from LDAP group to RADIUS attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupAttributeMapping {
    /// RADIUS attribute type number
    pub attr_type: u8,
    /// RADIUS attribute value
    pub attr_value: String,
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

fn default_max_connections() -> u32 {
    10
}

fn default_acquire_timeout() -> u64 {
    10
}

fn default_group_attribute() -> String {
    "memberOf".to_string()
}

impl Default for LdapConfig {
    fn default() -> Self {
        LdapConfig {
            url: "ldap://localhost:389".to_string(),
            urls: Vec::new(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: None,
            bind_password: None,
            search_filter: default_search_filter(),
            attributes: default_attributes(),
            timeout: default_timeout(),
            verify_tls: true,
            max_connections: default_max_connections(),
            acquire_timeout: default_acquire_timeout(),
            group_attribute: default_group_attribute(),
            group_attribute_mapping: std::collections::HashMap::new(),
        }
    }
}

impl LdapConfig {
    /// Get all configured LDAP server URLs
    ///
    /// Returns URLs from `urls` field if configured, otherwise falls back to single `url`
    pub fn get_server_urls(&self) -> Vec<String> {
        if !self.urls.is_empty() {
            self.urls.clone()
        } else if !self.url.is_empty() {
            vec![self.url.clone()]
        } else {
            Vec::new()
        }
    }
}

/// Server health state for failover
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerHealth {
    /// Server is healthy and available
    Up,
    /// Server is experiencing failures
    Down,
}

/// Health information for an LDAP server
#[derive(Debug, Clone)]
struct ServerHealthInfo {
    /// Current health state
    state: ServerHealth,
    /// Number of consecutive failures
    consecutive_failures: u32,
    /// Number of consecutive successes
    consecutive_successes: u32,
    /// Last successful connection time
    last_success: Option<std::time::Instant>,
    /// Last failure time
    last_failure: Option<std::time::Instant>,
}

impl Default for ServerHealthInfo {
    fn default() -> Self {
        ServerHealthInfo {
            state: ServerHealth::Up,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_success: None,
            last_failure: None,
        }
    }
}

/// LDAP connection pool
///
/// Manages a pool of reusable LDAP connections to reduce connection overhead.
/// Uses a semaphore to limit concurrent connections and supports connection reuse.
/// Supports automatic failover across multiple LDAP servers.
pub struct LdapPool {
    config: Arc<LdapConfig>,
    semaphore: Arc<Semaphore>,
    /// Health tracking for each server URL
    /// Key is server URL, value is health information
    server_health: Arc<dashmap::DashMap<String, ServerHealthInfo>>,
    /// Number of consecutive failures before marking server as Down
    failures_before_down: u32,
    /// Number of consecutive successes before marking server as Up
    successes_before_up: u32,
}

impl LdapPool {
    /// Create a new LDAP connection pool
    pub fn new(config: LdapConfig) -> Self {
        let max_connections = config.max_connections as usize;
        let server_urls = config.get_server_urls();

        debug!(
            servers = ?server_urls,
            max_connections = max_connections,
            "Creating LDAP connection pool with failover support"
        );

        // Initialize health tracking for all servers
        let server_health = dashmap::DashMap::new();
        for url in &server_urls {
            server_health.insert(url.clone(), ServerHealthInfo::default());
        }

        LdapPool {
            config: Arc::new(config),
            semaphore: Arc::new(Semaphore::new(max_connections)),
            server_health: Arc::new(server_health),
            failures_before_down: 3,
            successes_before_up: 2,
        }
    }

    /// Record a successful connection to a server
    fn record_success(&self, url: &str) {
        let mut entry = self.server_health.entry(url.to_string()).or_default();

        entry.consecutive_successes += 1;
        entry.consecutive_failures = 0;
        entry.last_success = Some(std::time::Instant::now());

        // Transition to Up state if enough successes
        if entry.state == ServerHealth::Down
            && entry.consecutive_successes >= self.successes_before_up
        {
            info!(url = %url, "LDAP server recovered");
            entry.state = ServerHealth::Up;
        }
    }

    /// Record a failed connection to a server
    fn record_failure(&self, url: &str) {
        let mut entry = self.server_health.entry(url.to_string()).or_default();

        entry.consecutive_failures += 1;
        entry.consecutive_successes = 0;
        entry.last_failure = Some(std::time::Instant::now());

        // Transition to Down state if enough failures
        if entry.state == ServerHealth::Up
            && entry.consecutive_failures >= self.failures_before_down
        {
            warn!(url = %url, "LDAP server marked as down after {} failures", self.failures_before_down);
            entry.state = ServerHealth::Down;
        }
    }

    /// Check if a server is healthy
    fn is_server_healthy(&self, url: &str) -> bool {
        self.server_health
            .get(url)
            .map(|info| info.state == ServerHealth::Up)
            .unwrap_or(true) // Assume healthy if not tracked yet
    }

    /// Get the list of available servers (healthy servers first, then unhealthy)
    fn get_prioritized_servers(&self) -> Vec<String> {
        let all_urls = self.config.get_server_urls();
        let mut healthy_servers = Vec::new();
        let mut unhealthy_servers = Vec::new();

        for url in all_urls {
            if self.is_server_healthy(&url) {
                healthy_servers.push(url);
            } else {
                unhealthy_servers.push(url);
            }
        }

        // Try healthy servers first, then unhealthy (for recovery)
        healthy_servers.extend(unhealthy_servers);
        healthy_servers
    }

    /// Acquire a connection from the pool
    ///
    /// This will create a new connection and bind with the service account credentials.
    /// The connection is returned when the guard is dropped.
    /// Automatically tries servers in order with failover support.
    pub async fn acquire(&self) -> Result<LdapConnection, LdapError> {
        // Acquire permit from semaphore (blocks if pool is full)
        let acquire_timeout = Duration::from_secs(self.config.acquire_timeout);
        let permit =
            tokio::time::timeout(acquire_timeout, Arc::clone(&self.semaphore).acquire_owned())
                .await
                .map_err(|_| LdapError::Connection("Connection pool timeout".to_string()))?
                .map_err(|e| LdapError::Connection(format!("Failed to acquire permit: {}", e)))?;

        debug!("Acquired LDAP connection from pool");

        // Try servers in prioritized order (healthy first)
        let servers = self.get_prioritized_servers();
        let mut last_error = None;

        for server_url in servers {
            debug!(url = %server_url, "Attempting LDAP connection");

            // Try to connect to this server
            match self.try_connect_and_bind(&server_url).await {
                Ok(ldap) => {
                    // Connection successful
                    self.record_success(&server_url);
                    info!(url = %server_url, "LDAP connection established");

                    return Ok(LdapConnection {
                        ldap,
                        _permit: permit,
                    });
                }
                Err(e) => {
                    // Connection failed, record and try next server
                    self.record_failure(&server_url);
                    warn!(url = %server_url, error = ?e, "LDAP connection failed, trying next server");
                    last_error = Some(e);
                }
            }
        }

        // All servers failed
        Err(last_error
            .unwrap_or_else(|| LdapError::Connection("No LDAP servers configured".to_string())))
    }

    /// Try to connect to a specific server and bind with service account
    async fn try_connect_and_bind(&self, server_url: &str) -> Result<ldap3::Ldap, LdapError> {
        let settings =
            LdapConnSettings::new().set_conn_timeout(Duration::from_secs(self.config.timeout));

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, server_url)
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
            debug!(bind_dn = %bind_dn, "Bound LDAP connection");
        } else {
            // Anonymous bind
            ldap.simple_bind("", "")
                .await
                .map_err(|e| LdapError::Bind(e.to_string()))?
                .success()
                .map_err(|e| LdapError::Bind(e.to_string()))?;
            debug!("Anonymous bind to LDAP connection");
        }

        Ok(ldap)
    }

    /// Create a connection for user authentication (separate from pool)
    ///
    /// User authentication requires binding with user credentials, so we create
    /// a separate connection that doesn't affect the pool.
    /// Automatically tries servers in order with failover support.
    pub async fn connect_for_auth(
        &self,
        user_dn: &str,
        password: &str,
    ) -> Result<ldap3::Ldap, LdapError> {
        debug!(dn = %user_dn, "Creating LDAP connection for user authentication");

        // Try servers in prioritized order (healthy first)
        let servers = self.get_prioritized_servers();
        let mut last_error = None;

        for server_url in servers {
            debug!(url = %server_url, dn = %user_dn, "Attempting user authentication");

            let settings =
                LdapConnSettings::new().set_conn_timeout(Duration::from_secs(self.config.timeout));

            match LdapConnAsync::with_settings(settings, &server_url).await {
                Ok((conn, mut ldap)) => {
                    // Start connection driver
                    tokio::spawn(async move {
                        if let Err(e) = conn.drive().await {
                            error!("LDAP auth connection driver error: {}", e);
                        }
                    });

                    // Try to bind as the user
                    match ldap.simple_bind(user_dn, password).await {
                        Ok(bind_result) => {
                            match bind_result.success() {
                                Ok(_) => {
                                    // Authentication successful
                                    self.record_success(&server_url);
                                    debug!(url = %server_url, "User authentication successful");
                                    return Ok(ldap);
                                }
                                Err(_) => {
                                    // Authentication failed (wrong credentials)
                                    // Don't mark server as down for auth failures
                                    return Err(LdapError::AuthFailed);
                                }
                            }
                        }
                        Err(e) => {
                            // Bind request failed (connection issue)
                            self.record_failure(&server_url);
                            warn!(url = %server_url, error = %e, "Bind request failed, trying next server");
                            last_error = Some(LdapError::Bind(e.to_string()));
                        }
                    }
                }
                Err(e) => {
                    // Connection failed
                    self.record_failure(&server_url);
                    warn!(url = %server_url, error = %e, "Connection failed for auth, trying next server");
                    last_error = Some(LdapError::Connection(e.to_string()));
                }
            }
        }

        // All servers failed
        Err(last_error
            .unwrap_or_else(|| LdapError::Connection("No LDAP servers configured".to_string())))
    }
}

/// LDAP connection guard
///
/// Holds a connection and a semaphore permit. When dropped, the permit is released
/// back to the pool, allowing another connection to be created.
pub struct LdapConnection {
    ldap: ldap3::Ldap,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl LdapConnection {
    /// Get a reference to the underlying LDAP connection
    pub fn as_ref(&mut self) -> &mut ldap3::Ldap {
        &mut self.ldap
    }
}

/// LDAP authentication handler
pub struct LdapAuthHandler {
    config: LdapConfig,
    pool: Arc<LdapPool>,
    /// Cache of user attributes from last successful search
    /// Key is username, value is the LDAP entry attributes
    user_attrs_cache: Arc<dashmap::DashMap<String, std::collections::HashMap<String, Vec<String>>>>,
}

impl LdapAuthHandler {
    /// Create a new LDAP authentication handler with connection pooling
    pub fn new(config: LdapConfig) -> Self {
        let pool = LdapPool::new(config.clone());
        info!(
            url = %config.url,
            max_connections = config.max_connections,
            "LDAP authentication handler created with connection pool"
        );
        LdapAuthHandler {
            config,
            pool: Arc::new(pool),
            user_attrs_cache: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Search for user in LDAP using pooled connection
    async fn find_user(&self, username: &str) -> Result<String, LdapError> {
        // Acquire connection from pool
        let mut conn = self.pool.acquire().await?;
        let ldap = conn.as_ref();

        // Build search filter by replacing {username}
        let filter = self.config.search_filter.replace("{username}", username);

        debug!(
            username = %username,
            base_dn = %self.config.base_dn,
            filter = %filter,
            "Searching for user in LDAP (using pooled connection)"
        );

        // Search for user
        let (rs, _res) = ldap
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &filter,
                &self.config.attributes,
            )
            .await
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

        // Get user DN and attributes
        let entry = SearchEntry::construct(rs[0].clone());
        let user_dn = entry.dn.clone();

        // Cache user attributes for later retrieval
        self.user_attrs_cache
            .insert(username.to_string(), entry.attrs.clone());

        debug!(
            username = %username,
            dn = %user_dn,
            "Found user in LDAP and cached attributes"
        );

        Ok(user_dn)
    }

    /// Authenticate user with LDAP bind
    async fn authenticate_ldap(&self, user_dn: &str, password: &str) -> Result<(), LdapError> {
        debug!(dn = %user_dn, "Attempting LDAP bind for user authentication");

        // Use pool's connect_for_auth method which handles bind
        match self.pool.connect_for_auth(user_dn, password).await {
            Ok(_ldap) => {
                info!(dn = %user_dn, "LDAP authentication successful");
                Ok(())
            }
            Err(e) => {
                warn!(dn = %user_dn, error = %e, "LDAP authentication failed");
                Err(e)
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

    // CHAP authentication is not supported for LDAP
    // LDAP uses bind authentication which doesn't provide access to plaintext passwords
    // The default implementation in AuthHandler will return false

    fn get_accept_attributes(&self, username: &str) -> Vec<Attribute> {
        let mut attributes = Vec::new();

        // Retrieve cached user attributes
        if let Some(user_attrs) = self.user_attrs_cache.get(username) {
            // Get group memberships from the configured group attribute (default: memberOf)
            if let Some(groups) = user_attrs.get(&self.config.group_attribute) {
                debug!(
                    username = %username,
                    groups = ?groups,
                    "Retrieved group memberships from LDAP"
                );

                // Map each group to RADIUS attributes based on configuration
                for group in groups {
                    if let Some(mappings) = self.config.group_attribute_mapping.get(group) {
                        for mapping in mappings {
                            // Create RADIUS attribute from mapping
                            match Attribute::string(mapping.attr_type, &mapping.attr_value) {
                                Ok(attr) => {
                                    debug!(
                                        username = %username,
                                        group = %group,
                                        attr_type = mapping.attr_type,
                                        attr_value = %mapping.attr_value,
                                        "Mapped LDAP group to RADIUS attribute"
                                    );
                                    attributes.push(attr);
                                }
                                Err(e) => {
                                    warn!(
                                        username = %username,
                                        group = %group,
                                        attr_type = mapping.attr_type,
                                        error = ?e,
                                        "Failed to create RADIUS attribute from group mapping"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        attributes
    }

    fn get_reject_attributes(&self, _username: &str) -> Vec<Attribute> {
        vec![
            Attribute::string(
                radius_proto::attributes::AttributeType::ReplyMessage as u8,
                "LDAP authentication failed",
            )
            .unwrap(),
        ]
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
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.acquire_timeout, 10);
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
