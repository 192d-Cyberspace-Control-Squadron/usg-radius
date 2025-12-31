use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

/// User configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    /// Client IP address or network (supports CIDR notation)
    pub address: String,
    /// Shared secret for this client
    pub secret: String,
    /// Optional client name/description
    #[serde(default)]
    pub name: Option<String>,
    /// Enable/disable this client
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl Client {
    /// Parse the client address as an IP network
    pub fn parse_network(&self) -> Result<IpNetwork, ConfigError> {
        // Try to parse as CIDR notation first
        if let Ok(network) = self.address.parse::<IpNetwork>() {
            return Ok(network);
        }

        // Try to parse as a single IP address
        if let Ok(ip) = self.address.parse::<IpAddr>() {
            // Convert to /32 (IPv4) or /128 (IPv6) network
            return Ok(IpNetwork::from(ip));
        }

        Err(ConfigError::Invalid(format!(
            "Invalid client address: {}",
            self.address
        )))
    }

    /// Check if a source IP address matches this client
    pub fn matches(&self, source_ip: IpAddr) -> Result<bool, ConfigError> {
        let network = self.parse_network()?;
        Ok(network.contains(source_ip))
    }

    /// Get the shared secret for this client
    pub fn get_secret(&self) -> &[u8] {
        self.secret.as_bytes()
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server listen address
    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    /// Server listen port
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    /// Default shared secret (used if client doesn't specify one)
    #[serde(default = "default_secret")]
    pub secret: String,

    /// List of authorized clients
    #[serde(default)]
    pub clients: Vec<Client>,

    /// List of users for authentication
    #[serde(default)]
    pub users: Vec<User>,

    /// Enable verbose logging (deprecated: use log_level instead)
    #[serde(default)]
    pub verbose: bool,

    /// Log level: "trace", "debug", "info", "warn", "error" (default: "info")
    #[serde(default)]
    pub log_level: Option<String>,

    /// Audit log file path (JSON format, optional)
    #[serde(default)]
    pub audit_log_path: Option<String>,

    /// Strict RFC 2865 compliance mode (default: true)
    /// When enabled, enforces strict validation of attribute values and types.
    /// Set to false for lenient mode if compatibility with non-compliant clients is needed.
    #[serde(default = "default_strict_rfc_compliance")]
    pub strict_rfc_compliance: bool,

    /// Request cache TTL in seconds (default: 60)
    #[serde(default)]
    pub request_cache_ttl: Option<u64>,

    /// Maximum number of cached requests (default: 10000)
    #[serde(default)]
    pub request_cache_max_entries: Option<usize>,

    /// Rate limit: requests per second per client (default: 100, 0 = unlimited)
    #[serde(default)]
    pub rate_limit_per_client_rps: Option<u32>,

    /// Rate limit: burst capacity per client (default: 200)
    #[serde(default)]
    pub rate_limit_per_client_burst: Option<u32>,

    /// Rate limit: requests per second globally (default: 1000, 0 = unlimited)
    #[serde(default)]
    pub rate_limit_global_rps: Option<u32>,

    /// Rate limit: global burst capacity (default: 2000)
    #[serde(default)]
    pub rate_limit_global_burst: Option<u32>,
}

fn default_listen_address() -> String {
    "0.0.0.0".to_string()
}

fn default_listen_port() -> u16 {
    1812 // Standard RADIUS authentication port
}

fn default_secret() -> String {
    "testing123".to_string()
}

fn default_strict_rfc_compliance() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_address: default_listen_address(),
            listen_port: default_listen_port(),
            secret: default_secret(),
            clients: vec![],
            users: vec![],
            verbose: false,
            log_level: None,
            audit_log_path: None,
            strict_rfc_compliance: true,
            request_cache_ttl: None,
            request_cache_max_entries: None,
            rate_limit_per_client_rps: None,
            rate_limit_per_client_burst: None,
            rate_limit_global_rps: None,
            rate_limit_global_burst: None,
        }
    }
}

impl Config {
    /// Load configuration from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Save configuration to a JSON file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }

    /// Get socket address for binding
    pub fn socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        let addr: IpAddr = self
            .listen_address
            .parse()
            .map_err(|_| ConfigError::Invalid(format!("Invalid IP address: {}", self.listen_address)))?;
        Ok(SocketAddr::new(addr, self.listen_port))
    }

    /// Find a client by source IP address
    ///
    /// Returns the first enabled client that matches the source IP.
    /// Returns None if no matching client is found or if the clients list is empty.
    pub fn find_client(&self, source_ip: IpAddr) -> Option<&Client> {
        for client in &self.clients {
            if !client.enabled {
                continue;
            }
            if let Ok(true) = client.matches(source_ip) {
                return Some(client);
            }
        }
        None
    }

    /// Get the shared secret for a source IP
    ///
    /// Returns the client-specific secret if a matching client is found,
    /// otherwise returns the default shared secret.
    pub fn get_secret_for_client(&self, source_ip: IpAddr) -> &[u8] {
        self.find_client(source_ip)
            .map(|client| client.get_secret())
            .unwrap_or_else(|| self.secret.as_bytes())
    }

    /// Validate configuration
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate listen address
        let _: IpAddr = self
            .listen_address
            .parse()
            .map_err(|_| ConfigError::Invalid(format!("Invalid listen address: {}", self.listen_address)))?;

        // Validate port
        if self.listen_port == 0 {
            return Err(ConfigError::Invalid("Port cannot be 0".to_string()));
        }

        // Validate secret is not empty
        if self.secret.is_empty() {
            return Err(ConfigError::Invalid("Secret cannot be empty".to_string()));
        }

        // Validate clients
        for client in &self.clients {
            if client.secret.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "Client {} has empty secret",
                    client.address
                )));
            }
            // Validate that address can be parsed
            client.parse_network()?;
        }

        // Validate users
        for user in &self.users {
            if user.username.is_empty() {
                return Err(ConfigError::Invalid("User has empty username".to_string()));
            }
        }

        Ok(())
    }

    /// Create an example configuration file
    pub fn example() -> Self {
        Config {
            listen_address: "0.0.0.0".to_string(),
            listen_port: 1812,
            secret: "testing123".to_string(),
            clients: vec![
                Client {
                    address: "192.168.1.0/24".to_string(),
                    secret: "client_secret_1".to_string(),
                    name: Some("Internal Network".to_string()),
                    enabled: true,
                },
                Client {
                    address: "10.0.0.1".to_string(),
                    secret: "client_secret_2".to_string(),
                    name: Some("VPN Gateway".to_string()),
                    enabled: true,
                },
            ],
            users: vec![
                User {
                    username: "admin".to_string(),
                    password: "admin123".to_string(),
                    attributes: HashMap::new(),
                },
                User {
                    username: "user1".to_string(),
                    password: "password1".to_string(),
                    attributes: HashMap::new(),
                },
            ],
            verbose: false,
            log_level: Some("info".to_string()),
            audit_log_path: Some("/var/log/radius/audit.log".to_string()),
            strict_rfc_compliance: true,
            request_cache_ttl: Some(60),
            request_cache_max_entries: Some(10000),
            rate_limit_per_client_rps: Some(100),
            rate_limit_per_client_burst: Some(200),
            rate_limit_global_rps: Some(1000),
            rate_limit_global_burst: Some(2000),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.listen_port, 1812);
        assert!(!config.secret.is_empty());
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        config.secret = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_socket_addr() {
        let config = Config::default();
        let addr = config.socket_addr().unwrap();
        assert_eq!(addr.port(), 1812);
    }

    #[test]
    fn test_client_parse_network_single_ip() {
        let client = Client {
            address: "192.168.1.1".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
        };

        let network = client.parse_network().unwrap();
        assert!(network.contains("192.168.1.1".parse().unwrap()));
        assert!(!network.contains("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_client_parse_network_cidr() {
        let client = Client {
            address: "192.168.1.0/24".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
        };

        let network = client.parse_network().unwrap();
        assert!(network.contains("192.168.1.1".parse().unwrap()));
        assert!(network.contains("192.168.1.254".parse().unwrap()));
        assert!(!network.contains("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_client_matches() {
        let client = Client {
            address: "10.0.0.0/8".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
        };

        assert!(client.matches("10.1.2.3".parse().unwrap()).unwrap());
        assert!(client.matches("10.255.255.255".parse().unwrap()).unwrap());
        assert!(!client.matches("11.0.0.1".parse().unwrap()).unwrap());
    }

    #[test]
    fn test_client_invalid_address() {
        let client = Client {
            address: "invalid".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
        };

        assert!(client.parse_network().is_err());
    }

    #[test]
    fn test_config_find_client() {
        let mut config = Config::default();
        config.clients = vec![
            Client {
                address: "192.168.1.0/24".to_string(),
                secret: "secret1".to_string(),
                name: Some("Network 1".to_string()),
                enabled: true,
            },
            Client {
                address: "10.0.0.1".to_string(),
                secret: "secret2".to_string(),
                name: Some("Single IP".to_string()),
                enabled: true,
            },
        ];

        // Should find matching client
        let client = config.find_client("192.168.1.50".parse().unwrap());
        assert!(client.is_some());
        assert_eq!(client.unwrap().secret, "secret1");

        // Should find exact IP match
        let client = config.find_client("10.0.0.1".parse().unwrap());
        assert!(client.is_some());
        assert_eq!(client.unwrap().secret, "secret2");

        // Should not find non-matching IP
        let client = config.find_client("172.16.0.1".parse().unwrap());
        assert!(client.is_none());
    }

    #[test]
    fn test_config_find_client_disabled() {
        let mut config = Config::default();
        config.clients = vec![Client {
            address: "192.168.1.0/24".to_string(),
            secret: "secret1".to_string(),
            name: Some("Network 1".to_string()),
            enabled: false, // Disabled
        }];

        // Should not find disabled client
        let client = config.find_client("192.168.1.50".parse().unwrap());
        assert!(client.is_none());
    }

    #[test]
    fn test_config_get_secret_for_client() {
        let mut config = Config::default();
        config.secret = "default_secret".to_string();
        config.clients = vec![Client {
            address: "192.168.1.0/24".to_string(),
            secret: "client_secret".to_string(),
            name: Some("Network 1".to_string()),
            enabled: true,
        }];

        // Should return client-specific secret
        let secret = config.get_secret_for_client("192.168.1.50".parse().unwrap());
        assert_eq!(secret, b"client_secret");

        // Should return default secret for non-matching IP
        let secret = config.get_secret_for_client("10.0.0.1".parse().unwrap());
        assert_eq!(secret, b"default_secret");
    }

    #[test]
    fn test_config_validation_with_invalid_client_address() {
        let mut config = Config::default();
        config.clients = vec![Client {
            address: "invalid_ip".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
        }];

        // Should fail validation due to invalid address
        assert!(config.validate().is_err());
    }
}
