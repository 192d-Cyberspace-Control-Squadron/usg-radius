//! Realm matching and routing
//!
//! This module implements realm-based routing for RADIUS proxy.
//! Realms are extracted from usernames and matched against configured patterns.

use crate::proxy::error::{ProxyError, ProxyResult};
use crate::proxy::pool::HomeServerPool;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Realm match configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmMatchConfig {
    /// Match type: "exact", "suffix", "regex"
    #[serde(rename = "type")]
    pub match_type: String,
    /// Pattern to match
    pub pattern: String,
}

/// Realm matcher
#[derive(Debug, Clone)]
pub enum RealmMatcher {
    /// Exact match - matches the exact realm string
    /// Example: "CORPORATE" matches "CORPORATE\user"
    Exact(String),

    /// Suffix match - matches username@realm pattern
    /// Example: "@example.com" matches "user@example.com"
    Suffix(String),

    /// Regex match - matches using regular expression
    /// Example: "^.*@.*\.example\.com$" matches any subdomain
    Regex(Regex),
}

impl RealmMatcher {
    /// Create a matcher from configuration
    pub fn from_config(config: &RealmMatchConfig) -> ProxyResult<Self> {
        match config.match_type.as_str() {
            "exact" => Ok(RealmMatcher::Exact(config.pattern.clone())),
            "suffix" => Ok(RealmMatcher::Suffix(config.pattern.clone())),
            "regex" => {
                let regex = Regex::new(&config.pattern).map_err(|e| {
                    ProxyError::InvalidRealmPattern(format!("Invalid regex pattern '{}': {}", config.pattern, e))
                })?;
                Ok(RealmMatcher::Regex(regex))
            }
            other => Err(ProxyError::Configuration(format!(
                "Invalid realm match type: '{}' (must be 'exact', 'suffix', or 'regex')",
                other
            ))),
        }
    }

    /// Check if a realm matches this matcher
    pub fn matches(&self, realm: &str) -> bool {
        match self {
            RealmMatcher::Exact(pattern) => realm == pattern,
            RealmMatcher::Suffix(pattern) => realm.ends_with(pattern),
            RealmMatcher::Regex(regex) => regex.is_match(realm),
        }
    }
}

/// Realm configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmConfig {
    /// Realm name (for logging/display)
    pub name: String,

    /// Match configuration
    #[serde(rename = "match")]
    pub match_config: RealmMatchConfig,

    /// Target pool name
    pub pool: String,

    /// Strip realm from username before forwarding
    #[serde(default)]
    pub strip_realm: bool,
}

impl RealmConfig {
    /// Validate configuration
    pub fn validate(&self) -> ProxyResult<()> {
        if self.name.is_empty() {
            return Err(ProxyError::Configuration("Realm name cannot be empty".to_string()));
        }

        if self.pool.is_empty() {
            return Err(ProxyError::Configuration(format!(
                "Realm '{}' has no pool configured",
                self.name
            )));
        }

        // Validate matcher can be created
        RealmMatcher::from_config(&self.match_config)?;

        Ok(())
    }
}

/// Realm
pub struct Realm {
    /// Realm name
    pub name: String,
    /// Realm matcher
    pub matcher: RealmMatcher,
    /// Target home server pool
    pub pool: Arc<HomeServerPool>,
    /// Strip realm from username before forwarding
    pub strip_realm: bool,
}

impl Realm {
    /// Create a new realm
    pub fn new(config: RealmConfig, pool: Arc<HomeServerPool>) -> ProxyResult<Self> {
        config.validate()?;

        let matcher = RealmMatcher::from_config(&config.match_config)?;

        Ok(Realm {
            name: config.name,
            matcher,
            pool,
            strip_realm: config.strip_realm,
        })
    }

    /// Check if a realm matches this realm configuration
    pub fn matches(&self, realm: &str) -> bool {
        self.matcher.matches(realm)
    }
}

/// Extract realm from username
///
/// Supports two common realm formats:
/// 1. Suffix format: "user@example.com" → "example.com"
/// 2. Prefix format: "DOMAIN\user" → "DOMAIN"
///
/// # Examples
///
/// ```
/// # use radius_server::proxy::realm::extract_realm;
/// assert_eq!(extract_realm("user@example.com"), Some("example.com".to_string()));
/// assert_eq!(extract_realm("CORPORATE\\john"), Some("CORPORATE".to_string()));
/// assert_eq!(extract_realm("plainuser"), None);
/// ```
pub fn extract_realm(username: &str) -> Option<String> {
    // Check for suffix format (user@realm)
    if let Some(at_pos) = username.rfind('@') {
        // Found @ symbol, extract realm after it
        let realm = &username[at_pos + 1..];
        if !realm.is_empty() {
            return Some(realm.to_string());
        }
    }

    // Check for prefix format (REALM\user)
    if let Some(backslash_pos) = username.find('\\') {
        // Found \ symbol, extract realm before it
        let realm = &username[..backslash_pos];
        if !realm.is_empty() {
            return Some(realm.to_string());
        }
    }

    // No realm found
    None
}

/// Strip realm from username
///
/// Removes the realm portion from username, leaving just the user part.
///
/// # Examples
///
/// ```
/// # use radius_server::proxy::realm::strip_realm;
/// assert_eq!(strip_realm("user@example.com"), "user");
/// assert_eq!(strip_realm("CORPORATE\\john"), "john");
/// assert_eq!(strip_realm("plainuser"), "plainuser");
/// ```
pub fn strip_realm(username: &str) -> String {
    // Remove suffix format (@realm)
    if let Some(at_pos) = username.rfind('@') {
        return username[..at_pos].to_string();
    }

    // Remove prefix format (REALM\)
    if let Some(backslash_pos) = username.find('\\') {
        return username[backslash_pos + 1..].to_string();
    }

    // No realm, return as-is
    username.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_realm_suffix() {
        assert_eq!(extract_realm("user@example.com"), Some("example.com".to_string()));
        assert_eq!(extract_realm("john.doe@corporate.local"), Some("corporate.local".to_string()));
        assert_eq!(extract_realm("admin@"), None); // Empty realm
    }

    #[test]
    fn test_extract_realm_prefix() {
        assert_eq!(extract_realm("CORPORATE\\john"), Some("CORPORATE".to_string()));
        assert_eq!(extract_realm("DOMAIN\\admin"), Some("DOMAIN".to_string()));
        assert_eq!(extract_realm("\\user"), None); // Empty realm
    }

    #[test]
    fn test_extract_realm_none() {
        assert_eq!(extract_realm("plainuser"), None);
        assert_eq!(extract_realm("user.name"), None);
        assert_eq!(extract_realm("123456"), None);
    }

    #[test]
    fn test_strip_realm_suffix() {
        assert_eq!(strip_realm("user@example.com"), "user");
        assert_eq!(strip_realm("john.doe@corporate.local"), "john.doe");
    }

    #[test]
    fn test_strip_realm_prefix() {
        assert_eq!(strip_realm("CORPORATE\\john"), "john");
        assert_eq!(strip_realm("DOMAIN\\admin"), "admin");
    }

    #[test]
    fn test_strip_realm_none() {
        assert_eq!(strip_realm("plainuser"), "plainuser");
        assert_eq!(strip_realm("user.name"), "user.name");
    }

    #[test]
    fn test_realm_matcher_exact() {
        let config = RealmMatchConfig {
            match_type: "exact".to_string(),
            pattern: "CORPORATE".to_string(),
        };
        let matcher = RealmMatcher::from_config(&config).unwrap();

        assert!(matcher.matches("CORPORATE"));
        assert!(!matcher.matches("corporate")); // Case sensitive
        assert!(!matcher.matches("CORPORATE_LOCAL"));
    }

    #[test]
    fn test_realm_matcher_suffix() {
        let config = RealmMatchConfig {
            match_type: "suffix".to_string(),
            pattern: "example.com".to_string(),
        };
        let matcher = RealmMatcher::from_config(&config).unwrap();

        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("test.example.com"));
        assert!(!matcher.matches("example.org"));
    }

    #[test]
    fn test_realm_matcher_regex() {
        let config = RealmMatchConfig {
            match_type: "regex".to_string(),
            pattern: r"^.*\.example\.com$".to_string(),
        };
        let matcher = RealmMatcher::from_config(&config).unwrap();

        assert!(matcher.matches("sub.example.com"));
        assert!(matcher.matches("test.example.com"));
        assert!(!matcher.matches("example.com")); // No subdomain
        assert!(!matcher.matches("example.org"));
    }

    #[test]
    fn test_realm_matcher_invalid_type() {
        let config = RealmMatchConfig {
            match_type: "invalid".to_string(),
            pattern: "test".to_string(),
        };
        assert!(RealmMatcher::from_config(&config).is_err());
    }

    #[test]
    fn test_realm_matcher_invalid_regex() {
        let config = RealmMatchConfig {
            match_type: "regex".to_string(),
            pattern: "[invalid".to_string(), // Unclosed bracket
        };
        assert!(RealmMatcher::from_config(&config).is_err());
    }

    #[test]
    fn test_realm_config_validation() {
        let valid_config = RealmConfig {
            name: "test_realm".to_string(),
            match_config: RealmMatchConfig {
                match_type: "exact".to_string(),
                pattern: "TEST".to_string(),
            },
            pool: "test_pool".to_string(),
            strip_realm: true,
        };
        assert!(valid_config.validate().is_ok());
    }

    #[test]
    fn test_realm_config_empty_name() {
        let config = RealmConfig {
            name: "".to_string(),
            match_config: RealmMatchConfig {
                match_type: "exact".to_string(),
                pattern: "TEST".to_string(),
            },
            pool: "test_pool".to_string(),
            strip_realm: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_realm_config_empty_pool() {
        let config = RealmConfig {
            name: "test".to_string(),
            match_config: RealmMatchConfig {
                match_type: "exact".to_string(),
                pattern: "TEST".to_string(),
            },
            pool: "".to_string(),
            strip_realm: false,
        };
        assert!(config.validate().is_err());
    }
}
