//! Telemetry module for PyBun.
//!
//! This module provides opt-in telemetry management with privacy controls.
//! By default, telemetry is **disabled** (opt-in model).
//!
//! ## Configuration Priority
//! 1. Environment variable: `PYBUN_TELEMETRY=1|0`
//! 2. Config file: `~/.pybun/telemetry.json`
//! 3. Default: disabled
//!
//! ## Redaction
//! Sensitive data is automatically redacted from telemetry data using
//! predefined patterns for tokens, keys, passwords, etc.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default redaction patterns for sensitive data.
pub const DEFAULT_REDACTION_PATTERNS: &[&str] = &[
    "*_KEY",
    "*_TOKEN",
    "*_SECRET",
    "*_PASSWORD",
    "*_CREDENTIAL*",
    "AWS_*",
    "GITHUB_*",
    "AZURE_*",
    "GCP_*",
    "PYBUN_*_TOKEN",
];

/// Source of the telemetry configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TelemetrySource {
    /// Default value (not explicitly configured)
    Default,
    /// Set via config file
    Config,
    /// Set via environment variable
    Environment,
}

impl std::fmt::Display for TelemetrySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TelemetrySource::Default => write!(f, "default"),
            TelemetrySource::Config => write!(f, "config"),
            TelemetrySource::Environment => write!(f, "environment"),
        }
    }
}

/// Telemetry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Whether telemetry is enabled.
    pub enabled: bool,
    /// Patterns for redacting sensitive data.
    #[serde(default = "default_redaction_patterns")]
    pub redaction_patterns: Vec<String>,
}

fn default_redaction_patterns() -> Vec<String> {
    DEFAULT_REDACTION_PATTERNS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            redaction_patterns: default_redaction_patterns(),
        }
    }
}

impl TelemetryConfig {
    /// Create a new config with telemetry enabled.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }

    /// Create a new config with telemetry disabled.
    pub fn disabled() -> Self {
        Self::default()
    }
}

/// Telemetry status with source information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryStatus {
    /// Whether telemetry is enabled.
    pub enabled: bool,
    /// Source of the configuration.
    pub source: TelemetrySource,
    /// Redaction patterns in use.
    pub redaction_patterns: Vec<String>,
}

/// Telemetry manager for loading and saving configuration.
#[derive(Debug, Clone)]
pub struct TelemetryManager {
    /// Path to the config file.
    config_path: PathBuf,
}

impl TelemetryManager {
    /// Create a new telemetry manager with the given config directory.
    pub fn new(config_dir: &Path) -> Self {
        Self {
            config_path: config_dir.join("telemetry.json"),
        }
    }

    /// Get the path to the config file.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Load the telemetry configuration.
    /// Returns the config and its source.
    fn load_config(&self) -> (TelemetryConfig, TelemetrySource) {
        if self.config_path.exists()
            && let Ok(content) = std::fs::read_to_string(&self.config_path)
            && let Ok(config) = serde_json::from_str::<TelemetryConfig>(&content)
        {
            return (config, TelemetrySource::Config);
        }
        (TelemetryConfig::default(), TelemetrySource::Default)
    }

    /// Get the current telemetry status, considering env overrides.
    pub fn status(&self) -> TelemetryStatus {
        // Check environment variable first
        if let Ok(env_value) = std::env::var("PYBUN_TELEMETRY") {
            let enabled = matches!(env_value.as_str(), "1" | "true" | "yes" | "on");
            return TelemetryStatus {
                enabled,
                source: TelemetrySource::Environment,
                redaction_patterns: default_redaction_patterns(),
            };
        }

        // Load from config file or use default
        let (config, source) = self.load_config();
        TelemetryStatus {
            enabled: config.enabled,
            source,
            redaction_patterns: config.redaction_patterns,
        }
    }

    /// Check if telemetry is enabled (considering env overrides).
    pub fn is_enabled(&self) -> bool {
        self.status().enabled
    }

    /// Enable telemetry and save to config.
    pub fn enable(&self) -> Result<TelemetryStatus, String> {
        let config = TelemetryConfig::enabled();
        self.save_config(&config)?;
        Ok(TelemetryStatus {
            enabled: true,
            source: TelemetrySource::Config,
            redaction_patterns: config.redaction_patterns,
        })
    }

    /// Disable telemetry and save to config.
    pub fn disable(&self) -> Result<TelemetryStatus, String> {
        let config = TelemetryConfig::disabled();
        self.save_config(&config)?;
        Ok(TelemetryStatus {
            enabled: false,
            source: TelemetrySource::Config,
            redaction_patterns: config.redaction_patterns,
        })
    }

    /// Save the config to disk.
    fn save_config(&self, config: &TelemetryConfig) -> Result<(), String> {
        // Ensure parent directory exists
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create config directory: {}", e))?;
        }

        let content = serde_json::to_string_pretty(config)
            .map_err(|e| format!("failed to serialize config: {}", e))?;

        std::fs::write(&self.config_path, content)
            .map_err(|e| format!("failed to write config: {}", e))
    }

    /// Check if a value matches any redaction pattern.
    pub fn should_redact(&self, key: &str) -> bool {
        let status = self.status();
        for pattern in &status.redaction_patterns {
            if matches_glob_pattern(pattern, key) {
                return true;
            }
        }
        false
    }
}

/// Simple glob pattern matching (supports * as wildcard).
fn matches_glob_pattern(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_uppercase();
    let text = text.to_uppercase();

    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') {
        return pattern == text;
    }

    // Handle patterns like "*_KEY", "AWS_*", "*_TOKEN*"
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 2 {
        // Single wildcard
        let (prefix, suffix) = (parts[0], parts[1]);
        if prefix.is_empty() {
            return text.ends_with(suffix);
        }
        if suffix.is_empty() {
            return text.starts_with(prefix);
        }
        return text.starts_with(prefix) && text.ends_with(suffix);
    }

    // Multiple wildcards: check prefix, suffix, and all middle parts
    // For pattern "A*B*C", parts = ["A", "B", "C"]
    // Text must start with A, end with C, and contain B in between
    if !parts[0].is_empty() && !text.starts_with(parts[0]) {
        return false;
    }
    if !parts[parts.len() - 1].is_empty() && !text.ends_with(parts[parts.len() - 1]) {
        return false;
    }

    // Check middle parts exist in text
    let mut search_start = parts[0].len();
    let search_end = text.len().saturating_sub(parts[parts.len() - 1].len());
    
    for part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = text[search_start..search_end].find(part) {
            search_start = search_start + pos + part.len();
        } else {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = TelemetryConfig::default();
        assert!(!config.enabled);
        assert!(!config.redaction_patterns.is_empty());
    }

    #[test]
    fn test_enabled_config() {
        let config = TelemetryConfig::enabled();
        assert!(config.enabled);
    }

    #[test]
    fn test_manager_default_status() {
        let temp = tempdir().unwrap();
        let manager = TelemetryManager::new(temp.path());
        let status = manager.status();

        assert!(!status.enabled);
        assert_eq!(status.source, TelemetrySource::Default);
    }

    #[test]
    fn test_manager_enable() {
        let temp = tempdir().unwrap();
        let manager = TelemetryManager::new(temp.path());

        let status = manager.enable().unwrap();
        assert!(status.enabled);
        assert_eq!(status.source, TelemetrySource::Config);

        // Verify persistence
        let status2 = manager.status();
        assert!(status2.enabled);
        assert_eq!(status2.source, TelemetrySource::Config);
    }

    #[test]
    fn test_manager_disable() {
        let temp = tempdir().unwrap();
        let manager = TelemetryManager::new(temp.path());

        manager.enable().unwrap();
        let status = manager.disable().unwrap();

        assert!(!status.enabled);
        assert_eq!(status.source, TelemetrySource::Config);
    }

    #[test]
    fn test_glob_pattern_suffix() {
        assert!(matches_glob_pattern("*_KEY", "AWS_SECRET_KEY"));
        assert!(matches_glob_pattern("*_KEY", "GITHUB_KEY"));
        assert!(!matches_glob_pattern("*_KEY", "KEY_VALUE"));
    }

    #[test]
    fn test_glob_pattern_prefix() {
        assert!(matches_glob_pattern("AWS_*", "AWS_SECRET_KEY"));
        assert!(matches_glob_pattern("AWS_*", "AWS_ACCESS_KEY_ID"));
        assert!(!matches_glob_pattern("AWS_*", "SOME_AWS_KEY"));
    }

    #[test]
    fn test_glob_pattern_contains() {
        assert!(matches_glob_pattern("*_TOKEN*", "GITHUB_TOKEN"));
        assert!(matches_glob_pattern("*_TOKEN*", "MY_TOKEN_VALUE"));
        assert!(matches_glob_pattern("*_CREDENTIAL*", "AWS_CREDENTIAL_ID"));
    }

    #[test]
    fn test_should_redact() {
        let temp = tempdir().unwrap();
        let manager = TelemetryManager::new(temp.path());

        assert!(manager.should_redact("AWS_SECRET_KEY"));
        assert!(manager.should_redact("GITHUB_TOKEN"));
        assert!(manager.should_redact("MY_PASSWORD"));
        assert!(!manager.should_redact("PYBUN_HOME"));
        assert!(!manager.should_redact("PATH"));
    }

    #[test]
    fn test_serialization() {
        let config = TelemetryConfig::enabled();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TelemetryConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.enabled, deserialized.enabled);
    }

    #[test]
    fn test_source_display() {
        assert_eq!(TelemetrySource::Default.to_string(), "default");
        assert_eq!(TelemetrySource::Config.to_string(), "config");
        assert_eq!(TelemetrySource::Environment.to_string(), "environment");
    }
}
