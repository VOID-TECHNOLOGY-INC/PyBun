//! Launch profiles module.
//!
//! This module provides profile-based configuration for different runtime
//! environments: dev, prod, and benchmark.
//!
//! ## Profiles
//! - **dev**: Development mode with hot reload, lazy imports disabled, verbose logging
//! - **prod**: Production mode with optimizations enabled, minimal logging
//! - **benchmark**: Benchmarking mode with tracing enabled, timing output

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Available launch profiles.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Development profile - verbose, hot reload enabled.
    #[default]
    Dev,
    /// Production profile - optimized, minimal logging.
    Prod,
    /// Benchmark profile - timing and tracing enabled.
    Benchmark,
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Profile::Dev => write!(f, "dev"),
            Profile::Prod => write!(f, "prod"),
            Profile::Benchmark => write!(f, "benchmark"),
        }
    }
}

impl std::str::FromStr for Profile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dev" | "development" => Ok(Profile::Dev),
            "prod" | "production" => Ok(Profile::Prod),
            "bench" | "benchmark" => Ok(Profile::Benchmark),
            _ => Err(format!(
                "Invalid profile '{}'. Valid options: dev, prod, benchmark",
                s
            )),
        }
    }
}

/// Configuration settings for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// Profile name.
    pub profile: Profile,
    /// Enable hot reload (dev only).
    pub hot_reload: bool,
    /// Enable lazy imports.
    pub lazy_imports: bool,
    /// Enable module finder cache.
    pub module_cache: bool,
    /// Logging verbosity: 0 = quiet, 1 = normal, 2 = verbose, 3 = debug.
    pub log_level: u8,
    /// Enable performance tracing.
    pub tracing: bool,
    /// Enable timing output for benchmarks.
    pub timing: bool,
    /// Enable assertions and debug checks.
    pub debug_checks: bool,
    /// Python optimization level (-O, -OO flags).
    pub optimization_level: u8,
    /// Custom environment variables to set.
    pub env_vars: HashMap<String, String>,
}

impl ProfileConfig {
    /// Create a dev profile configuration.
    pub fn dev() -> Self {
        Self {
            profile: Profile::Dev,
            hot_reload: true,
            lazy_imports: false,
            module_cache: true,
            log_level: 2,
            tracing: false,
            timing: false,
            debug_checks: true,
            optimization_level: 0,
            env_vars: HashMap::new(),
        }
    }

    /// Create a prod profile configuration.
    pub fn prod() -> Self {
        Self {
            profile: Profile::Prod,
            hot_reload: false,
            lazy_imports: true,
            module_cache: true,
            log_level: 1,
            tracing: false,
            timing: false,
            debug_checks: false,
            optimization_level: 2,
            env_vars: HashMap::new(),
        }
    }

    /// Create a benchmark profile configuration.
    pub fn benchmark() -> Self {
        Self {
            profile: Profile::Benchmark,
            hot_reload: false,
            lazy_imports: false,
            module_cache: false, // Disable cache for accurate benchmarking
            log_level: 1,
            tracing: true,
            timing: true,
            debug_checks: false,
            optimization_level: 2,
            env_vars: HashMap::new(),
        }
    }

    /// Create a configuration for a given profile.
    pub fn for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Dev => Self::dev(),
            Profile::Prod => Self::prod(),
            Profile::Benchmark => Self::benchmark(),
        }
    }

    /// Get Python optimization flags based on optimization level.
    pub fn python_opt_flags(&self) -> Vec<&str> {
        match self.optimization_level {
            0 => vec![],
            1 => vec!["-O"],
            _ => vec!["-OO"],
        }
    }

    /// Get log level as a string for PYBUN_LOG environment variable.
    pub fn log_level_str(&self) -> &str {
        match self.log_level {
            0 => "error",
            1 => "warn",
            2 => "info",
            3 => "debug",
            _ => "trace",
        }
    }

    /// Check if this is a development profile.
    pub fn is_dev(&self) -> bool {
        self.profile == Profile::Dev
    }

    /// Check if this is a production profile.
    pub fn is_prod(&self) -> bool {
        self.profile == Profile::Prod
    }

    /// Check if this is a benchmark profile.
    pub fn is_benchmark(&self) -> bool {
        self.profile == Profile::Benchmark
    }

    /// Apply profile settings to the environment.
    pub fn apply_to_env(&self) {
        // Set PYBUN-specific environment variables
        // SAFETY: Single-threaded CLI context
        unsafe {
            std::env::set_var("PYBUN_PROFILE", self.profile.to_string());
            std::env::set_var("PYBUN_LOG", self.log_level_str());

            if self.tracing {
                std::env::set_var("PYBUN_TRACE", "1");
            }

            // Apply custom env vars
            for (key, value) in &self.env_vars {
                std::env::set_var(key, value);
            }
        }
    }

    /// Generate a summary of the profile settings.
    pub fn summary(&self) -> String {
        format!(
            "Profile: {}\n  Hot reload: {}\n  Lazy imports: {}\n  Module cache: {}\n  Log level: {} ({})\n  Tracing: {}\n  Timing: {}\n  Debug checks: {}\n  Python optimization: -O{}",
            self.profile,
            if self.hot_reload {
                "enabled"
            } else {
                "disabled"
            },
            if self.lazy_imports {
                "enabled"
            } else {
                "disabled"
            },
            if self.module_cache {
                "enabled"
            } else {
                "disabled"
            },
            self.log_level,
            self.log_level_str(),
            if self.tracing { "enabled" } else { "disabled" },
            if self.timing { "enabled" } else { "disabled" },
            if self.debug_checks {
                "enabled"
            } else {
                "disabled"
            },
            self.optimization_level,
        )
    }

    /// Load profile overrides from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read profile: {}", e))?;
        toml::from_str(&content).map_err(|e| format!("failed to parse profile: {}", e))
    }

    /// Save profile to a TOML file.
    pub fn to_file(&self, path: &Path) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize profile: {}", e))?;
        std::fs::write(path, content).map_err(|e| format!("failed to write profile: {}", e))
    }

    /// Merge with another profile config (other takes precedence).
    pub fn merge(&mut self, other: &ProfileConfig) {
        self.hot_reload = other.hot_reload;
        self.lazy_imports = other.lazy_imports;
        self.module_cache = other.module_cache;
        self.log_level = other.log_level;
        self.tracing = other.tracing;
        self.timing = other.timing;
        self.debug_checks = other.debug_checks;
        self.optimization_level = other.optimization_level;
        for (key, value) in &other.env_vars {
            self.env_vars.insert(key.clone(), value.clone());
        }
    }
}

/// Profile manager for loading and selecting profiles.
#[derive(Debug, Clone)]
pub struct ProfileManager {
    /// Current active profile.
    current: ProfileConfig,
    /// Available profiles.
    profiles: HashMap<Profile, ProfileConfig>,
}

impl ProfileManager {
    /// Create a new profile manager with default profiles.
    pub fn new() -> Self {
        let mut profiles = HashMap::new();
        profiles.insert(Profile::Dev, ProfileConfig::dev());
        profiles.insert(Profile::Prod, ProfileConfig::prod());
        profiles.insert(Profile::Benchmark, ProfileConfig::benchmark());

        Self {
            current: ProfileConfig::dev(),
            profiles,
        }
    }

    /// Get the current profile configuration.
    pub fn current(&self) -> &ProfileConfig {
        &self.current
    }

    /// Set the active profile by name.
    pub fn set_profile(&mut self, profile: Profile) {
        if let Some(config) = self.profiles.get(&profile) {
            self.current = config.clone();
        }
    }

    /// Get all available profile names.
    pub fn available_profiles(&self) -> Vec<Profile> {
        vec![Profile::Dev, Profile::Prod, Profile::Benchmark]
    }

    /// Register a custom profile.
    pub fn register_profile(&mut self, profile: Profile, config: ProfileConfig) {
        self.profiles.insert(profile, config);
    }

    /// Detect profile from environment or project configuration.
    pub fn detect_profile() -> Profile {
        // Check PYBUN_PROFILE environment variable
        if let Ok(profile_str) = std::env::var("PYBUN_PROFILE")
            && let Ok(profile) = profile_str.parse()
        {
            return profile;
        }

        // Default to dev
        Profile::Dev
    }
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_from_str() {
        assert_eq!("dev".parse::<Profile>().unwrap(), Profile::Dev);
        assert_eq!("prod".parse::<Profile>().unwrap(), Profile::Prod);
        assert_eq!("benchmark".parse::<Profile>().unwrap(), Profile::Benchmark);
        assert_eq!("development".parse::<Profile>().unwrap(), Profile::Dev);
        assert_eq!("production".parse::<Profile>().unwrap(), Profile::Prod);
        assert_eq!("bench".parse::<Profile>().unwrap(), Profile::Benchmark);
    }

    #[test]
    fn test_profile_display() {
        assert_eq!(Profile::Dev.to_string(), "dev");
        assert_eq!(Profile::Prod.to_string(), "prod");
        assert_eq!(Profile::Benchmark.to_string(), "benchmark");
    }

    #[test]
    fn test_invalid_profile() {
        let result = "invalid".parse::<Profile>();
        assert!(result.is_err());
    }

    #[test]
    fn test_dev_profile_config() {
        let config = ProfileConfig::dev();
        assert!(config.is_dev());
        assert!(config.hot_reload);
        assert!(!config.lazy_imports);
        assert!(config.debug_checks);
        assert_eq!(config.optimization_level, 0);
    }

    #[test]
    fn test_prod_profile_config() {
        let config = ProfileConfig::prod();
        assert!(config.is_prod());
        assert!(!config.hot_reload);
        assert!(config.lazy_imports);
        assert!(!config.debug_checks);
        assert_eq!(config.optimization_level, 2);
    }

    #[test]
    fn test_benchmark_profile_config() {
        let config = ProfileConfig::benchmark();
        assert!(config.is_benchmark());
        assert!(config.tracing);
        assert!(config.timing);
        assert!(!config.module_cache);
    }

    #[test]
    fn test_python_opt_flags() {
        let dev = ProfileConfig::dev();
        assert!(dev.python_opt_flags().is_empty());

        let mut prod = ProfileConfig::prod();
        prod.optimization_level = 1;
        assert_eq!(prod.python_opt_flags(), vec!["-O"]);

        prod.optimization_level = 2;
        assert_eq!(prod.python_opt_flags(), vec!["-OO"]);
    }

    #[test]
    fn test_log_level_str() {
        let mut config = ProfileConfig::dev();
        config.log_level = 0;
        assert_eq!(config.log_level_str(), "error");
        config.log_level = 1;
        assert_eq!(config.log_level_str(), "warn");
        config.log_level = 2;
        assert_eq!(config.log_level_str(), "info");
        config.log_level = 3;
        assert_eq!(config.log_level_str(), "debug");
    }

    #[test]
    fn test_profile_summary() {
        let config = ProfileConfig::dev();
        let summary = config.summary();
        assert!(summary.contains("dev"));
        assert!(summary.contains("Hot reload: enabled"));
    }

    #[test]
    fn test_profile_manager() {
        let mut manager = ProfileManager::new();
        assert!(manager.current().is_dev());

        manager.set_profile(Profile::Prod);
        assert!(manager.current().is_prod());

        manager.set_profile(Profile::Benchmark);
        assert!(manager.current().is_benchmark());
    }

    #[test]
    fn test_available_profiles() {
        let manager = ProfileManager::new();
        let profiles = manager.available_profiles();
        assert_eq!(profiles.len(), 3);
        assert!(profiles.contains(&Profile::Dev));
        assert!(profiles.contains(&Profile::Prod));
        assert!(profiles.contains(&Profile::Benchmark));
    }

    #[test]
    fn test_for_profile() {
        let dev = ProfileConfig::for_profile(Profile::Dev);
        assert!(dev.is_dev());

        let prod = ProfileConfig::for_profile(Profile::Prod);
        assert!(prod.is_prod());

        let bench = ProfileConfig::for_profile(Profile::Benchmark);
        assert!(bench.is_benchmark());
    }

    #[test]
    fn test_profile_serialization() {
        let config = ProfileConfig::dev();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ProfileConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.profile, deserialized.profile);
        assert_eq!(config.hot_reload, deserialized.hot_reload);
        assert_eq!(config.lazy_imports, deserialized.lazy_imports);
    }

    #[test]
    fn test_merge_profiles() {
        let mut base = ProfileConfig::dev();
        let other = ProfileConfig::prod();

        base.merge(&other);

        // Values should be from 'other'
        assert!(!base.hot_reload);
        assert!(base.lazy_imports);
        assert_eq!(base.optimization_level, 2);
    }

    #[test]
    fn test_custom_env_vars() {
        let mut config = ProfileConfig::dev();
        config
            .env_vars
            .insert("MY_VAR".to_string(), "my_value".to_string());

        assert_eq!(config.env_vars.get("MY_VAR"), Some(&"my_value".to_string()));
    }
}
