//! Hot reload watcher module.
//!
//! This module provides filesystem watching and hot reload functionality
//! for Python scripts and modules during development.
//!
//! ## Features
//! - Filesystem change detection (create, modify, delete)
//! - Configurable watch patterns (include/exclude)
//! - Debouncing to prevent rapid successive reloads
//! - Dev profile toggle to enable/disable in production

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Configuration for the hot reload watcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotReloadConfig {
    /// Whether hot reload is enabled.
    pub enabled: bool,
    /// Directories to watch.
    pub watch_paths: Vec<PathBuf>,
    /// File patterns to include (glob-style, e.g., "*.py").
    pub include_patterns: Vec<String>,
    /// File patterns to exclude (e.g., "__pycache__", ".git").
    pub exclude_patterns: Vec<String>,
    /// Debounce delay in milliseconds.
    pub debounce_ms: u64,
    /// Whether to clear terminal on reload.
    pub clear_on_reload: bool,
    /// Callback command to run on change (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_change_command: Option<String>,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_paths: vec![],
            include_patterns: vec!["*.py".to_string()],
            exclude_patterns: default_exclude_patterns(),
            debounce_ms: 300,
            clear_on_reload: false,
            on_change_command: None,
        }
    }
}

/// Default patterns to exclude from watching.
fn default_exclude_patterns() -> Vec<String> {
    vec![
        "__pycache__".to_string(),
        ".git".to_string(),
        ".svn".to_string(),
        ".hg".to_string(),
        "*.pyc".to_string(),
        "*.pyo".to_string(),
        ".pybun".to_string(),
        "node_modules".to_string(),
        ".venv".to_string(),
        "venv".to_string(),
        ".tox".to_string(),
        ".mypy_cache".to_string(),
        ".pytest_cache".to_string(),
        "dist".to_string(),
        "build".to_string(),
        "*.egg-info".to_string(),
    ]
}

/// Type of file system change event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
    Renamed,
}

/// A file change event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChangeEvent {
    /// Path to the changed file.
    pub path: PathBuf,
    /// Type of change.
    pub change_type: ChangeType,
    /// Timestamp of the event.
    pub timestamp_ms: u64,
}

impl FileChangeEvent {
    pub fn new(path: PathBuf, change_type: ChangeType, timestamp_ms: u64) -> Self {
        Self {
            path,
            change_type,
            timestamp_ms,
        }
    }
}

/// Status of the watcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatcherStatus {
    /// Watcher is not running.
    Stopped,
    /// Watcher is running and monitoring files.
    Running,
    /// Watcher encountered an error.
    Error(String),
}

/// Result of starting the watcher.
#[derive(Debug)]
pub struct WatcherHandle {
    /// Status of the watcher.
    pub status: WatcherStatus,
    /// Number of paths being watched.
    pub watched_paths: usize,
    /// Receiver for change events.
    pub event_receiver: Option<mpsc::Receiver<FileChangeEvent>>,
}

/// The hot reload watcher.
#[derive(Debug)]
pub struct HotReloadWatcher {
    config: HotReloadConfig,
    status: WatcherStatus,
    last_event_time: Option<Instant>,
    pending_events: Vec<FileChangeEvent>,
}

impl HotReloadWatcher {
    /// Create a new watcher with the given configuration.
    pub fn new(config: HotReloadConfig) -> Self {
        Self {
            config,
            status: WatcherStatus::Stopped,
            last_event_time: None,
            pending_events: Vec::new(),
        }
    }

    /// Create a watcher with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(HotReloadConfig::default())
    }

    /// Check if the watcher is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the current status.
    pub fn status(&self) -> &WatcherStatus {
        &self.status
    }

    /// Get the configuration.
    pub fn config(&self) -> &HotReloadConfig {
        &self.config
    }

    /// Add a path to watch.
    pub fn add_watch_path(&mut self, path: PathBuf) {
        if !self.config.watch_paths.contains(&path) {
            self.config.watch_paths.push(path);
        }
    }

    /// Check if a path should be watched based on include/exclude patterns.
    pub fn should_watch(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check exclude patterns first
        for pattern in &self.config.exclude_patterns {
            if matches_pattern(&path_str, pattern) {
                return false;
            }
        }

        // Check include patterns
        if self.config.include_patterns.is_empty() {
            return true;
        }

        for pattern in &self.config.include_patterns {
            if matches_pattern(&path_str, pattern) {
                return true;
            }
        }

        false
    }

    /// Start watching (stub implementation - actual fs watching would use notify crate).
    ///
    /// Returns a handle with a channel to receive events.
    pub fn start(&mut self) -> WatcherHandle {
        if !self.config.enabled {
            return WatcherHandle {
                status: WatcherStatus::Stopped,
                watched_paths: 0,
                event_receiver: None,
            };
        }

        if self.config.watch_paths.is_empty() {
            return WatcherHandle {
                status: WatcherStatus::Error("No paths to watch".to_string()),
                watched_paths: 0,
                event_receiver: None,
            };
        }

        // Verify paths exist
        let valid_paths = self
            .config
            .watch_paths
            .iter()
            .filter(|p| p.exists())
            .count();

        if valid_paths == 0 {
            return WatcherHandle {
                status: WatcherStatus::Error("No valid paths to watch".to_string()),
                watched_paths: 0,
                event_receiver: None,
            };
        }

        // Create channel for events
        let (tx, rx) = mpsc::channel();

        // In a real implementation, we would:
        // 1. Use the `notify` crate to set up file system watchers
        // 2. Spawn a thread to handle events
        // 3. Filter events based on include/exclude patterns
        // 4. Apply debouncing
        // 5. Send filtered events through the channel

        self.status = WatcherStatus::Running;

        // Store sender for later use (would be used in actual implementation)
        let _ = tx; // Suppress unused warning

        WatcherHandle {
            status: WatcherStatus::Running,
            watched_paths: valid_paths,
            event_receiver: Some(rx),
        }
    }

    /// Stop watching.
    pub fn stop(&mut self) {
        self.status = WatcherStatus::Stopped;
        self.pending_events.clear();
    }

    /// Process an event (with debouncing).
    pub fn process_event(&mut self, event: FileChangeEvent) -> Option<FileChangeEvent> {
        let now = Instant::now();

        // Check if we should debounce
        if let Some(last_time) = self.last_event_time {
            let elapsed = now.duration_since(last_time);
            if elapsed < Duration::from_millis(self.config.debounce_ms) {
                // Store for later
                self.pending_events.push(event);
                return None;
            }
        }

        self.last_event_time = Some(now);

        // Return the event (it passed debounce check)
        Some(event)
    }

    /// Flush pending events after debounce period.
    pub fn flush_pending(&mut self) -> Vec<FileChangeEvent> {
        // Deduplicate events by path
        let mut seen: HashSet<PathBuf> = HashSet::new();
        let events: Vec<_> = self
            .pending_events
            .drain(..)
            .filter(|e| seen.insert(e.path.clone()))
            .collect();

        self.last_event_time = Some(Instant::now());
        events
    }

    /// Get reload statistics.
    pub fn stats(&self) -> WatcherStats {
        WatcherStats {
            is_running: matches!(self.status, WatcherStatus::Running),
            watched_paths: self.config.watch_paths.len(),
            include_patterns: self.config.include_patterns.len(),
            exclude_patterns: self.config.exclude_patterns.len(),
            debounce_ms: self.config.debounce_ms,
            pending_events: self.pending_events.len(),
        }
    }
}

/// Statistics about the watcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherStats {
    pub is_running: bool,
    pub watched_paths: usize,
    pub include_patterns: usize,
    pub exclude_patterns: usize,
    pub debounce_ms: u64,
    pub pending_events: usize,
}

/// Simple glob-style pattern matching.
fn matches_pattern(path: &str, pattern: &str) -> bool {
    if pattern.starts_with('*') && pattern.len() > 1 {
        // *.py style pattern
        let suffix = &pattern[1..];
        return path.ends_with(suffix);
    }

    if pattern.ends_with('*') && pattern.len() > 1 {
        // prefix* style pattern
        let prefix = &pattern[..pattern.len() - 1];
        return path.starts_with(prefix);
    }

    // Exact match or contains
    path.contains(pattern)
}

impl HotReloadConfig {
    /// Create a dev-friendly configuration with hot reload enabled.
    pub fn dev() -> Self {
        Self {
            enabled: true,
            watch_paths: vec![PathBuf::from(".")],
            ..Default::default()
        }
    }

    /// Check if this is a dev profile configuration.
    pub fn is_dev_profile(&self) -> bool {
        self.enabled
    }

    /// Load configuration from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read config: {}", e))?;
        toml::from_str(&content).map_err(|e| format!("failed to parse config: {}", e))
    }

    /// Save configuration to a TOML file.
    pub fn to_file(&self, path: &Path) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize config: {}", e))?;
        std::fs::write(path, content).map_err(|e| format!("failed to write config: {}", e))
    }
}

/// Generate a shell command for a basic file watcher.
///
/// This is useful when the native watcher isn't available.
pub fn generate_shell_watcher_command(config: &HotReloadConfig, run_command: &str) -> String {
    let paths = config
        .watch_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" ");

    // Generate a basic fswatch/inotifywait command
    if cfg!(target_os = "macos") {
        format!("fswatch -o {} | xargs -n1 -I{{}} {}", paths, run_command)
    } else if cfg!(target_os = "linux") {
        format!(
            "inotifywait -m -r -e modify,create,delete {} --format '%w%f' | while read file; do {}; done",
            paths, run_command
        )
    } else {
        format!(
            "# Windows: Use watchdog or similar\n# Command: {}",
            run_command
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HotReloadConfig::default();
        assert!(!config.enabled);
        assert!(config.watch_paths.is_empty());
        assert!(config.include_patterns.contains(&"*.py".to_string()));
        assert!(!config.exclude_patterns.is_empty());
    }

    #[test]
    fn test_dev_config() {
        let config = HotReloadConfig::dev();
        assert!(config.enabled);
        assert!(!config.watch_paths.is_empty());
    }

    #[test]
    fn test_matches_pattern_suffix() {
        assert!(matches_pattern("foo.py", "*.py"));
        assert!(matches_pattern("bar/baz.py", "*.py"));
        assert!(!matches_pattern("foo.rs", "*.py"));
    }

    #[test]
    fn test_matches_pattern_prefix() {
        assert!(matches_pattern("test_foo.py", "test_*"));
        assert!(!matches_pattern("foo_test.py", "test_*"));
    }

    #[test]
    fn test_matches_pattern_contains() {
        assert!(matches_pattern("path/__pycache__/foo.pyc", "__pycache__"));
        assert!(matches_pattern(".git/config", ".git"));
    }

    #[test]
    fn test_should_watch_python_file() {
        let watcher = HotReloadWatcher::with_defaults();
        assert!(watcher.should_watch(Path::new("foo.py")));
        assert!(watcher.should_watch(Path::new("src/main.py")));
    }

    #[test]
    fn test_should_not_watch_excluded() {
        let watcher = HotReloadWatcher::with_defaults();
        assert!(!watcher.should_watch(Path::new("__pycache__/foo.pyc")));
        assert!(!watcher.should_watch(Path::new(".git/config")));
    }

    #[test]
    fn test_should_not_watch_non_python() {
        let watcher = HotReloadWatcher::with_defaults();
        assert!(!watcher.should_watch(Path::new("foo.rs")));
        assert!(!watcher.should_watch(Path::new("Cargo.toml")));
    }

    #[test]
    fn test_add_watch_path() {
        let mut watcher = HotReloadWatcher::with_defaults();
        watcher.add_watch_path(PathBuf::from("src"));
        assert!(watcher.config().watch_paths.contains(&PathBuf::from("src")));

        // Adding same path again should not duplicate
        watcher.add_watch_path(PathBuf::from("src"));
        assert_eq!(watcher.config().watch_paths.len(), 1);
    }

    #[test]
    fn test_watcher_status() {
        let watcher = HotReloadWatcher::with_defaults();
        assert_eq!(*watcher.status(), WatcherStatus::Stopped);
    }

    #[test]
    fn test_start_without_paths() {
        let mut config = HotReloadConfig::dev();
        config.watch_paths.clear();
        let mut watcher = HotReloadWatcher::new(config);

        let handle = watcher.start();
        assert!(matches!(handle.status, WatcherStatus::Error(_)));
    }

    #[test]
    fn test_file_change_event() {
        let event = FileChangeEvent::new(PathBuf::from("foo.py"), ChangeType::Modified, 12345);

        assert_eq!(event.path, PathBuf::from("foo.py"));
        assert_eq!(event.change_type, ChangeType::Modified);
        assert_eq!(event.timestamp_ms, 12345);
    }

    #[test]
    fn test_watcher_stats() {
        let mut config = HotReloadConfig::dev();
        config.watch_paths = vec![PathBuf::from("src"), PathBuf::from("tests")];
        let watcher = HotReloadWatcher::new(config);

        let stats = watcher.stats();
        assert!(!stats.is_running);
        assert_eq!(stats.watched_paths, 2);
    }

    #[test]
    fn test_debounce_events() {
        let mut watcher = HotReloadWatcher::new(HotReloadConfig::dev());

        let event1 = FileChangeEvent::new(PathBuf::from("foo.py"), ChangeType::Modified, 0);
        let event2 = FileChangeEvent::new(PathBuf::from("foo.py"), ChangeType::Modified, 100);

        // First event should pass
        let result1 = watcher.process_event(event1);
        assert!(result1.is_some());

        // Second event within debounce window should be delayed
        let result2 = watcher.process_event(event2);
        assert!(result2.is_none());
        assert_eq!(watcher.pending_events.len(), 1);
    }

    #[test]
    fn test_flush_pending_deduplicates() {
        let mut watcher = HotReloadWatcher::new(HotReloadConfig::dev());

        // Add duplicate events
        watcher.pending_events.push(FileChangeEvent::new(
            PathBuf::from("foo.py"),
            ChangeType::Modified,
            0,
        ));
        watcher.pending_events.push(FileChangeEvent::new(
            PathBuf::from("foo.py"),
            ChangeType::Modified,
            100,
        ));
        watcher.pending_events.push(FileChangeEvent::new(
            PathBuf::from("bar.py"),
            ChangeType::Modified,
            50,
        ));

        let flushed = watcher.flush_pending();

        // Should deduplicate
        assert_eq!(flushed.len(), 2);
        assert!(watcher.pending_events.is_empty());
    }

    #[test]
    fn test_generate_shell_command() {
        let mut config = HotReloadConfig::dev();
        config.watch_paths = vec![PathBuf::from("src")];

        let cmd = generate_shell_watcher_command(&config, "python main.py");
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let config = HotReloadConfig::dev();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: HotReloadConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.enabled, deserialized.enabled);
        assert_eq!(config.debounce_ms, deserialized.debounce_ms);
    }
}
