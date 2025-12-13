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
//! - Native file watching with `notify` crate (optional feature: `native-watch`)

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[cfg(feature = "native-watch")]
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};

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

/// Native watcher result (with the actual watcher object for lifetime management).
#[cfg(feature = "native-watch")]
pub struct NativeWatcherHandle {
    /// Status of the watcher.
    pub status: WatcherStatus,
    /// Number of paths being watched.
    pub watched_paths: usize,
    /// Receiver for change events.
    pub event_receiver: mpsc::Receiver<FileChangeEvent>,
    /// The actual notify watcher (keep alive for watching to continue).
    _watcher: RecommendedWatcher,
}

#[cfg(feature = "native-watch")]
impl std::fmt::Debug for NativeWatcherHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeWatcherHandle")
            .field("status", &self.status)
            .field("watched_paths", &self.watched_paths)
            .finish_non_exhaustive()
    }
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

    /// Start native file watching using the `notify` crate.
    ///
    /// This requires the `native-watch` feature to be enabled.
    /// Returns a handle that must be kept alive for watching to continue.
    #[cfg(feature = "native-watch")]
    pub fn start_native(&mut self) -> Result<NativeWatcherHandle, String> {
        if !self.config.enabled {
            return Err("Watcher is not enabled".to_string());
        }

        if self.config.watch_paths.is_empty() {
            return Err("No paths to watch".to_string());
        }

        // Create channel for events
        let (tx, rx) = mpsc::channel();
        let config_clone = self.config.clone();

        // Create the watcher with event handler
        let watcher_result = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        // Filter and convert events
                        if let Some(change_event) = convert_notify_event(&event, &config_clone) {
                            // Ignore send errors (receiver might be dropped)
                            let _ = tx.send(change_event);
                        }
                    }
                    Err(e) => {
                        eprintln!("watch error: {:?}", e);
                    }
                }
            },
            Config::default().with_poll_interval(Duration::from_millis(self.config.debounce_ms)),
        );

        let mut watcher = match watcher_result {
            Ok(w) => w,
            Err(e) => return Err(format!("Failed to create watcher: {}", e)),
        };

        // Watch all configured paths
        let mut watched_count = 0;
        for path in &self.config.watch_paths {
            if !path.exists() {
                eprintln!("warning: path does not exist: {}", path.display());
                continue;
            }

            match watcher.watch(path, RecursiveMode::Recursive) {
                Ok(()) => {
                    watched_count += 1;
                    eprintln!("info: watching {}", path.display());
                }
                Err(e) => {
                    eprintln!("warning: failed to watch {}: {}", path.display(), e);
                }
            }
        }

        if watched_count == 0 {
            return Err("No valid paths to watch".to_string());
        }

        self.status = WatcherStatus::Running;

        Ok(NativeWatcherHandle {
            status: WatcherStatus::Running,
            watched_paths: watched_count,
            event_receiver: rx,
            _watcher: watcher,
        })
    }

    /// Check if native watching is available.
    #[cfg(feature = "native-watch")]
    pub fn native_watch_available() -> bool {
        true
    }

    /// Check if native watching is available (returns false when feature is disabled).
    #[cfg(not(feature = "native-watch"))]
    pub fn native_watch_available() -> bool {
        false
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

/// Convert a notify event to a FileChangeEvent.
/// Returns None if the event should be filtered out.
#[cfg(feature = "native-watch")]
fn convert_notify_event(
    event: &notify::Event,
    config: &HotReloadConfig,
) -> Option<FileChangeEvent> {
    use notify::EventKind;

    // Determine change type from notify event kind
    let change_type = match event.kind {
        EventKind::Create(_) => ChangeType::Created,
        EventKind::Modify(_) => ChangeType::Modified,
        EventKind::Remove(_) => ChangeType::Deleted,
        EventKind::Other => return None, // Ignore other events
        EventKind::Any => ChangeType::Modified, // Default to modified
        EventKind::Access(_) => return None, // Ignore access events
    };

    // Get the first path from the event
    let path = event.paths.first()?;

    // Check if this path should be watched based on patterns
    let path_str = path.to_string_lossy();

    // Check exclude patterns
    for pattern in &config.exclude_patterns {
        if matches_pattern(&path_str, pattern) {
            return None;
        }
    }

    // Check include patterns
    if !config.include_patterns.is_empty() {
        let mut included = false;
        for pattern in &config.include_patterns {
            if matches_pattern(&path_str, pattern) {
                included = true;
                break;
            }
        }
        if !included {
            return None;
        }
    }

    // Get current timestamp in milliseconds
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    Some(FileChangeEvent::new(
        path.clone(),
        change_type,
        timestamp_ms,
    ))
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

/// Callback type for file change events.
#[cfg(feature = "native-watch")]
pub type OnChangeCallback = Box<dyn Fn(&FileChangeEvent)>;

/// Run a command when files change using native watching.
///
/// This function blocks and runs until interrupted (Ctrl+C).
/// Requires the `native-watch` feature.
#[cfg(feature = "native-watch")]
pub fn run_native_watch_loop(
    config: &HotReloadConfig,
    command: &str,
    on_change: Option<OnChangeCallback>,
) -> Result<(), String> {
    use std::process::Command;

    let mut watcher = HotReloadWatcher::new(config.clone());
    let handle = watcher.start_native()?;

    eprintln!("info: native file watching started");
    eprintln!("info: press Ctrl+C to stop");

    // Debounce tracking
    let mut last_run = Instant::now();
    let debounce = Duration::from_millis(config.debounce_ms);

    // Process events in a loop
    loop {
        match handle
            .event_receiver
            .recv_timeout(Duration::from_millis(100))
        {
            Ok(event) => {
                // Debounce check
                let now = Instant::now();
                if now.duration_since(last_run) < debounce {
                    continue;
                }
                last_run = now;

                // Optional callback
                if let Some(ref callback) = on_change {
                    callback(&event);
                }

                eprintln!("info: {:?} {}", event.change_type, event.path.display());

                // Clear terminal if configured
                if config.clear_on_reload {
                    // ANSI escape sequence to clear screen
                    print!("\x1B[2J\x1B[1;1H");
                }

                // Run the command
                eprintln!("info: running: {}", command);
                let status = if cfg!(windows) {
                    Command::new("cmd").args(["/C", command]).status()
                } else {
                    Command::new("sh").args(["-c", command]).status()
                };

                match status {
                    Ok(s) => {
                        if s.success() {
                            eprintln!("info: command completed successfully");
                        } else {
                            eprintln!(
                                "warning: command exited with code {}",
                                s.code().unwrap_or(-1)
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("error: failed to run command: {}", e);
                    }
                }

                eprintln!("info: watching for changes...");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Normal timeout, continue watching
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Watcher was dropped
                break;
            }
        }
    }

    Ok(())
}

/// Watch result containing collected events.
#[cfg(feature = "native-watch")]
pub struct WatchResult {
    /// Events collected during watching.
    pub events: Vec<FileChangeEvent>,
    /// Duration of watching.
    pub duration_ms: u64,
}

/// Watch for file changes and collect events for a specified duration.
/// Useful for testing.
#[cfg(feature = "native-watch")]
pub fn watch_for_duration(
    config: &HotReloadConfig,
    timeout: Duration,
) -> Result<WatchResult, String> {
    let mut watcher = HotReloadWatcher::new(config.clone());
    let handle = watcher.start_native()?;

    let start = Instant::now();
    let mut events = Vec::new();

    // Collect events until timeout
    loop {
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }

        match handle
            .event_receiver
            .recv_timeout(remaining.min(Duration::from_millis(100)))
        {
            Ok(event) => {
                events.push(event);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if start.elapsed() >= timeout {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    Ok(WatchResult {
        events,
        duration_ms: start.elapsed().as_millis() as u64,
    })
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

    #[test]
    fn test_native_watch_available() {
        // Test that the function exists and returns the expected value
        let available = HotReloadWatcher::native_watch_available();
        // When compiled without the feature, this should be false
        // When compiled with the feature, this should be true
        #[cfg(feature = "native-watch")]
        assert!(available);
        #[cfg(not(feature = "native-watch"))]
        assert!(!available);
    }

    #[cfg(feature = "native-watch")]
    mod native_watch_tests {
        use super::*;
        use std::fs::File;
        use std::io::Write;
        use tempfile::TempDir;

        #[test]
        fn test_start_native_no_paths() {
            let mut config = HotReloadConfig::dev();
            config.watch_paths.clear();
            let mut watcher = HotReloadWatcher::new(config);

            let result = watcher.start_native();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("No paths to watch"));
        }

        #[test]
        fn test_start_native_disabled() {
            let mut config = HotReloadConfig::dev();
            config.enabled = false;
            let mut watcher = HotReloadWatcher::new(config);

            let result = watcher.start_native();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("not enabled"));
        }

        #[test]
        fn test_start_native_with_temp_dir() {
            let temp = TempDir::new().unwrap();
            let mut config = HotReloadConfig::dev();
            config.watch_paths = vec![temp.path().to_path_buf()];

            let mut watcher = HotReloadWatcher::new(config);
            let result = watcher.start_native();

            assert!(result.is_ok());
            let handle = result.unwrap();
            assert_eq!(handle.status, WatcherStatus::Running);
            assert_eq!(handle.watched_paths, 1);
        }

        #[test]
        fn test_native_event_detection() {
            let temp = TempDir::new().unwrap();
            let mut config = HotReloadConfig::dev();
            config.watch_paths = vec![temp.path().to_path_buf()];
            config.debounce_ms = 50;

            let mut watcher = HotReloadWatcher::new(config);
            let handle = watcher.start_native().unwrap();

            // Give the watcher a moment to initialize
            std::thread::sleep(Duration::from_millis(100));

            // Create a Python file
            let test_file = temp.path().join("test.py");
            let mut file = File::create(&test_file).unwrap();
            writeln!(file, "print('hello')").unwrap();
            file.sync_all().unwrap();
            drop(file);

            // Wait for the event with timeout
            let event = handle.event_receiver.recv_timeout(Duration::from_secs(2));

            // We should receive at least one event
            assert!(event.is_ok(), "Expected to receive file change event");
            let event = event.unwrap();
            assert!(event.path.ends_with("test.py"));
        }

        #[test]
        fn test_event_filtering_excludes_pycache() {
            let temp = TempDir::new().unwrap();

            // Create __pycache__ directory
            let pycache = temp.path().join("__pycache__");
            std::fs::create_dir(&pycache).unwrap();

            let mut config = HotReloadConfig::dev();
            config.watch_paths = vec![temp.path().to_path_buf()];
            config.debounce_ms = 50;

            let mut watcher = HotReloadWatcher::new(config);
            let handle = watcher.start_native().unwrap();

            std::thread::sleep(Duration::from_millis(100));

            // Create a .pyc file in __pycache__ (should be filtered)
            let pyc_file = pycache.join("test.cpython-311.pyc");
            File::create(&pyc_file).unwrap();

            // Create a .py file (should be included)
            let py_file = temp.path().join("main.py");
            let mut file = File::create(&py_file).unwrap();
            writeln!(file, "print('main')").unwrap();
            file.sync_all().unwrap();

            // Collect events
            let mut events = Vec::new();
            for _ in 0..10 {
                match handle
                    .event_receiver
                    .recv_timeout(Duration::from_millis(200))
                {
                    Ok(e) => events.push(e),
                    Err(_) => break,
                }
            }

            // Should have received event for main.py but not for .pyc
            assert!(events.iter().any(|e| e.path.ends_with("main.py")));
            // .pyc file changes should be filtered out by exclude pattern
            assert!(
                !events
                    .iter()
                    .any(|e| e.path.to_string_lossy().contains(".pyc"))
            );
        }
    }
}
