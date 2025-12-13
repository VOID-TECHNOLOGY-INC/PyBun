//! Snapshot testing primitives for PyBun test runner.
//!
//! This module provides snapshot testing functionality that allows:
//! - Capturing test output as snapshots
//! - Comparing current output against stored snapshots
//! - Updating snapshots when tests change intentionally
//!
//! Snapshot files are stored in a `__snapshots__` directory adjacent to the test file.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Result of a snapshot comparison
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotResult {
    /// Snapshot matches expected value
    Match,
    /// Snapshot differs from expected value
    Mismatch {
        expected: String,
        actual: String,
        diff: String,
    },
    /// No existing snapshot (new test)
    New { actual: String },
    /// Snapshot file could not be read
    Error { message: String },
}

/// A single snapshot entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Name of the test that created this snapshot
    pub test_name: String,
    /// The snapshot content
    pub content: String,
    /// Metadata about when this was last updated
    pub updated_at: Option<String>,
    /// Format of the snapshot (text, json, etc.)
    pub format: SnapshotFormat,
}

/// Format of snapshot content
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotFormat {
    #[default]
    Text,
    Json,
    Binary,
}

/// Collection of snapshots for a test file
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotFile {
    /// Schema version for future compatibility
    pub version: u32,
    /// Map of test name to snapshot
    pub snapshots: HashMap<String, Snapshot>,
}

impl SnapshotFile {
    /// Create a new empty snapshot file
    pub fn new() -> Self {
        Self {
            version: 1,
            snapshots: HashMap::new(),
        }
    }

    /// Load snapshots from a file path
    pub fn load(path: &Path) -> Result<Self, SnapshotError> {
        if !path.exists() {
            return Ok(Self::new());
        }

        let content =
            fs::read_to_string(path).map_err(|e| SnapshotError::IoError(e.to_string()))?;

        serde_json::from_str(&content).map_err(|e| SnapshotError::ParseError(e.to_string()))
    }

    /// Save snapshots to a file path
    pub fn save(&self, path: &Path) -> Result<(), SnapshotError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| SnapshotError::IoError(e.to_string()))?;
        }

        let content = serde_json::to_string_pretty(self)
            .map_err(|e| SnapshotError::SerializeError(e.to_string()))?;

        fs::write(path, content).map_err(|e| SnapshotError::IoError(e.to_string()))
    }

    /// Get a snapshot by test name
    pub fn get(&self, test_name: &str) -> Option<&Snapshot> {
        self.snapshots.get(test_name)
    }

    /// Set or update a snapshot
    pub fn set(&mut self, test_name: &str, content: String, format: SnapshotFormat) {
        let now = chrono_now();
        self.snapshots.insert(
            test_name.to_string(),
            Snapshot {
                test_name: test_name.to_string(),
                content,
                updated_at: Some(now),
                format,
            },
        );
    }

    /// Remove a snapshot
    pub fn remove(&mut self, test_name: &str) -> Option<Snapshot> {
        self.snapshots.remove(test_name)
    }

    /// Check if a snapshot exists
    pub fn contains(&self, test_name: &str) -> bool {
        self.snapshots.contains_key(test_name)
    }

    /// Get the number of snapshots
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}

/// Snapshot testing errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum SnapshotError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Serialize error: {0}")]
    SerializeError(String),
    #[error("Snapshot mismatch for {test_name}")]
    Mismatch { test_name: String },
}

/// Snapshot manager for a test session
#[derive(Debug)]
pub struct SnapshotManager {
    /// Base directory for snapshots (usually __snapshots__)
    snapshot_dir: PathBuf,
    /// Whether to update snapshots instead of comparing
    update_mode: bool,
    /// Loaded snapshot files (keyed by source file path)
    files: HashMap<PathBuf, SnapshotFile>,
    /// Results of snapshot comparisons
    results: Vec<SnapshotTestResult>,
}

/// Result of a single snapshot test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotTestResult {
    /// Test name
    pub test_name: String,
    /// Source file path
    pub source_file: PathBuf,
    /// Comparison result
    pub result: SnapshotResult,
    /// Whether the snapshot was updated
    pub updated: bool,
}

impl SnapshotManager {
    /// Create a new snapshot manager
    pub fn new(snapshot_dir: PathBuf, update_mode: bool) -> Self {
        Self {
            snapshot_dir,
            update_mode,
            files: HashMap::new(),
            results: Vec::new(),
        }
    }

    /// Get the snapshot file path for a source file
    pub fn snapshot_path_for(&self, source_file: &Path) -> PathBuf {
        let file_name = source_file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Replace .py extension with .snap.json
        let snap_name = if file_name.ends_with(".py") {
            format!("{}.snap.json", &file_name[..file_name.len() - 3])
        } else {
            format!("{}.snap.json", file_name)
        };

        self.snapshot_dir.join(snap_name)
    }

    /// Load snapshot file for a source file
    pub fn load_for(&mut self, source_file: &Path) -> Result<&mut SnapshotFile, SnapshotError> {
        let snap_path = self.snapshot_path_for(source_file);

        if !self.files.contains_key(&snap_path) {
            let file = SnapshotFile::load(&snap_path)?;
            self.files.insert(snap_path.clone(), file);
        }

        Ok(self.files.get_mut(&snap_path).unwrap())
    }

    /// Assert that a value matches its snapshot
    pub fn assert_snapshot(
        &mut self,
        source_file: &Path,
        test_name: &str,
        actual: &str,
    ) -> SnapshotResult {
        let snap_path = self.snapshot_path_for(source_file);
        let update_mode = self.update_mode; // Copy before mutable borrow

        // Load or create snapshot file
        let file = match self.load_for(source_file) {
            Ok(f) => f,
            Err(e) => {
                let result = SnapshotResult::Error {
                    message: e.to_string(),
                };
                self.results.push(SnapshotTestResult {
                    test_name: test_name.to_string(),
                    source_file: source_file.to_path_buf(),
                    result: result.clone(),
                    updated: false,
                });
                return result;
            }
        };

        // Check existing snapshot
        let result = if let Some(snapshot) = file.get(test_name) {
            if snapshot.content == actual {
                SnapshotResult::Match
            } else {
                let diff = generate_diff(&snapshot.content, actual);
                SnapshotResult::Mismatch {
                    expected: snapshot.content.clone(),
                    actual: actual.to_string(),
                    diff,
                }
            }
        } else {
            SnapshotResult::New {
                actual: actual.to_string(),
            }
        };

        // Update if in update mode and not a match
        let updated = if update_mode && result != SnapshotResult::Match {
            file.set(test_name, actual.to_string(), SnapshotFormat::Text);
            // Save immediately
            if let Err(e) = file.save(&snap_path) {
                eprintln!("Warning: failed to save snapshot: {}", e);
                false
            } else {
                true
            }
        } else {
            false
        };

        self.results.push(SnapshotTestResult {
            test_name: test_name.to_string(),
            source_file: source_file.to_path_buf(),
            result: result.clone(),
            updated,
        });

        result
    }

    /// Assert that a JSON value matches its snapshot
    pub fn assert_snapshot_json<T: Serialize>(
        &mut self,
        source_file: &Path,
        test_name: &str,
        actual: &T,
    ) -> SnapshotResult {
        let json_str = match serde_json::to_string_pretty(actual) {
            Ok(s) => s,
            Err(e) => {
                return SnapshotResult::Error {
                    message: format!("Failed to serialize value: {}", e),
                };
            }
        };

        self.assert_snapshot(source_file, test_name, &json_str)
    }

    /// Get all results
    pub fn results(&self) -> &[SnapshotTestResult] {
        &self.results
    }

    /// Get summary statistics
    pub fn summary(&self) -> SnapshotSummary {
        let mut summary = SnapshotSummary::default();

        for result in &self.results {
            match &result.result {
                SnapshotResult::Match => summary.passed += 1,
                SnapshotResult::Mismatch { .. } => {
                    if result.updated {
                        summary.updated += 1;
                    } else {
                        summary.failed += 1;
                    }
                }
                SnapshotResult::New { .. } => {
                    if result.updated {
                        summary.created += 1;
                    } else {
                        summary.new += 1;
                    }
                }
                SnapshotResult::Error { .. } => summary.errors += 1,
            }
        }

        summary
    }

    /// Save all modified snapshot files
    pub fn save_all(&self) -> Result<(), SnapshotError> {
        for (path, file) in &self.files {
            if !file.is_empty() {
                file.save(path)?;
            }
        }
        Ok(())
    }

    /// Check if update mode is enabled
    pub fn is_update_mode(&self) -> bool {
        self.update_mode
    }
}

/// Summary of snapshot test results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotSummary {
    /// Snapshots that matched
    pub passed: usize,
    /// Snapshots that didn't match (failures)
    pub failed: usize,
    /// New snapshots that were created
    pub created: usize,
    /// Snapshots that were updated
    pub updated: usize,
    /// New snapshots pending (not in update mode)
    pub new: usize,
    /// Errors during comparison
    pub errors: usize,
}

impl SnapshotSummary {
    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.new == 0 && self.errors == 0
    }

    /// Total number of snapshots processed
    pub fn total(&self) -> usize {
        self.passed + self.failed + self.created + self.updated + self.new + self.errors
    }
}

/// Generate a simple diff between two strings
fn generate_diff(expected: &str, actual: &str) -> String {
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();

    let mut diff = String::new();
    let max_lines = expected_lines.len().max(actual_lines.len());

    for i in 0..max_lines {
        let expected_line = expected_lines.get(i).copied().unwrap_or("");
        let actual_line = actual_lines.get(i).copied().unwrap_or("");

        if expected_line != actual_line {
            if expected_lines.get(i).is_some() {
                diff.push_str(&format!("- {}\n", expected_line));
            }
            if actual_lines.get(i).is_some() {
                diff.push_str(&format!("+ {}\n", actual_line));
            }
        } else {
            diff.push_str(&format!("  {}\n", expected_line));
        }
    }

    diff
}

/// Get current timestamp as ISO 8601 string (simple implementation)
fn chrono_now() -> String {
    use std::time::SystemTime;

    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();
    format!("epoch:{}", secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_snapshot_file_new() {
        let file = SnapshotFile::new();
        assert_eq!(file.version, 1);
        assert!(file.is_empty());
    }

    #[test]
    fn test_snapshot_file_set_get() {
        let mut file = SnapshotFile::new();
        file.set(
            "test_example",
            "hello world".to_string(),
            SnapshotFormat::Text,
        );

        assert!(file.contains("test_example"));
        assert_eq!(file.len(), 1);

        let snapshot = file.get("test_example").unwrap();
        assert_eq!(snapshot.content, "hello world");
        assert_eq!(snapshot.format, SnapshotFormat::Text);
    }

    #[test]
    fn test_snapshot_file_save_load() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("test.snap.json");

        let mut file = SnapshotFile::new();
        file.set("test_one", "content one".to_string(), SnapshotFormat::Text);
        file.set("test_two", "content two".to_string(), SnapshotFormat::Json);

        file.save(&path).unwrap();
        assert!(path.exists());

        let loaded = SnapshotFile::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get("test_one").unwrap().content, "content one");
        assert_eq!(loaded.get("test_two").unwrap().content, "content two");
    }

    #[test]
    fn test_snapshot_manager_match() {
        let temp = TempDir::new().unwrap();
        let snap_dir = temp.path().join("__snapshots__");
        let source = temp.path().join("test_example.py");

        // Create initial snapshot
        let mut manager = SnapshotManager::new(snap_dir.clone(), true);
        let result = manager.assert_snapshot(&source, "test_match", "hello");
        assert!(matches!(result, SnapshotResult::New { .. }));

        // Now check it matches
        let mut manager2 = SnapshotManager::new(snap_dir, false);
        let result2 = manager2.assert_snapshot(&source, "test_match", "hello");
        assert!(matches!(result2, SnapshotResult::Match));
    }

    #[test]
    fn test_snapshot_manager_mismatch() {
        let temp = TempDir::new().unwrap();
        let snap_dir = temp.path().join("__snapshots__");
        let source = temp.path().join("test_example.py");

        // Create initial snapshot
        let mut manager = SnapshotManager::new(snap_dir.clone(), true);
        manager.assert_snapshot(&source, "test_mismatch", "original");

        // Check with different content
        let mut manager2 = SnapshotManager::new(snap_dir, false);
        let result = manager2.assert_snapshot(&source, "test_mismatch", "changed");
        assert!(matches!(result, SnapshotResult::Mismatch { .. }));

        if let SnapshotResult::Mismatch {
            expected, actual, ..
        } = result
        {
            assert_eq!(expected, "original");
            assert_eq!(actual, "changed");
        }
    }

    #[test]
    fn test_snapshot_summary() {
        let summary = SnapshotSummary {
            passed: 5,
            failed: 1,
            created: 2,
            updated: 0,
            new: 1,
            errors: 0,
        };

        assert!(!summary.all_passed());
        assert_eq!(summary.total(), 9);

        let all_pass = SnapshotSummary {
            passed: 10,
            ..Default::default()
        };
        assert!(all_pass.all_passed());
    }

    #[test]
    fn test_generate_diff() {
        let expected = "line 1\nline 2\nline 3";
        let actual = "line 1\nmodified\nline 3";

        let diff = generate_diff(expected, actual);
        assert!(diff.contains("- line 2"));
        assert!(diff.contains("+ modified"));
    }

    #[test]
    fn test_snapshot_path_for() {
        let temp = TempDir::new().unwrap();
        let manager = SnapshotManager::new(temp.path().join("__snapshots__"), false);

        let source = Path::new("/path/to/test_example.py");
        let snap_path = manager.snapshot_path_for(source);

        assert!(snap_path.ends_with("test_example.snap.json"));
    }

    #[test]
    fn test_snapshot_update_mode() {
        let temp = TempDir::new().unwrap();
        let snap_dir = temp.path().join("__snapshots__");
        let source = temp.path().join("test_example.py");

        // Create initial snapshot
        let mut manager = SnapshotManager::new(snap_dir.clone(), true);
        manager.assert_snapshot(&source, "test_update", "version 1");

        // Update with new content
        let mut manager2 = SnapshotManager::new(snap_dir.clone(), true);
        let result = manager2.assert_snapshot(&source, "test_update", "version 2");

        // Should be mismatch but updated
        assert!(matches!(result, SnapshotResult::Mismatch { .. }));

        // Check it was actually updated
        let mut manager3 = SnapshotManager::new(snap_dir, false);
        let result3 = manager3.assert_snapshot(&source, "test_update", "version 2");
        assert!(matches!(result3, SnapshotResult::Match));
    }
}
