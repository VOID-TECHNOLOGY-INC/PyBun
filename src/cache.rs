//! Global cache management for PyBun.
//!
//! Layout:
//! - ~/.cache/pybun/packages/    (wheels)
//! - ~/.cache/pybun/envs/        (virtual environments)
//! - ~/.cache/pybun/build/       (build object cache)
//! - ~/.cache/pybun/logs/        (structured event logs)
//! - ~/.cache/pybun/pep723-envs/ (PEP 723 script venvs)
//!
//! ## GC (Garbage Collection)
//! The cache supports LRU-based garbage collection with configurable size limits.
//! Use `pybun gc --max-size` to enforce cache size limits.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use thiserror::Error;

const DEFAULT_CACHE_DIR: &str = ".cache/pybun";
const PACKAGES_DIR: &str = "packages";
const ENVS_DIR: &str = "envs";
const BUILD_DIR: &str = "build";
const LOGS_DIR: &str = "logs";
const PEP723_ENVS_DIR: &str = "pep723-envs";

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("failed to determine home directory")]
    NoHomeDir,
    #[error("failed to create cache directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CacheError>;

/// Represents the global cache configuration and paths.
#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    /// Create a new cache instance using default or env-configured location.
    ///
    /// Priority:
    /// 1. `PYBUN_HOME` environment variable
    /// 2. `~/.cache/pybun`
    pub fn new() -> Result<Self> {
        let root = if let Ok(home) = env::var("PYBUN_HOME") {
            PathBuf::from(home)
        } else {
            let home_dir = dirs::home_dir().ok_or(CacheError::NoHomeDir)?;
            home_dir.join(DEFAULT_CACHE_DIR)
        };
        Ok(Self { root })
    }

    /// Create a cache instance with a custom root directory (useful for testing).
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Root directory of the cache.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Directory for cached wheel packages.
    pub fn packages_dir(&self) -> PathBuf {
        self.root.join(PACKAGES_DIR)
    }

    /// Directory for virtual environments.
    pub fn envs_dir(&self) -> PathBuf {
        self.root.join(ENVS_DIR)
    }

    /// Directory for build artifacts.
    pub fn build_dir(&self) -> PathBuf {
        self.root.join(BUILD_DIR)
    }

    /// Directory for logs.
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join(LOGS_DIR)
    }

    /// Directory for PEP 723 script venv cache.
    pub fn pep723_envs_dir(&self) -> PathBuf {
        self.root.join(PEP723_ENVS_DIR)
    }

    /// Ensure all cache directories exist.
    pub fn ensure_dirs(&self) -> Result<()> {
        for dir in [
            self.packages_dir(),
            self.envs_dir(),
            self.build_dir(),
            self.logs_dir(),
            self.pep723_envs_dir(),
        ] {
            if !dir.exists() {
                fs::create_dir_all(&dir).map_err(|source| CacheError::CreateDir {
                    path: dir.clone(),
                    source,
                })?;
            }
        }
        Ok(())
    }

    /// Get the path where a specific package wheel would be stored.
    ///
    /// Layout: packages/{name}/{name}-{version}-{wheel_tag}.whl
    pub fn wheel_path(&self, name: &str, _version: &str, wheel_file: &str) -> PathBuf {
        self.packages_dir().join(name).join(wheel_file)
    }

    /// Get the directory for a specific package in the cache.
    pub fn package_dir(&self, name: &str) -> PathBuf {
        self.packages_dir().join(name)
    }

    /// Check if a wheel exists in the cache.
    pub fn has_wheel(&self, name: &str, version: &str, wheel_file: &str) -> bool {
        self.wheel_path(name, version, wheel_file).exists()
    }

    /// Ensure package directory exists.
    pub fn ensure_package_dir(&self, name: &str) -> Result<PathBuf> {
        let dir = self.package_dir(name);
        if !dir.exists() {
            fs::create_dir_all(&dir).map_err(|source| CacheError::CreateDir {
                path: dir.clone(),
                source,
            })?;
        }
        Ok(dir)
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new().expect("failed to initialize default cache")
    }
}

/// Result of a garbage collection operation
#[derive(Debug, Clone, Default)]
pub struct GcResult {
    /// Total bytes freed
    pub freed_bytes: u64,
    /// Number of files removed
    pub files_removed: usize,
    /// Files that would be removed (dry-run mode)
    pub would_remove: Vec<PathBuf>,
    /// Current cache size before GC (bytes)
    pub size_before: u64,
    /// Current cache size after GC (bytes)
    pub size_after: u64,
}

/// A cached entry with metadata for LRU eviction
#[derive(Debug, Clone)]
struct CacheEntry {
    path: PathBuf,
    size: u64,
    accessed: SystemTime,
}

impl Cache {
    /// Run garbage collection on the cache.
    ///
    /// If `max_bytes` is provided, removes least-recently-used files until
    /// the cache is under the limit.
    ///
    /// If `dry_run` is true, reports what would be deleted without actually deleting.
    pub fn gc(&self, max_bytes: Option<u64>, dry_run: bool) -> Result<GcResult> {
        let mut result = GcResult::default();

        // Collect all cache entries
        let mut entries = self.collect_cache_entries()?;
        result.size_before = entries.iter().map(|e| e.size).sum();

        // Sort by access time (oldest first for LRU eviction)
        entries.sort_by(|a, b| a.accessed.cmp(&b.accessed));

        let max_bytes = max_bytes.unwrap_or(u64::MAX);
        let mut current_size = result.size_before;

        // Evict entries until we're under the limit
        for entry in entries {
            if current_size <= max_bytes {
                break;
            }

            if dry_run {
                result.would_remove.push(entry.path.clone());
            } else {
                if let Err(e) = fs::remove_file(&entry.path) {
                    // Log but don't fail on individual file errors
                    eprintln!("warning: failed to remove {}: {}", entry.path.display(), e);
                    continue;
                }
                result.files_removed += 1;
            }

            result.freed_bytes += entry.size;
            current_size = current_size.saturating_sub(entry.size);
        }

        result.size_after = if dry_run {
            result.size_before - result.freed_bytes
        } else {
            current_size
        };

        // Clean up empty directories
        if !dry_run {
            self.remove_empty_dirs()?;
        }

        Ok(result)
    }

    /// Calculate total cache size in bytes
    pub fn total_size(&self) -> Result<u64> {
        let entries = self.collect_cache_entries()?;
        Ok(entries.iter().map(|e| e.size).sum())
    }

    /// Collect all cache entries with metadata
    fn collect_cache_entries(&self) -> Result<Vec<CacheEntry>> {
        let mut entries = Vec::new();

        // Collect from packages directory
        if let Ok(dirs) = fs::read_dir(self.packages_dir()) {
            for dir_entry in dirs.flatten() {
                if dir_entry.path().is_dir() {
                    self.collect_entries_from_dir(&dir_entry.path(), &mut entries)?;
                }
            }
        }

        // Collect from build directory
        if let Ok(files) = fs::read_dir(self.build_dir()) {
            for file_entry in files.flatten() {
                if let Some(entry) = self.entry_from_path(&file_entry.path())? {
                    entries.push(entry);
                }
            }
        }

        Ok(entries)
    }

    fn collect_entries_from_dir(&self, dir: &Path, entries: &mut Vec<CacheEntry>) -> Result<()> {
        if let Ok(files) = fs::read_dir(dir) {
            for file_entry in files.flatten() {
                let path = file_entry.path();
                if path.is_file() {
                    if let Some(entry) = self.entry_from_path(&path)? {
                        entries.push(entry);
                    }
                } else if path.is_dir() {
                    self.collect_entries_from_dir(&path, entries)?;
                }
            }
        }
        Ok(())
    }

    fn entry_from_path(&self, path: &Path) -> Result<Option<CacheEntry>> {
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return Ok(None),
        };

        if !metadata.is_file() {
            return Ok(None);
        }

        // Use modified time as a proxy for access time (more reliably available)
        let accessed = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        Ok(Some(CacheEntry {
            path: path.to_path_buf(),
            size: metadata.len(),
            accessed,
        }))
    }

    fn remove_empty_dirs(&self) -> Result<()> {
        self.remove_empty_dirs_recursive(&self.packages_dir())?;
        self.remove_empty_dirs_recursive(&self.build_dir())?;
        Ok(())
    }

    fn remove_empty_dirs_recursive(&self, dir: &Path) -> Result<bool> {
        if !dir.exists() || !dir.is_dir() {
            return Ok(false);
        }

        let mut is_empty = true;
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if !self.remove_empty_dirs_recursive(&path)? {
                        is_empty = false;
                    }
                } else {
                    is_empty = false;
                }
            }
        }

        if is_empty && dir != self.packages_dir() && dir != self.build_dir() {
            let _ = fs::remove_dir(dir);
        }

        Ok(is_empty)
    }
}

/// Parse a size string like "10G", "500M", "1K" into bytes
pub fn parse_size(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim().to_uppercase();

    // Handle plain numbers
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }

    // Find where the number ends and unit begins
    let (num_str, unit) = if let Some(pos) = s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        (&s[..pos], &s[pos..])
    } else {
        return Err(format!("invalid size format: {}", s));
    };

    let num: f64 = num_str
        .parse()
        .map_err(|_| format!("invalid number: {}", num_str))?;

    let multiplier: u64 = match unit {
        "B" => 1,
        "K" | "KB" | "KIB" => 1024,
        "M" | "MB" | "MIB" => 1024 * 1024,
        "G" | "GB" | "GIB" => 1024 * 1024 * 1024,
        "T" | "TB" | "TIB" => 1024 * 1024 * 1024 * 1024,
        _ => return Err(format!("unknown size unit: {}", unit)),
    };

    Ok((num * multiplier as f64) as u64)
}

/// Format bytes as human-readable size
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn cache_with_custom_root() {
        let temp = tempdir().unwrap();
        let cache = Cache::with_root(temp.path());

        assert_eq!(cache.root(), temp.path());
        assert_eq!(cache.packages_dir(), temp.path().join("packages"));
        assert_eq!(cache.envs_dir(), temp.path().join("envs"));
    }

    #[test]
    fn ensure_dirs_creates_structure() {
        let temp = tempdir().unwrap();
        let cache = Cache::with_root(temp.path());

        cache.ensure_dirs().unwrap();

        assert!(cache.packages_dir().exists());
        assert!(cache.envs_dir().exists());
        assert!(cache.build_dir().exists());
        assert!(cache.logs_dir().exists());
    }

    #[test]
    fn wheel_path_layout() {
        let temp = tempdir().unwrap();
        let cache = Cache::with_root(temp.path());

        let path = cache.wheel_path("requests", "2.31.0", "requests-2.31.0-py3-none-any.whl");
        assert_eq!(
            path,
            temp.path()
                .join("packages/requests/requests-2.31.0-py3-none-any.whl")
        );
    }

    #[test]
    fn has_wheel_returns_false_for_missing() {
        let temp = tempdir().unwrap();
        let cache = Cache::with_root(temp.path());

        assert!(!cache.has_wheel("foo", "1.0.0", "foo-1.0.0-py3-none-any.whl"));
    }

    #[test]
    fn gc_on_empty_cache() {
        let temp = tempdir().unwrap();
        let cache = Cache::with_root(temp.path());
        cache.ensure_dirs().unwrap();

        let result = cache.gc(None, false).unwrap();
        assert_eq!(result.freed_bytes, 0);
        assert_eq!(result.files_removed, 0);
    }

    #[test]
    fn gc_removes_files_when_over_limit() {
        let temp = tempdir().unwrap();
        let cache = Cache::with_root(temp.path());
        cache.ensure_dirs().unwrap();

        // Create some files
        let pkg_dir = cache.packages_dir().join("test-pkg");
        fs::create_dir_all(&pkg_dir).unwrap();

        let file1 = pkg_dir.join("file1.whl");
        let file2 = pkg_dir.join("file2.whl");

        fs::write(&file1, vec![0u8; 1024]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(&file2, vec![0u8; 1024]).unwrap();

        // GC with max 1KB should remove at least one file
        let result = cache.gc(Some(1024), false).unwrap();
        assert!(result.files_removed >= 1);
        assert!(result.freed_bytes >= 1024);
    }

    #[test]
    fn gc_dry_run_does_not_delete() {
        let temp = tempdir().unwrap();
        let cache = Cache::with_root(temp.path());
        cache.ensure_dirs().unwrap();

        let pkg_dir = cache.packages_dir().join("test-pkg");
        fs::create_dir_all(&pkg_dir).unwrap();
        let file = pkg_dir.join("file.whl");
        fs::write(&file, vec![0u8; 1024]).unwrap();

        let result = cache.gc(Some(0), true).unwrap();
        assert!(!result.would_remove.is_empty());
        assert_eq!(result.files_removed, 0);
        // File should still exist
        assert!(file.exists());
    }

    #[test]
    fn parse_size_various_formats() {
        assert_eq!(parse_size("100").unwrap(), 100);
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("1KB").unwrap(), 1024);
        assert_eq!(parse_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("10g").unwrap(), 10 * 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_size_invalid() {
        assert!(parse_size("invalid").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn format_size_various() {
        assert_eq!(format_size(100), "100 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
    }
}
