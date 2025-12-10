//! Global cache management for PyBun.
//!
//! Layout:
//! - ~/.cache/pybun/packages/  (wheels)
//! - ~/.cache/pybun/envs/      (virtual environments)
//! - ~/.cache/pybun/build/     (build object cache)
//! - ~/.cache/pybun/logs/      (structured event logs)

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const DEFAULT_CACHE_DIR: &str = ".cache/pybun";
const PACKAGES_DIR: &str = "packages";
const ENVS_DIR: &str = "envs";
const BUILD_DIR: &str = "build";
const LOGS_DIR: &str = "logs";

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

    /// Ensure all cache directories exist.
    pub fn ensure_dirs(&self) -> Result<()> {
        for dir in [
            self.packages_dir(),
            self.envs_dir(),
            self.build_dir(),
            self.logs_dir(),
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
}

