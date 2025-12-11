//! Path management and artifact layout for PyBun.
//!
//! This module defines the standard directory structure for PyBun's
//! data, cache, and configuration files.
//!
//! ## Directory Layout
//!
//! ```text
//! ~/.pybun/                     # Data directory (PYBUN_HOME)
//! ├── bin/                      # Symlinks to active Python versions
//! ├── python/                   # Managed Python installations
//! │   ├── 3.9.18/
//! │   ├── 3.10.13/
//! │   └── ...
//! ├── cache/                    # Cache directory
//! │   ├── packages/             # Downloaded wheels
//! │   ├── index/                # Cached package indexes
//! │   └── build/                # Build artifacts
//! ├── envs/                     # Virtual environments
//! └── logs/                     # Structured logs
//! ```

use std::env;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PathError {
    #[error("failed to determine home directory")]
    NoHomeDir,
    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, PathError>;

/// PyBun data directory manager.
///
/// Manages all paths related to PyBun's data, cache, and configuration.
#[derive(Debug, Clone)]
pub struct PyBunPaths {
    /// Root data directory (~/.pybun or PYBUN_HOME)
    root: PathBuf,
}

impl PyBunPaths {
    /// Create a new paths manager using default or env-configured location.
    ///
    /// Priority:
    /// 1. `PYBUN_HOME` environment variable
    /// 2. `~/.pybun`
    pub fn new() -> Result<Self> {
        let root = if let Ok(home) = env::var("PYBUN_HOME") {
            PathBuf::from(home)
        } else {
            let home_dir = dirs::home_dir().ok_or(PathError::NoHomeDir)?;
            home_dir.join(".pybun")
        };
        Ok(Self { root })
    }

    /// Create a paths manager with a custom root directory (useful for testing).
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Root data directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Binary symlinks directory.
    pub fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }

    /// Managed Python installations directory.
    pub fn python_dir(&self) -> PathBuf {
        self.root.join("python")
    }

    /// Specific Python version directory.
    pub fn python_version_dir(&self, version: &str) -> PathBuf {
        self.python_dir().join(version)
    }

    /// Python binary path for a specific version.
    pub fn python_binary(&self, version: &str) -> PathBuf {
        let version_dir = self.python_version_dir(version);
        if cfg!(windows) {
            version_dir.join("python.exe")
        } else {
            version_dir.join("bin").join("python3")
        }
    }

    /// Cache directory.
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }

    /// Cached packages (wheels) directory.
    pub fn packages_cache_dir(&self) -> PathBuf {
        self.cache_dir().join("packages")
    }

    /// Cached package indexes directory.
    pub fn index_cache_dir(&self) -> PathBuf {
        self.cache_dir().join("index")
    }

    /// Build artifacts cache directory.
    pub fn build_cache_dir(&self) -> PathBuf {
        self.cache_dir().join("build")
    }

    /// Virtual environments directory.
    pub fn envs_dir(&self) -> PathBuf {
        self.root.join("envs")
    }

    /// Logs directory.
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// Ensure all required directories exist.
    pub fn ensure_dirs(&self) -> Result<()> {
        let dirs = [
            self.root.clone(),
            self.bin_dir(),
            self.python_dir(),
            self.cache_dir(),
            self.packages_cache_dir(),
            self.index_cache_dir(),
            self.build_cache_dir(),
            self.envs_dir(),
            self.logs_dir(),
        ];

        for dir in dirs {
            if !dir.exists() {
                std::fs::create_dir_all(&dir).map_err(|source| PathError::CreateDir {
                    path: dir.clone(),
                    source,
                })?;
            }
        }

        Ok(())
    }
}

impl Default for PyBunPaths {
    fn default() -> Self {
        Self::new().expect("failed to initialize default paths")
    }
}

/// Artifact metadata for release builds.
#[derive(Debug, Clone)]
pub struct ArtifactInfo {
    /// Target triple (e.g., "x86_64-apple-darwin")
    pub target: String,
    /// Version string (e.g., "0.1.0")
    pub version: String,
    /// Git commit hash (short)
    pub commit: Option<String>,
}

impl ArtifactInfo {
    /// Create artifact info from build environment.
    pub fn from_env() -> Self {
        Self {
            target: env::var("TARGET").unwrap_or_else(|_| "unknown".to_string()),
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: option_env!("GIT_HASH").map(|s| s.to_string()),
        }
    }

    /// Generate artifact filename.
    pub fn filename(&self) -> String {
        format!("pybun-{}-{}", self.version, self.target)
    }

    /// Generate artifact filename with extension.
    pub fn filename_with_ext(&self, ext: &str) -> String {
        format!("{}.{}", self.filename(), ext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn paths_with_custom_root() {
        let temp = tempdir().unwrap();
        let paths = PyBunPaths::with_root(temp.path());

        assert_eq!(paths.root(), temp.path());
        assert_eq!(paths.bin_dir(), temp.path().join("bin"));
        assert_eq!(paths.python_dir(), temp.path().join("python"));
        assert_eq!(paths.cache_dir(), temp.path().join("cache"));
    }

    #[test]
    fn python_version_paths() {
        let temp = tempdir().unwrap();
        let paths = PyBunPaths::with_root(temp.path());

        assert_eq!(
            paths.python_version_dir("3.11.0"),
            temp.path().join("python").join("3.11.0")
        );

        #[cfg(not(windows))]
        assert_eq!(
            paths.python_binary("3.11.0"),
            temp.path()
                .join("python")
                .join("3.11.0")
                .join("bin")
                .join("python3")
        );
    }

    #[test]
    fn cache_paths() {
        let temp = tempdir().unwrap();
        let paths = PyBunPaths::with_root(temp.path());

        assert_eq!(
            paths.packages_cache_dir(),
            temp.path().join("cache").join("packages")
        );
        assert_eq!(
            paths.index_cache_dir(),
            temp.path().join("cache").join("index")
        );
        assert_eq!(
            paths.build_cache_dir(),
            temp.path().join("cache").join("build")
        );
    }

    #[test]
    fn ensure_dirs_creates_structure() {
        let temp = tempdir().unwrap();
        let paths = PyBunPaths::with_root(temp.path());

        paths.ensure_dirs().unwrap();

        assert!(paths.bin_dir().exists());
        assert!(paths.python_dir().exists());
        assert!(paths.cache_dir().exists());
        assert!(paths.packages_cache_dir().exists());
        assert!(paths.index_cache_dir().exists());
        assert!(paths.build_cache_dir().exists());
        assert!(paths.envs_dir().exists());
        assert!(paths.logs_dir().exists());
    }

    #[test]
    fn artifact_info_filename() {
        let info = ArtifactInfo {
            target: "x86_64-apple-darwin".to_string(),
            version: "0.1.0".to_string(),
            commit: Some("abc1234".to_string()),
        };

        assert_eq!(info.filename(), "pybun-0.1.0-x86_64-apple-darwin");
        assert_eq!(
            info.filename_with_ext("tar.gz"),
            "pybun-0.1.0-x86_64-apple-darwin.tar.gz"
        );
    }
}
