//! PEP 723 virtual environment cache.
//!
//! Caches virtual environments based on dependency hash to avoid
//! recreating venvs for scripts with identical dependencies.
//!
//! Cache layout:
//! ```text
//! ~/.cache/pybun/pep723-envs/
//!   {hash}/
//!     venv/           # The actual virtual environment
//!     deps.json       # Dependency list for debugging
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use thiserror::Error;

const PEP723_ENVS_DIR: &str = "pep723-envs";

#[derive(Debug, Error)]
pub enum Pep723CacheError {
    #[error("failed to determine home directory")]
    NoHomeDir,
    #[error("failed to create cache directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Pep723CacheError>;

/// Metadata stored alongside cached venv
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedEnvInfo {
    /// Hash of the dependencies
    pub hash: String,
    /// Original dependencies list
    pub dependencies: Vec<String>,
    /// Python version used to create the venv
    pub python_version: String,
    /// When the venv was created
    pub created_at: u64,
    /// Last time the venv was used
    pub last_used: u64,
}

/// PEP 723 virtual environment cache manager.
#[derive(Debug, Clone)]
pub struct Pep723Cache {
    root: PathBuf,
}

impl Pep723Cache {
    /// Create a new cache instance using default or env-configured location.
    pub fn new() -> Result<Self> {
        let root = if let Ok(home) = std::env::var("PYBUN_HOME") {
            PathBuf::from(home)
        } else {
            let home_dir = dirs::home_dir().ok_or(Pep723CacheError::NoHomeDir)?;
            home_dir.join(".cache/pybun")
        };
        Ok(Self { root })
    }

    /// Create a cache instance with a custom root directory (useful for testing).
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Root directory for PEP 723 venv cache
    pub fn envs_dir(&self) -> PathBuf {
        self.root.join(PEP723_ENVS_DIR)
    }

    /// Get the cache directory for a specific hash
    pub fn cache_dir_for_hash(&self, hash: &str) -> PathBuf {
        self.envs_dir().join(hash)
    }

    /// Get the venv path for a specific hash
    pub fn venv_path_for_hash(&self, hash: &str) -> PathBuf {
        self.cache_dir_for_hash(hash).join("venv")
    }

    /// Get the Python binary path in a cached venv
    pub fn python_path_for_hash(&self, hash: &str) -> PathBuf {
        let venv = self.venv_path_for_hash(hash);
        if cfg!(windows) {
            venv.join("Scripts").join("python.exe")
        } else {
            venv.join("bin").join("python")
        }
    }

    /// Compute a deterministic hash for a list of dependencies.
    ///
    /// The hash is computed by:
    /// 1. Normalizing dependencies (lowercase, strip whitespace)
    /// 2. Sorting them alphabetically
    /// 3. Joining with newlines
    /// 4. Computing SHA-256
    pub fn compute_deps_hash(dependencies: &[String]) -> String {
        let mut normalized: Vec<String> = dependencies
            .iter()
            .map(|d| d.trim().to_lowercase())
            .collect();
        normalized.sort();

        let joined = normalized.join("\n");
        let mut hasher = Sha256::new();
        hasher.update(joined.as_bytes());
        let result = hasher.finalize();

        // Use first 16 bytes (32 hex chars) for shorter paths
        hex::encode(&result[..16])
    }

    /// Check if a cached venv exists for the given dependencies.
    pub fn get_cached_env(&self, dependencies: &[String]) -> Option<CachedEnvPath> {
        let hash = Self::compute_deps_hash(dependencies);
        let venv_path = self.venv_path_for_hash(&hash);
        let python_path = self.python_path_for_hash(&hash);

        if venv_path.exists() && python_path.exists() {
            // Update last_used timestamp
            let _ = self.update_last_used(&hash);
            Some(CachedEnvPath {
                hash,
                venv_path,
                python_path,
                cache_hit: true,
            })
        } else {
            None
        }
    }

    /// Create a new cached venv for the given dependencies.
    ///
    /// Returns the path where the venv should be created.
    /// The caller is responsible for actually creating the venv and installing deps.
    pub fn prepare_cache_dir(&self, dependencies: &[String]) -> Result<CachedEnvPath> {
        let hash = Self::compute_deps_hash(dependencies);
        let cache_dir = self.cache_dir_for_hash(&hash);
        let venv_path = self.venv_path_for_hash(&hash);
        let python_path = self.python_path_for_hash(&hash);

        // Ensure parent directories exist
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir).map_err(|source| Pep723CacheError::CreateDir {
                path: cache_dir.clone(),
                source,
            })?;
        }

        Ok(CachedEnvPath {
            hash,
            venv_path,
            python_path,
            cache_hit: false,
        })
    }

    /// Record metadata about a cached venv after creation.
    pub fn record_cache_entry(
        &self,
        hash: &str,
        dependencies: &[String],
        python_version: &str,
    ) -> Result<()> {
        let cache_dir = self.cache_dir_for_hash(hash);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let info = CachedEnvInfo {
            hash: hash.to_string(),
            dependencies: dependencies.to_vec(),
            python_version: python_version.to_string(),
            created_at: now,
            last_used: now,
        };

        let info_path = cache_dir.join("deps.json");
        let json = serde_json::to_string_pretty(&info)?;
        let mut file = fs::File::create(&info_path)?;
        file.write_all(json.as_bytes())?;

        Ok(())
    }

    /// Update the last_used timestamp for a cached venv.
    fn update_last_used(&self, hash: &str) -> Result<()> {
        let cache_dir = self.cache_dir_for_hash(hash);
        let info_path = cache_dir.join("deps.json");

        if info_path.exists() {
            let content = fs::read_to_string(&info_path)?;
            let mut info: CachedEnvInfo = serde_json::from_str(&content)?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            info.last_used = now;

            let json = serde_json::to_string_pretty(&info)?;
            let mut file = fs::File::create(&info_path)?;
            file.write_all(json.as_bytes())?;
        }

        Ok(())
    }

    /// List all cached environments.
    pub fn list_cached_envs(&self) -> Result<Vec<CachedEnvInfo>> {
        let envs_dir = self.envs_dir();
        let mut envs = Vec::new();

        if !envs_dir.exists() {
            return Ok(envs);
        }

        for entry in fs::read_dir(&envs_dir)? {
            let entry = entry?;
            if entry.path().is_dir() {
                let info_path = entry.path().join("deps.json");
                if info_path.exists()
                    && let Ok(content) = fs::read_to_string(&info_path)
                    && let Ok(info) = serde_json::from_str::<CachedEnvInfo>(&content)
                {
                    envs.push(info);
                }
            }
        }

        // Sort by last_used (most recent first)
        envs.sort_by(|a, b| b.last_used.cmp(&a.last_used));

        Ok(envs)
    }

    /// Remove a cached environment by hash.
    pub fn remove_env(&self, hash: &str) -> Result<bool> {
        let cache_dir = self.cache_dir_for_hash(hash);
        if cache_dir.exists() {
            fs::remove_dir_all(&cache_dir)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Calculate total size of cached environments.
    pub fn total_size(&self) -> Result<u64> {
        let envs_dir = self.envs_dir();
        if !envs_dir.exists() {
            return Ok(0);
        }
        Self::dir_size(&envs_dir)
    }

    fn dir_size(path: &Path) -> Result<u64> {
        let mut total = 0;
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    total += Self::dir_size(&path)?;
                } else {
                    total += entry.metadata()?.len();
                }
            }
        }
        Ok(total)
    }

    /// Run garbage collection on PEP 723 venv cache.
    /// Removes least recently used environments until under max_bytes.
    pub fn gc(&self, max_bytes: Option<u64>, dry_run: bool) -> Result<Pep723GcResult> {
        let mut result = Pep723GcResult::default();

        let mut envs = self.list_cached_envs()?;
        // Sort by last_used (oldest first for LRU eviction)
        envs.sort_by(|a, b| a.last_used.cmp(&b.last_used));

        result.size_before = self.total_size()?;
        let max_bytes = max_bytes.unwrap_or(u64::MAX);
        let mut current_size = result.size_before;

        for env in envs {
            if current_size <= max_bytes {
                break;
            }

            let cache_dir = self.cache_dir_for_hash(&env.hash);
            let env_size = Self::dir_size(&cache_dir)?;

            if dry_run {
                result.would_remove.push(env.hash.clone());
            } else {
                if let Err(e) = fs::remove_dir_all(&cache_dir) {
                    eprintln!("warning: failed to remove {}: {}", cache_dir.display(), e);
                    continue;
                }
                result.envs_removed += 1;
            }

            result.freed_bytes += env_size;
            current_size = current_size.saturating_sub(env_size);
        }

        result.size_after = if dry_run {
            result.size_before - result.freed_bytes
        } else {
            current_size
        };

        Ok(result)
    }
}

/// Result of looking up or creating a cached venv
#[derive(Debug, Clone)]
pub struct CachedEnvPath {
    /// Hash of the dependencies
    pub hash: String,
    /// Path to the venv directory
    pub venv_path: PathBuf,
    /// Path to the Python binary in the venv
    pub python_path: PathBuf,
    /// Whether this was a cache hit
    pub cache_hit: bool,
}

/// Result of garbage collection on PEP 723 cache
#[derive(Debug, Clone, Default)]
pub struct Pep723GcResult {
    /// Total bytes freed
    pub freed_bytes: u64,
    /// Number of environments removed
    pub envs_removed: usize,
    /// Hashes that would be removed (dry-run)
    pub would_remove: Vec<String>,
    /// Cache size before GC
    pub size_before: u64,
    /// Cache size after GC
    pub size_after: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn compute_deps_hash_deterministic() {
        let deps1 = vec!["requests>=2.28.0".to_string(), "numpy".to_string()];
        let deps2 = vec!["requests>=2.28.0".to_string(), "numpy".to_string()];

        assert_eq!(
            Pep723Cache::compute_deps_hash(&deps1),
            Pep723Cache::compute_deps_hash(&deps2)
        );
    }

    #[test]
    fn compute_deps_hash_order_independent() {
        let deps1 = vec!["numpy".to_string(), "requests>=2.28.0".to_string()];
        let deps2 = vec!["requests>=2.28.0".to_string(), "numpy".to_string()];

        assert_eq!(
            Pep723Cache::compute_deps_hash(&deps1),
            Pep723Cache::compute_deps_hash(&deps2)
        );
    }

    #[test]
    fn compute_deps_hash_case_insensitive() {
        let deps1 = vec!["NUMPY".to_string(), "Requests>=2.28.0".to_string()];
        let deps2 = vec!["numpy".to_string(), "requests>=2.28.0".to_string()];

        assert_eq!(
            Pep723Cache::compute_deps_hash(&deps1),
            Pep723Cache::compute_deps_hash(&deps2)
        );
    }

    #[test]
    fn compute_deps_hash_whitespace_normalized() {
        let deps1 = vec!["  numpy  ".to_string(), " requests ".to_string()];
        let deps2 = vec!["numpy".to_string(), "requests".to_string()];

        assert_eq!(
            Pep723Cache::compute_deps_hash(&deps1),
            Pep723Cache::compute_deps_hash(&deps2)
        );
    }

    #[test]
    fn compute_deps_hash_different_deps() {
        let deps1 = vec!["numpy".to_string()];
        let deps2 = vec!["pandas".to_string()];

        assert_ne!(
            Pep723Cache::compute_deps_hash(&deps1),
            Pep723Cache::compute_deps_hash(&deps2)
        );
    }

    #[test]
    fn empty_deps_hash() {
        let hash = Pep723Cache::compute_deps_hash(&[]);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn cache_with_custom_root() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());

        assert_eq!(cache.envs_dir(), temp.path().join("pep723-envs"));
    }

    #[test]
    fn get_cached_env_returns_none_for_missing() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());

        let deps = vec!["numpy".to_string()];
        assert!(cache.get_cached_env(&deps).is_none());
    }

    #[test]
    fn prepare_cache_dir_creates_dir() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());

        let deps = vec!["numpy".to_string()];
        let result = cache.prepare_cache_dir(&deps).unwrap();

        assert!(!result.cache_hit);
        assert!(result.venv_path.parent().unwrap().exists());
    }

    #[test]
    fn record_and_list_cache_entry() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());

        let deps = vec!["numpy".to_string(), "requests".to_string()];
        let prepared = cache.prepare_cache_dir(&deps).unwrap();

        // Create the venv directory to simulate actual venv creation
        fs::create_dir_all(&prepared.venv_path).unwrap();

        // Record the cache entry
        cache
            .record_cache_entry(&prepared.hash, &deps, "3.11.0")
            .unwrap();

        // List should return it
        let envs = cache.list_cached_envs().unwrap();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].hash, prepared.hash);
        assert_eq!(envs[0].dependencies, deps);
        assert_eq!(envs[0].python_version, "3.11.0");
    }

    #[test]
    fn remove_env_works() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());

        let deps = vec!["numpy".to_string()];
        let prepared = cache.prepare_cache_dir(&deps).unwrap();
        fs::create_dir_all(&prepared.venv_path).unwrap();
        cache
            .record_cache_entry(&prepared.hash, &deps, "3.11.0")
            .unwrap();

        // Remove it
        assert!(cache.remove_env(&prepared.hash).unwrap());

        // Should be gone
        let envs = cache.list_cached_envs().unwrap();
        assert!(envs.is_empty());
    }

    #[test]
    fn gc_removes_lru_envs() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());

        // Create two envs with different ages
        let deps1 = vec!["numpy".to_string()];
        let deps2 = vec!["pandas".to_string()];

        let p1 = cache.prepare_cache_dir(&deps1).unwrap();
        fs::create_dir_all(&p1.venv_path).unwrap();
        // Create a file to give it some size
        fs::write(p1.venv_path.join("test.txt"), vec![0u8; 1024]).unwrap();
        cache
            .record_cache_entry(&p1.hash, &deps1, "3.11.0")
            .unwrap();

        // Small delay to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(50));

        let p2 = cache.prepare_cache_dir(&deps2).unwrap();
        fs::create_dir_all(&p2.venv_path).unwrap();
        fs::write(p2.venv_path.join("test.txt"), vec![0u8; 1024]).unwrap();
        cache
            .record_cache_entry(&p2.hash, &deps2, "3.11.0")
            .unwrap();

        // GC with very small limit should remove oldest
        let result = cache.gc(Some(1024), false).unwrap();
        assert!(result.envs_removed >= 1);
        assert!(result.freed_bytes >= 1024);
    }

    #[test]
    fn gc_dry_run_does_not_delete() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());

        let deps = vec!["numpy".to_string()];
        let prepared = cache.prepare_cache_dir(&deps).unwrap();
        fs::create_dir_all(&prepared.venv_path).unwrap();
        fs::write(prepared.venv_path.join("test.txt"), vec![0u8; 1024]).unwrap();
        cache
            .record_cache_entry(&prepared.hash, &deps, "3.11.0")
            .unwrap();

        let result = cache.gc(Some(0), true).unwrap();
        assert!(!result.would_remove.is_empty());
        assert_eq!(result.envs_removed, 0);

        // Should still exist
        let envs = cache.list_cached_envs().unwrap();
        assert_eq!(envs.len(), 1);
    }
}
