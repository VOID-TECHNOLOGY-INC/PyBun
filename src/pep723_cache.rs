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
use std::fs::OpenOptions;
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
    #[error("failed to lock script environment {path}: {source}")]
    Lock {
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
    /// Index settings used for dependency resolution
    #[serde(default)]
    pub index_settings: Vec<String>,
    /// Script lock hash (if any)
    #[serde(default)]
    pub lock_hash: Option<String>,
    /// When the venv was created
    pub created_at: u64,
    /// Last time the venv was used
    pub last_used: u64,
}

/// Cache key information for a PEP 723 environment.
#[derive(Debug, Clone)]
pub struct Pep723CacheKey {
    /// Hash used to locate the cached environment
    pub hash: String,
    /// Normalized dependency list
    pub dependencies: Vec<String>,
    /// Python version string
    pub python_version: String,
    /// Normalized index settings
    pub index_settings: Vec<String>,
    /// Lock hash for script lock (if any)
    pub lock_hash: Option<String>,
}

impl Pep723CacheKey {
    pub fn new(
        dependencies: &[String],
        python_version: &str,
        index_settings: &[String],
        lock_hash: Option<&str>,
    ) -> Self {
        let mut normalized_deps: Vec<String> = dependencies
            .iter()
            .map(|d| d.trim().to_lowercase())
            .collect();
        normalized_deps.sort();

        let mut normalized_indexes: Vec<String> = index_settings
            .iter()
            .map(|i| i.trim().to_lowercase())
            .collect();
        normalized_indexes.sort();

        let mut parts = Vec::new();
        parts.push(format!("python={}", python_version.trim()));
        parts.push(format!("deps={}", normalized_deps.join("\n")));
        parts.push(format!("index={}", normalized_indexes.join("\n")));
        if let Some(lock_hash) = lock_hash {
            parts.push(format!("lock={}", lock_hash.trim()));
        }

        let joined = parts.join("\n");
        let mut hasher = Sha256::new();
        hasher.update(joined.as_bytes());
        let result = hasher.finalize();
        let hash = hex::encode(&result[..16]);

        Self {
            hash,
            dependencies: normalized_deps,
            python_version: python_version.trim().to_string(),
            index_settings: normalized_indexes,
            lock_hash: lock_hash.map(|v| v.trim().to_string()),
        }
    }
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

    /// Determine the stable script environment root for a script path.
    pub fn script_env_root(&self, script_path: &Path) -> Result<PathBuf> {
        let absolute =
            std::path::absolute(script_path).unwrap_or_else(|_| script_path.to_path_buf());
        let mut hasher = Sha256::new();
        hasher.update(absolute.to_string_lossy().as_bytes());
        let digest = hex::encode(&hasher.finalize()[..16]);

        let entry = if let Some(stem) = script_path.file_stem().and_then(|s| s.to_str()) {
            if let Some(cleaned) = sanitize_cache_name(stem) {
                format!("{}-{}", cleaned, digest)
            } else {
                digest
            }
        } else {
            digest
        };

        Ok(self.envs_dir().join(entry))
    }

    /// Get the venv path inside a script environment root.
    pub fn venv_path_for_root(&self, root: &Path) -> PathBuf {
        root.join("venv")
    }

    /// Get the Python binary path for a given venv path.
    pub fn python_path_for_venv(&self, venv_path: &Path) -> PathBuf {
        if cfg!(windows) {
            venv_path.join("Scripts").join("python.exe")
        } else {
            venv_path.join("bin").join("python")
        }
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
    pub fn get_cached_env(&self, cache_key: &Pep723CacheKey) -> Option<CachedEnvPath> {
        let hash = &cache_key.hash;
        let venv_path = self.venv_path_for_hash(hash);
        let python_path = self.python_path_for_hash(hash);

        if venv_path.exists() && python_path.exists() {
            // Update last_used timestamp
            let _ = self.update_last_used(hash);
            Some(CachedEnvPath {
                hash: hash.to_string(),
                venv_path,
                python_path,
                cache_hit: true,
            })
        } else {
            None
        }
    }

    /// Fast cache validation using mtime comparison.
    ///
    /// Returns the cached environment if:
    /// 1. The venv exists
    /// 2. The script hasn't been modified since the cache was created
    ///
    /// This avoids expensive hash computation on every run.
    pub fn get_cached_env_fast(
        &self,
        script_path: &Path,
        cache_root: &Path,
    ) -> Option<CachedEnvPath> {
        let venv_path = self.venv_path_for_root(cache_root);
        let python_path = self.python_path_for_venv(&venv_path);
        let deps_json_path = cache_root.join("deps.json");

        // Fast path: check if venv and deps.json exist
        if !venv_path.exists() || !python_path.exists() || !deps_json_path.exists() {
            return None;
        }

        // Mtime-based validation: if script is older than cache, skip hash check
        if let (Ok(script_meta), Ok(cache_meta)) =
            (fs::metadata(script_path), fs::metadata(&deps_json_path))
        {
            if let (Ok(script_mtime), Ok(cache_mtime)) =
                (script_meta.modified(), cache_meta.modified())
            {
                // Script hasn't been modified since cache was created
                if script_mtime <= cache_mtime {
                    // Update last_used timestamp (throttled)
                    let _ = self.update_last_used_at(cache_root);

                    // Return cached environment
                    return Some(CachedEnvPath {
                        hash: cache_root
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        venv_path,
                        python_path,
                        cache_hit: true,
                    });
                }
            }
        }

        // Fallback: require full validation
        None
    }

    /// Create a new cached venv for the given dependencies.
    ///
    /// Returns the path where the venv should be created.
    /// The caller is responsible for actually creating the venv and installing deps.
    pub fn prepare_cache_dir(&self, cache_key: &Pep723CacheKey) -> Result<CachedEnvPath> {
        let hash = &cache_key.hash;
        let cache_dir = self.cache_dir_for_hash(hash);
        let venv_path = self.venv_path_for_hash(hash);
        let python_path = self.python_path_for_hash(hash);

        // Ensure parent directories exist
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir).map_err(|source| Pep723CacheError::CreateDir {
                path: cache_dir.clone(),
                source,
            })?;
        }

        Ok(CachedEnvPath {
            hash: hash.to_string(),
            venv_path,
            python_path,
            cache_hit: false,
        })
    }

    /// Record metadata about a cached venv after creation.
    pub fn record_cache_entry(&self, cache_key: &Pep723CacheKey) -> Result<()> {
        let cache_dir = self.cache_dir_for_hash(&cache_key.hash);
        self.record_cache_entry_at(&cache_dir, cache_key)
    }

    /// Record metadata about a cached venv in a specific root directory.
    pub fn record_cache_entry_at(&self, root: &Path, cache_key: &Pep723CacheKey) -> Result<()> {
        if !root.exists() {
            fs::create_dir_all(root).map_err(|source| Pep723CacheError::CreateDir {
                path: root.to_path_buf(),
                source,
            })?;
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let info = CachedEnvInfo {
            hash: cache_key.hash.clone(),
            dependencies: cache_key.dependencies.clone(),
            python_version: cache_key.python_version.clone(),
            index_settings: cache_key.index_settings.clone(),
            lock_hash: cache_key.lock_hash.clone(),
            created_at: now,
            last_used: now,
        };

        let info_path = root.join("deps.json");
        let json = serde_json::to_string_pretty(&info)?;
        let mut file = fs::File::create(&info_path)?;
        file.write_all(json.as_bytes())?;

        Ok(())
    }

    /// Read metadata about a cached venv from a specific root directory.
    pub fn read_cache_entry(&self, root: &Path) -> Result<Option<CachedEnvInfo>> {
        let info_path = root.join("deps.json");
        if !info_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&info_path)?;
        let info: CachedEnvInfo = serde_json::from_str(&content)?;
        Ok(Some(info))
    }

    /// Determine if the cached entry matches the expected cache key.
    pub fn cache_entry_matches_key(info: &CachedEnvInfo, cache_key: &Pep723CacheKey) -> bool {
        info.hash == cache_key.hash
            && info.dependencies == cache_key.dependencies
            && info.python_version == cache_key.python_version
            && info.index_settings == cache_key.index_settings
            && info.lock_hash == cache_key.lock_hash
    }

    /// Update the last_used timestamp for a cached venv.
    fn update_last_used(&self, hash: &str) -> Result<()> {
        let cache_dir = self.cache_dir_for_hash(hash);
        self.update_last_used_at(&cache_dir)
    }

    /// Update the last_used timestamp for a cached venv in a specific root directory.
    pub fn update_last_used_at(&self, root: &Path) -> Result<()> {
        let info_path = root.join("deps.json");

        if info_path.exists() {
            // Optimization: Check file mtime first to avoid reading/parsing operations.
            // If the file was modified recently (e.g. < 1 hour), we assume last_used is up to date enough.
            // This prevents the expensive Read-Modify-Write cycle on every warm start.
            if let Ok(metadata) = fs::metadata(&info_path)
                && let Ok(modified) = metadata.modified()
            {
                let now = SystemTime::now();
                if let Ok(duration) = now.duration_since(modified) {
                    // 1 hour window to skip updates
                    if duration.as_secs() < 3600 {
                        return Ok(());
                    }
                }
            }

            let content = fs::read_to_string(&info_path)?;
            let mut info: CachedEnvInfo = serde_json::from_str(&content)?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Optimization: Only update if older than 1 hour (3600 seconds)
            // This avoids writing to disk on every run (Read-Modify-Write cycle)
            if now.saturating_sub(info.last_used) < 3600 {
                return Ok(());
            }

            info.last_used = now;

            let json = serde_json::to_string_pretty(&info)?;
            let mut file = fs::File::create(&info_path)?;
            file.write_all(json.as_bytes())?;
        }

        Ok(())
    }

    /// Acquire an exclusive lock for a script environment root.
    pub fn lock_script_env(&self, root: &Path) -> Result<ScriptEnvLock> {
        if !root.exists() {
            fs::create_dir_all(root).map_err(|source| Pep723CacheError::CreateDir {
                path: root.to_path_buf(),
                source,
            })?;
        }
        let lock_path = root.join(".lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&lock_path)
            .map_err(|source| Pep723CacheError::Lock {
                path: lock_path.clone(),
                source,
            })?;
        fs2::FileExt::lock_exclusive(&file).map_err(|source| Pep723CacheError::Lock {
            path: lock_path,
            source,
        })?;
        Ok(ScriptEnvLock { _file: file })
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

/// Guard for a script environment lock file.
#[derive(Debug)]
pub struct ScriptEnvLock {
    _file: fs::File,
}

fn sanitize_cache_name(name: &str) -> Option<String> {
    let cleaned: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
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
        let key = Pep723CacheKey::new(&deps, "3.11.0", &[], None);
        assert!(cache.get_cached_env(&key).is_none());
    }

    #[test]
    fn prepare_cache_dir_creates_dir() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());

        let deps = vec!["numpy".to_string()];
        let key = Pep723CacheKey::new(&deps, "3.11.0", &[], None);
        let result = cache.prepare_cache_dir(&key).unwrap();

        assert!(!result.cache_hit);
        assert!(result.venv_path.parent().unwrap().exists());
    }

    #[test]
    fn record_and_list_cache_entry() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());

        let deps = vec!["numpy".to_string(), "requests".to_string()];
        let key = Pep723CacheKey::new(&deps, "3.11.0", &[], None);
        let prepared = cache.prepare_cache_dir(&key).unwrap();

        // Create the venv directory to simulate actual venv creation
        fs::create_dir_all(&prepared.venv_path).unwrap();

        // Record the cache entry
        cache.record_cache_entry(&key).unwrap();

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
        let key = Pep723CacheKey::new(&deps, "3.11.0", &[], None);
        let prepared = cache.prepare_cache_dir(&key).unwrap();
        fs::create_dir_all(&prepared.venv_path).unwrap();
        cache.record_cache_entry(&key).unwrap();

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

        let key1 = Pep723CacheKey::new(&deps1, "3.11.0", &[], None);
        let p1 = cache.prepare_cache_dir(&key1).unwrap();
        fs::create_dir_all(&p1.venv_path).unwrap();
        // Create a file to give it some size
        fs::write(p1.venv_path.join("test.txt"), vec![0u8; 1024]).unwrap();
        cache.record_cache_entry(&key1).unwrap();

        // Small delay to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(50));

        let key2 = Pep723CacheKey::new(&deps2, "3.11.0", &[], None);
        let p2 = cache.prepare_cache_dir(&key2).unwrap();
        fs::create_dir_all(&p2.venv_path).unwrap();
        fs::write(p2.venv_path.join("test.txt"), vec![0u8; 1024]).unwrap();
        cache.record_cache_entry(&key2).unwrap();

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
        let key = Pep723CacheKey::new(&deps, "3.11.0", &[], None);
        let prepared = cache.prepare_cache_dir(&key).unwrap();
        fs::create_dir_all(&prepared.venv_path).unwrap();
        fs::write(prepared.venv_path.join("test.txt"), vec![0u8; 1024]).unwrap();
        cache.record_cache_entry(&key).unwrap();

        let result = cache.gc(Some(0), true).unwrap();
        assert!(!result.would_remove.is_empty());
        assert_eq!(result.envs_removed, 0);

        // Should still exist
        let envs = cache.list_cached_envs().unwrap();
        assert_eq!(envs.len(), 1);
    }

    #[test]
    fn script_env_root_uses_stable_name() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());
        let script_path = temp.path().join("my_script.py");
        fs::write(&script_path, "print('hello')").unwrap();

        let root = cache.script_env_root(&script_path).unwrap();
        let name = root.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("my_script-"));
    }

    #[test]
    fn cache_entry_matches_key_checks_fields() {
        let deps = vec!["requests".to_string()];
        let indexes = vec!["https://pypi.org/simple".to_string()];
        let key = Pep723CacheKey::new(&deps, "3.11.0", &indexes, Some("lock-hash"));

        let info = CachedEnvInfo {
            hash: key.hash.clone(),
            dependencies: key.dependencies.clone(),
            python_version: key.python_version.clone(),
            index_settings: key.index_settings.clone(),
            lock_hash: key.lock_hash.clone(),
            created_at: 0,
            last_used: 0,
        };

        assert!(Pep723Cache::cache_entry_matches_key(&info, &key));
    }

    #[test]
    fn record_and_read_cache_entry_at_root() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());
        let script_path = temp.path().join("script.py");
        fs::write(&script_path, "print('hello')").unwrap();

        let root = cache.script_env_root(&script_path).unwrap();
        let key = Pep723CacheKey::new(&["requests".to_string()], "3.11.0", &[], None);

        cache.record_cache_entry_at(&root, &key).unwrap();
        let info = cache.read_cache_entry(&root).unwrap().unwrap();
        assert!(Pep723Cache::cache_entry_matches_key(&info, &key));
    }

    #[test]
    fn lock_script_env_prevents_second_lock() {
        let temp = tempdir().unwrap();
        let cache = Pep723Cache::with_root(temp.path());
        let root = temp.path().join("env");

        let _lock = cache.lock_script_env(&root).unwrap();

        let lock_path = root.join(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        let result = fs2::FileExt::try_lock_exclusive(&file);
        assert!(result.is_err());
    }

    #[test]
    fn cache_key_includes_python_version() {
        let deps = vec!["requests".to_string()];
        let index = vec!["https://pypi.org/simple".to_string()];
        let key1 = Pep723CacheKey::new(&deps, "3.11.0", &index, None);
        let key2 = Pep723CacheKey::new(&deps, "3.12.0", &index, None);

        assert_ne!(key1.hash, key2.hash);
    }

    #[test]
    fn cache_key_includes_index_settings() {
        let deps = vec!["requests".to_string()];
        let key1 = Pep723CacheKey::new(
            &deps,
            "3.11.0",
            &["https://pypi.org/simple".to_string()],
            None,
        );
        let key2 = Pep723CacheKey::new(
            &deps,
            "3.11.0",
            &["https://example.com/simple".to_string()],
            None,
        );

        assert_ne!(key1.hash, key2.hash);
    }

    #[test]
    fn cache_key_includes_lock_hash() {
        let deps = vec!["requests".to_string()];
        let index = vec!["https://pypi.org/simple".to_string()];
        let key1 = Pep723CacheKey::new(&deps, "3.11.0", &index, Some("lock-a"));
        let key2 = Pep723CacheKey::new(&deps, "3.11.0", &index, Some("lock-b"));

        assert_ne!(key1.hash, key2.hash);
    }
}
