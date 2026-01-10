use crate::resolver::{InMemoryIndex, PackageArtifacts, Wheel};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Package record as stored in the simple JSON index fixture.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct IndexPackage {
    pub name: String,
    pub version: String,
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub wheels: Vec<IndexWheel>,
    #[serde(default)]
    pub sdist: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct IndexWheel {
    pub file: String,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub hash: Option<String>,
}

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("failed to read index {path}: {source}")]
    Io {
        source: std::io::Error,
        path: PathBuf,
    },
    #[error("failed to parse index json: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("index not found in cache and offline mode is enabled")]
    OfflineNotCached,
}

pub type Result<T> = std::result::Result<T, IndexError>;

/// Load a JSON index file into an in-memory index usable by the resolver.
pub fn load_index_from_path(path: impl AsRef<Path>) -> Result<InMemoryIndex> {
    let path = path.as_ref();
    let data = fs::read_to_string(path).map_err(|source| IndexError::Io {
        source,
        path: path.to_path_buf(),
    })?;
    let packages: Vec<IndexPackage> = serde_json::from_str(&data)?;
    Ok(build_index(packages))
}

fn build_index(packages: Vec<IndexPackage>) -> InMemoryIndex {
    let mut index = InMemoryIndex::default();
    for pkg in packages {
        let artifacts = if pkg.wheels.is_empty() && pkg.sdist.is_none() {
            PackageArtifacts::universal(&pkg.name, &pkg.version)
        } else {
            let wheels = pkg
                .wheels
                .iter()
                .map(|w| Wheel {
                    file: w.file.clone(),
                    url: None,
                    hash: w.hash.clone(),
                    platforms: if w.platforms.is_empty() {
                        vec!["any".into()]
                    } else {
                        w.platforms.clone()
                    },
                })
                .collect();
            PackageArtifacts {
                wheels,
                sdist: pkg.sdist.clone(),
            }
        };
        index.add_with_artifacts(pkg.name, pkg.version, pkg.dependencies, artifacts);
    }
    index
}

/// Index cache for offline support.
///
/// The cache stores index data locally so that resolution can work without
/// network access when the index has been previously fetched.
#[derive(Debug)]
pub struct IndexCache {
    cache_dir: PathBuf,
}

impl IndexCache {
    /// Create a new index cache with the specified cache directory.
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
        }
    }

    /// Get the cache file path for a given index name.
    fn cache_path(&self, index_name: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", index_name))
    }

    /// Save index packages to the cache.
    pub fn save(&self, index_name: &str, packages: &[IndexPackage]) -> Result<()> {
        // Ensure cache directory exists
        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir).map_err(|source| IndexError::Io {
                source,
                path: self.cache_dir.clone(),
            })?;
        }

        let path = self.cache_path(index_name);
        let data = serde_json::to_string_pretty(packages)?;
        fs::write(&path, data).map_err(|source| IndexError::Io { source, path })?;
        Ok(())
    }

    /// Load index packages from the cache.
    pub fn load(&self, index_name: &str) -> Result<Vec<IndexPackage>> {
        let path = self.cache_path(index_name);
        let data = fs::read_to_string(&path).map_err(|source| IndexError::Io { source, path })?;
        let packages: Vec<IndexPackage> = serde_json::from_str(&data)?;
        Ok(packages)
    }

    /// Check if an index is cached.
    pub fn is_cached(&self, index_name: &str) -> bool {
        self.cache_path(index_name).exists()
    }

    /// Remove an index from the cache.
    pub fn remove(&self, index_name: &str) -> Result<()> {
        let path = self.cache_path(index_name);
        if path.exists() {
            fs::remove_file(&path).map_err(|source| IndexError::Io { source, path })?;
        }
        Ok(())
    }

    /// Build an InMemoryIndex from cached data.
    pub fn load_index(&self, index_name: &str) -> Result<InMemoryIndex> {
        let packages = self.load(index_name)?;
        Ok(build_index(packages))
    }
}

/// Cached index loader with offline mode support.
///
/// Provides a unified interface for loading indexes with automatic caching
/// and offline fallback support.
#[derive(Debug)]
pub struct CachedIndexLoader {
    cache: IndexCache,
    offline_mode: bool,
}

impl CachedIndexLoader {
    /// Create a new cached index loader.
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache: IndexCache::new(cache_dir),
            offline_mode: false,
        }
    }

    /// Enable offline mode (only use cached data).
    pub fn offline(mut self) -> Self {
        self.offline_mode = true;
        self
    }

    /// Set offline mode.
    pub fn set_offline(&mut self, offline: bool) {
        self.offline_mode = offline;
    }

    /// Check if offline mode is enabled.
    pub fn is_offline(&self) -> bool {
        self.offline_mode
    }

    /// Load an index from a file path, caching it for offline use.
    ///
    /// In offline mode, returns cached data if available.
    /// In online mode, loads from the path and updates the cache.
    pub fn load_from_path(
        &self,
        index_name: &str,
        path: impl AsRef<Path>,
    ) -> Result<InMemoryIndex> {
        if self.offline_mode {
            // In offline mode, only use cached data
            if self.cache.is_cached(index_name) {
                return self.cache.load_index(index_name);
            } else {
                return Err(IndexError::OfflineNotCached);
            }
        }

        // Online mode: load from path and update cache
        let path = path.as_ref();
        let data = fs::read_to_string(path).map_err(|source| IndexError::Io {
            source,
            path: path.to_path_buf(),
        })?;
        let packages: Vec<IndexPackage> = serde_json::from_str(&data)?;

        // Update cache (ignore errors for now - caching is best effort)
        let _ = self.cache.save(index_name, &packages);

        Ok(build_index(packages))
    }

    /// Load an index from cache only.
    pub fn load_from_cache(&self, index_name: &str) -> Result<InMemoryIndex> {
        self.cache.load_index(index_name)
    }

    /// Check if an index is cached.
    pub fn is_cached(&self, index_name: &str) -> bool {
        self.cache.is_cached(index_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::PackageIndex;
    use tempfile::tempdir;

    #[tokio::test]
    async fn builds_inmemory_index() {
        let index = build_index(vec![IndexPackage {
            name: "app".into(),
            version: "1.0.0".into(),
            dependencies: vec!["dep==2.0.0".into()],
            ..Default::default()
        }]);
        let pkg = index
            .get("app", "1.0.0")
            .await
            .expect("no error")
            .expect("package");
        assert_eq!(pkg.dependencies.len(), 1);
        assert_eq!(pkg.dependencies[0].to_string(), "dep==2.0.0");
    }

    // ==========================================================================
    // Index cache tests
    // ==========================================================================

    #[test]
    fn index_cache_save_and_load() {
        let temp = tempdir().unwrap();
        let cache = IndexCache::new(temp.path().join("cache"));

        let packages = vec![
            IndexPackage {
                name: "pkg-a".into(),
                version: "1.0.0".into(),
                dependencies: vec!["pkg-b>=1.0.0".into()],
                ..Default::default()
            },
            IndexPackage {
                name: "pkg-b".into(),
                version: "1.0.0".into(),
                dependencies: vec![],
                ..Default::default()
            },
        ];

        // Save to cache
        cache.save("test-index", &packages).unwrap();
        assert!(cache.is_cached("test-index"));

        // Load from cache
        let loaded = cache.load("test-index").unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "pkg-a");
        assert_eq!(loaded[1].name, "pkg-b");
    }

    #[tokio::test]
    async fn index_cache_load_index() {
        let temp = tempdir().unwrap();
        let cache = IndexCache::new(temp.path().join("cache"));

        let packages = vec![IndexPackage {
            name: "my-pkg".into(),
            version: "2.0.0".into(),
            dependencies: vec![],
            ..Default::default()
        }];

        cache.save("my-index", &packages).unwrap();

        let index = cache.load_index("my-index").unwrap();
        let pkg = index
            .get("my-pkg", "2.0.0")
            .await
            .expect("no error")
            .expect("package should exist");
        assert_eq!(pkg.name, "my-pkg");
        assert_eq!(pkg.version, "2.0.0");
    }

    #[test]
    fn index_cache_remove() {
        let temp = tempdir().unwrap();
        let cache = IndexCache::new(temp.path().join("cache"));

        let packages = vec![IndexPackage {
            name: "to-remove".into(),
            version: "1.0.0".into(),
            dependencies: vec![],
            ..Default::default()
        }];

        cache.save("remove-test", &packages).unwrap();
        assert!(cache.is_cached("remove-test"));

        cache.remove("remove-test").unwrap();
        assert!(!cache.is_cached("remove-test"));
    }

    #[test]
    fn index_cache_not_cached() {
        let temp = tempdir().unwrap();
        let cache = IndexCache::new(temp.path().join("cache"));

        assert!(!cache.is_cached("nonexistent"));
    }

    // ==========================================================================
    // Cached index loader tests
    // ==========================================================================

    #[tokio::test]
    async fn cached_loader_loads_and_caches() {
        let temp = tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let loader = CachedIndexLoader::new(&cache_dir);

        // Create a test index file
        let index_file = temp.path().join("index.json");
        let packages = vec![IndexPackage {
            name: "cached-pkg".into(),
            version: "1.0.0".into(),
            dependencies: vec![],
            ..Default::default()
        }];
        std::fs::write(&index_file, serde_json::to_string(&packages).unwrap()).unwrap();

        // Load (should cache)
        let index = loader.load_from_path("test", &index_file).unwrap();
        let pkg = index
            .get("cached-pkg", "1.0.0")
            .await
            .expect("no error")
            .expect("package");
        assert_eq!(pkg.name, "cached-pkg");

        // Verify it was cached
        assert!(loader.is_cached("test"));

        // Load from cache should work
        let cached_index = loader.load_from_cache("test").unwrap();
        let cached_pkg = cached_index
            .get("cached-pkg", "1.0.0")
            .await
            .expect("no error")
            .expect("package");
        assert_eq!(cached_pkg.name, "cached-pkg");
    }

    #[tokio::test]
    async fn cached_loader_offline_mode_uses_cache() {
        let temp = tempdir().unwrap();
        let cache_dir = temp.path().join("cache");

        // First, create cache in online mode
        let loader = CachedIndexLoader::new(&cache_dir);
        let index_file = temp.path().join("index.json");
        let packages = vec![IndexPackage {
            name: "offline-pkg".into(),
            version: "1.0.0".into(),
            dependencies: vec![],
            ..Default::default()
        }];
        std::fs::write(&index_file, serde_json::to_string(&packages).unwrap()).unwrap();
        loader.load_from_path("offline-test", &index_file).unwrap();

        // Now delete the source file
        std::fs::remove_file(&index_file).unwrap();

        // Offline mode should still work from cache
        let offline_loader = CachedIndexLoader::new(&cache_dir).offline();
        assert!(offline_loader.is_offline());

        let index = offline_loader
            .load_from_path("offline-test", &index_file)
            .unwrap();
        let pkg = index
            .get("offline-pkg", "1.0.0")
            .await
            .expect("no error")
            .expect("package");
        assert_eq!(pkg.name, "offline-pkg");
    }

    #[test]
    fn cached_loader_offline_mode_fails_without_cache() {
        let temp = tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let loader = CachedIndexLoader::new(&cache_dir).offline();

        let result = loader.load_from_path("uncached", temp.path().join("nonexistent.json"));
        assert!(matches!(result, Err(IndexError::OfflineNotCached)));
    }

    #[test]
    fn cached_loader_set_offline() {
        let temp = tempdir().unwrap();
        let mut loader = CachedIndexLoader::new(temp.path());

        assert!(!loader.is_offline());
        loader.set_offline(true);
        assert!(loader.is_offline());
        loader.set_offline(false);
        assert!(!loader.is_offline());
    }
}
