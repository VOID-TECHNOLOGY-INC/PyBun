//! Build backend detection and build cache helpers.

use crate::cache::Cache;
use crate::project::BuildSystem;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BuildBackendKind {
    Setuptools,
    Maturin,
    ScikitBuild,
    Unknown,
}

impl BuildBackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Setuptools => "setuptools",
            Self::Maturin => "maturin",
            Self::ScikitBuild => "scikit-build",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BuildBackend {
    pub name: String,
    pub kind: BuildBackendKind,
    pub requires: Vec<String>,
    pub isolated: bool,
}

impl BuildBackend {
    pub fn from_build_system(build_system: BuildSystem) -> Self {
        let backend_name = build_system
            .build_backend
            .unwrap_or_else(|| "setuptools.build_meta".to_string());
        let lower = backend_name.to_lowercase();
        let kind = if lower.contains("maturin") {
            BuildBackendKind::Maturin
        } else if lower.contains("scikit") {
            BuildBackendKind::ScikitBuild
        } else if lower.contains("setuptools") {
            BuildBackendKind::Setuptools
        } else {
            BuildBackendKind::Unknown
        };
        let isolated = !matches!(kind, BuildBackendKind::Unknown);
        Self {
            name: backend_name,
            kind,
            requires: build_system.requires,
            isolated,
        }
    }

    pub fn env_overrides(&self, cache_dir: &Path) -> Vec<(String, String)> {
        let mut envs = vec![
            ("PYTHONNOUSERSITE".to_string(), "1".to_string()),
            ("PIP_DISABLE_PIP_VERSION_CHECK".to_string(), "1".to_string()),
            ("PIP_NO_PYTHON_VERSION_WARNING".to_string(), "1".to_string()),
            ("PYBUN_BUILD_ISOLATION".to_string(), "1".to_string()),
            ("PYBUN_BUILD_BACKEND".to_string(), self.name.clone()),
            (
                "PYBUN_BUILD_CACHE_DIR".to_string(),
                cache_dir.display().to_string(),
            ),
        ];

        match self.kind {
            BuildBackendKind::Maturin => {
                envs.push((
                    "CARGO_TARGET_DIR".to_string(),
                    cache_dir.join("cargo").display().to_string(),
                ));
            }
            BuildBackendKind::ScikitBuild => {
                envs.push((
                    "SKBUILD_BUILD_DIR".to_string(),
                    cache_dir.join("scikit-build").display().to_string(),
                ));
            }
            BuildBackendKind::Setuptools | BuildBackendKind::Unknown => {}
        }

        envs
    }
}

#[derive(Debug, Error)]
pub enum BuildCacheError {
    #[error("failed to initialize cache: {0}")]
    Cache(#[from] crate::cache::CacheError),
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to copy build cache: {0}")]
    Copy(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, BuildCacheError>;

#[derive(Debug, Clone)]
pub struct BuildCache {
    root: PathBuf,
}

impl BuildCache {
    pub fn new() -> Result<Self> {
        let cache = Cache::new()?;
        cache.ensure_dirs()?;
        Ok(Self {
            root: cache.build_dir(),
        })
    }

    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn cache_dir_for_key(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }

    pub fn compute_cache_key(
        &self,
        project_root: &Path,
        python_path: &Path,
        backend: &BuildBackend,
    ) -> Result<String> {
        let inputs = collect_build_inputs(project_root)?;
        let mut hasher = Sha256::new();
        hasher.update(backend.name.as_bytes());
        hasher.update(b"|");
        hasher.update(backend.kind.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(python_path.display().to_string().as_bytes());

        for path in inputs {
            hasher.update(b"|");
            hasher.update(
                path.strip_prefix(project_root)
                    .unwrap_or(&path)
                    .display()
                    .to_string()
                    .as_bytes(),
            );
            let data = fs::read(&path).map_err(|source| BuildCacheError::Read {
                path: path.clone(),
                source,
            })?;
            hasher.update(&data);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn restore_dist(&self, cache_key: &str, dist_dir: &Path) -> Result<bool> {
        let cache_dist = self.cache_dir_for_key(cache_key).join("dist");
        if !cache_dist.exists() {
            return Ok(false);
        }
        if !has_files(&cache_dist)? {
            return Ok(false);
        }
        copy_dir_recursive(&cache_dist, dist_dir)?;
        Ok(true)
    }

    pub fn store_dist(&self, cache_key: &str, dist_dir: &Path) -> Result<()> {
        if !dist_dir.exists() {
            return Ok(());
        }
        let cache_dist = self.cache_dir_for_key(cache_key).join("dist");
        if cache_dist.exists() {
            fs::remove_dir_all(&cache_dist)?;
        }
        copy_dir_recursive(dist_dir, &cache_dist)?;
        Ok(())
    }
}

fn collect_build_inputs(project_root: &Path) -> Result<Vec<PathBuf>> {
    let mut inputs = Vec::new();
    let ignore = ignored_dirs();
    collect_inputs_recursive(project_root, &ignore, &mut inputs)?;
    inputs.sort();
    Ok(inputs)
}

fn collect_inputs_recursive(
    current: &Path,
    ignore: &BTreeSet<&'static str>,
    inputs: &mut Vec<PathBuf>,
) -> Result<()> {
    let entries = fs::read_dir(current).map_err(|source| BuildCacheError::Read {
        path: current.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| BuildCacheError::Read {
            path: current.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            if ignore.contains(name.as_ref()) {
                continue;
            }
            collect_inputs_recursive(&path, ignore, inputs)?;
        } else if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            inputs.push(path);
        }
    }
    Ok(())
}

fn ignored_dirs() -> BTreeSet<&'static str> {
    [
        ".git",
        ".venv",
        ".pybun",
        ".pytest_cache",
        ".mypy_cache",
        "__pycache__",
        "dist",
        "build",
        "target",
        "node_modules",
        ".cache",
    ]
    .into_iter()
    .collect()
}

fn copy_dir_recursive(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let path = entry.path();
        let dest = to.join(entry.file_name());
        if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            copy_dir_recursive(&path, &dest)?;
        } else if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            fs::create_dir_all(dest.parent().unwrap_or_else(|| Path::new(".")))?;
            fs::copy(&path, &dest)?;
        }
    }
    Ok(())
}

fn has_files(dir: &Path) -> Result<bool> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn cache_key_changes_with_input() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        fs::write(root.join("pyproject.toml"), "name = \"demo\"").unwrap();
        fs::write(root.join("module.c"), "int demo() { return 1; }").unwrap();

        let cache = BuildCache::with_root(temp.path().join("cache"));
        let backend = BuildBackend {
            name: "setuptools.build_meta".to_string(),
            kind: BuildBackendKind::Setuptools,
            requires: Vec::new(),
            isolated: true,
        };

        let first = cache
            .compute_cache_key(root, Path::new("python"), &backend)
            .unwrap();

        fs::write(root.join("module.c"), "int demo() { return 2; }").unwrap();
        let second = cache
            .compute_cache_key(root, Path::new("python"), &backend)
            .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn cache_store_and_restore_dist() {
        let temp = TempDir::new().unwrap();
        let cache_root = temp.path().join("cache");
        let cache = BuildCache::with_root(cache_root);
        let cache_key = "demo";

        let dist_dir = temp.path().join("dist");
        fs::create_dir_all(&dist_dir).unwrap();
        fs::write(dist_dir.join("demo.whl"), "wheel").unwrap();

        cache.store_dist(cache_key, &dist_dir).unwrap();
        fs::remove_dir_all(&dist_dir).unwrap();

        let restored = cache.restore_dist(cache_key, &dist_dir).unwrap();
        assert!(restored);
        assert!(dist_dir.join("demo.whl").exists());
    }
}
