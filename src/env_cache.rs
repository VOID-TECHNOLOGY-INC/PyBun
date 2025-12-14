use crate::env::PythonEnv;
use color_eyre::eyre::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    env: PythonEnv,
    timestamp: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EnvCache {
    entries: HashMap<PathBuf, CacheEntry>, // CWD -> Entry
}

impl EnvCache {
    fn cache_file_path() -> PathBuf {
        crate::env::pybun_home().join("env_cache.json")
    }

    #[allow(clippy::collapsible_if)]
    pub fn load() -> Self {
        let path = Self::cache_file_path();
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(cache) = serde_json::from_str(&content) {
                return cache;
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::cache_file_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string(&self)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn get(&self, cwd: &Path) -> Option<PythonEnv> {
        if let Some(entry) = self.entries.get(cwd) {
            // Check existence
            if entry.env.python_path.exists() {
                // Invalidation logic:
                // If it's cached for more than X time? Maybe 1 hour is fine for non-interactive.
                // Or just rely on existence.
                // Let's assume validity for now to maximize speed.
                return Some(entry.env.clone());
            }
        }
        None
    }

    pub fn put(&mut self, cwd: &Path, env: &PythonEnv) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.entries.insert(
            cwd.to_path_buf(),
            CacheEntry {
                env: env.clone(),
                timestamp,
            },
        );
    }
}
