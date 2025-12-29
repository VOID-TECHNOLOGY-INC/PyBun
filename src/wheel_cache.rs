//! Cache for downloaded wheels, organized by package name.
//!
//! Layout:
//! ~/.cache/pybun/packages/
//!   {package_name}/
//!     {filename}.whl
//!
//! Uses content-addressable storage concepts where possible (SHA256 check).

use crate::cache::Cache;
use crate::downloader::Downloader;
use std::path::{PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WheelCacheError {
    #[error("cache error: {0}")]
    Cache(#[from] crate::cache::CacheError),
    #[error("download error: {0}")]
    Download(#[from] crate::downloader::DownloadError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, WheelCacheError>;

#[derive(Debug)]
pub struct WheelCache {
    cache: Cache,
    downloader: Downloader,
}

impl WheelCache {
    pub fn new() -> Result<Self> {
        let cache = Cache::new().map_err(WheelCacheError::Cache)?;
        cache.ensure_dirs().map_err(WheelCacheError::Cache)?;
        Ok(Self {
            cache,
            downloader: Downloader::new(),
        })
    }

    /// Get a wheel from the cache, downloading it if necessary.
    ///
    /// - `name`: Package name (used for directory organization)
    /// - `filename`: Wheel filename (e.g. `requests-2.31.0-py3-none-any.whl`)
    /// - `url`: Download URL
    /// - `sha256`: Optional SHA256 checksum for verification
    pub async fn get_wheel(
        &self,
        name: &str,
        filename: &str,
        url: &str,
        sha256: Option<&str>,
    ) -> Result<PathBuf> {
        let package_dir = self.cache.ensure_package_dir(name).map_err(WheelCacheError::Cache)?;
        let wheel_path = package_dir.join(filename);

        // Optimization: If file exists and we have a hash, check it first?
        // Downloader::download_file handles verification, but we might want to skip network req entirely
        // if we trust the fs. For now, rely on Downloader logic or add simple check here.
        
        // Actually Downloader doesn't skip if exists unless we optimize it.
        // Let's optimize here: check existence + size > 0.
        // If hash is provided, ideally we verify (or assume trusted if recently written).
        // For cold start speed, we assume "if it exists with correct name, it's good" 
        // OR we trust the downloader to not re-download if verified.
        // Let's delegate to downloader but hint it to skip if verified?
        // Currently Downloader overwrites. We should update Downloader or logic here.
        
        // Logic:
        // 1. If file exists:
        //    - if sha256 provided: verify it. If matches, return path. If not, delete and download.
        //    - if no sha256: return path (optimistic) or re-download? 
        //      Safety: re-download if no hash (unless we trust name uniqueness).
        //      PyPI wheels are immutable by filename usually.
        
        if wheel_path.exists() {
            if let Some(expected_hash) = sha256 {
                if expected_hash != "sha256:placeholder" {
                    // Verify hash
                    // This can be slow for large wheels, but necessary for security/correctness.
                    // Implementation detail: we could rely on a separate integrity stamp?
                    // For now, let's verify.
                    // TODO: Move verification to a separate thread or use thread blocking?
                    // get_wheel is async.
                    
                    // Actually, let's trust generic file existence for speed in "cold" run?
                    // No, "Cold" means "No venv", but "Wheel cache might exist".
                    // If wheel exists, it's a "warm wheel cache" scenario.
                    // uv verifies hash.
                    
                    // Let's use Downloader but we need to modify Downloader to support "skip if exists and verified".
                }
            }
        }

        // For this PR, we rely on Downloader. We will update Downloader to be smart.
        self.downloader
            .download_file(url, &wheel_path, sha256)
            .await
            .map_err(WheelCacheError::from)
    }
    
    /// Get the Downloader instance reference
    pub fn downloader(&self) -> &Downloader {
        &self.downloader
    }
}
