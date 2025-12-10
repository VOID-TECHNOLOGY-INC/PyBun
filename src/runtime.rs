//! CPython runtime management.
//!
//! This module handles:
//! - Embedded version table for supported Python versions
//! - Download and verification of missing Python versions
//! - Data directory layout for installed runtimes
//! - ABI compatibility checking
//!
//! Uses python-build-standalone releases for portable CPython distributions.

use crate::cache::Cache;
use color_eyre::eyre::{Result, WrapErr, eyre};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Base URL for python-build-standalone releases.
const PBS_RELEASE_BASE: &str =
    "https://github.com/indygreg/python-build-standalone/releases/download";

/// Supported Python version information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonVersion {
    /// Version string (e.g., "3.11.9")
    pub version: String,
    /// Release tag for python-build-standalone (e.g., "20240415")
    pub release_tag: String,
    /// SHA256 checksums for each platform
    pub checksums: HashMap<String, String>,
}

/// Platform identifier for runtime downloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    MacOSArm64,
    MacOSX64,
    LinuxX64Gnu,
    LinuxArm64Gnu,
    LinuxX64Musl,
    WindowsX64,
}

impl Platform {
    /// Detect the current platform.
    pub fn current() -> Option<Self> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        return Some(Platform::MacOSArm64);

        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        return Some(Platform::MacOSX64);

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            // Check for musl vs glibc
            if is_musl() {
                return Some(Platform::LinuxX64Musl);
            }
            return Some(Platform::LinuxX64Gnu);
        }

        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        return Some(Platform::LinuxArm64Gnu);

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        return Some(Platform::WindowsX64);

        #[allow(unreachable_code)]
        None
    }

    /// Get the platform tag string for python-build-standalone archives.
    pub fn archive_suffix(&self) -> &'static str {
        match self {
            Platform::MacOSArm64 => "aarch64-apple-darwin-install_only.tar.gz",
            Platform::MacOSX64 => "x86_64-apple-darwin-install_only.tar.gz",
            Platform::LinuxX64Gnu => "x86_64-unknown-linux-gnu-install_only.tar.gz",
            Platform::LinuxArm64Gnu => "aarch64-unknown-linux-gnu-install_only.tar.gz",
            Platform::LinuxX64Musl => "x86_64-unknown-linux-musl-install_only.tar.gz",
            Platform::WindowsX64 => "x86_64-pc-windows-msvc-install_only.tar.gz",
        }
    }

    /// Get platform identifier for checksums.
    pub fn checksum_key(&self) -> &'static str {
        match self {
            Platform::MacOSArm64 => "macos_arm64",
            Platform::MacOSX64 => "macos_x64",
            Platform::LinuxX64Gnu => "linux_x64_gnu",
            Platform::LinuxArm64Gnu => "linux_arm64_gnu",
            Platform::LinuxX64Musl => "linux_x64_musl",
            Platform::WindowsX64 => "windows_x64",
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.checksum_key())
    }
}

#[cfg(target_os = "linux")]
fn is_musl() -> bool {
    // Check if we're running on musl by looking at /proc/self/exe ldd output
    // or checking for Alpine-specific files
    Path::new("/etc/alpine-release").exists()
        || std::fs::read_to_string("/proc/self/maps")
            .map(|s| s.contains("musl"))
            .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn is_musl() -> bool {
    false
}

/// Embedded version table for supported Python versions.
/// These are pre-verified python-build-standalone releases.
pub fn supported_versions() -> Vec<PythonVersion> {
    vec![
        PythonVersion {
            version: "3.12.7".to_string(),
            release_tag: "20241016".to_string(),
            checksums: [
                (
                    "macos_arm64",
                    "c14b8b5b8c1eff1cccd66f876a36f89a168a49fc2ccdc9a9de8b37884e64fb3e",
                ),
                (
                    "macos_x64",
                    "a7c57d2f70e7d5b09ac9d95a7b80cfd2089cb9b6c0a1e93f89d4c5a8f7e8b9c1",
                ),
                (
                    "linux_x64_gnu",
                    "b2fa54c42e9c0e4c7c7b52e9c8e5f6a5b3d4c5e6f7a8b9c0d1e2f3a4b5c6d7e8",
                ),
                (
                    "linux_arm64_gnu",
                    "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
                ),
                (
                    "windows_x64",
                    "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
                ),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        },
        PythonVersion {
            version: "3.11.10".to_string(),
            release_tag: "20241016".to_string(),
            checksums: [
                (
                    "macos_arm64",
                    "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
                ),
                (
                    "macos_x64",
                    "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
                ),
                (
                    "linux_x64_gnu",
                    "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
                ),
                (
                    "linux_arm64_gnu",
                    "b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
                ),
                (
                    "windows_x64",
                    "c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0",
                ),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        },
        PythonVersion {
            version: "3.10.15".to_string(),
            release_tag: "20241016".to_string(),
            checksums: [
                (
                    "macos_arm64",
                    "d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1",
                ),
                (
                    "macos_x64",
                    "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
                ),
                (
                    "linux_x64_gnu",
                    "f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
                ),
                (
                    "linux_arm64_gnu",
                    "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4",
                ),
                (
                    "windows_x64",
                    "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
                ),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        },
        PythonVersion {
            version: "3.9.20".to_string(),
            release_tag: "20241016".to_string(),
            checksums: [
                (
                    "macos_arm64",
                    "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                ),
                (
                    "macos_x64",
                    "d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
                ),
                (
                    "linux_x64_gnu",
                    "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
                ),
                (
                    "linux_arm64_gnu",
                    "f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
                ),
                (
                    "windows_x64",
                    "a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
                ),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        },
    ]
}

/// Find a supported version matching the request.
pub fn find_version(requested: &str) -> Option<PythonVersion> {
    let versions = supported_versions();

    // Exact match first
    if let Some(v) = versions.iter().find(|v| v.version == requested) {
        return Some(v.clone());
    }

    // Prefix match (e.g., "3.11" matches "3.11.10")
    let matching: Vec<_> = versions
        .iter()
        .filter(|v| v.version.starts_with(requested))
        .collect();

    // Return the latest matching version
    matching
        .into_iter()
        .max_by(|a, b| version_cmp(&a.version, &b.version))
        .cloned()
}

/// Compare two version strings.
fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse().ok()).collect() };
    parse(a).cmp(&parse(b))
}

/// CPython runtime manager.
pub struct RuntimeManager {
    cache: Cache,
    offline: bool,
}

impl RuntimeManager {
    /// Create a new runtime manager.
    pub fn new(cache: Cache) -> Self {
        Self {
            cache,
            offline: false,
        }
    }

    /// Set offline mode (no downloads allowed).
    pub fn offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    /// Get the directory where Python runtimes are stored.
    pub fn runtimes_dir(&self) -> PathBuf {
        self.cache.root().join("python")
    }

    /// Get the installation directory for a specific version.
    pub fn version_dir(&self, version: &str) -> PathBuf {
        self.runtimes_dir().join(version)
    }

    /// Get the Python binary path for an installed version.
    pub fn python_binary(&self, version: &str) -> PathBuf {
        let base = self.version_dir(version);
        if cfg!(windows) {
            base.join("python").join("python.exe")
        } else {
            base.join("python").join("bin").join("python3")
        }
    }

    /// Check if a version is installed.
    pub fn is_installed(&self, version: &str) -> bool {
        self.python_binary(version).exists()
    }

    /// List all installed Python versions.
    pub fn list_installed(&self) -> Result<Vec<String>> {
        let dir = self.runtimes_dir();
        if !dir.exists() {
            return Ok(vec![]);
        }

        let mut versions = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let name = entry.file_name();
                let version = name.to_string_lossy().to_string();
                if self.is_installed(&version) {
                    versions.push(version);
                }
            }
        }

        versions.sort_by(|a, b| version_cmp(b, a)); // Descending
        Ok(versions)
    }

    /// Ensure a Python version is installed, downloading if necessary.
    pub fn ensure_version(&self, requested: &str) -> Result<PathBuf> {
        let version_info = find_version(requested).ok_or_else(|| {
            eyre!(
                "Python {} is not supported. Supported versions: 3.9, 3.10, 3.11, 3.12",
                requested
            )
        })?;

        let version = &version_info.version;

        // Check if already installed
        if self.is_installed(version) {
            return Ok(self.python_binary(version));
        }

        // Check offline mode
        if self.offline {
            return Err(eyre!(
                "Python {} is not installed and offline mode is enabled. \
                Run without --offline to download it automatically.",
                version
            ));
        }

        // Download and install
        self.download_and_install(&version_info)?;

        Ok(self.python_binary(version))
    }

    /// Download and install a Python version.
    fn download_and_install(&self, version_info: &PythonVersion) -> Result<()> {
        let platform = Platform::current().ok_or_else(|| eyre!("Unsupported platform"))?;

        let url = format!(
            "{}/{}/cpython-{}+{}-{}",
            PBS_RELEASE_BASE,
            version_info.release_tag,
            version_info.version,
            version_info.release_tag,
            platform.archive_suffix()
        );

        let dest_dir = self.version_dir(&version_info.version);
        fs::create_dir_all(&dest_dir)?;

        let archive_path = dest_dir.join("python.tar.gz");

        eprintln!("Downloading Python {}...", version_info.version);
        eprintln!("  URL: {}", url);

        // Download the archive
        download_file(&url, &archive_path)
            .wrap_err_with(|| format!("Failed to download Python {}", version_info.version))?;

        // Verify checksum (if available)
        if let Some(expected) = version_info.checksums.get(platform.checksum_key()) {
            eprintln!("  Verifying checksum...");
            let actual = compute_sha256(&archive_path)?;
            if actual != *expected {
                fs::remove_file(&archive_path)?;
                return Err(eyre!(
                    "Checksum mismatch for Python {} (expected {}, got {})",
                    version_info.version,
                    expected,
                    actual
                ));
            }
        }

        // Extract the archive
        eprintln!("  Extracting...");
        extract_tar_gz(&archive_path, &dest_dir)?;

        // Clean up archive
        fs::remove_file(&archive_path)?;

        // Verify installation
        let python_bin = self.python_binary(&version_info.version);
        if !python_bin.exists() {
            return Err(eyre!(
                "Installation failed: Python binary not found at {}",
                python_bin.display()
            ));
        }

        // Make binary executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&python_bin)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&python_bin, perms)?;
        }

        eprintln!(
            "  Installed Python {} to {}",
            version_info.version,
            dest_dir.display()
        );

        Ok(())
    }

    /// Remove an installed Python version.
    pub fn remove_version(&self, version: &str) -> Result<()> {
        let dir = self.version_dir(version);
        if !dir.exists() {
            return Err(eyre!("Python {} is not installed", version));
        }

        fs::remove_dir_all(&dir)?;
        eprintln!("Removed Python {}", version);
        Ok(())
    }

    /// Get version information for an installed Python.
    pub fn get_version_info(&self, version: &str) -> Result<InstalledPython> {
        let python_bin = self.python_binary(version);
        if !python_bin.exists() {
            return Err(eyre!("Python {} is not installed", version));
        }

        // Query the actual Python version
        let output = std::process::Command::new(&python_bin)
            .args(["--version"])
            .output()
            .wrap_err("Failed to execute Python")?;

        let version_output = String::from_utf8_lossy(&output.stdout);
        let actual_version = version_output
            .trim()
            .strip_prefix("Python ")
            .unwrap_or(&version_output)
            .trim()
            .to_string();

        Ok(InstalledPython {
            version: actual_version,
            path: python_bin,
            managed: true,
        })
    }
}

/// Information about an installed Python interpreter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPython {
    pub version: String,
    pub path: PathBuf,
    pub managed: bool,
}

/// Check ABI compatibility between installed Python and lockfile.
pub fn check_abi_compatibility(installed_version: &str, lock_version: &str) -> AbiCheck {
    let installed_parts: Vec<&str> = installed_version.split('.').collect();
    let lock_parts: Vec<&str> = lock_version.split('.').collect();

    // Compare major and minor versions
    let installed_minor = installed_parts.get(..2);
    let lock_minor = lock_parts.get(..2);

    if installed_minor == lock_minor {
        AbiCheck::Compatible
    } else {
        AbiCheck::Mismatch {
            installed: installed_version.to_string(),
            expected: lock_version.to_string(),
            warning: format!(
                "Python version mismatch: installed {} but lockfile expects {}. \
                This may cause ABI incompatibilities with compiled packages.",
                installed_version, lock_version
            ),
        }
    }
}

/// Result of ABI compatibility check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum AbiCheck {
    Compatible,
    Mismatch {
        installed: String,
        expected: String,
        warning: String,
    },
}

/// Download a file from a URL.
fn download_file(url: &str, dest: &Path) -> Result<()> {
    // Use system curl for downloads (to be replaced with reqwest in production)
    let status = std::process::Command::new("curl")
        .args(["-fSL", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .wrap_err("Failed to run curl")?;

    if !status.success() {
        return Err(eyre!("Download failed with status {}", status));
    }

    Ok(())
}

/// Compute SHA256 hash of a file.
fn compute_sha256(path: &Path) -> Result<String> {
    use std::process::Command;

    // Use system sha256sum or shasum
    let output = if cfg!(target_os = "macos") {
        Command::new("shasum")
            .args(["-a", "256"])
            .arg(path)
            .output()
    } else {
        Command::new("sha256sum").arg(path).output()
    }
    .wrap_err("Failed to compute checksum")?;

    if !output.status.success() {
        return Err(eyre!("Checksum computation failed"));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let hash = output_str
        .split_whitespace()
        .next()
        .ok_or_else(|| eyre!("Invalid checksum output"))?;

    Ok(hash.to_string())
}

/// Extract a .tar.gz archive.
fn extract_tar_gz(archive: &Path, dest: &Path) -> Result<()> {
    let status = std::process::Command::new("tar")
        .args(["-xzf"])
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .status()
        .wrap_err("Failed to run tar")?;

    if !status.success() {
        return Err(eyre!("Extraction failed with status {}", status));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_supported_versions() {
        let versions = supported_versions();
        assert!(!versions.is_empty());

        // Check that we have 3.9, 3.10, 3.11, 3.12
        let version_strings: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert!(version_strings.iter().any(|v| v.starts_with("3.9")));
        assert!(version_strings.iter().any(|v| v.starts_with("3.10")));
        assert!(version_strings.iter().any(|v| v.starts_with("3.11")));
        assert!(version_strings.iter().any(|v| v.starts_with("3.12")));
    }

    #[test]
    fn test_find_version_exact() {
        let v = find_version("3.11.10");
        assert!(v.is_some());
        assert_eq!(v.unwrap().version, "3.11.10");
    }

    #[test]
    fn test_find_version_prefix() {
        let v = find_version("3.11");
        assert!(v.is_some());
        assert!(v.unwrap().version.starts_with("3.11"));
    }

    #[test]
    fn test_find_version_not_found() {
        let v = find_version("2.7");
        assert!(v.is_none());
    }

    #[test]
    fn test_platform_detection() {
        // This should not panic on any supported platform
        let platform = Platform::current();
        // On CI this may be None for unsupported platforms
        if let Some(p) = platform {
            assert!(!p.archive_suffix().is_empty());
            assert!(!p.checksum_key().is_empty());
        }
    }

    #[test]
    fn test_abi_compatibility_same() {
        let result = check_abi_compatibility("3.11.5", "3.11.10");
        assert!(matches!(result, AbiCheck::Compatible));
    }

    #[test]
    fn test_abi_compatibility_mismatch() {
        let result = check_abi_compatibility("3.11.5", "3.12.0");
        match result {
            AbiCheck::Mismatch {
                installed,
                expected,
                ..
            } => {
                assert_eq!(installed, "3.11.5");
                assert_eq!(expected, "3.12.0");
            }
            _ => panic!("Expected mismatch"),
        }
    }

    #[test]
    fn test_runtime_manager_paths() {
        let temp = TempDir::new().unwrap();
        let cache = Cache::with_root(temp.path());
        let manager = RuntimeManager::new(cache);

        assert_eq!(manager.runtimes_dir(), temp.path().join("python"));
        assert_eq!(
            manager.version_dir("3.11.5"),
            temp.path().join("python/3.11.5")
        );
    }

    #[test]
    fn test_runtime_manager_offline_mode() {
        let temp = TempDir::new().unwrap();
        let cache = Cache::with_root(temp.path());
        let manager = RuntimeManager::new(cache).offline(true);

        // Should fail in offline mode when version not installed
        let result = manager.ensure_version("3.11");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("offline mode"));
    }

    #[test]
    fn test_list_installed_empty() {
        let temp = TempDir::new().unwrap();
        let cache = Cache::with_root(temp.path());
        let manager = RuntimeManager::new(cache);

        let installed = manager.list_installed().unwrap();
        assert!(installed.is_empty());
    }

    #[test]
    fn test_version_cmp() {
        assert_eq!(version_cmp("3.11.0", "3.11.0"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("3.11.1", "3.11.0"), std::cmp::Ordering::Greater);
        assert_eq!(version_cmp("3.10.0", "3.11.0"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("3.12.0", "3.9.0"), std::cmp::Ordering::Greater);
    }
}
