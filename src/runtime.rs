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

    /// Get the target triple used for PyBun release artifacts.
    pub fn release_target(&self) -> &'static str {
        match self {
            Platform::MacOSArm64 => "aarch64-apple-darwin",
            Platform::MacOSX64 => "x86_64-apple-darwin",
            Platform::LinuxX64Gnu => "x86_64-unknown-linux-gnu",
            Platform::LinuxArm64Gnu => "aarch64-unknown-linux-gnu",
            Platform::LinuxX64Musl => "x86_64-unknown-linux-musl",
            Platform::WindowsX64 => "x86_64-pc-windows-msvc",
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

    /// Platform tags suitable for wheel selection preference (most specific first).
    pub fn wheel_tags(&self) -> Vec<&'static str> {
        match self {
            Platform::MacOSArm64 => vec!["macos_arm64", "macos"],
            Platform::MacOSX64 => vec!["macos_x64", "macos"],
            Platform::LinuxX64Gnu => vec!["linux_x86_64", "manylinux_x86_64", "linux"],
            Platform::LinuxArm64Gnu => vec!["linux_aarch64", "manylinux_aarch64", "linux"],
            Platform::LinuxX64Musl => vec![
                "linux_x86_64_musl",
                "linux_x86_64",
                "manylinux_x86_64",
                "linux",
            ],
            Platform::WindowsX64 => vec!["windows_x86_64", "win_amd64", "windows"],
        }
    }
}

/// Wheel tags for the current platform.
pub fn current_wheel_tags() -> Vec<String> {
    let mut tags = Platform::current()
        .map(|p| {
            p.wheel_tags()
                .into_iter()
                .map(ToString::to_string)
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    if !tags.iter().any(|t| t == "any") {
        tags.push("any".into());
    }
    tags
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.checksum_key())
    }
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn is_musl() -> bool {
    // Check if we're running on musl by looking at /proc/self/exe ldd output
    // or checking for Alpine-specific files
    Path::new("/etc/alpine-release").exists()
        || std::fs::read_to_string("/proc/self/maps")
            .map(|s| s.contains("musl"))
            .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
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
                    "4c18852bf9c1a11b56f21bcf0df1946f7e98ee43e9e4c0c5374b2b3765cf9508",
                ),
                (
                    "macos_x64",
                    "60c5271e7edc3c2ab47440b7abf4ed50fbc693880b474f74f05768f5b657045a",
                ),
                (
                    "linux_x64_gnu",
                    "43576f7db1033dd57b900307f09c2e86f371152ac8a2607133afa51cbfc36064",
                ),
                (
                    "linux_arm64_gnu",
                    "bba3c6be6153f715f2941da34f3a6a69c2d0035c9c5396bc5bb68c6d2bd1065a",
                ),
                (
                    "windows_x64",
                    "f05531bff16fa77b53be0776587b97b466070e768e6d5920894de988bdcd547a",
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
                    "5a69382da99c4620690643517ca1f1f53772331b347e75f536088c42a4cf6620",
                ),
                (
                    "macos_x64",
                    "1e23ffe5bc473e1323ab8f51464da62d77399afb423babf67f8e13c82b69c674",
                ),
                (
                    "linux_x64_gnu",
                    "8b50a442b04724a24c1eebb65a36a0c0e833d35374dbdf9c9470d8a97b164cd9",
                ),
                (
                    "linux_arm64_gnu",
                    "803e49259280af0f5466d32829cd9d65a302b0226e424b3f0b261f9daf6aee8f",
                ),
                (
                    "windows_x64",
                    "647b66ff4552e70aec3bf634dd470891b4a2b291e8e8715b3bdb162f577d4c55",
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
                    "f64776f455a44c24d50f947c813738cfb7b9ac43732c44891bc831fa7940a33c",
                ),
                (
                    "macos_x64",
                    "90b46dfb1abd98d45663c7a2a8c45d3047a59391d8586d71b459cec7b75f662b",
                ),
                (
                    "linux_x64_gnu",
                    "3db2171e03c1a7acdc599fba583c1b92306d3788b375c9323077367af1e9d9de",
                ),
                (
                    "linux_arm64_gnu",
                    "eb58581f85fde83d1f3e8e1f8c6f5a15c7ae4fdbe3b1d1083931f9167fdd8dbc",
                ),
                (
                    "windows_x64",
                    "e48952619796c66ec9719867b87be97edca791c2ef7fbf87d42c417c3331609e",
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
                    "34ab2bc4c51502145e1a624b4e4ea06877e3d1934a88cc73ac2e0fd5fd439b75",
                ),
                (
                    "macos_x64",
                    "193dc7f0284e4917d52b17a077924474882ee172872f2257cfe3375d6d468ed9",
                ),
                (
                    "linux_x64_gnu",
                    "c20ee831f7f46c58fa57919b75a40eb2b6a31e03fd29aaa4e8dab4b9c4b60d5d",
                ),
                (
                    "linux_arm64_gnu",
                    "1e486c054a4e86666cf24e04f5e29456324ba9c2b95bf1cae1805be90d3da154",
                ),
                (
                    "windows_x64",
                    "5069008a237b90f6f7a86956903f2a0221b90d471daa6e4a94831eaa399e3993",
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

    /// Test that ensure_version successfully downloads and verifies a Python runtime.
    /// This validates that checksums are correct and the download/verification flow works.
    #[test]
    #[ignore = "requires network access"]
    fn test_ensure_version_success() {
        let temp = TempDir::new().unwrap();
        let cache = Cache::with_root(temp.path());
        let manager = RuntimeManager::new(cache);

        let result = manager.ensure_version("3.12.7");
        assert!(result.is_ok(), "ensure_version failed: {:?}", result.err());
    }
}
