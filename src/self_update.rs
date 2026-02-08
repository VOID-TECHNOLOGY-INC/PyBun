use crate::release_manifest::{ReleaseAsset, ReleaseSignature};
use crate::security::{sha256_file, verify_ed25519_signature};
use reqwest::blocking::Client;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use zip::ZipArchive;

#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub install_path: PathBuf,
    pub rollback_performed: bool,
}

#[derive(Debug, Clone)]
pub struct ApplyError {
    pub message: String,
    pub rollback_performed: bool,
}

impl Display for ApplyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ApplyError {}

type ApplyResult<T> = std::result::Result<T, ApplyError>;

#[derive(Debug)]
struct AtomicSwapOutcome {
    rollback_performed: bool,
}

pub fn apply_update_for_asset(
    asset: &ReleaseAsset,
    target: &str,
    install_path_override: Option<PathBuf>,
    fail_swap_for_test: bool,
) -> ApplyResult<ApplyOutcome> {
    let install_path = resolve_install_path(install_path_override)?;

    let temp = tempfile::Builder::new()
        .prefix("pybun-self-update-")
        .tempdir()
        .map_err(|e| err(format!("failed to create temp dir: {e}")))?;
    let archive_path = temp.path().join(&asset.name);

    download_asset(&asset.url, &archive_path)?;
    verify_asset(&archive_path, asset)?;

    let extract_root = temp.path().join("extract");
    fs::create_dir_all(&extract_root)
        .map_err(|e| err(format!("failed to create extract directory: {e}")))?;
    extract_archive(&archive_path, &extract_root)?;
    let extracted_binary = locate_binary(&extract_root, target)?;

    let swap = atomic_replace_binary(&install_path, &extracted_binary, fail_swap_for_test)?;

    Ok(ApplyOutcome {
        install_path,
        rollback_performed: swap.rollback_performed,
    })
}

fn err(message: impl Into<String>) -> ApplyError {
    ApplyError {
        message: message.into(),
        rollback_performed: false,
    }
}

fn resolve_install_path(install_path_override: Option<PathBuf>) -> ApplyResult<PathBuf> {
    let install_path = if let Some(path) = install_path_override {
        path
    } else {
        std::env::current_exe()
            .map_err(|e| err(format!("failed to resolve current binary: {e}")))?
    };

    if !install_path.exists() {
        return Err(err(format!(
            "current binary not found at {}",
            install_path.display()
        )));
    }

    Ok(install_path)
}

fn download_asset(url: &str, destination: &Path) -> ApplyResult<()> {
    if let Some(path) = url.strip_prefix("file://") {
        fs::copy(path, destination)
            .map_err(|e| err(format!("failed to copy local asset from {path}: {e}")))?;
        return Ok(());
    }

    if url.starts_with("http://") || url.starts_with("https://") {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| err(format!("failed to build http client: {e}")))?;
        let mut response = client
            .get(url)
            .send()
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| err(format!("failed to download asset from {url}: {e}")))?;
        let mut file = fs::File::create(destination).map_err(|e| {
            err(format!(
                "failed to create destination {}: {e}",
                destination.display()
            ))
        })?;
        io::copy(&mut response, &mut file)
            .map_err(|e| err(format!("failed to write downloaded asset: {e}")))?;
        file.flush()
            .map_err(|e| err(format!("failed to flush downloaded asset: {e}")))?;
        return Ok(());
    }

    if Path::new(url).exists() {
        fs::copy(url, destination)
            .map_err(|e| err(format!("failed to copy local asset from {url}: {e}")))?;
        return Ok(());
    }

    Err(err(format!("unsupported asset url: {url}")))
}

fn verify_asset(archive_path: &Path, asset: &ReleaseAsset) -> ApplyResult<()> {
    verify_checksum(archive_path, &asset.sha256)?;
    if let Some(signature) = asset.signature.as_ref() {
        verify_signature(archive_path, signature)?;
    }
    Ok(())
}

fn verify_checksum(path: &Path, expected: &str) -> ApplyResult<()> {
    if expected.trim().is_empty() {
        return Err(err("manifest missing sha256 for asset"));
    }
    let normalized = expected.trim().strip_prefix("sha256:").unwrap_or(expected);
    if normalized == "placeholder" || normalized == "sha256:placeholder" {
        return Err(err("placeholder checksum is not allowed for self update"));
    }
    let actual =
        sha256_file(path).map_err(|e| err(format!("failed to compute checksum for asset: {e}")))?;
    if actual != normalized {
        return Err(err(format!(
            "checksum mismatch: expected {normalized}, got {actual}"
        )));
    }
    Ok(())
}

fn verify_signature(path: &Path, signature: &ReleaseSignature) -> ApplyResult<()> {
    match signature.signature_type.as_str() {
        "ed25519" => verify_signature_ed25519(path, signature),
        "minisign" => verify_signature_minisign(path, signature),
        other => Err(err(format!("unsupported signature type: {other}"))),
    }
}

fn verify_signature_ed25519(path: &Path, signature: &ReleaseSignature) -> ApplyResult<()> {
    let public_key = signature
        .public_key
        .as_deref()
        .ok_or_else(|| err("signature missing public key for ed25519 verification"))?;
    let payload = fs::read(path).map_err(|e| {
        err(format!(
            "failed to read asset for signature verification: {e}"
        ))
    })?;
    verify_ed25519_signature(public_key, &signature.value, &payload)
        .map_err(|e| err(format!("signature verification failed: {e}")))?;
    Ok(())
}

fn verify_signature_minisign(path: &Path, signature: &ReleaseSignature) -> ApplyResult<()> {
    let public_key = signature
        .public_key
        .as_deref()
        .ok_or_else(|| err("signature missing public key for minisign verification"))?;

    let sig_dir = TempDir::new().map_err(|e| err(format!("failed to create sig temp dir: {e}")))?;
    let sig_path = sig_dir.path().join("asset.minisig");
    let pub_path = sig_dir.path().join("release.pub");
    write_text_with_newline(&sig_path, &signature.value)?;
    write_text_with_newline(&pub_path, public_key)?;

    let output = Command::new("minisign")
        .arg("-Vm")
        .arg(path)
        .arg("-x")
        .arg(&sig_path)
        .arg("-p")
        .arg(&pub_path)
        .output()
        .map_err(|e| err(format!("failed to run minisign: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(err(format!(
            "minisign verification failed: {}",
            stderr.trim()
        )));
    }
    Ok(())
}

fn write_text_with_newline(path: &Path, value: &str) -> ApplyResult<()> {
    let mut file = fs::File::create(path)
        .map_err(|e| err(format!("failed to create {}: {e}", path.display())))?;
    file.write_all(value.as_bytes())
        .map_err(|e| err(format!("failed to write {}: {e}", path.display())))?;
    if !value.ends_with('\n') {
        file.write_all(b"\n")
            .map_err(|e| err(format!("failed to terminate {}: {e}", path.display())))?;
    }
    Ok(())
}

fn extract_archive(archive_path: &Path, destination: &Path) -> ApplyResult<()> {
    let name = archive_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.ends_with(".zip") {
        return extract_zip(archive_path, destination);
    }
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        return extract_tar_gz(archive_path, destination);
    }
    Err(err(format!(
        "unsupported archive format: {}",
        archive_path.display()
    )))
}

fn extract_tar_gz(archive_path: &Path, destination: &Path) -> ApplyResult<()> {
    let output = Command::new("tar")
        .arg("-xzf")
        .arg(archive_path)
        .arg("-C")
        .arg(destination)
        .output()
        .map_err(|e| err(format!("failed to run tar: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(err(format!(
            "failed to extract archive {}: {}",
            archive_path.display(),
            stderr.trim()
        )));
    }
    Ok(())
}

fn extract_zip(archive_path: &Path, destination: &Path) -> ApplyResult<()> {
    let file = fs::File::open(archive_path).map_err(|e| {
        err(format!(
            "failed to open zip archive {}: {e}",
            archive_path.display()
        ))
    })?;
    let mut archive =
        ZipArchive::new(file).map_err(|e| err(format!("failed to parse zip archive: {e}")))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|e| err(format!("failed to read zip entry: {e}")))?;
        let enclosed = match entry.enclosed_name() {
            Some(path) => path.to_path_buf(),
            None => continue,
        };
        let out_path = destination.join(enclosed);
        if entry.is_dir() {
            fs::create_dir_all(&out_path).map_err(|e| {
                err(format!(
                    "failed to create directory {}: {e}",
                    out_path.display()
                ))
            })?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                err(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let mut out_file = fs::File::create(&out_path)
            .map_err(|e| err(format!("failed to create file {}: {e}", out_path.display())))?;
        io::copy(&mut entry, &mut out_file)
            .map_err(|e| err(format!("failed to extract {}: {e}", out_path.display())))?;
    }
    Ok(())
}

fn locate_binary(extracted_root: &Path, target: &str) -> ApplyResult<PathBuf> {
    let expected = extracted_root
        .join(format!("pybun-{target}"))
        .join(binary_name());
    if expected.exists() {
        return Ok(expected);
    }
    find_binary_recursive(extracted_root).ok_or_else(|| {
        err(format!(
            "updated binary not found after extraction (expected {})",
            expected.display()
        ))
    })
}

fn find_binary_recursive(root: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name == binary_name())
                .unwrap_or(false)
        {
            return Some(path);
        }
        if path.is_dir()
            && let Some(found) = find_binary_recursive(&path)
        {
            return Some(found);
        }
    }
    None
}

fn atomic_replace_binary(
    install_path: &Path,
    new_binary_path: &Path,
    fail_swap_for_test: bool,
) -> ApplyResult<AtomicSwapOutcome> {
    let parent = install_path.parent().ok_or_else(|| {
        err(format!(
            "cannot determine parent directory for {}",
            install_path.display()
        ))
    })?;
    let file_name = install_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| err(format!("invalid binary name: {}", install_path.display())))?;
    let staged_path = parent.join(format!(".{file_name}.new-{}", unique_suffix()));
    let backup_path = parent.join(format!(".{file_name}.bak-{}", unique_suffix()));

    fs::copy(new_binary_path, &staged_path).map_err(|e| {
        err(format!(
            "failed to stage update binary from {} to {}: {e}",
            new_binary_path.display(),
            staged_path.display()
        ))
    })?;

    if let Ok(metadata) = fs::metadata(install_path) {
        let _ = fs::set_permissions(&staged_path, metadata.permissions());
    }

    if let Err(error) = fs::rename(install_path, &backup_path) {
        cleanup_if_exists(&staged_path);
        return Err(err(format!(
            "failed to move current binary to backup: {error}"
        )));
    }

    if fail_swap_for_test {
        let rollback_performed = fs::rename(&backup_path, install_path).is_ok();
        cleanup_if_exists(&staged_path);
        return Err(ApplyError {
            message: "simulated swap failure".to_string(),
            rollback_performed,
        });
    }

    if let Err(error) = fs::rename(&staged_path, install_path) {
        let rollback_performed = fs::rename(&backup_path, install_path).is_ok();
        cleanup_if_exists(&staged_path);
        return Err(ApplyError {
            message: if rollback_performed {
                format!("failed to swap updated binary: {error}")
            } else {
                format!("failed to swap updated binary and rollback: {error}")
            },
            rollback_performed,
        });
    }

    cleanup_if_exists(&backup_path);

    Ok(AtomicSwapOutcome {
        rollback_performed: false,
    })
}

fn cleanup_if_exists(path: &Path) {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn binary_name() -> &'static str {
    if cfg!(windows) { "pybun.exe" } else { "pybun" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn atomic_swap_replaces_binary() {
        let temp = tempdir().unwrap();
        let current = temp.path().join(binary_name());
        let candidate = temp.path().join(format!("{}-candidate", binary_name()));
        fs::write(&current, b"old").unwrap();
        fs::write(&candidate, b"new").unwrap();

        let outcome = atomic_replace_binary(&current, &candidate, false).unwrap();

        assert!(!outcome.rollback_performed);
        assert_eq!(fs::read(&current).unwrap(), b"new");
    }

    #[test]
    fn atomic_swap_rolls_back_on_injected_failure() {
        let temp = tempdir().unwrap();
        let current = temp.path().join(binary_name());
        let candidate = temp.path().join(format!("{}-candidate", binary_name()));
        fs::write(&current, b"old").unwrap();
        fs::write(&candidate, b"new").unwrap();

        let error = atomic_replace_binary(&current, &candidate, true).unwrap_err();

        assert!(error.rollback_performed);
        assert_eq!(fs::read(&current).unwrap(), b"old");
    }
}
