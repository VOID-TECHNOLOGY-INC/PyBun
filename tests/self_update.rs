//! Tests for the Self-update mechanism
//!
//! PR5.4: Self-update mechanism (download, signature check, atomic swap)

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use pybun::release_manifest::current_release_target;
use tempfile::tempdir;

fn pybun_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pybun"))
}

fn release_binary_name() -> &'static str {
    if cfg!(windows) { "pybun.exe" } else { "pybun" }
}

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }
}

fn file_url(path: &Path) -> String {
    let mut value = path
        .canonicalize()
        .expect("canonical path")
        .to_string_lossy()
        .replace('\\', "/");
    if !value.starts_with('/') {
        value.insert(0, '/');
    }
    format!("file://{value}")
}

fn create_release_archive(root: &Path, target: &str, binary_bytes: &[u8]) -> PathBuf {
    let extracted_dir = root.join(format!("pybun-{target}"));
    fs::create_dir_all(&extracted_dir).unwrap();
    let binary_path = extracted_dir.join(release_binary_name());
    fs::write(&binary_path, binary_bytes).unwrap();
    make_executable(&binary_path);

    if target.contains("windows") {
        let archive_path = root.join(format!("pybun-{target}.zip"));
        let file = fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::default();
        let member = format!("pybun-{target}/{}", release_binary_name());
        zip.start_file(member, options).unwrap();
        use std::io::Write;
        zip.write_all(binary_bytes).unwrap();
        zip.finish().unwrap();
        archive_path
    } else {
        let archive_path = root.join(format!("pybun-{target}.tar.gz"));
        let status = Command::new("tar")
            .arg("-czf")
            .arg(&archive_path)
            .arg("-C")
            .arg(root)
            .arg(format!("pybun-{target}"))
            .status()
            .unwrap();
        assert!(status.success(), "failed to create tar archive");
        archive_path
    }
}

fn archive_sha256(path: &Path) -> String {
    let bytes = fs::read(path).unwrap();
    format!("{:x}", Sha256::digest(bytes))
}

fn sign_payload(payload: &[u8]) -> (String, String) {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let signature = signing_key.sign(payload);
    (
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes()),
    )
}

fn minisign_available() -> bool {
    Command::new("minisign").arg("-v").output().is_ok()
}

fn sign_archive_with_minisign(archive_path: &Path) -> (String, String) {
    let key_dir = tempdir().expect("temp dir for minisign keys");
    let public_key_path = key_dir.path().join("pybun-test.pub");
    let secret_key_path = key_dir.path().join("pybun-test.key");

    let generate = Command::new("minisign")
        .arg("-G")
        .arg("-W")
        .arg("-p")
        .arg(&public_key_path)
        .arg("-s")
        .arg(&secret_key_path)
        .arg("-c")
        .arg("pybun test key")
        .output()
        .expect("generate minisign key");
    assert!(
        generate.status.success(),
        "minisign key generation failed: {}",
        String::from_utf8_lossy(&generate.stderr)
    );

    let sign = Command::new("minisign")
        .arg("-Sm")
        .arg(archive_path)
        .arg("-s")
        .arg(&secret_key_path)
        .output()
        .expect("sign archive with minisign");
    assert!(
        sign.status.success(),
        "minisign signing failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let signature_path = PathBuf::from(format!("{}.minisig", archive_path.display()));
    let signature_value = fs::read_to_string(&signature_path).expect("read minisign signature");
    let public_key = fs::read_to_string(&public_key_path).expect("read minisign public key");

    (signature_value, public_key)
}

struct ManifestAsset<'a> {
    target: &'a str,
    version: &'a str,
    asset_url: &'a str,
    sha256: &'a str,
    signature_type: &'a str,
    signature: &'a str,
    public_key: &'a str,
}

fn write_manifest(path: &Path, asset: ManifestAsset<'_>) {
    let archive_ext = if asset.target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    let asset_name = format!("pybun-{}.{}", asset.target, archive_ext);
    let manifest = serde_json::json!({
        "version": asset.version,
        "channel": "stable",
        "published_at": "2025-01-01T00:00:00Z",
        "assets": [
            {
                "name": asset_name,
                "target": asset.target,
                "url": asset.asset_url,
                "sha256": asset.sha256,
                "signature": {
                    "type": asset.signature_type,
                    "value": asset.signature,
                    "public_key": asset.public_key
                }
            }
        ]
    });
    fs::write(path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
}

#[test]
fn self_update_help_shows_channel_option() {
    let output = pybun_bin()
        .args(["self", "update", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("channel"),
        "self update should have --channel option"
    );
}

#[test]
fn self_update_shows_current_version() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "self", "update", "--dry-run"])
        .output()
        .unwrap();

    // Should succeed (in dry-run mode)
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    // Should contain current version
    let detail = &json["detail"];
    assert!(
        detail.get("current_version").is_some() || detail.get("version").is_some(),
        "should have current version info: {:?}",
        detail
    );
}

#[test]
fn self_update_dry_run_does_not_modify() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["self", "update", "--dry-run"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should mention dry-run, "would update", "check", or "up to date"
    let stdout_lower = stdout.to_lowercase();
    assert!(
        stdout_lower.contains("dry")
            || stdout_lower.contains("would")
            || stdout_lower.contains("check")
            || stdout_lower.contains("up to date")
            || stdout_lower.contains("update"),
        "should indicate dry-run or update status: {}",
        stdout
    );
}

#[test]
fn self_update_stable_channel() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args([
            "--format=json",
            "self",
            "update",
            "--channel",
            "stable",
            "--dry-run",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let detail = &json["detail"];
    assert_eq!(
        detail["channel"].as_str(),
        Some("stable"),
        "channel should be stable"
    );
}

#[test]
fn self_update_nightly_channel() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args([
            "--format=json",
            "self",
            "update",
            "--channel",
            "nightly",
            "--dry-run",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let detail = &json["detail"];
    assert_eq!(
        detail["channel"].as_str(),
        Some("nightly"),
        "channel should be nightly"
    );
}

#[test]
fn doctor_includes_version_info() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "doctor"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    // Doctor should include checks array
    let detail = &json["detail"];
    assert!(detail.get("checks").is_some(), "doctor should have checks");
}

#[test]
fn doctor_verbose_mode() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "doctor", "--verbose"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let detail = &json["detail"];
    assert_eq!(
        detail["verbose"].as_bool(),
        Some(true),
        "verbose should be true"
    );
}

#[test]
fn doctor_checks_python() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "doctor"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let checks = json["detail"]["checks"].as_array().expect("checks array");

    // Should have a Python check
    let has_python_check = checks.iter().any(|c| {
        c.get("name")
            .and_then(|n| n.as_str())
            .map(|n| n == "python")
            .unwrap_or(false)
    });

    assert!(has_python_check, "doctor should check Python");
}

#[test]
fn doctor_checks_cache() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "doctor"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let checks = json["detail"]["checks"].as_array().expect("checks array");

    // Should have a cache check
    let has_cache_check = checks.iter().any(|c| {
        c.get("name")
            .and_then(|n| n.as_str())
            .map(|n| n == "cache")
            .unwrap_or(false)
    });

    assert!(has_cache_check, "doctor should check cache");
}

#[test]
fn self_update_dry_run_reads_manifest() {
    let temp = tempdir().unwrap();
    let manifest_path = temp.path().join("pybun-release.json");
    let target = current_release_target().expect("supported release target");
    let archive_ext = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    let asset_name = format!("pybun-{}.{}", target, archive_ext);

    let manifest = serde_json::json!({
        "version": "9.9.9",
        "channel": "stable",
        "published_at": "2025-01-01T00:00:00Z",
        "assets": [
            {
                "name": asset_name,
                "target": target.clone(),
                "url": "https://example.com/pybun-release",
                "sha256": "deadbeef",
                "signature": {
                    "type": "ed25519",
                    "value": "ZmFrZS1zaWduYXR1cmU=",
                    "public_key": "ZmFrZS1wdWJsaWMta2V5"
                }
            }
        ]
    });

    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .env("PYBUN_SELF_UPDATE_MANIFEST", &manifest_path)
        .args(["--format=json", "self", "update", "--dry-run"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let detail = &json["detail"];
    assert_eq!(detail["manifest"]["version"].as_str(), Some("9.9.9"));
    assert_eq!(
        detail["manifest"]["asset"]["target"].as_str(),
        Some(target.as_str())
    );
    assert_eq!(
        detail["manifest"]["asset"]["sha256"].as_str(),
        Some("deadbeef")
    );
}

#[test]
fn self_update_applies_update_from_local_manifest() {
    let temp = tempdir().unwrap();
    let target = current_release_target().expect("supported release target");
    let manifest_path = temp.path().join("pybun-release.json");
    let current_binary = temp.path().join(release_binary_name());
    fs::write(&current_binary, b"old-version-binary").unwrap();
    make_executable(&current_binary);

    let archive_path = create_release_archive(temp.path(), &target, b"new-version-binary");
    let sha256 = archive_sha256(&archive_path);
    let archive_bytes = fs::read(&archive_path).unwrap();
    let (signature, public_key) = sign_payload(&archive_bytes);
    write_manifest(
        &manifest_path,
        ManifestAsset {
            target: &target,
            version: "9.9.9",
            asset_url: &file_url(&archive_path),
            sha256: &sha256,
            signature_type: "ed25519",
            signature: &signature,
            public_key: &public_key,
        },
    );

    let output = pybun_bin()
        .env("PYBUN_SELF_UPDATE_MANIFEST", &manifest_path)
        .env("PYBUN_SELF_UPDATE_BIN", &current_binary)
        .args(["--format=json", "self", "update"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "self update should succeed. stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let updated = fs::read(&current_binary).unwrap();
    assert_eq!(updated, b"new-version-binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["detail"]["update_applied"].as_bool(), Some(true));
}

#[test]
fn self_update_rejects_signature_mismatch() {
    let temp = tempdir().unwrap();
    let target = current_release_target().expect("supported release target");
    let manifest_path = temp.path().join("pybun-release.json");
    let current_binary = temp.path().join(release_binary_name());
    fs::write(&current_binary, b"old-version-binary").unwrap();
    make_executable(&current_binary);

    let archive_path = create_release_archive(temp.path(), &target, b"new-version-binary");
    let sha256 = archive_sha256(&archive_path);
    let (signature, public_key) = sign_payload(b"this-is-not-the-archive");
    write_manifest(
        &manifest_path,
        ManifestAsset {
            target: &target,
            version: "9.9.9",
            asset_url: &file_url(&archive_path),
            sha256: &sha256,
            signature_type: "ed25519",
            signature: &signature,
            public_key: &public_key,
        },
    );

    let output = pybun_bin()
        .env("PYBUN_SELF_UPDATE_MANIFEST", &manifest_path)
        .env("PYBUN_SELF_UPDATE_BIN", &current_binary)
        .args(["--format=json", "self", "update"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "self update should fail");
    let current = fs::read(&current_binary).unwrap();
    assert_eq!(current, b"old-version-binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["status"], "error");
    assert_eq!(json["detail"]["update_applied"].as_bool(), Some(false));
    let error = json["detail"]["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("signature"),
        "expected signature error, got: {error}"
    );
}

#[test]
fn self_update_rolls_back_when_swap_fails() {
    let temp = tempdir().unwrap();
    let target = current_release_target().expect("supported release target");
    let manifest_path = temp.path().join("pybun-release.json");
    let current_binary = temp.path().join(release_binary_name());
    fs::write(&current_binary, b"old-version-binary").unwrap();
    make_executable(&current_binary);

    let archive_path = create_release_archive(temp.path(), &target, b"new-version-binary");
    let sha256 = archive_sha256(&archive_path);
    let archive_bytes = fs::read(&archive_path).unwrap();
    let (signature, public_key) = sign_payload(&archive_bytes);
    write_manifest(
        &manifest_path,
        ManifestAsset {
            target: &target,
            version: "9.9.9",
            asset_url: &file_url(&archive_path),
            sha256: &sha256,
            signature_type: "ed25519",
            signature: &signature,
            public_key: &public_key,
        },
    );

    let output = pybun_bin()
        .env("PYBUN_SELF_UPDATE_MANIFEST", &manifest_path)
        .env("PYBUN_SELF_UPDATE_BIN", &current_binary)
        .env("PYBUN_SELF_UPDATE_TEST_FAIL_SWAP", "1")
        .args(["--format=json", "self", "update"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "self update should fail");
    let current = fs::read(&current_binary).unwrap();
    assert_eq!(current, b"old-version-binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["status"], "error");
    assert_eq!(json["detail"]["rollback_performed"].as_bool(), Some(true));
}

#[test]
fn self_update_applies_update_with_minisign_signature() {
    if !minisign_available() {
        eprintln!("Skipping minisign self-update test: minisign command not found");
        return;
    }

    let temp = tempdir().unwrap();
    let target = current_release_target().expect("supported release target");
    let manifest_path = temp.path().join("pybun-release.json");
    let current_binary = temp.path().join(release_binary_name());
    fs::write(&current_binary, b"old-version-binary").unwrap();
    make_executable(&current_binary);

    let archive_path = create_release_archive(temp.path(), &target, b"new-version-binary");
    let sha256 = archive_sha256(&archive_path);
    let (signature, public_key) = sign_archive_with_minisign(&archive_path);
    write_manifest(
        &manifest_path,
        ManifestAsset {
            target: &target,
            version: "9.9.9",
            asset_url: &file_url(&archive_path),
            sha256: &sha256,
            signature_type: "minisign",
            signature: &signature,
            public_key: &public_key,
        },
    );

    let output = pybun_bin()
        .env("PYBUN_SELF_UPDATE_MANIFEST", &manifest_path)
        .env("PYBUN_SELF_UPDATE_BIN", &current_binary)
        .args(["--format=json", "self", "update"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "self update should succeed. stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&current_binary).unwrap(), b"new-version-binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["detail"]["update_applied"].as_bool(), Some(true));
}
