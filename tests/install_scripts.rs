//! Tests for installer scripts (dry-run).

use std::fs;
use std::process::Command;

#[cfg(not(windows))]
use httpmock::prelude::*;
use pybun::release_manifest::current_release_target;
use serde_json::json;
use tempfile::tempdir;

/// Generates a fresh, unencrypted minisign keypair for test use via the
/// locally installed `minisign` binary. Returns `None` if minisign is
/// unavailable so callers can skip gracefully.
#[cfg(not(windows))]
fn generate_test_minisign_keypair(dir: &std::path::Path) -> Option<(String, std::path::PathBuf)> {
    if Command::new("minisign").arg("-v").output().is_err() {
        return None;
    }
    let pub_path = dir.join("test.pub");
    let sec_path = dir.join("test.key");
    let status = Command::new("minisign")
        .args(["-G", "-W", "-p"])
        .arg(&pub_path)
        .arg("-s")
        .arg(&sec_path)
        .output()
        .expect("failed to run minisign -G")
        .status;
    assert!(status.success(), "minisign keypair generation failed");
    let pub_contents = fs::read_to_string(&pub_path).unwrap();
    let public_key = pub_contents
        .lines()
        .nth(1)
        .expect("minisign pubkey file should have a key line")
        .to_string();
    Some((public_key, sec_path))
}

#[cfg(not(windows))]
fn sign_file(sec_path: &std::path::Path, artifact_path: &std::path::Path) -> String {
    let sig_path = artifact_path.with_extension("minisig");
    let status = Command::new("minisign")
        .arg("-S")
        .arg("-s")
        .arg(sec_path)
        .arg("-m")
        .arg(artifact_path)
        .arg("-x")
        .arg(&sig_path)
        .output()
        .expect("failed to run minisign -S")
        .status;
    assert!(status.success(), "minisign signing failed");
    fs::read_to_string(&sig_path).unwrap()
}

fn write_manifest(target: &str, path: &std::path::Path) -> (String, String) {
    let archive_ext = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    let asset_name = format!("pybun-{}.{}", target, archive_ext);
    let asset_url = format!(
        "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v9.9.9/{}",
        asset_name
    );
    let manifest = json!({
        "version": "9.9.9",
        "channel": "stable",
        "published_at": "2025-01-01T00:00:00Z",
        "assets": [
            {
                "name": asset_name,
                "target": target,
                "url": asset_url,
                "sha256": "deadbeef",
                "signature": {
                    "type": "minisign",
                    "value": "ZHVtbXktc2lnbmF0dXJl",
                    "public_key": "ZHVtbXktcHVibGljLWtleQ=="
                }
            }
        ]
    });

    fs::write(path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
    (asset_url, "deadbeef".to_string())
}

#[cfg(not(windows))]
#[test]
fn install_sh_dry_run_emits_json() {
    let temp = tempdir().unwrap();
    let manifest_path = temp.path().join("pybun-release.json");
    let target = current_release_target().expect("supported release target");
    let (asset_url, asset_sha) = write_manifest(&target, &manifest_path);
    let prefix = temp.path().join("prefix");
    let expected_bin = prefix.join("bin");
    let expected_bin_str = expected_bin.display().to_string();
    let expected_alias = expected_bin.join("pybun-cli");
    let expected_alias_str = expected_alias.display().to_string();
    let expected_alias_with_ext = format!("{expected_alias_str}.exe");

    let output = Command::new("sh")
        .arg("scripts/install.sh")
        .arg("--dry-run")
        .arg("--format")
        .arg("json")
        .arg("--prefix")
        .arg(&prefix)
        .env("PYBUN_INSTALL_MANIFEST", &manifest_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "installer should exit cleanly: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(detail["status"].as_str(), Some("dry-run"));
    assert_eq!(detail["target"].as_str(), Some(target.as_str()));
    assert_eq!(detail["asset"]["url"].as_str(), Some(asset_url.as_str()));
    assert_eq!(detail["asset"]["sha256"].as_str(), Some(asset_sha.as_str()));
    assert_eq!(detail["bin_dir"].as_str(), Some(expected_bin_str.as_str()));
    assert_eq!(detail["verify"].as_bool(), Some(true));
    let aliases = detail["aliases"].as_array().expect("aliases array");
    assert!(
        aliases.iter().any(|alias| {
            alias["name"].as_str() == Some("pybun-cli")
                && (alias["path"].as_str() == Some(expected_alias_str.as_str())
                    || alias["path"].as_str() == Some(expected_alias_with_ext.as_str()))
                && alias["status"].as_str() == Some("planned")
        }),
        "expected pybun-cli alias entry in aliases: {aliases:?}"
    );
    let warnings = detail["warnings"]
        .as_array()
        .expect("warnings array should be present");
    assert!(warnings.is_empty(), "no warnings expected: {warnings:?}");
}

#[test]
fn install_ps1_dry_run_emits_json() {
    let temp = tempdir().unwrap();
    let manifest_path = temp.path().join("pybun-release.json");
    let target = current_release_target().expect("supported release target");
    let (asset_url, asset_sha) = write_manifest(&target, &manifest_path);
    let prefix = temp.path().join("prefix");
    let expected_bin = prefix.join("bin");
    let expected_bin_str = expected_bin.display().to_string();
    let expected_alias = expected_bin.join("pybun-cli");
    let expected_alias_str = expected_alias.display().to_string();
    let expected_alias_with_ext = format!("{expected_alias_str}.exe");

    let pwsh_available = Command::new("pwsh")
        .args(["-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"])
        .output()
        .is_ok();
    if !pwsh_available {
        eprintln!("pwsh not available; skipping PowerShell installer test");
        return;
    }

    let output = Command::new("pwsh")
        .args([
            "-NoProfile",
            "-File",
            "scripts/install.ps1",
            "-DryRun",
            "-Format",
            "json",
            "-Prefix",
        ])
        .arg(&prefix)
        .env("PYBUN_INSTALL_MANIFEST", &manifest_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "installer should exit cleanly: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(detail["status"].as_str(), Some("dry-run"));
    assert_eq!(detail["target"].as_str(), Some(target.as_str()));
    assert_eq!(detail["asset"]["url"].as_str(), Some(asset_url.as_str()));
    assert_eq!(detail["asset"]["sha256"].as_str(), Some(asset_sha.as_str()));
    assert_eq!(detail["bin_dir"].as_str(), Some(expected_bin_str.as_str()));
    assert_eq!(detail["verify"].as_bool(), Some(true));
    let aliases = detail["aliases"].as_array().expect("aliases array");
    assert!(
        aliases.iter().any(|alias| {
            alias["name"].as_str() == Some("pybun-cli")
                && (alias["path"].as_str() == Some(expected_alias_str.as_str())
                    || alias["path"].as_str() == Some(expected_alias_with_ext.as_str()))
                && alias["status"].as_str() == Some("planned")
        }),
        "expected pybun-cli alias entry in aliases: {aliases:?}"
    );
    let warnings = detail["warnings"]
        .as_array()
        .expect("warnings array should be present");
    assert!(warnings.is_empty(), "no warnings expected: {warnings:?}");
}

// --- Issue #387: unvalidated `-Version` input hardening ---

#[test]
fn install_ps1_rejects_malformed_version() {
    let temp = tempdir().unwrap();
    let prefix = temp.path().join("prefix");

    let pwsh_available = Command::new("pwsh")
        .args(["-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"])
        .output()
        .is_ok();
    if !pwsh_available {
        eprintln!("pwsh not available; skipping PowerShell installer test");
        return;
    }

    let output = Command::new("pwsh")
        .args([
            "-NoProfile",
            "-File",
            "scripts/install.ps1",
            "-Version",
            "1.2.3/../../etc/passwd",
            "-DryRun",
            "-Prefix",
        ])
        .arg(&prefix)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "installer should reject a malformed version string"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid version string rejected"),
        "unexpected stderr: {stderr}"
    );
}

#[cfg(not(windows))]
#[test]
fn install_sh_warns_when_bun_pybun_present() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let manifest_path = temp.path().join("pybun-release.json");
    let target = current_release_target().expect("supported release target");
    write_manifest(&target, &manifest_path);

    let bun_dir = temp.path().join(".bun/bin");
    fs::create_dir_all(&bun_dir).unwrap();
    let bun_pybun = bun_dir.join("pybun");
    fs::write(&bun_pybun, "#!/usr/bin/env bun\n").unwrap();
    fs::set_permissions(&bun_pybun, fs::Permissions::from_mode(0o755)).unwrap();
    let bun_pybun_str = bun_pybun.display().to_string();

    let prefix = temp.path().join("prefix");
    let output = Command::new("sh")
        .arg("scripts/install.sh")
        .arg("--dry-run")
        .arg("--format")
        .arg("json")
        .arg("--prefix")
        .arg(&prefix)
        .env(
            "PATH",
            format!(
                "{}:{}",
                bun_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("PYBUN_INSTALL_MANIFEST", &manifest_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "installer should exit cleanly: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let warnings = detail["warnings"]
        .as_array()
        .expect("warnings array should be present");
    assert!(
        warnings.iter().any(|warning| {
            warning["kind"].as_str() == Some("bun-pybun-detected")
                && warning["path"].as_str() == Some(bun_pybun_str.as_str())
        }),
        "expected bun pybun warning in {warnings:?}"
    );
}

// --- Issue #378: install script supply-chain hardening tests ---

#[cfg(not(windows))]
#[test]
fn install_sh_rejects_http_manifest_source() {
    let temp = tempdir().unwrap();
    let prefix = temp.path().join("prefix");

    let output = Command::new("sh")
        .arg("scripts/install.sh")
        .arg("--dry-run")
        .arg("--prefix")
        .arg(&prefix)
        .env(
            "PYBUN_INSTALL_MANIFEST",
            "http://example.com/pybun-release.json",
        )
        .env("PYBUN_INSTALL_FETCH", "1")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "installer should reject http manifest source"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("insecure manifest source rejected"),
        "unexpected stderr: {stderr}"
    );
}

#[cfg(not(windows))]
#[test]
fn install_sh_rejects_manifest_asset_url_outside_allowlist() {
    let temp = tempdir().unwrap();
    let manifest_path = temp.path().join("pybun-release.json");
    let target = current_release_target().expect("supported release target");
    let asset_name = format!(
        "pybun-{}.{}",
        target,
        if target.contains("windows") {
            "zip"
        } else {
            "tar.gz"
        }
    );
    let manifest = json!({
        "version": "9.9.9",
        "channel": "stable",
        "assets": [
            {
                "name": asset_name,
                "target": target,
                "url": format!("https://evil.example.com/{asset_name}"),
                "sha256": "deadbeef",
                "signature": {
                    "type": "minisign",
                    "value": "ZHVtbXktc2lnbmF0dXJl",
                    "public_key": "ZHVtbXktcHVibGljLWtleQ=="
                }
            }
        ]
    });
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let prefix = temp.path().join("prefix");
    let output = Command::new("sh")
        .arg("scripts/install.sh")
        .arg("--dry-run")
        .arg("--prefix")
        .arg(&prefix)
        .env("PYBUN_INSTALL_MANIFEST", &manifest_path)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "installer should reject asset URL host outside allowlist"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("asset URL host not in allowlist"),
        "unexpected stderr: {stderr}"
    );
}

#[cfg(not(windows))]
#[test]
fn install_sh_rejects_asset_url_with_userinfo_host_confusion() {
    let temp = tempdir().unwrap();
    let manifest_path = temp.path().join("pybun-release.json");
    let target = current_release_target().expect("supported release target");
    let asset_name = format!(
        "pybun-{}.{}",
        target,
        if target.contains("windows") {
            "zip"
        } else {
            "tar.gz"
        }
    );
    // Userinfo syntax (user:pass@host) must not let the allowlist check see
    // the trusted host while curl/wget actually connect to evil.com.
    let manifest = json!({
        "version": "9.9.9",
        "channel": "stable",
        "assets": [
            {
                "name": asset_name,
                "target": target,
                "url": format!("https://github.com:@evil.com/{asset_name}"),
                "sha256": "deadbeef",
                "signature": {
                    "type": "minisign",
                    "value": "ZHVtbXktc2lnbmF0dXJl",
                    "public_key": "ZHVtbXktcHVibGljLWtleQ=="
                }
            }
        ]
    });
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let prefix = temp.path().join("prefix");
    let output = Command::new("sh")
        .arg("scripts/install.sh")
        .arg("--dry-run")
        .arg("--prefix")
        .arg(&prefix)
        .env("PYBUN_INSTALL_MANIFEST", &manifest_path)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "installer should reject asset URL host outside allowlist via userinfo confusion"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("asset URL host not in allowlist"),
        "unexpected stderr: {stderr}"
    );
}

#[cfg(not(windows))]
#[test]
fn install_sh_manifest_field_injection_is_inert() {
    let temp = tempdir().unwrap();
    let manifest_path = temp.path().join("pybun-release.json");
    let target = current_release_target().expect("supported release target");
    let canary = temp.path().join("pwned");
    let canary_str = canary.display().to_string();
    let (asset_url, asset_sha) = write_manifest(&target, &manifest_path);
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    // Attempt shell injection via a manifest field that flows through
    // parse_manifest -> shell variable assignment. With eval removed, this
    // must never execute as shell code.
    manifest["release_notes"] = json!({
        "name": format!("$(touch {canary_str})`touch {canary_str}`"),
        "url": "https://github.com/example/notes",
        "sha256": "deadbeef"
    });
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let prefix = temp.path().join("prefix");
    let output = Command::new("sh")
        .arg("scripts/install.sh")
        .arg("--dry-run")
        .arg("--format")
        .arg("json")
        .arg("--prefix")
        .arg(&prefix)
        .env("PYBUN_INSTALL_MANIFEST", &manifest_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "installer should exit cleanly: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !canary.exists(),
        "manifest field content must never be executed as shell code"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(detail["asset"]["url"].as_str(), Some(asset_url.as_str()));
    assert_eq!(detail["asset"]["sha256"].as_str(), Some(asset_sha.as_str()));
}

#[cfg(not(windows))]
#[test]
fn install_sh_ignores_manifest_supplied_public_key() {
    let temp = tempdir().unwrap();
    let manifest_path = temp.path().join("pybun-release.json");
    let target = current_release_target().expect("supported release target");
    write_manifest(&target, &manifest_path);

    let prefix = temp.path().join("prefix");
    let output = Command::new("sh")
        .arg("scripts/install.sh")
        .arg("--dry-run")
        .arg("--format")
        .arg("json")
        .arg("--prefix")
        .arg(&prefix)
        .env("PYBUN_INSTALL_MANIFEST", &manifest_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "installer should exit cleanly: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let sig_pub = detail["asset"]["signature"]["public_key"]
        .as_str()
        .expect("signature.public_key should be present");
    assert_ne!(
        sig_pub, "ZHVtbXktcHVibGljLWtleQ==",
        "installer must never trust a public key supplied by the manifest itself"
    );
    assert_eq!(
        sig_pub, "RWQtfZNEyNnATcgzxfwDB+iNwGwW8bwflfnjHMizq6H84B1VRXO92yZ5",
        "installer should use the trusted embedded public key"
    );
}

#[cfg(not(windows))]
#[test]
fn install_sh_full_install_fails_closed_without_signature() {
    let Some(tar_ok) = Command::new("tar").arg("--version").output().ok() else {
        eprintln!("tar not available; skipping");
        return;
    };
    if !tar_ok.status.success() {
        eprintln!("tar not available; skipping");
        return;
    }

    let temp = tempdir().unwrap();
    let target = current_release_target().expect("supported release target");
    let archive_path = temp.path().join(format!("pybun-{target}.tar.gz"));
    build_archive(&target, &archive_path);
    let asset_sha = sha256_hex(&archive_path);
    let archive_bytes = fs::read(&archive_path).unwrap();

    let server = MockServer::start();
    let _asset_mock = server.mock(|when, then| {
        when.method(GET).path(format!("/pybun-{target}.tar.gz"));
        then.status(200).body(archive_bytes);
    });

    let manifest_path = temp.path().join("pybun-release.json");
    let manifest = json!({
        "version": "9.9.9",
        "channel": "stable",
        "assets": [
            {
                "name": format!("pybun-{target}.tar.gz"),
                "target": target,
                "url": format!("{}/pybun-{target}.tar.gz", server.base_url()),
                "sha256": asset_sha,
            }
        ]
    });
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let prefix = temp.path().join("prefix");
    let output = Command::new("sh")
        .arg("scripts/install.sh")
        .arg("--prefix")
        .arg(&prefix)
        .env("PYBUN_INSTALL_MANIFEST", &manifest_path)
        .env("PYBUN_INSTALL_ASSET_HOST_ALLOWLIST", "127.0.0.1")
        .env("PYBUN_INSTALL_ASSET_ALLOW_INSECURE", "1")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "installer must fail closed when the manifest lacks a signature"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing signature value"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !prefix.join("bin/pybun").exists(),
        "unsigned artifact must not be installed"
    );
}

#[cfg(not(windows))]
#[test]
fn install_sh_full_install_succeeds_with_trusted_signature() {
    let Some(tar_ok) = Command::new("tar").arg("--version").output().ok() else {
        eprintln!("tar not available; skipping");
        return;
    };
    if !tar_ok.status.success() {
        eprintln!("tar not available; skipping");
        return;
    }

    let temp = tempdir().unwrap();
    let Some((public_key, secret_key_path)) = generate_test_minisign_keypair(temp.path()) else {
        eprintln!("minisign not available; skipping");
        return;
    };

    let target = current_release_target().expect("supported release target");
    let archive_path = temp.path().join(format!("pybun-{target}.tar.gz"));
    build_archive(&target, &archive_path);
    let asset_sha = sha256_hex(&archive_path);
    let signature = sign_file(&secret_key_path, &archive_path);
    let archive_bytes = fs::read(&archive_path).unwrap();

    let server = MockServer::start();
    let _asset_mock = server.mock(|when, then| {
        when.method(GET).path(format!("/pybun-{target}.tar.gz"));
        then.status(200).body(archive_bytes);
    });

    let manifest_path = temp.path().join("pybun-release.json");
    let manifest = json!({
        "version": "9.9.9",
        "channel": "stable",
        "assets": [
            {
                "name": format!("pybun-{target}.tar.gz"),
                "target": target,
                "url": format!("{}/pybun-{target}.tar.gz", server.base_url()),
                "sha256": asset_sha,
                "signature": {
                    "type": "minisign",
                    "value": signature,
                    // Deliberately a bogus key: must be ignored in favor of
                    // the trusted PYBUN_INSTALL_TRUSTED_PUBKEY override below.
                    "public_key": "ZHVtbXktcHVibGljLWtleQ=="
                }
            }
        ]
    });
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let prefix = temp.path().join("prefix");
    let output = Command::new("sh")
        .arg("scripts/install.sh")
        .arg("--prefix")
        .arg(&prefix)
        .env("PYBUN_INSTALL_MANIFEST", &manifest_path)
        .env("PYBUN_INSTALL_ASSET_HOST_ALLOWLIST", "127.0.0.1")
        .env("PYBUN_INSTALL_ASSET_ALLOW_INSECURE", "1")
        .env("PYBUN_INSTALL_TRUSTED_PUBKEY", &public_key)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "installer should succeed with a valid trusted signature: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        prefix.join("bin/pybun").exists(),
        "expected pybun binary to be installed"
    );
}

/// Builds a minimal tar.gz archive containing `pybun-<target>/pybun`, matching
/// the layout install.sh expects to extract.
#[cfg(not(windows))]
fn build_archive(target: &str, archive_path: &std::path::Path) {
    let stage = tempdir().unwrap();
    let dir = stage.path().join(format!("pybun-{target}"));
    fs::create_dir_all(&dir).unwrap();
    let bin_path = dir.join("pybun");
    fs::write(&bin_path, "#!/bin/sh\necho pybun-test-binary\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let status = Command::new("tar")
        .arg("-czf")
        .arg(archive_path)
        .arg("-C")
        .arg(stage.path())
        .arg(format!("pybun-{target}"))
        .status()
        .expect("failed to run tar");
    assert!(status.success(), "failed to build test archive");
}

#[cfg(not(windows))]
fn sha256_hex(path: &std::path::Path) -> String {
    let output = Command::new("shasum")
        .arg("-a")
        .arg("256")
        .arg(path)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .unwrap_or_else(|| {
            Command::new("sha256sum")
                .arg(path)
                .output()
                .expect("sha256sum or shasum required")
        });
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .next()
        .expect("sha256 output should contain a hash")
        .to_string()
}
