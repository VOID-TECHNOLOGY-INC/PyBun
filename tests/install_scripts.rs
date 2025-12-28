//! Tests for installer scripts (dry-run).

use std::fs;
use std::process::Command;

use pybun::release_manifest::current_release_target;
use serde_json::json;
use tempfile::tempdir;

fn write_manifest(target: &str, path: &std::path::Path) -> (String, String) {
    let archive_ext = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    let asset_name = format!("pybun-{}.{}", target, archive_ext);
    let asset_url = format!("https://example.com/{}", asset_name);
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
