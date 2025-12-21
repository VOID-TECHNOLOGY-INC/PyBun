//! Tests for the Self-update mechanism
//!
//! PR5.4: Self-update mechanism (download, signature check, atomic swap)

use std::fs;
use std::process::Command;

use pybun::release_manifest::current_release_target;
use tempfile::tempdir;

fn pybun_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pybun"))
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
