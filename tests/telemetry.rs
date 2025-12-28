//! E2E tests for telemetry functionality.
//!
//! PR7.2: Telemetry UX/Privacy finalize
//! Tests for `pybun telemetry status|enable|disable` commands.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::TempDir;

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
}

fn pybun_with_home(home: &std::path::Path) -> Command {
    let mut cmd = cargo_bin_cmd!("pybun");
    cmd.env("PYBUN_HOME", home);
    cmd
}

#[test]
fn test_telemetry_help() {
    pybun()
        .args(["telemetry", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("telemetry"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("enable"))
        .stdout(predicate::str::contains("disable"));
}

#[test]
fn test_telemetry_status_default_disabled() {
    let temp = TempDir::new().unwrap();

    pybun_with_home(temp.path())
        .args(["telemetry", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("disabled"));
}

#[test]
fn test_telemetry_status_json() {
    let temp = TempDir::new().unwrap();

    pybun_with_home(temp.path())
        .args(["--format=json", "telemetry", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"enabled\""))
        .stdout(predicate::str::contains("false"));
}

#[test]
fn test_telemetry_enable() {
    let temp = TempDir::new().unwrap();

    // Enable telemetry
    pybun_with_home(temp.path())
        .args(["telemetry", "enable"])
        .assert()
        .success()
        .stdout(predicate::str::contains("enabled"));

    // Verify status shows enabled
    pybun_with_home(temp.path())
        .args(["telemetry", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("enabled"));
}

#[test]
fn test_telemetry_disable() {
    let temp = TempDir::new().unwrap();

    // Enable first
    pybun_with_home(temp.path())
        .args(["telemetry", "enable"])
        .assert()
        .success();

    // Disable
    pybun_with_home(temp.path())
        .args(["telemetry", "disable"])
        .assert()
        .success()
        .stdout(predicate::str::contains("disabled"));

    // Verify status shows disabled
    pybun_with_home(temp.path())
        .args(["telemetry", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("disabled"));
}

#[test]
fn test_telemetry_enable_json() {
    let temp = TempDir::new().unwrap();

    pybun_with_home(temp.path())
        .args(["--format=json", "telemetry", "enable"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"enabled\":true"));
}

#[test]
fn test_telemetry_disable_json() {
    let temp = TempDir::new().unwrap();

    // Enable first
    pybun_with_home(temp.path())
        .args(["telemetry", "enable"])
        .assert()
        .success();

    pybun_with_home(temp.path())
        .args(["--format=json", "telemetry", "disable"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"enabled\":false"));
}

#[test]
fn test_telemetry_env_override_disable() {
    let temp = TempDir::new().unwrap();

    // Enable via command
    pybun_with_home(temp.path())
        .args(["telemetry", "enable"])
        .assert()
        .success();

    // Override with env var to disable
    pybun_with_home(temp.path())
        .env("PYBUN_TELEMETRY", "0")
        .args(["telemetry", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("disabled"))
        .stdout(predicate::str::contains("environment"));
}

#[test]
fn test_telemetry_env_override_enable() {
    let temp = TempDir::new().unwrap();

    // Override with env var to enable (even without config)
    pybun_with_home(temp.path())
        .env("PYBUN_TELEMETRY", "1")
        .args(["telemetry", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("enabled"))
        .stdout(predicate::str::contains("environment"));
}

#[test]
fn test_telemetry_status_shows_source() {
    let temp = TempDir::new().unwrap();

    // Default source
    pybun_with_home(temp.path())
        .args(["telemetry", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("default"));

    // After enable, source is config
    pybun_with_home(temp.path())
        .args(["telemetry", "enable"])
        .assert()
        .success();

    pybun_with_home(temp.path())
        .args(["telemetry", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("config"));
}

#[test]
fn test_telemetry_json_has_proper_structure() {
    let temp = TempDir::new().unwrap();

    let output = pybun_with_home(temp.path())
        .args(["--format=json", "telemetry", "status"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    // Check envelope structure
    assert!(json.get("command").is_some());
    assert!(json.get("status").is_some());
    assert!(json.get("version").is_some());

    // Check detail has telemetry info
    let detail = &json["detail"];
    assert!(detail.get("enabled").is_some());
    assert!(detail.get("source").is_some());
}

#[test]
fn test_telemetry_redaction_patterns_in_config() {
    let temp = TempDir::new().unwrap();

    // Get status to verify redaction patterns exist in JSON output
    pybun_with_home(temp.path())
        .args(["--format=json", "telemetry", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("redaction_patterns"));
}
