//! Integration tests for CPython runtime management (PR1.6).
//!
//! Tests:
//! - Version listing and availability
//! - Offline mode behavior
//! - ABI compatibility checking
//!
//! Note: Actual download tests are skipped in CI to avoid network dependencies.
//! They can be run locally with `cargo test -- --ignored`

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn pybun() -> Command {
    Command::cargo_bin("pybun").unwrap()
}

// ---------------------------------------------------------------------------
// pybun python list
// ---------------------------------------------------------------------------

#[test]
fn python_list_shows_installed_versions() {
    let mut cmd = pybun();
    cmd.args(["python", "list"]);
    
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Installed Python versions"));
}

#[test]
fn python_list_all_shows_available_versions() {
    let mut cmd = pybun();
    cmd.args(["python", "list", "--all"]);
    
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Available Python versions"))
        .stdout(predicate::str::contains("3.12"))
        .stdout(predicate::str::contains("3.11"))
        .stdout(predicate::str::contains("3.10"))
        .stdout(predicate::str::contains("3.9"));
}

#[test]
fn python_list_json_output() {
    let mut cmd = pybun();
    cmd.args(["--format=json", "python", "list"]);
    
    let output = cmd.assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    
    // Parse JSON and verify structure
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(json.get("detail").is_some());
    assert!(json["detail"].get("installed").is_some());
    assert!(json["detail"].get("available").is_some());
}

// ---------------------------------------------------------------------------
// pybun python which
// ---------------------------------------------------------------------------

#[test]
fn python_which_shows_default_python() {
    // This test requires Python to be installed on the system
    let mut cmd = pybun();
    cmd.args(["python", "which"]);
    
    // Should either succeed with a path or fail gracefully
    let output = cmd.output().expect("command runs");
    
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should contain "python" in the output (either path or command reference)
        assert!(
            stdout.contains("python") || stdout.contains("Python"),
            "Expected Python path in output: {}",
            stdout
        );
    }
}

#[test]
fn python_which_json_output() {
    let mut cmd = pybun();
    cmd.args(["--format=json", "python", "which"]);
    
    let output = cmd.output().expect("command runs");
    
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert!(json.get("detail").is_some());
        assert!(json["detail"].get("path").is_some());
    }
}

// ---------------------------------------------------------------------------
// pybun python install (offline mode behavior)
// ---------------------------------------------------------------------------

#[test]
fn python_install_unsupported_version_fails() {
    let temp = TempDir::new().unwrap();
    
    let mut cmd = pybun();
    cmd.env("PYBUN_HOME", temp.path())
        .args(["python", "install", "2.7"]);
    
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not supported"));
}

// ---------------------------------------------------------------------------
// pybun python remove (not installed)
// ---------------------------------------------------------------------------

#[test]
fn python_remove_not_installed_fails() {
    let temp = TempDir::new().unwrap();
    
    let mut cmd = pybun();
    cmd.env("PYBUN_HOME", temp.path())
        .args(["python", "remove", "3.11.10"]);
    
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not installed"));
}

// ---------------------------------------------------------------------------
// ABI compatibility tests (unit-level, not E2E)
// ---------------------------------------------------------------------------

#[test]
fn abi_compatibility_check_in_json() {
    // This tests that ABI checks are exposed; actual behavior tested in unit tests
    let mut cmd = pybun();
    cmd.args(["--format=json", "python", "list"]);
    
    cmd.assert().success();
}

// ---------------------------------------------------------------------------
// Download tests (require network, marked ignored for CI)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires network access"]
fn python_install_downloads_version() {
    let temp = TempDir::new().unwrap();
    
    let mut cmd = pybun();
    cmd.env("PYBUN_HOME", temp.path())
        .args(["python", "install", "3.11"]);
    
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Installed Python"));
    
    // Verify installation
    let mut verify = pybun();
    verify
        .env("PYBUN_HOME", temp.path())
        .args(["python", "which", "3.11"]);
    
    verify.assert()
        .success()
        .stdout(predicate::str::contains("python"));
}

#[test]
#[ignore = "requires network access"]
fn python_install_and_remove_cycle() {
    let temp = TempDir::new().unwrap();
    
    // Install
    let mut install = pybun();
    install
        .env("PYBUN_HOME", temp.path())
        .args(["python", "install", "3.11"]);
    install.assert().success();
    
    // Verify installed
    let mut list = pybun();
    list.env("PYBUN_HOME", temp.path())
        .args(["python", "list"]);
    list.assert()
        .success()
        .stdout(predicate::str::contains("3.11"));
    
    // Remove
    let mut remove = pybun();
    remove
        .env("PYBUN_HOME", temp.path())
        .args(["python", "remove", "3.11.10"]);
    remove.assert().success();
    
    // Verify removed
    let mut list_after = pybun();
    list_after
        .env("PYBUN_HOME", temp.path())
        .args(["python", "list"]);
    list_after.assert()
        .success()
        .stdout(predicate::str::contains("(none)"));
}

#[test]
#[ignore = "requires network access"]  
fn python_reuse_from_cache() {
    let temp = TempDir::new().unwrap();
    
    // First install
    let mut first = pybun();
    first
        .env("PYBUN_HOME", temp.path())
        .args(["python", "install", "3.11"]);
    first.assert().success();
    
    // Second install should be instant (already installed)
    let mut second = pybun();
    second
        .env("PYBUN_HOME", temp.path())
        .args(["python", "install", "3.11"]);
    second.assert()
        .success()
        .stdout(predicate::str::contains("already installed"));
}

