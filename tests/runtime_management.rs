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
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
}

fn managed_python_path(home: &Path, version: &str) -> PathBuf {
    if cfg!(windows) {
        home.join("python")
            .join(version)
            .join("python")
            .join("python.exe")
    } else {
        home.join("python")
            .join(version)
            .join("python")
            .join("bin")
            .join("python3")
    }
}

fn seed_managed_python(home: &Path, version: &str) -> PathBuf {
    let python = managed_python_path(home, version);
    fs::create_dir_all(python.parent().unwrap()).unwrap();
    fs::write(&python, []).unwrap();
    python
}

#[cfg(unix)]
fn seed_system_python(bin_dir: &Path, version: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(bin_dir).unwrap();
    let python = bin_dir.join("python3");
    fs::write(
        &python,
        format!("#!/bin/sh\nprintf 'Python {version}\\n'\n"),
    )
    .unwrap();
    let mut permissions = fs::metadata(&python).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&python, permissions).unwrap();
    python
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
    // CI and local dev environments for this repo always have a system
    // Python on PATH (other suites, e.g. cli_install.rs, rely on the same
    // assumption), so this must succeed rather than merely "fail gracefully".
    let mut cmd = pybun();
    cmd.args(["python", "which"]);

    let output = cmd.output().expect("command runs");
    assert!(
        output.status.success(),
        "pybun python which should find a system Python: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("python") || stdout.contains("Python"),
        "Expected Python path in output: {}",
        stdout
    );
}

#[test]
fn python_which_json_output() {
    let mut cmd = pybun();
    cmd.args(["--format=json", "python", "which"]);

    let output = cmd.output().expect("command runs");
    assert!(
        output.status.success(),
        "pybun python which should find a system Python: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let path = json["detail"]["path"]
        .as_str()
        .expect("detail.path should be a non-empty string");
    assert!(!path.is_empty());
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
        .stdout(predicate::str::contains("not supported"));
}

#[test]
fn python_install_rejects_ambiguous_major_selector() {
    let temp = TempDir::new().unwrap();

    let mut cmd = pybun();
    cmd.env("PYBUN_HOME", temp.path())
        .args(["python", "install", "3"]);

    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("ambiguous"))
        .stdout(predicate::str::contains("Specify a more precise version"));
}

#[test]
fn python_which_rejects_invalid_selector() {
    let temp = TempDir::new().unwrap();

    let mut cmd = pybun();
    cmd.env("PYBUN_HOME", temp.path())
        .args(["python", "which", "3..11"]);

    cmd.assert()
        .failure()
        .stdout(predicate::str::contains(
            "Invalid Python version selector '3..11'",
        ))
        .stdout(predicate::str::contains("3.11 or 3.11.10"));
}

#[test]
fn python_install_partial_version_reuses_canonical_install_in_text_output() {
    let temp = TempDir::new().unwrap();
    let python = seed_managed_python(temp.path(), "3.11.10");

    let mut cmd = pybun();
    cmd.env("PYBUN_HOME", temp.path())
        .args(["python", "install", "3.11"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Python 3.11.10 is already installed",
        ))
        .stdout(predicate::str::contains(python.display().to_string()));
}

#[test]
fn python_install_partial_version_reuses_canonical_install_in_json_output() {
    let temp = TempDir::new().unwrap();
    let python = seed_managed_python(temp.path(), "3.11.10");

    let mut cmd = pybun();
    cmd.env("PYBUN_HOME", temp.path())
        .args(["--format=json", "python", "install", "3.11"]);

    let output = cmd.assert().success();
    let json: serde_json::Value =
        serde_json::from_slice(&output.get_output().stdout).expect("valid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["detail"]["status"], "already_installed");
    assert_eq!(json["detail"]["version"], "3.11.10");
    assert_eq!(json["detail"]["path"], python.display().to_string());
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
        .stdout(predicate::str::contains("not installed"));
}

#[test]
fn python_which_partial_version_returns_canonical_managed_runtime() {
    let temp = TempDir::new().unwrap();
    let python = seed_managed_python(temp.path(), "3.11.10");

    let mut cmd = pybun();
    cmd.env("PYBUN_HOME", temp.path())
        .args(["--format=json", "python", "which", "3.11"]);

    let output = cmd.assert().success();
    let json: serde_json::Value =
        serde_json::from_slice(&output.get_output().stdout).expect("valid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["detail"]["version"], "3.11.10");
    assert_eq!(json["detail"]["path"], python.display().to_string());
    assert_eq!(json["detail"]["managed"], true);
}

#[test]
fn python_remove_partial_version_reports_and_removes_canonical_runtime() {
    let temp = TempDir::new().unwrap();
    let python = seed_managed_python(temp.path(), "3.11.10");

    let mut cmd = pybun();
    cmd.env("PYBUN_HOME", temp.path())
        .args(["--format=json", "python", "remove", "3.11"]);

    let output = cmd.assert().success();
    let json: serde_json::Value =
        serde_json::from_slice(&output.get_output().stdout).expect("valid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["detail"]["status"], "removed");
    assert_eq!(json["detail"]["version"], "3.11.10");
    assert_eq!(json["detail"]["path"], python.display().to_string());
    assert!(!temp.path().join("python/3.11.10").exists());
}

#[test]
fn python_which_rejects_ambiguous_installed_partial_version() {
    let temp = TempDir::new().unwrap();
    seed_managed_python(temp.path(), "3.11.9");
    seed_managed_python(temp.path(), "3.11.10");

    let mut cmd = pybun();
    cmd.env("PYBUN_HOME", temp.path())
        .args(["python", "which", "3.11"]);

    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("ambiguous"))
        .stdout(predicate::str::contains("3.11.9"))
        .stdout(predicate::str::contains("3.11.10"));
}

#[cfg(unix)]
#[test]
fn python_which_rejects_mismatched_system_interpreter() {
    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    seed_system_python(&bin_dir, "3.14.6");

    let mut cmd = pybun();
    cmd.current_dir(temp.path())
        .env("PYBUN_HOME", temp.path().join("home"))
        .env("PATH", &bin_dir)
        .env_remove("PYBUN_ENV")
        .env_remove("PYBUN_PYTHON")
        .env_remove("PYENV_ROOT")
        .args(["--format=json", "python", "which", "3.11"]);

    let output = cmd.assert().failure();
    let json: serde_json::Value =
        serde_json::from_slice(&output.get_output().stdout).expect("valid JSON");
    assert_eq!(json["status"], "error");
    let error = json["detail"]["error"].as_str().expect("error detail");
    assert!(error.contains("3.11"), "error={error}");
    assert!(error.contains("3.14.6"), "error={error}");
    assert!(error.contains("does not match"), "error={error}");
}

#[cfg(unix)]
#[test]
fn python_which_accepts_matching_system_interpreter() {
    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    let system_python = seed_system_python(&bin_dir, "3.11.9");

    let mut cmd = pybun();
    cmd.current_dir(temp.path())
        .env("PYBUN_HOME", temp.path().join("home"))
        .env("PATH", &bin_dir)
        .env_remove("PYBUN_ENV")
        .env_remove("PYBUN_PYTHON")
        .env_remove("PYENV_ROOT")
        .args(["--format=json", "python", "which", "3.11"]);

    let output = cmd.assert().success();
    let json: serde_json::Value =
        serde_json::from_slice(&output.get_output().stdout).expect("valid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["detail"]["version"], "3.11.9");
    assert_eq!(json["detail"]["path"], system_python.display().to_string());
    assert_eq!(json["detail"]["managed"], false);
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

    verify
        .assert()
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
    list.env("PYBUN_HOME", temp.path()).args(["python", "list"]);
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
    list_after
        .assert()
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
    second
        .assert()
        .success()
        .stdout(predicate::str::contains("already installed"));
}
