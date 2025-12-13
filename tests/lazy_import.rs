//! E2E tests for lazy import functionality.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::TempDir;

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn test_lazy_import_help() {
    pybun()
        .args(["lazy-import", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("lazy-import"));
}

#[test]
fn test_lazy_import_show_config() {
    pybun()
        .args(["lazy-import", "--show-config"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Enabled"))
        .stdout(predicate::str::contains("Denylist"));
}

#[test]
fn test_lazy_import_show_config_json() {
    pybun()
        .args(["--format=json", "lazy-import", "--show-config"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"enabled\""))
        .stdout(predicate::str::contains("\"denylist\""));
}

#[test]
fn test_lazy_import_check_denied_module() {
    pybun()
        .args(["lazy-import", "--check", "sys"])
        .assert()
        .success()
        .stdout(predicate::str::contains("denied"));
}

#[test]
fn test_lazy_import_check_allowed_module() {
    pybun()
        .args(["lazy-import", "--check", "numpy"])
        .assert()
        .success()
        .stdout(predicate::str::contains("lazy"));
}

#[test]
fn test_lazy_import_check_json() {
    pybun()
        .args(["--format=json", "lazy-import", "--check", "pandas"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"decision\""))
        .stdout(predicate::str::contains("\"lazy\""));
}

#[test]
fn test_lazy_import_generate() {
    pybun()
        .args(["lazy-import", "--generate"])
        .assert()
        .success()
        .stdout(predicate::str::contains("class LazyModule"))
        .stdout(predicate::str::contains("class LazyFinder"));
}

#[test]
fn test_lazy_import_generate_with_allowlist() {
    pybun()
        .args(["lazy-import", "--generate", "--allow", "numpy"])
        .assert()
        .success()
        .stdout(predicate::str::contains("numpy"));
}

#[test]
fn test_lazy_import_generate_with_log() {
    pybun()
        .args(["lazy-import", "--generate", "--log-imports"])
        .assert()
        .success()
        .stdout(predicate::str::contains("_LOG_IMPORTS = True"));
}

#[test]
fn test_lazy_import_generate_to_file() {
    let temp = TempDir::new().unwrap();
    let output_file = temp.path().join("lazy_import.py");

    pybun()
        .args([
            "lazy-import",
            "--generate",
            "-o",
            output_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated"));

    // Verify file was created
    assert!(output_file.exists());
    let content = std::fs::read_to_string(&output_file).unwrap();
    assert!(content.contains("class LazyModule"));
}

#[test]
fn test_lazy_import_check_with_custom_denylist() {
    pybun()
        .args(["lazy-import", "--check", "mymodule", "--deny", "mymodule"])
        .assert()
        .success()
        .stdout(predicate::str::contains("denied"));
}

#[test]
fn test_lazy_import_default_shows_usage() {
    pybun()
        .args(["lazy-import"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));
}
