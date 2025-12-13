//! E2E tests for launch profiles functionality.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::TempDir;

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn test_profile_help() {
    pybun()
        .args(["profile", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("profile"));
}

#[test]
fn test_profile_list() {
    pybun()
        .args(["profile", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dev"))
        .stdout(predicate::str::contains("prod"))
        .stdout(predicate::str::contains("benchmark"));
}

#[test]
fn test_profile_list_json() {
    pybun()
        .args(["--format=json", "profile", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"profiles\""));
}

#[test]
fn test_profile_dev() {
    pybun()
        .args(["profile", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dev"));
}

#[test]
fn test_profile_prod() {
    pybun()
        .args(["profile", "prod"])
        .assert()
        .success()
        .stdout(predicate::str::contains("prod"));
}

#[test]
fn test_profile_benchmark() {
    pybun()
        .args(["profile", "benchmark"])
        .assert()
        .success()
        .stdout(predicate::str::contains("benchmark"));
}

#[test]
fn test_profile_show() {
    pybun()
        .args(["profile", "dev", "--show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Hot reload"))
        .stdout(predicate::str::contains("Lazy imports"));
}

#[test]
fn test_profile_show_json() {
    pybun()
        .args(["--format=json", "profile", "prod", "--show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"hot_reload\""))
        .stdout(predicate::str::contains("\"lazy_imports\""))
        .stdout(predicate::str::contains("\"optimization_level\""));
}

#[test]
fn test_profile_compare() {
    pybun()
        .args(["profile", "dev", "--compare", "prod"])
        .assert()
        .success()
        .stdout(predicate::str::contains("vs"));
}

#[test]
fn test_profile_compare_json() {
    pybun()
        .args(["--format=json", "profile", "dev", "--compare", "benchmark"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"base_profile\""))
        .stdout(predicate::str::contains("\"compare_profile\""));
}

#[test]
fn test_profile_export() {
    let temp = TempDir::new().unwrap();
    let output_file = temp.path().join("profile.toml");

    pybun()
        .args(["profile", "prod", "-o", output_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported"));

    // Verify file was created
    assert!(output_file.exists());
    let content = std::fs::read_to_string(&output_file).unwrap();
    assert!(content.contains("profile"));
}

#[test]
fn test_profile_invalid() {
    pybun()
        .args(["profile", "invalid"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Invalid profile"));
}

#[test]
fn test_profile_default_shows_current() {
    pybun()
        .args(["profile"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Current profile"));
}

#[test]
fn test_profile_dev_config_values() {
    pybun()
        .args(["--format=json", "profile", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"hot_reload\":true"))
        .stdout(predicate::str::contains("\"lazy_imports\":false"));
}

#[test]
fn test_profile_prod_config_values() {
    pybun()
        .args(["--format=json", "profile", "prod"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"hot_reload\":false"))
        .stdout(predicate::str::contains("\"lazy_imports\":true"));
}

#[test]
fn test_profile_benchmark_config_values() {
    pybun()
        .args(["--format=json", "profile", "benchmark"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"tracing\":true"))
        .stdout(predicate::str::contains("\"timing\":true"));
}
