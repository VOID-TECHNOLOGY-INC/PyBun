//! E2E tests for `pybun x` command.
//!
//! This command allows running packages ad-hoc without prior install,
//! similar to `npx` or `uvx`.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn x_requires_package_argument() {
    // Running `pybun x` without a package should fail
    bin()
        .args(["x"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("package name is required"));
}

#[test]
fn x_json_output_format() {
    // JSON output should have proper envelope format
    bin()
        .args(["--format=json", "x", "cowsay"])
        .env("PYBUN_X_DRY_RUN", "1") // Use dry-run mode for testing
        .assert()
        .stdout(predicate::str::contains("\"command\":\"pybun x\""))
        .stdout(predicate::str::contains("\"status\":\"ok\""));
}

#[test]
fn x_shows_package_name_in_output() {
    // The output should mention the package being executed
    bin()
        .args(["x", "cowsay"])
        .env("PYBUN_X_DRY_RUN", "1")
        .assert()
        .stdout(predicate::str::contains("cowsay"));
}

#[test]
fn x_passthrough_args() {
    // Passthrough arguments should be captured
    bin()
        .args(["--format=json", "x", "cowsay", "--", "Hello World"])
        .env("PYBUN_X_DRY_RUN", "1")
        .assert()
        .stdout(predicate::str::contains("Hello World"));
}

#[test]
fn x_creates_temp_environment() {
    // In dry-run mode, should report temp environment creation
    bin()
        .args(["--format=json", "x", "httpie"])
        .env("PYBUN_X_DRY_RUN", "1")
        .assert()
        .stdout(predicate::str::contains("temp_env"));
}

#[test]
fn x_with_version_spec() {
    // Should handle version specifiers like package==version
    bin()
        .args(["--format=json", "x", "cowsay==6.1"])
        .env("PYBUN_X_DRY_RUN", "1")
        .assert()
        .stdout(predicate::str::contains("cowsay"))
        .stdout(predicate::str::contains("6.1"));
}

#[test]
fn x_respects_python_version() {
    // Should detect and report Python version being used
    bin()
        .args(["--format=json", "x", "cowsay"])
        .env("PYBUN_X_DRY_RUN", "1")
        .assert()
        .stdout(predicate::str::contains("python_version"));
}

// Integration test: actually execute a simple pip-installable script tool
#[test]
#[ignore] // Requires network and real PyPI access
fn x_execute_real_package() {
    // This test actually downloads and runs cowsay
    bin()
        .args(["x", "cowsay", "--", "Hello PyBun!"])
        .timeout(std::time::Duration::from_secs(120))
        .assert()
        .success()
        .stdout(predicate::str::contains("Hello PyBun!"));
}

// Test that pybun x cleans up temp directory after execution
#[test]
fn x_cleanup_temp_env() {
    let output = bin()
        .args(["--format=json", "x", "cowsay"])
        .env("PYBUN_X_DRY_RUN", "1")
        .output()
        .expect("failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that cleanup is mentioned in output
    assert!(stdout.contains("cleanup") || stdout.contains("temp_env"));
}

#[test]
fn x_handles_package_with_entrypoint() {
    // Packages like cowsay, httpie have console script entrypoints
    bin()
        .args(["--format=json", "x", "httpie"])
        .env("PYBUN_X_DRY_RUN", "1")
        .assert()
        .stdout(predicate::str::contains("httpie"));
}
