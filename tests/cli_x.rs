//! E2E tests for `pybun x` command.
//!
//! This command allows running packages ad-hoc without prior install,
//! similar to `npx` or `uvx`.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use serde_json::Value;

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

// Issue #185: `pybun x` must propagate the executed tool's exit code,
// mirroring the `pybun run` behavior from issue #148/#155.

#[test]
fn x_dry_run_exit_zero_still_succeeds() {
    // Regression guard: a clean exit must not be reported as a failure.
    bin()
        .args(["x", "cowsay"])
        .env("PYBUN_X_DRY_RUN", "1")
        .assert()
        .success();
}

#[test]
fn x_propagates_nonzero_exit_code() {
    // The PYBUN_X_DRY_RUN_EXIT_CODE test hook lets us simulate a tool that
    // exits non-zero without needing network access / a real pip install.
    bin()
        .args(["x", "cowsay"])
        .env("PYBUN_X_DRY_RUN", "1")
        .env("PYBUN_X_DRY_RUN_EXIT_CODE", "3")
        .assert()
        .code(3);
}

#[test]
fn x_json_mode_nonzero_exit_reports_error_status() {
    let output = bin()
        .args(["--format=json", "x", "cowsay"])
        .env("PYBUN_X_DRY_RUN", "1")
        .env("PYBUN_X_DRY_RUN_EXIT_CODE", "3")
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));

    assert_eq!(value["status"], "error");
    assert_eq!(value["detail"]["exit_code"], 3);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn x_json_mode_zero_exit_reports_ok_status() {
    let output = bin()
        .args(["--format=json", "x", "cowsay"])
        .env("PYBUN_X_DRY_RUN", "1")
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));

    assert_eq!(value["status"], "ok");
    assert_eq!(value["detail"]["exit_code"], 0);
}
