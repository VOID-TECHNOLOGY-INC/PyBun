//! E2E tests for `pybun test` command
//!
//! Tests for the test runner functionality:
//! - Basic test discovery and execution (pytest/unittest wrapper)
//! - JSON output format
//! - --fail-fast option
//! - --shard option
//! - Exit codes

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn pybun() -> Command {
    Command::cargo_bin("pybun").unwrap()
}

// ---------------------------------------------------------------------------
// CLI Help Tests
// ---------------------------------------------------------------------------

#[test]
fn test_help_shows_test_command() {
    pybun()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("test"));
}

#[test]
fn test_test_help() {
    pybun()
        .args(["test", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test"))
        .stdout(predicate::str::contains("--fail-fast"))
        .stdout(predicate::str::contains("--shard"))
        .stdout(predicate::str::contains("--pytest-compat"));
}

// ---------------------------------------------------------------------------
// Basic Execution Tests
// ---------------------------------------------------------------------------

#[test]
fn test_run_pytest_simple() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_example.py");

    fs::write(
        &test_file,
        r#"
def test_passing():
    assert 1 + 1 == 2

def test_another_passing():
    assert True
"#,
    )
    .unwrap();

    // Note: This test requires pytest to be installed
    // In dry-run/test mode, we check the command structure
    pybun()
        .current_dir(temp.path())
        .args(["test", "--format=json"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"command\":"))
        .stdout(predicate::str::contains("\"status\":"));
}

#[test]
fn test_run_with_path_argument() {
    let temp = TempDir::new().unwrap();
    let test_dir = temp.path().join("tests");
    fs::create_dir(&test_dir).unwrap();

    let test_file = test_dir.join("test_specific.py");
    fs::write(
        &test_file,
        r#"
def test_specific():
    assert True
"#,
    )
    .unwrap();

    pybun()
        .current_dir(temp.path())
        .args(["test", "tests/test_specific.py", "--format=json"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("test_specific.py"));
}

// ---------------------------------------------------------------------------
// JSON Output Tests
// ---------------------------------------------------------------------------

#[test]
fn test_json_output_structure() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_json.py");

    fs::write(
        &test_file,
        r#"
def test_json():
    assert True
"#,
    )
    .unwrap();

    let output = pybun()
        .current_dir(temp.path())
        .args(["test", "--format=json"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse as JSON to validate structure
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    // Check required fields
    assert!(json.get("command").is_some(), "Should have 'command' field");
    assert!(json.get("status").is_some(), "Should have 'status' field");
    assert!(json.get("detail").is_some(), "Should have 'detail' field");
}

#[test]
fn test_json_output_includes_test_results() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_results.py");

    fs::write(
        &test_file,
        r#"
def test_one():
    assert True

def test_two():
    assert True
"#,
    )
    .unwrap();

    let output = pybun()
        .current_dir(temp.path())
        .args(["test", "--format=json"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    let detail = json.get("detail").expect("Should have detail");
    assert!(
        detail.get("test_runner").is_some() || detail.get("backend").is_some(),
        "Should indicate test runner/backend"
    );
}

// ---------------------------------------------------------------------------
// Fail-Fast Tests
// ---------------------------------------------------------------------------

#[test]
fn test_fail_fast_flag() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_failfast.py");

    fs::write(
        &test_file,
        r#"
def test_first():
    assert False  # This should fail

def test_second():
    assert True  # This should not run with --fail-fast
"#,
    )
    .unwrap();

    // With dry-run, we just verify the flag is passed correctly
    pybun()
        .current_dir(temp.path())
        .args(["test", "--fail-fast", "--format=json"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("fail_fast"));
}

// ---------------------------------------------------------------------------
// Shard Tests
// ---------------------------------------------------------------------------

#[test]
fn test_shard_flag_format() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_shard.py");

    fs::write(
        &test_file,
        r#"
def test_a(): assert True
def test_b(): assert True
def test_c(): assert True
def test_d(): assert True
"#,
    )
    .unwrap();

    // Test shard 1/2
    pybun()
        .current_dir(temp.path())
        .args(["test", "--shard", "1/2", "--format=json"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"shard\""));
}

#[test]
fn test_shard_invalid_format() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_shard_invalid.py");
    fs::write(&test_file, "def test_a(): pass").unwrap();

    // Invalid shard format should error
    pybun()
        .current_dir(temp.path())
        .args(["test", "--shard", "invalid", "--format=json"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .assert()
        .failure()
        .stdout(predicate::str::contains("error").or(predicate::str::contains("invalid")));
}

// ---------------------------------------------------------------------------
// pytest-compat Tests
// ---------------------------------------------------------------------------

#[test]
fn test_pytest_compat_flag() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_compat.py");

    fs::write(
        &test_file,
        r#"
import pytest

@pytest.fixture
def my_fixture():
    return 42

def test_with_fixture(my_fixture):
    assert my_fixture == 42
"#,
    )
    .unwrap();

    pybun()
        .current_dir(temp.path())
        .args(["test", "--pytest-compat", "--format=json"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("pytest_compat"));
}

// ---------------------------------------------------------------------------
// Exit Code Tests
// ---------------------------------------------------------------------------

#[test]
fn test_exit_code_on_success_dry_run() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_success.py");

    fs::write(
        &test_file,
        r#"
def test_pass():
    assert True
"#,
    )
    .unwrap();

    pybun()
        .current_dir(temp.path())
        .args(["test"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// Test Discovery Tests
// ---------------------------------------------------------------------------

#[test]
fn test_discovers_test_files() {
    let temp = TempDir::new().unwrap();

    // Create multiple test files
    fs::write(temp.path().join("test_one.py"), "def test_a(): pass").unwrap();
    fs::write(temp.path().join("test_two.py"), "def test_b(): pass").unwrap();
    fs::write(temp.path().join("not_a_test.py"), "def helper(): pass").unwrap();

    let output = pybun()
        .current_dir(temp.path())
        .args(["test", "--format=json"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    // Should have discovered test files
    let detail = json.get("detail").expect("Should have detail");
    assert!(
        detail.get("discovered_files").is_some() || detail.get("tests_found").is_some(),
        "Should report discovered tests: {}",
        stdout
    );
}

// ---------------------------------------------------------------------------
// unittest Tests
// ---------------------------------------------------------------------------

#[test]
fn test_discovers_unittest_style() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_unittest.py");

    fs::write(
        &test_file,
        r#"
import unittest

class TestExample(unittest.TestCase):
    def test_method(self):
        self.assertEqual(1, 1)
"#,
    )
    .unwrap();

    pybun()
        .current_dir(temp.path())
        .args(["test", "--format=json"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\":"));
}

// ---------------------------------------------------------------------------
// Verbose/Quiet Output Tests
// ---------------------------------------------------------------------------

#[test]
fn test_text_output_format() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_text.py");

    fs::write(&test_file, "def test_pass(): pass").unwrap();

    pybun()
        .current_dir(temp.path())
        .args(["test"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .assert()
        .success()
        .stdout(predicate::str::contains("pybun test:"));
}
