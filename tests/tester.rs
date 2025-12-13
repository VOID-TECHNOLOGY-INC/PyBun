//! E2E tests for `pybun test` command
//!
//! Tests for the test runner functionality:
//! - Basic test discovery and execution (pytest/unittest wrapper)
//! - JSON output format
//! - --fail-fast option
//! - --shard option
//! - Exit codes

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
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

// ---------------------------------------------------------------------------
// AST-based Discovery Tests (PR3.1)
// ---------------------------------------------------------------------------

#[test]
fn test_discover_mode() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_discover.py");

    fs::write(
        &test_file,
        r#"
def test_one():
    assert True

def test_two():
    assert 1 + 1 == 2

class TestExample:
    def test_method(self):
        assert True
"#,
    )
    .unwrap();

    let output = pybun()
        .current_dir(temp.path())
        .args(["test", "--discover", "--format=json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    // Check discover mode output structure
    let detail = json.get("detail").expect("Should have detail");
    assert!(detail.get("discover").is_some(), "Should have discover flag");
    assert!(detail.get("tests").is_some(), "Should have tests array");

    // Check tests were discovered
    let tests = detail.get("tests").unwrap().as_array().unwrap();
    assert!(tests.len() >= 2, "Should discover at least 2 test functions");
}

#[test]
fn test_discover_pytest_markers() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_markers.py");

    fs::write(
        &test_file,
        r#"
import pytest

@pytest.mark.skip(reason="not ready")
def test_skipped():
    pass

@pytest.mark.xfail
def test_expected_fail():
    assert False

@pytest.mark.parametrize("x", [1, 2, 3])
def test_parametrized(x):
    assert x > 0
"#,
    )
    .unwrap();

    let output = pybun()
        .current_dir(temp.path())
        .args(["test", "--discover", "--format=json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    let detail = json.get("detail").expect("Should have detail");
    let tests = detail.get("tests").unwrap().as_array().unwrap();

    // Find skipped test
    let skipped = tests.iter().find(|t| {
        t.get("short_name")
            .and_then(|n| n.as_str())
            .map(|n| n == "test_skipped")
            .unwrap_or(false)
    });
    assert!(skipped.is_some(), "Should find test_skipped");
    let skipped = skipped.unwrap();
    assert_eq!(skipped.get("skipped").unwrap().as_bool().unwrap(), true);
    assert!(skipped.get("skip_reason").is_some());

    // Find xfail test
    let xfail = tests.iter().find(|t| {
        t.get("short_name")
            .and_then(|n| n.as_str())
            .map(|n| n == "test_expected_fail")
            .unwrap_or(false)
    });
    assert!(xfail.is_some(), "Should find test_expected_fail");
    assert_eq!(xfail.unwrap().get("xfail").unwrap().as_bool().unwrap(), true);

    // Find parametrized test
    let param = tests.iter().find(|t| {
        t.get("short_name")
            .and_then(|n| n.as_str())
            .map(|n| n == "test_parametrized")
            .unwrap_or(false)
    });
    assert!(param.is_some(), "Should find test_parametrized");
    assert!(param.unwrap().get("parametrize").is_some());
}

#[test]
fn test_discover_fixtures() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_fixtures.py");

    fs::write(
        &test_file,
        r#"
import pytest

@pytest.fixture
def simple_fixture():
    return 42

@pytest.fixture(scope="session")
def session_fixture():
    yield "session"

def test_with_fixtures(simple_fixture, session_fixture):
    assert simple_fixture == 42
"#,
    )
    .unwrap();

    let output = pybun()
        .current_dir(temp.path())
        .args(["test", "--discover", "--format=json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    let detail = json.get("detail").expect("Should have detail");

    // Check fixtures were discovered
    let fixtures = detail.get("fixtures").unwrap().as_array().unwrap();
    assert!(fixtures.len() >= 2, "Should discover at least 2 fixtures");

    // Check fixture dependencies in test
    let tests = detail.get("tests").unwrap().as_array().unwrap();
    let test_with_fixtures = tests.iter().find(|t| {
        t.get("short_name")
            .and_then(|n| n.as_str())
            .map(|n| n == "test_with_fixtures")
            .unwrap_or(false)
    });
    assert!(test_with_fixtures.is_some());
    let fixtures_used = test_with_fixtures
        .unwrap()
        .get("fixtures")
        .unwrap()
        .as_array()
        .unwrap();
    assert!(fixtures_used.len() >= 2, "Test should use at least 2 fixtures");
}

#[test]
fn test_discover_with_filter() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_filter.py");

    fs::write(
        &test_file,
        r#"
def test_foo_one():
    pass

def test_foo_two():
    pass

def test_bar_one():
    pass
"#,
    )
    .unwrap();

    // Filter with -k foo
    let output = pybun()
        .current_dir(temp.path())
        .args(["test", "--format=json", "-k", "foo"])
        .env("PYBUN_TEST_DRY_RUN", "1")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    let detail = json.get("detail").expect("Should have detail");
    // Filter should be recorded
    assert!(detail.get("filter").is_some());
}

#[test]
fn test_discover_verbose_output() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_verbose.py");

    fs::write(
        &test_file,
        r#"
import pytest

@pytest.fixture
def my_fixture():
    return 1

def test_with_info(my_fixture):
    assert my_fixture == 1
"#,
    )
    .unwrap();

    // Verbose discover mode
    pybun()
        .current_dir(temp.path())
        .args(["test", "--discover", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Tests:"))
        .stdout(predicate::str::contains("Fixtures:"));
}

#[test]
fn test_discover_compat_warnings() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_compat_warn.py");

    fs::write(
        &test_file,
        r#"
import pytest

@pytest.fixture(scope="session")
def session_fixture():
    yield

@pytest.mark.parametrize("x", [1, 2])
def test_param(x, session_fixture):
    assert x > 0
"#,
    )
    .unwrap();

    let output = pybun()
        .current_dir(temp.path())
        .args(["test", "--discover", "--format=json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    let detail = json.get("detail").expect("Should have detail");

    // Check compat warnings were generated
    let warnings = detail.get("compat_warnings").unwrap().as_array().unwrap();
    assert!(!warnings.is_empty(), "Should have compatibility warnings");

    // Check warning structure
    let warning = &warnings[0];
    assert!(warning.get("code").is_some());
    assert!(warning.get("message").is_some());
    assert!(warning.get("severity").is_some());
}

#[test]
fn test_discover_async_tests() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_async.py");

    fs::write(
        &test_file,
        r#"
async def test_async_function():
    assert True

def test_sync_function():
    assert True
"#,
    )
    .unwrap();

    let output = pybun()
        .current_dir(temp.path())
        .args(["test", "--discover", "--format=json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    let detail = json.get("detail").expect("Should have detail");
    let tests = detail.get("tests").unwrap().as_array().unwrap();

    // Should discover both async and sync tests
    assert!(tests.len() >= 2, "Should discover at least 2 tests");

    let async_test = tests.iter().find(|t| {
        t.get("short_name")
            .and_then(|n| n.as_str())
            .map(|n| n == "test_async_function")
            .unwrap_or(false)
    });
    assert!(async_test.is_some(), "Should discover async test");
}

#[test]
fn test_discover_test_class_methods() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_class.py");

    fs::write(
        &test_file,
        r#"
class TestMyClass:
    def test_method_one(self):
        assert True

    def test_method_two(self):
        assert True

    def helper_method(self):
        pass  # Not a test
"#,
    )
    .unwrap();

    let output = pybun()
        .current_dir(temp.path())
        .args(["test", "--discover", "--format=json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    let detail = json.get("detail").expect("Should have detail");
    let tests = detail.get("tests").unwrap().as_array().unwrap();

    // Find test methods
    let methods: Vec<_> = tests
        .iter()
        .filter(|t| {
            t.get("type")
                .and_then(|t| t.as_str())
                .map(|t| t == "method")
                .unwrap_or(false)
        })
        .collect();

    assert_eq!(methods.len(), 2, "Should discover 2 test methods");

    // Check class name is recorded
    for method in methods {
        assert_eq!(
            method.get("class").and_then(|c| c.as_str()),
            Some("TestMyClass")
        );
    }
}

#[test]
fn test_discover_reports_duration() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_duration.py");

    fs::write(&test_file, "def test_one(): pass\ndef test_two(): pass").unwrap();

    let output = pybun()
        .current_dir(temp.path())
        .args(["test", "--discover", "--format=json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    let detail = json.get("detail").expect("Should have detail");

    // Check duration is reported
    assert!(detail.get("duration_us").is_some(), "Should report discovery duration");
}

#[test]
fn test_ast_discovery_in_dry_run() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test_ast.py");

    fs::write(
        &test_file,
        r#"
def test_one():
    pass

def test_two():
    pass
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

    // Check AST discovery info is included
    assert!(
        detail.get("ast_discovery").is_some(),
        "Should include ast_discovery info in dry-run"
    );
}

#[test]
fn test_help_shows_new_options() {
    pybun()
        .args(["test", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--discover"))
        .stdout(predicate::str::contains("--filter"))
        .stdout(predicate::str::contains("--parallel"))
        .stdout(predicate::str::contains("--verbose"));
}
