#![allow(deprecated)]
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_env_source_display_labels() {
    // This test verifies that pybun run outputs (LOCAL) or (GLOBAL) based on context.

    // 1. System/Global context (no venv)
    let temp = TempDir::new().unwrap();
    let bin = assert_cmd::cargo::cargo_bin("pybun");

    // We need to ensure we don't accidentally pick up a venv or .python-version from parents
    // But since we can't easily isolate completely from system headers in this env without mocking,
    // we'll rely on the fact that if we just run `pybun run -c "pass"`, it should print info.

    let output = Command::new(bin)
        .current_dir(temp.path())
        .env_remove("PYBUN_ENV")
        .env_remove("PYBUN_PYTHON")
        .arg("run")
        .arg("-c")
        .arg("--")
        .arg("pass")
        .output()
        .expect("Failed to run pybun");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // It should say "info: using Python from ... (GLOBAL)" or similar if it falls back to system
    // Or (LOCAL) if we accidentally picked up something local.
    // The key is that the suffix is present.
    assert!(
        stderr.contains("(GLOBAL)") || stderr.contains("(LOCAL)"),
        "Output should contain context suffix: {}",
        stderr
    );
}

#[test]
fn test_pybun_test_directory_arg() {
    // This test verifies that `pybun test <dir>` implies `discover -s <dir>`
    // We can't easily mock the internal ProcessCommand construction without unit tests,
    // but we can check if it fails with a specific error or behaves as expected.
    //
    // Improve: We can inspect the "info: using Python from ..." logs or behavior?
    // A better check might be to create a test file in a subdir and see if it runs.

    let temp = TempDir::new().unwrap();
    let test_dir = temp.path().join("my_tests");
    fs::create_dir(&test_dir).unwrap();

    // Create a dummy test that prints a unique string
    let test_file = test_dir.join("test_foo.py");
    fs::write(
        &test_file,
        r#"
import unittest
class TestFoo(unittest.TestCase):
    def test_pass(self):
        print("UNIQUE_MARKER_EXECUTED")
"#,
    )
    .unwrap();

    let bin = assert_cmd::cargo::cargo_bin("pybun");

    let output = Command::new(bin)
        .current_dir(temp.path())
        .env("PYBUN_TRACE", "1")
        .arg("test")
        .arg("my_tests") // passing directory directly
        .arg("--backend=unittest") // Force unittest backend to trigger logic
        .output()
        .expect("Failed to run pybun test");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT:\n{}", stdout);
    println!("STDERR:\n{}", stderr);

    // If "discover -s my_tests" was used, it should find and run the test
    assert!(
        stderr.contains("UNIQUE_MARKER_EXECUTED") || stdout.contains("UNIQUE_MARKER_EXECUTED"),
        "Test should have executed. If it failed to discover, it implies logic is broken."
    );
}
