use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use pybun::lockfile::Lockfile;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

fn script_lock_path(script: &Path) -> PathBuf {
    let mut lock_path = script.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

fn index_path() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index.json")
}

#[test]
fn lock_script_creates_lockfile_from_index() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("example.py");
    let content = r#"# /// script
# dependencies = ["app==1.0.0"]
# ///
print("hello")
"#;
    fs::write(&script, content).unwrap();

    let index_path = PathBuf::from("tests/fixtures/index.json");
    let lock_path = script_lock_path(&script);

    bin()
        .args([
            "--format=json",
            "lock",
            "--script",
            script.to_str().unwrap(),
            "--index",
            index_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"lockfile\""));

    assert!(lock_path.exists());

    let lock = pybun::lockfile::Lockfile::load_from_path(&lock_path).unwrap();
    assert!(lock.packages.contains_key("app"));
    assert!(lock.packages.contains_key("lib-a"));
    assert!(lock.packages.contains_key("lib-b"));
    assert!(lock.packages.contains_key("lib-c"));
}

#[test]
fn lock_json_output_reports_error_in_diagnostics_array() {
    let temp = tempdir().unwrap();
    let missing_script = temp.path().join("does-not-exist.py");
    // lock_dependencies() returns a generic "script not found" error without
    // pushing a structured diagnostic itself; the dispatcher must still surface
    // it as a Diagnostic in the JSON envelope (Issue #126).

    let assert = bin()
        .args([
            "--format=json",
            "lock",
            "--script",
            missing_script.to_str().unwrap(),
        ])
        .assert()
        .failure();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(stdout.trim()).expect("valid JSON output");

    assert_eq!(json["status"], "error");
    let diagnostics = json["diagnostics"].as_array().cloned().unwrap_or_default();
    assert!(
        diagnostics.iter().any(|d| {
            d["level"] == "error"
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("script not found"))
        }),
        "expected an error diagnostic about the missing script: {diagnostics:?}"
    );
}

#[test]
fn lock_script_fails_when_selected_artifact_is_missing_hash() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("example.py");
    let content = r#"# /// script
# dependencies = ["app==1.0.0"]
# ///
print("hello")
"#;
    fs::write(&script, content).unwrap();

    let index_path = PathBuf::from("tests/fixtures/index_missing_hash.json");
    let lock_path = script_lock_path(&script);

    bin()
        .args([
            "--format=json",
            "lock",
            "--script",
            script.to_str().unwrap(),
            "--index",
            index_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("missing sha256"));

    assert!(
        !lock_path.exists(),
        "lock should fail before writing an unverifiable lockfile"
    );
}

// =============================================================================
// Issue #149: `pybun lock` should support locking project dependencies
// without requiring `--script` when a `pyproject.toml` is present.
// =============================================================================

#[test]
fn lock_project_creates_pybun_lockb_without_script_flag() {
    let temp = tempdir().unwrap();
    let pyproject_path = temp.path().join("pyproject.toml");
    let lock_path = temp.path().join("pybun.lockb");

    let pyproject_content = r#"[project]
name = "test-project"
version = "0.1.0"
dependencies = [
    "app==1.0.0",
]
"#;
    fs::write(&pyproject_path, pyproject_content).unwrap();

    bin()
        .current_dir(temp.path())
        .args([
            "--format=json",
            "lock",
            "--index",
            index_path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"lockfile\""));

    assert!(lock_path.exists(), "expected pybun.lockb to be created");

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    assert!(lock.packages.contains_key("app"));
    assert!(lock.packages.contains_key("lib-a"));
}

#[test]
fn lock_project_with_no_dependencies_creates_empty_lockfile() {
    let temp = tempdir().unwrap();
    let pyproject_path = temp.path().join("pyproject.toml");
    let lock_path = temp.path().join("pybun.lockb");

    let pyproject_content = r#"[project]
name = "empty-project"
version = "0.1.0"
"#;
    fs::write(&pyproject_path, pyproject_content).unwrap();

    bin()
        .current_dir(temp.path())
        .args(["--format=json", "lock"])
        .assert()
        .success();

    assert!(lock_path.exists(), "expected pybun.lockb to be created");
    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    assert!(lock.packages.is_empty());
}

#[test]
fn lock_without_script_or_pyproject_fails_with_actionable_error() {
    let temp = tempdir().unwrap();

    let assert = bin()
        .current_dir(temp.path())
        .args(["--format=json", "lock"])
        .assert()
        .failure();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(stdout.trim()).expect("valid JSON output");

    assert_eq!(json["status"], "error");
    let diagnostics = json["diagnostics"].as_array().cloned().unwrap_or_default();
    assert!(
        diagnostics.iter().any(|d| {
            d["level"] == "error"
                && d["suggestion"]
                    .as_str()
                    .is_some_and(|s| s.contains("--script") && s.contains("pyproject.toml"))
        }),
        "expected an actionable error diagnostic mentioning --script and pyproject.toml: {diagnostics:?}"
    );
}
