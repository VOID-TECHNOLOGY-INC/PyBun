use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

/// Create a virtual environment in the given directory
fn create_venv(dir: &std::path::Path) {
    std::process::Command::new("python3")
        .args(["-m", "venv", ".venv"])
        .current_dir(dir)
        .status()
        .expect("Failed to create venv");
}

#[test]
fn add_creates_pyproject_if_missing() {
    let temp = tempdir().unwrap();
    create_venv(temp.path());

    bin()
        .current_dir(temp.path())
        .args(["add", "requests>=2.28.0"])
        .assert()
        .success()
        .stdout(predicate::str::contains("added requests>=2.28.0"));

    // Check pyproject.toml was created
    let pyproject_path = temp.path().join("pyproject.toml");
    assert!(pyproject_path.exists(), "pyproject.toml should be created");

    let content = fs::read_to_string(&pyproject_path).unwrap();
    assert!(
        content.contains("requests>=2.28.0"),
        "should contain the added package"
    );
}

#[test]
fn add_updates_existing_pyproject() {
    let temp = tempdir().unwrap();
    create_venv(temp.path());

    // Create initial pyproject.toml
    let pyproject = r#"[project]
name = "test-project"
version = "0.1.0"
dependencies = []
"#;
    fs::write(temp.path().join("pyproject.toml"), pyproject).unwrap();

    bin()
        .current_dir(temp.path())
        .args(["add", "click>=2.0.0"])
        .assert()
        .success();

    let content = fs::read_to_string(temp.path().join("pyproject.toml")).unwrap();
    assert!(
        content.contains("click>=2.0.0"),
        "should contain the added package"
    );
    assert!(
        content.contains("name = \"test-project\""),
        "should preserve existing fields"
    );
}

#[test]
fn add_replaces_existing_version() {
    let temp = tempdir().unwrap();
    create_venv(temp.path());

    // Create pyproject.toml with existing requests
    let pyproject = r#"[project]
name = "test-project"
dependencies = ["requests>=2.28.0"]
"#;
    fs::write(temp.path().join("pyproject.toml"), pyproject).unwrap();

    bin()
        .current_dir(temp.path())
        .args(["add", "requests>=2.31.0"])
        .assert()
        .success();

    let content = fs::read_to_string(temp.path().join("pyproject.toml")).unwrap();
    assert!(
        content.contains("requests>=2.31.0"),
        "should have new version"
    );
    assert!(
        !content.contains("requests>=2.28.0"),
        "should not have old version"
    );
}

#[test]
fn add_fails_without_package_name() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["add"])
        .assert()
        .failure();
}

#[test]
fn remove_removes_dependency() {
    let temp = tempdir().unwrap();

    // Create pyproject.toml with dependencies
    let pyproject = r#"[project]
name = "test-project"
dependencies = ["requests>=2.28.0", "click>=2.0.0"]
"#;
    fs::write(temp.path().join("pyproject.toml"), pyproject).unwrap();

    bin()
        .current_dir(temp.path())
        .args(["remove", "requests"])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed requests"));

    let content = fs::read_to_string(temp.path().join("pyproject.toml")).unwrap();
    assert!(
        !content.contains("requests"),
        "should not contain removed package"
    );
    assert!(content.contains("click"), "should keep other packages");
}

#[test]
fn remove_reports_not_found() {
    let temp = tempdir().unwrap();

    let pyproject = r#"[project]
name = "test-project"
dependencies = []
"#;
    fs::write(temp.path().join("pyproject.toml"), pyproject).unwrap();

    bin()
        .current_dir(temp.path())
        .args(["remove", "nonexistent"])
        .assert()
        .success()
        .stdout(predicate::str::contains("was not found"));
}

#[test]
fn remove_fails_without_pyproject() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["remove", "requests"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("pyproject.toml not found"));
}

#[test]
fn add_json_output() {
    let temp = tempdir().unwrap();
    create_venv(temp.path());

    bin()
        .current_dir(temp.path())
        .args(["--format=json", "add", "requests>=2.28.0"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"package\":\"requests\""));
}

#[test]
fn remove_json_output() {
    let temp = tempdir().unwrap();

    let pyproject = r#"[project]
dependencies = ["requests>=2.28.0"]
"#;
    fs::write(temp.path().join("pyproject.toml"), pyproject).unwrap();

    bin()
        .current_dir(temp.path())
        .args(["--format=json", "remove", "requests"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"removed\":true"));
}
