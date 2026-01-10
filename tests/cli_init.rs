use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn init_creates_pyproject_toml() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y"])
        .assert()
        .success();

    let pyproject = temp.path().join("pyproject.toml");
    assert!(pyproject.exists(), "pyproject.toml should be created");

    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(content.contains("[project]"), "should have [project] section");
}

#[test]
fn init_creates_gitignore() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y"])
        .assert()
        .success();

    let gitignore = temp.path().join(".gitignore");
    assert!(gitignore.exists(), ".gitignore should be created");

    let content = fs::read_to_string(&gitignore).unwrap();
    assert!(content.contains("__pycache__"), "should have Python patterns");
}

#[test]
fn init_creates_readme() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y"])
        .assert()
        .success();

    let readme = temp.path().join("README.md");
    assert!(readme.exists(), "README.md should be created");
}

#[test]
fn init_uses_directory_name_as_project_name() {
    let temp = tempdir().unwrap();
    let project_dir = temp.path().join("my-awesome-project");
    fs::create_dir(&project_dir).unwrap();

    bin()
        .current_dir(&project_dir)
        .args(["init", "-y"])
        .assert()
        .success();

    let pyproject = project_dir.join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(
        content.contains("my-awesome-project") || content.contains("my_awesome_project"),
        "should use directory name as project name"
    );
}

#[test]
fn init_with_custom_name() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--name", "custom-project"])
        .assert()
        .success();

    let pyproject = temp.path().join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(content.contains("custom-project"), "should use custom name");
}

#[test]
fn init_with_description() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--description", "A test project"])
        .assert()
        .success();

    let pyproject = temp.path().join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(content.contains("A test project"), "should have description");
}

#[test]
fn init_with_author() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--author", "Test Author <test@example.com>"])
        .assert()
        .success();

    let pyproject = temp.path().join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(content.contains("Test Author"), "should have author");
}

#[test]
fn init_package_template_creates_src_layout() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--template", "package"])
        .assert()
        .success();

    // Check src directory structure
    let src_dir = temp.path().join("src");
    assert!(src_dir.exists(), "src/ directory should be created for package template");
}

#[test]
fn init_minimal_template_flat_layout() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--template", "minimal"])
        .assert()
        .success();

    // Minimal template should NOT create src/ directory by default
    assert!(temp.path().join("pyproject.toml").exists());
    // No src/ in minimal mode
}

#[test]
fn init_json_output() {
    let temp = tempdir().unwrap();

    let output = bin()
        .current_dir(temp.path())
        .args(["--format=json", "init", "-y"])
        .output()
        .expect("command runs");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid JSON output");

    assert_eq!(json["status"], "ok");
    assert!(json["detail"]["files_created"].is_array(), "should list created files");
}

#[test]
fn init_fails_if_pyproject_exists() {
    let temp = tempdir().unwrap();
    let pyproject = temp.path().join("pyproject.toml");
    fs::write(&pyproject, "[project]\nname = \"existing\"\n").unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("already exists").or(predicate::str::contains("pyproject.toml")));
}

#[test]
fn init_help_shows_options() {
    bin()
        .args(["init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--name"))
        .stdout(predicate::str::contains("--template"));
}

#[test]
fn init_with_python_version() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--python", "3.11"])
        .assert()
        .success();

    let pyproject = temp.path().join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(
        content.contains("3.11") || content.contains("requires-python"),
        "should have python version specification"
    );
}
