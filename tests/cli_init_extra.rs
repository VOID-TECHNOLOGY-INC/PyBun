use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;

use serde_json::Value;
use std::fs;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn init_skips_existing_files() {
    let temp = tempdir().unwrap();
    let gitignore = temp.path().join(".gitignore");
    fs::write(&gitignore, "existing content").unwrap();

    let output = bin()
        .current_dir(temp.path())
        .args(["--format=json", "init", "-y"])
        .output()
        .expect("command run");

    assert!(output.status.success());
    
    // Check content wasn't overwritten
    let content = fs::read_to_string(&gitignore).unwrap();
    assert_eq!(content, "existing content", ".gitignore should not be overwritten");

    // Check JSON output indicates skip
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout).unwrap();
    assert!(json["detail"]["files_skipped"].is_array());
    let skipped: Vec<String> = serde_json::from_value(json["detail"]["files_skipped"].clone()).unwrap();
    assert!(skipped.iter().any(|p| p.contains(".gitignore")));
}

#[test]
fn init_sanitizes_project_name() {
    let temp = tempdir().unwrap();
    let project_dir = temp.path().join("My Project!");
    fs::create_dir(&project_dir).unwrap();

    bin()
        .current_dir(&project_dir)
        .args(["init", "-y"])
        .assert()
        .success();

    let pyproject = project_dir.join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    // "My Project!" -> "my_project"
    assert!(content.contains("name = \"my_project\""), "project name should be sanitized");
}

#[test]
fn init_sanitizes_leading_numbers() {
    let temp = tempdir().unwrap();
    let project_dir = temp.path().join("123test");
    fs::create_dir(&project_dir).unwrap();

    bin()
        .current_dir(&project_dir)
        .args(["init", "-y"])
        .assert()
        .success();

    let pyproject = project_dir.join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(content.contains("name = \"_123test\""));
}

#[test]
fn init_separates_package_name_sanitization() {
    let temp = tempdir().unwrap();
    
    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--name", "123-pkg", "--template", "package"])
        .assert()
        .success();

    // pyproject allows start with number/dashes
    let pyproject = temp.path().join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(content.contains("name = \"123-pkg\""));

    // module name must be sanitized (start with _, no dashes)
    let src_pkg = temp.path().join("src").join("_123_pkg");
    assert!(src_pkg.exists(), "src/_123_pkg should exist");
    assert!(src_pkg.join("__init__.py").exists());
}
