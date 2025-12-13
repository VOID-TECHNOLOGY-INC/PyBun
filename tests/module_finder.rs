//! E2E tests for the module finder functionality.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn pybun() -> Command {
    Command::cargo_bin("pybun").unwrap()
}

/// Helper to create a Python package structure for testing.
fn create_python_packages(dir: &std::path::Path) {
    // Create package: mypackage/__init__.py
    let pkg_dir = dir.join("mypackage");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(pkg_dir.join("__init__.py"), "# mypackage").unwrap();
    fs::write(pkg_dir.join("core.py"), "# core module").unwrap();

    // Create subpackage: mypackage/utils/__init__.py
    let utils_dir = pkg_dir.join("utils");
    fs::create_dir_all(&utils_dir).unwrap();
    fs::write(utils_dir.join("__init__.py"), "# utils").unwrap();
    fs::write(utils_dir.join("helpers.py"), "# helpers").unwrap();

    // Create standalone module
    fs::write(dir.join("standalone.py"), "# standalone module").unwrap();
}

#[test]
fn test_module_finder_cli_help() {
    // The module-find command should show help
    pybun()
        .args(["module-find", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("module"));
}

#[test]
fn test_module_finder_find_simple() {
    let temp = TempDir::new().unwrap();
    create_python_packages(temp.path());

    pybun()
        .args([
            "module-find",
            "--path",
            temp.path().to_str().unwrap(),
            "standalone",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("standalone.py"));
}

#[test]
fn test_module_finder_find_package() {
    let temp = TempDir::new().unwrap();
    create_python_packages(temp.path());

    pybun()
        .args([
            "module-find",
            "--path",
            temp.path().to_str().unwrap(),
            "mypackage",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("mypackage"));
}

#[test]
fn test_module_finder_find_nested() {
    let temp = TempDir::new().unwrap();
    create_python_packages(temp.path());

    pybun()
        .args([
            "module-find",
            "--path",
            temp.path().to_str().unwrap(),
            "mypackage.utils.helpers",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("helpers.py"));
}

#[test]
fn test_module_finder_not_found() {
    let temp = TempDir::new().unwrap();
    create_python_packages(temp.path());

    pybun()
        .args([
            "module-find",
            "--path",
            temp.path().to_str().unwrap(),
            "nonexistent",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("not found"));
}

#[test]
fn test_module_finder_json_output() {
    let temp = TempDir::new().unwrap();
    create_python_packages(temp.path());

    pybun()
        .args([
            "--format=json",
            "module-find",
            "--path",
            temp.path().to_str().unwrap(),
            "standalone",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"module_type\""))
        .stdout(predicate::str::contains("\"path\""));
}

#[test]
fn test_module_finder_scan() {
    let temp = TempDir::new().unwrap();
    create_python_packages(temp.path());

    pybun()
        .args([
            "module-find",
            "--scan",
            "--path",
            temp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("standalone"))
        .stdout(predicate::str::contains("mypackage"));
}

#[test]
fn test_module_finder_scan_json() {
    let temp = TempDir::new().unwrap();
    create_python_packages(temp.path());

    pybun()
        .args([
            "--format=json",
            "module-find",
            "--scan",
            "--path",
            temp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"modules\""));
}

#[test]
fn test_module_finder_benchmark_flag() {
    let temp = TempDir::new().unwrap();
    create_python_packages(temp.path());

    pybun()
        .args([
            "module-find",
            "--benchmark",
            "--path",
            temp.path().to_str().unwrap(),
            "mypackage",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Duration"));
}
