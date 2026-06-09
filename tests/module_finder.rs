//! E2E tests for the module finder functionality.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
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

#[test]
fn test_scan_json_includes_duration_us() {
    let temp = TempDir::new().unwrap();
    create_python_packages(temp.path());

    let output = pybun()
        .args([
            "--format=json",
            "module-find",
            "--scan",
            "--path",
            temp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert!(
        json["detail"]["duration_us"].is_number(),
        "scan JSON detail must include duration_us: got {:?}",
        json["detail"]
    );
}

#[test]
fn test_scan_parallel_finds_all_modules_in_large_structure() {
    let temp = TempDir::new().unwrap();

    // Create 15+ top-level packages to trigger parallel subdirectory scanning
    for i in 0..15 {
        let pkg = temp.path().join(format!("pkg{i}"));
        fs::create_dir_all(&pkg).unwrap();
        fs::write(pkg.join("__init__.py"), "").unwrap();
        fs::write(pkg.join("module.py"), "").unwrap();
        let sub = pkg.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("__init__.py"), "").unwrap();
        fs::write(sub.join("leaf.py"), "").unwrap();
    }

    let output = pybun()
        .args([
            "--format=json",
            "module-find",
            "--scan",
            "--path",
            temp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    let count = json["detail"]["count"].as_u64().unwrap_or(0);
    // 15 packages × (package + module + sub-package + leaf) = 60 modules
    assert!(
        count >= 60,
        "expected ≥60 modules from 15 packages, got {count}"
    );
}

#[test]
fn test_scan_benchmark_includes_duration_in_text_output() {
    let temp = TempDir::new().unwrap();
    create_python_packages(temp.path());

    pybun()
        .args([
            "module-find",
            "--scan",
            "--benchmark",
            "--path",
            temp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("duration_us").or(predicate::str::contains("µs")));
}
