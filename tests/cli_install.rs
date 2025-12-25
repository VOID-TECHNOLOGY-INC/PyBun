use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::PredicateBooleanExt;
use pybun::lockfile::Lockfile;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn install_writes_lockfile_from_index() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "app==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let names: Vec<_> = lock.packages.keys().cloned().collect();
    assert_eq!(names, vec!["app", "lib-a", "lib-b", "lib-c"]);
}

#[test]
fn install_picks_latest_matching_version_for_minimum_spec() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_multi_version_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "app==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let lib = lock.packages.get("lib").expect("lib entry");
    assert_eq!(lib.version, "2.0.0");
}

#[test]
fn install_fails_on_missing_package() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "missing==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicates::str::contains("missing").or(predicates::str::contains("Missing")));
}

fn index_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index.json")
}

fn index_multi_version_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_multi_version.json")
}

fn index_specifiers_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_specifiers.json")
}

fn index_wheels_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_wheels.json")
}

fn expected_native_wheel() -> String {
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "native-wheels-1.0.0-cp311-cp311-macosx_11_0_arm64.whl".into()
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        "native-wheels-1.0.0-cp311-cp311-macosx_11_0_x86_64.whl".into()
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "native-wheels-1.0.0-cp311-cp311-manylinux_x86_64.whl".into()
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        "native-wheels-1.0.0-cp311-cp311-manylinux_aarch64.whl".into()
    } else if cfg!(target_os = "windows") && cfg!(target_arch = "x86_64") {
        "native-wheels-1.0.0-cp311-cp311-win_amd64.whl".into()
    } else {
        "native-wheels-1.0.0-py3-none-any.whl".into()
    }
}

// =============================================================================
// E2E tests for additional version specifiers (PR1.2 completion)
// =============================================================================

#[test]
fn install_with_maximum_inclusive_specifier() {
    // <=2.0.0 should select 2.0.0 (not 2.1.0)
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_specifiers_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "root-max==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let lib = lock.packages.get("lib").expect("lib entry");
    assert_eq!(lib.version, "2.0.0", "<=2.0.0 should select 2.0.0");
}

#[test]
fn install_with_maximum_exclusive_specifier() {
    // <2.0.0 should select 1.9.0 (not 2.0.0)
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_specifiers_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "root-max-excl==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let lib = lock.packages.get("lib").expect("lib entry");
    assert_eq!(lib.version, "1.9.0", "<2.0.0 should select 1.9.0");
}

#[test]
fn install_with_minimum_exclusive_specifier() {
    // >1.0.0 should select 2.1.0 (highest, excluding 1.0.0)
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_specifiers_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "root-min-excl==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let lib = lock.packages.get("lib").expect("lib entry");
    assert_eq!(lib.version, "2.1.0", ">1.0.0 should select 2.1.0");
}

#[test]
fn install_with_not_equal_specifier() {
    // !=1.5.0 should select 2.1.0 (highest, excluding 1.5.0)
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_specifiers_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "root-not-eq==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let lib = lock.packages.get("lib").expect("lib entry");
    assert_eq!(lib.version, "2.1.0", "!=1.5.0 should select 2.1.0");
}

#[test]
fn install_with_compatible_release_specifier() {
    // ~=1.4.0 should select 1.4.5 (highest in 1.4.x series)
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_specifiers_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "root-compat==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let lib = lock.packages.get("lib").expect("lib entry");
    assert_eq!(lib.version, "1.4.5", "~=1.4.0 should select 1.4.5");
}

#[test]
fn install_resolves_under_upper_bound_with_higher_version_available() {
    // numpy<2.4 should pick 2.3.5 even if 2.4.0 exists
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_specifiers_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "root-numpy==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let numpy = lock.packages.get("numpy").expect("numpy entry");
    assert_eq!(numpy.version, "2.3.5");
}

// =============================================================================
// PR1.8: Install from pyproject.toml (normal flow)
// =============================================================================

#[test]
fn install_from_pyproject_toml() {
    let temp = tempdir().unwrap();
    let pyproject_path = temp.path().join("pyproject.toml");
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    // Create a pyproject.toml with dependencies
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
            "install",
            "--index",
            index.to_str().unwrap(),
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let names: Vec<_> = lock.packages.keys().cloned().collect();
    assert_eq!(names, vec!["app", "lib-a", "lib-b", "lib-c"]);
}

#[test]
fn install_from_pyproject_with_multiple_deps() {
    let temp = tempdir().unwrap();
    let pyproject_path = temp.path().join("pyproject.toml");
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    // Create a pyproject.toml with multiple dependencies
    let pyproject_content = r#"[project]
name = "multi-dep-project"
version = "0.1.0"
dependencies = [
    "lib-a==1.0.0",
    "lib-c==1.0.0",
]
"#;
    fs::write(&pyproject_path, pyproject_content).unwrap();

    bin()
        .current_dir(temp.path())
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    assert!(lock.packages.contains_key("lib-a"));
    assert!(lock.packages.contains_key("lib-c"));
}

#[test]
fn install_from_pyproject_no_project_section_succeeds_empty() {
    let temp = tempdir().unwrap();
    let pyproject_path = temp.path().join("pyproject.toml");
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    // Create a pyproject.toml without [project] section
    // This is valid - means no dependencies, should create empty lockfile
    let pyproject_content = r#"[tool.pybun]
python = "3.11"
"#;
    fs::write(&pyproject_path, pyproject_content).unwrap();

    bin()
        .current_dir(temp.path())
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("no dependencies to install"));

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    assert!(lock.packages.is_empty());
}

#[test]
fn install_from_pyproject_empty_deps_succeeds() {
    let temp = tempdir().unwrap();
    let pyproject_path = temp.path().join("pyproject.toml");
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    // Create a pyproject.toml with empty dependencies
    let pyproject_content = r#"[project]
name = "empty-project"
version = "0.1.0"
dependencies = []
"#;
    fs::write(&pyproject_path, pyproject_content).unwrap();

    bin()
        .current_dir(temp.path())
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    assert!(lock.packages.is_empty());
}

#[test]
fn install_cli_require_overrides_pyproject() {
    // When --require is provided, it should be used instead of pyproject.toml
    let temp = tempdir().unwrap();
    let pyproject_path = temp.path().join("pyproject.toml");
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    // Create pyproject.toml with lib-a
    let pyproject_content = r#"[project]
name = "override-test"
version = "0.1.0"
dependencies = ["lib-a==1.0.0"]
"#;
    fs::write(&pyproject_path, pyproject_content).unwrap();

    // But install lib-c via --require
    bin()
        .current_dir(temp.path())
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "lib-c==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    // Should only have lib-c (from --require), not lib-a (from pyproject)
    assert!(lock.packages.contains_key("lib-c"));
    assert!(!lock.packages.contains_key("lib-a"));
}

#[test]
fn install_no_pyproject_and_no_require_error() {
    let temp = tempdir().unwrap();
    // No pyproject.toml exists in temp dir
    // No --require flag

    bin()
        .current_dir(temp.path())
        .args(["install"])
        .assert()
        .failure()
        .stdout(predicates::str::contains("no requirements provided"));
}

#[test]
fn install_json_output_from_pyproject() {
    let temp = tempdir().unwrap();
    let pyproject_path = temp.path().join("pyproject.toml");
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    let pyproject_content = r#"[project]
name = "json-test"
version = "0.1.0"
dependencies = ["lib-c==1.0.0"]
"#;
    fs::write(&pyproject_path, pyproject_content).unwrap();

    bin()
        .current_dir(temp.path())
        .args([
            "--format=json",
            "install",
            "--index",
            index.to_str().unwrap(),
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"status\":\"ok\""))
        .stdout(predicates::str::contains("\"packages\""));
}

// =============================================================================
// PR5.2: Pre-built wheel discovery & preference
// =============================================================================

#[test]
fn install_prefers_prebuilt_wheel_for_platform() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_wheels_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "native-wheels==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let pkg = lock.packages.get("native-wheels").expect("entry exists");
    assert_eq!(pkg.wheel, expected_native_wheel());
}

#[test]
fn install_warns_and_falls_back_to_source_when_no_wheel_matches() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_wheels_path();

    let output = bin()
        .args([
            "--format=json",
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "source-only==0.5.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .output()
        .expect("command runs");

    assert!(
        output.status.success(),
        "install should succeed even when building from source"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json output");
    let diagnostics = json["diagnostics"].as_array().cloned().unwrap_or_default();
    assert!(
        diagnostics.iter().any(|d| {
            d["level"] == "warning"
                && d["message"]
                    .as_str()
                    .map(|m| m.contains("source-only") && m.contains("source build"))
                    .unwrap_or(false)
        }),
        "should emit warning diagnostic about source build fallback: {stdout}"
    );

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let pkg = lock.packages.get("source-only").expect("entry exists");
    assert!(
        pkg.wheel.ends_with(".tar.gz"),
        "fallback should lock to source artifact"
    );
}
