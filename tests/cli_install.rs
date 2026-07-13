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

fn index_missing_hash_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_missing_hash.json")
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
fn install_fails_when_selected_artifact_is_missing_hash() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_missing_hash_path();

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
        .failure()
        .stdout(predicates::str::contains("missing sha256"));

    assert!(
        !lock_path.exists(),
        "install should fail before writing an unverifiable lockfile"
    );
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
fn install_json_output_reports_error_in_diagnostics_array() {
    let temp = tempdir().unwrap();
    // No pyproject.toml and no --require: install() returns a generic error
    // that must still surface as a structured Diagnostic in the JSON envelope
    // (Issue #126: inconsistent diagnostics reporting).

    let assert = bin()
        .current_dir(temp.path())
        .args(["--format=json", "install"])
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
                    .is_some_and(|m| m.contains("no requirements provided"))
        }),
        "expected an error diagnostic about missing requirements: {diagnostics:?}"
    );
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

    // Pin to cp311 so this test is independent of the system Python version.
    // The fixture only contains cp311 wheels; without the override the test would fall
    // back to py3-none-any on hosts running Python != 3.11.
    bin()
        .env("PYBUN_FORCE_CP_TAG", "cp311")
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
fn install_warns_and_errors_when_no_wheel_matches() {
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
        !output.status.success(),
        "install should fail when source builds are required"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json output");
    assert_eq!(json["status"], "error");
    let diagnostics = json["diagnostics"].as_array().cloned().unwrap_or_default();
    assert!(
        diagnostics.iter().any(|d| {
            d["level"] == "warning"
                && d["message"]
                    .as_str()
                    .map(|m| m.contains("source-only") && m.contains("source distributions"))
                    .unwrap_or(false)
        }),
        "should emit warning diagnostic about source build limitation: {stdout}"
    );
    assert!(
        diagnostics.iter().any(|d| {
            d["level"] == "error"
                && d["code"] == "E_VERIFY_MISSING_HASH"
                && d["message"]
                    .as_str()
                    .map(|m| m.contains("missing sha256"))
                    .unwrap_or(false)
        }),
        "should emit error diagnostic about unverifiable source artifact: {stdout}"
    );

    assert!(
        !lock_path.exists(),
        "install should fail before writing an unverifiable source artifact lockfile"
    );
}

// =============================================================================
// Issue #144: PEP 425/600 platform tag matching for macOS ARM64 and manylinux
// =============================================================================

fn index_pypi_wheels_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_pypi_wheels.json")
}

/// Expected wheel filename using PyPI/PEP 425 standard platform tags.
fn expected_pypi_native_wheel() -> String {
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "pypi-native-1.0.0-cp311-cp311-macosx_11_0_arm64.whl".into()
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        "pypi-native-1.0.0-cp311-cp311-macosx_11_0_x86_64.whl".into()
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "pypi-native-1.0.0-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl".into()
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        "pypi-native-1.0.0-cp311-cp311-manylinux_2_17_aarch64.manylinux2014_aarch64.whl".into()
    } else if cfg!(target_os = "windows") && cfg!(target_arch = "x86_64") {
        "pypi-native-1.0.0-cp311-cp311-win_amd64.whl".into()
    } else {
        "pypi-native-1.0.0-py3-none-any.whl".into()
    }
}

#[test]
fn install_resolves_pep425_macosx_arm64_wheel() {
    // Regression test for Issue #144: wheels with standard PEP 425 platform tags
    // like macosx_11_0_arm64 must be matched on macOS ARM64.
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_pypi_wheels_path();

    // Pin to cp311 so this test is independent of the system Python version.
    // The fixture only contains cp311 wheels; without the override the test would fall
    // back to py3-none-any on hosts running Python != 3.11.
    bin()
        .env("PYBUN_FORCE_CP_TAG", "cp311")
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "pypi-native==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let pkg = lock.packages.get("pypi-native").expect("entry exists");
    assert_eq!(
        pkg.wheel,
        expected_pypi_native_wheel(),
        "should select native platform wheel using PEP 425 tags"
    );
}

#[test]
fn install_resolves_universal2_wheel_on_macos() {
    // universal2 wheels should be matched on both macOS ARM64 and x86_64.
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_pypi_wheels_path();

    // Pin to cp311 so this test is independent of the system Python version.
    // The fixture only contains cp311 wheels; without the override the test would fall
    // back to sdist on hosts running Python != 3.11.
    let status = bin()
        .env("PYBUN_FORCE_CP_TAG", "cp311")
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "universal2-only==2.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .output()
        .expect("command runs");

    if cfg!(target_os = "macos") {
        assert!(
            status.status.success(),
            "universal2 wheel should install on macOS: {}",
            String::from_utf8_lossy(&status.stdout)
        );
        let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
        let pkg = lock.packages.get("universal2-only").expect("entry exists");
        assert_eq!(
            pkg.wheel, "universal2-only-2.0.0-cp311-cp311-macosx_11_0_universal2.whl",
            "should select universal2 wheel on macOS"
        );
    }
}

#[test]
fn install_resolves_manylinux_2_28_wheel_on_linux_x86_64() {
    // manylinux_2_28 wheels should be matched on Linux x86_64.
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_pypi_wheels_path();

    // Pin to cp311 so this test is independent of the system Python version.
    // The fixture only contains cp311 wheels; without the override the test would fall
    // back to sdist on hosts running Python != 3.11.
    let output = bin()
        .env("PYBUN_FORCE_CP_TAG", "cp311")
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "manylinux28-only==3.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .output()
        .expect("command runs");

    if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        assert!(
            output.status.success(),
            "manylinux_2_28 wheel should install on Linux x86_64: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
        let pkg = lock.packages.get("manylinux28-only").expect("entry exists");
        assert_eq!(
            pkg.wheel, "manylinux28-only-3.0.0-cp311-cp311-manylinux_2_28_x86_64.whl",
            "should select manylinux_2_28 wheel on Linux x86_64"
        );
    }
}

// =============================================================================
// Issue #291: off-by-one wheel python_tag selection — install must select
// wheels matching the *target* venv's Python, not whatever python3/python
// happens to resolve on PATH.
// =============================================================================

fn index_cp_tag_mismatch_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_cp_tag_mismatch.json")
}

/// Create a fake venv whose `bin/python` (or `Scripts/python.exe` on Windows)
/// reports a controlled `--version` output, independent of any real Python
/// installation on the host or on PATH.
#[cfg(unix)]
fn fake_venv_reporting_version(root: &std::path::Path, version_line: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let venv_dir = root.join(".fake-venv");
    let bin_dir = venv_dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let python = bin_dir.join("python");
    let mut file = fs::File::create(&python).unwrap();
    use std::io::Write;
    writeln!(file, "#!/bin/sh\necho '{version_line}'").unwrap();
    let mut perms = file.metadata().unwrap().permissions();
    perms.set_mode(0o755);
    file.set_permissions(perms).unwrap();

    fs::write(venv_dir.join("pyvenv.cfg"), "version = 3.12.5\n").unwrap();

    venv_dir
}

#[cfg(unix)]
#[test]
fn install_selects_wheel_for_target_venv_python_not_path_python() {
    // Regression test for Issue #291: pybun install resolved `cp311` wheels into a
    // Python 3.12 venv. The fake venv here reports "Python 3.12.5" regardless of
    // whatever python3/python is on PATH (which may be 3.11, 3.13, or anything
    // else on the machine running this test) — so a passing test proves install
    // consults the *venv's* interpreter, not PATH, when selecting wheels.
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_cp_tag_mismatch_path();
    let venv = fake_venv_reporting_version(temp.path(), "Python 3.12.5");

    bin()
        .env("PYBUN_ENV", &venv)
        .env_remove("PYBUN_FORCE_CP_TAG")
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "verpkg==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let pkg = lock.packages.get("verpkg").expect("entry exists");
    assert_eq!(
        pkg.wheel, "verpkg-1.0.0-cp312-cp312-any.whl",
        "should select the cp312 wheel matching the target venv's Python 3.12, \
         not whatever python3/python resolves to on PATH"
    );
}

// =============================================================================
// Issue #341: pre-release versions must be excluded by default (PEP 440) and
// only selected with the `--pre` opt-in, a specifier mentioning a pre-release,
// or as a fallback when only pre-releases satisfy the constraints.
// =============================================================================

fn index_prerelease_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_prerelease.json")
}

#[test]
fn install_excludes_prerelease_versions_by_default() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_prerelease_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "lib>=1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let lib = lock.packages.get("lib").expect("lib entry");
    assert_eq!(
        lib.version, "1.0.0",
        "pre-release 2.0.0rc1 must not be selected without --pre"
    );
}

#[test]
fn install_pre_flag_opts_in_to_prerelease_versions() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_prerelease_path();

    bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "lib>=1.0.0",
            "--pre",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let lib = lock.packages.get("lib").expect("lib entry");
    assert_eq!(
        lib.version, "2.0.0rc1",
        "--pre must allow the pre-release to be selected"
    );
}
