use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::PredicateBooleanExt;
use pybun::lockfile::Lockfile;
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
