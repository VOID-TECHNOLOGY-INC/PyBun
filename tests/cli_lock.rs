use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
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
