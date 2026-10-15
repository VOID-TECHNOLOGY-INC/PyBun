use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use std::fs;
use std::path::Path;

fn command(root: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    cargo_bin_cmd!("pybun")
        .current_dir(root)
        .env("PYBUN_HOME", home)
        .env("PYBUN_HISTORY", "1")
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_PYTHON", "python3")
        .args(["--format=json"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn history_records_success_failure_and_queries_without_logging_itself() {
    let temp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("ok.py"), "pass\n").unwrap();
    assert!(
        command(temp.path(), home.path(), &["run", "ok.py"])
            .status
            .success()
    );
    assert_eq!(
        command(
            temp.path(),
            home.path(),
            &["run", "-c", "raise SystemExit(7)"]
        )
        .status
        .code(),
        Some(7)
    );
    let output = command(temp.path(), home.path(), &["history", "--since", "20m"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let records = value["detail"]["records"].as_array().unwrap();
    assert_eq!(records.len(), 2, "{value}");
    assert_eq!(records[0]["exit_code"], 0);
    assert_eq!(records[1]["exit_code"], 7);
    assert!(records[0]["python"]["version"].is_string(), "{value}");
    assert!(records[0]["python"]["abi"].is_string(), "{value}");
    assert!(records[0]["receipt_id"].is_string());
    let second = command(temp.path(), home.path(), &["history"]);
    let second: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second["detail"]["records"].as_array().unwrap().len(), 2);
}

#[test]
fn history_redacts_args_and_opt_out_preserves_existing_log() {
    let temp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    assert!(
        command(
            temp.path(),
            home.path(),
            &[
                "run",
                "-c",
                "pass # inline-secret",
                "--",
                "--token",
                "hidden-secret"
            ]
        )
        .status
        .success()
    );
    let path = home.path().join("history.jsonl");
    let before = fs::read_to_string(&path).unwrap();
    assert!(!before.contains("inline-secret"));
    assert!(!before.contains("hidden-secret"));
    let output = cargo_bin_cmd!("pybun")
        .current_dir(temp.path())
        .env("PYBUN_HOME", home.path())
        .env("PYBUN_HISTORY", "0")
        .env("PYBUN_BACKEND", "native")
        .args(["run", "-c", "pass"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(fs::read_to_string(path).unwrap(), before);
}

#[test]
fn history_records_tests_and_failed_package_operations_with_lock_digest() {
    use sha2::{Digest, Sha256};
    let temp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("test_demo.py"),
        "def test_demo():\n    assert True\n",
    )
    .unwrap();
    assert!(
        command(temp.path(), home.path(), &["test", "--backend=pybun"])
            .status
            .success()
    );
    fs::write(temp.path().join("pyproject.toml"), "[project\n").unwrap();
    fs::write(temp.path().join("pybun.lockb"), "recorded-lock-evidence").unwrap();
    for args in [
        vec!["install", "--offline"],
        vec!["add", "demo", "--offline"],
        vec!["remove", "demo"],
    ] {
        assert!(!command(temp.path(), home.path(), &args).status.success());
    }
    let output = command(temp.path(), home.path(), &["history"]);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let records = value["detail"]["records"].as_array().unwrap();
    assert_eq!(records.len(), 4, "{value}");
    assert_eq!(
        records
            .iter()
            .map(|record| record["command"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["test", "install", "add", "remove"]
    );
    for record in &records[1..] {
        assert_eq!(record["exit_code"], 1);
        assert_eq!(
            record["lock"]["digest"],
            hex::encode(Sha256::digest(b"recorded-lock-evidence"))
        );
    }
}

#[test]
fn history_reports_partial_records_and_invalid_duration_without_echoing_contents() {
    let temp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(home.path().join("history.jsonl"), "{private-secret\n").unwrap();
    let output = command(temp.path(), home.path(), &["history"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("private-secret"));
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        value["detail"]["diagnostics"][0]["code"],
        "E_HISTORY_RECORD_INVALID"
    );
    let invalid = command(temp.path(), home.path(), &["history", "--since", "-3h"]);
    assert!(!invalid.status.success());
}

#[cfg(unix)]
#[test]
fn history_storage_is_private_and_rejects_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    assert!(
        command(temp.path(), home.path(), &["run", "-c", "pass"])
            .status
            .success()
    );
    let path = home.path().join("history.jsonl");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let before = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let rejected = command(temp.path(), home.path(), &["run", "-c", "pass"]);
    assert!(rejected.status.success());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(String::from_utf8_lossy(&rejected.stdout).contains("History storage permissions"));
    let outside = temp.path().join("private.jsonl");
    fs::write(&outside, "unchanged").unwrap();
    fs::remove_file(&path).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(
        command(temp.path(), home.path(), &["run", "-c", "pass"])
            .status
            .success()
    );
    assert_eq!(fs::read_to_string(outside).unwrap(), "unchanged");
    assert!(
        !command(temp.path(), home.path(), &["history"])
            .status
            .success()
    );
}
