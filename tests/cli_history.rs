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

#[cfg(unix)]
#[test]
fn text_runs_record_receipts_and_propagate_child_codes() {
    let temp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("script.py"),
        "print('script')\nraise SystemExit(5)\n",
    )
    .unwrap();
    for args in [
        vec!["run", "-c", "print('inline'); raise SystemExit(7)"],
        vec!["run", "script.py"],
    ] {
        let output = cargo_bin_cmd!("pybun")
            .current_dir(temp.path())
            .env("PYBUN_HOME", home.path())
            .env("PYBUN_HISTORY", "1")
            .env("PYBUN_BACKEND", "native")
            .args(args)
            .output()
            .unwrap();
        assert!(matches!(output.status.code(), Some(5 | 7)));
        let expected = if output.status.code() == Some(7) {
            "inline\n"
        } else {
            "script\n"
        };
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
    }
    let output = command(temp.path(), home.path(), &["history"]);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let records = value["detail"]["records"].as_array().unwrap();
    assert_eq!(records.len(), 2, "{value}");
    assert_eq!(records[0]["exit_code"], 7);
    assert_eq!(records[1]["exit_code"], 5);
}

fn set_include_system_site_packages(config_path: &Path, enabled: bool) {
    let mut replaced = false;
    let config = fs::read_to_string(config_path)
        .expect("read pyvenv.cfg")
        .lines()
        .map(|line| {
            if line
                .trim_start()
                .starts_with("include-system-site-packages")
            {
                replaced = true;
                format!("include-system-site-packages = {enabled}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert!(replaced, "pyvenv.cfg lacks include-system-site-packages");
    fs::write(config_path, config).expect("write pyvenv.cfg");
}

fn create_test_venv(
    root: &Path,
    include_system_site_packages: bool,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let venv = root.join("venv");
    let bootstraps: &[&str] = if cfg!(windows) {
        &["python"]
    } else {
        &["python3", "python"]
    };
    let mut failure = String::new();
    let mut created = false;
    for bootstrap in bootstraps {
        match std::process::Command::new(bootstrap)
            .args(["-m", "venv", "--without-pip"])
            .arg(&venv)
            .env_remove("PYTHONHOME")
            .env_remove("PYTHONPATH")
            .output()
        {
            Ok(output) if output.status.success() => {
                created = true;
                break;
            }
            Ok(output) => {
                failure = format!("{bootstrap}: {}", String::from_utf8_lossy(&output.stderr));
            }
            Err(error) => failure = format!("{bootstrap}: {error}"),
        }
    }
    assert!(created, "failed to create test venv ({failure})");

    let config_path = venv.join("pyvenv.cfg");
    set_include_system_site_packages(&config_path, include_system_site_packages);

    let python = if cfg!(windows) {
        venv.join("Scripts").join("python.exe")
    } else {
        venv.join("bin").join("python3")
    };
    assert!(
        python.is_file(),
        "missing venv interpreter: {}",
        python.display()
    );
    (python, config_path)
}

fn run_with_history(root: &Path, home: &Path, python: &Path) -> Value {
    let output = cargo_bin_cmd!("pybun")
        .current_dir(root)
        .env_remove("PYBUN_ENV")
        .env_remove("PYTHONHOME")
        .env_remove("PYTHONPATH")
        .env("PYBUN_HOME", home)
        .env("PYBUN_HISTORY", "1")
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_PYTHON", python)
        .args(["--format=json", "run", "-c", "pass"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = fs::read_to_string(home.join("history.jsonl")).expect("read history");
    serde_json::from_str(
        records
            .lines()
            .last()
            .expect("history should contain a record"),
    )
    .expect("history record should be JSON")
}

fn assert_python_state(record: &Value, expected_python: &Path) {
    assert_eq!(
        record["python_observation"], "execution_interpreter_before_command",
        "python_state should describe the execution interpreter: {record}"
    );
    assert!(
        record["python"]["version"].is_string(),
        "python_state should be populated: {record}"
    );
    let recorded = Path::new(
        record["python"]["executable"]
            .as_str()
            .expect("python executable should be recorded"),
    );
    assert_eq!(
        recorded.canonicalize().unwrap(),
        expected_python.canonicalize().unwrap(),
        "history should observe the configured interpreter: {record}"
    );
}

#[test]
fn venv_with_system_site_packages_is_not_reported_as_complete_inventory() {
    let temp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let (python, config_path) = create_test_venv(temp.path(), false);
    let record = run_with_history(temp.path(), home.path(), &python);
    assert_python_state(&record, &python);
    assert!(
        record["installed_packages"].is_array(),
        "a regular venv inventory should be reported, even when empty: {record}"
    );

    set_include_system_site_packages(&config_path, true);

    let record = run_with_history(temp.path(), home.path(), &python);
    assert_python_state(&record, &python);
    assert!(
        record["installed_packages"].is_null(),
        "System/user-site evidence cannot be treated as a complete empty inventory: {record}"
    );
}
