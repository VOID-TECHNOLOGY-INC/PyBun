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
fn run_simple_script() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("hello.py");
    fs::write(&script, "print('Hello from PyBun!')").unwrap();

    bin()
        .args(["run", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Hello from PyBun!"));
}

#[test]
fn run_script_with_args() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("args.py");
    fs::write(&script, "import sys; print(sys.argv[1:])").unwrap();

    bin()
        .args(["run", script.to_str().unwrap(), "--", "arg1", "arg2"])
        .assert()
        .success();
}

#[test]
fn run_inline_code() {
    bin()
        .args(["run", "-c", "--", "print('inline')"])
        .assert()
        .success()
        .stdout(predicate::str::contains("inline"));
}

#[test]
fn run_missing_script() {
    bin()
        .args(["run", "nonexistent.py"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("script not found"));
}

#[test]
fn run_no_target_error() {
    bin().args(["run"]).assert().failure();
}

#[test]
fn run_with_pep723_metadata() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("pep723.py");
    let content = r#"# /// script
# dependencies = ["requests>=2.28.0"]
# ///
print("PEP 723 script")
"#;
    fs::write(&script, content).unwrap();

    bin()
        .env("PYBUN_PEP723_DRY_RUN", "1")
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("pep723_dependencies"))
        .stdout(predicate::str::contains("requests>=2.28.0"));
}

#[test]
fn run_json_output() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("simple.py");
    fs::write(&script, "print('test')").unwrap();

    let output = bin()
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout).expect("valid JSON output");
    assert_eq!(value["status"], "ok");
    assert_eq!(value["detail"]["exit_code"], 0);
}

#[test]
fn run_script_with_exit_code() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("exit_nonzero.py");
    fs::write(&script, "import sys; sys.exit(42)").unwrap();

    // pybun propagates the script's exit code; JSON output is still emitted
    let output = bin()
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun");
    assert_eq!(output.status.code(), Some(42));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"exit_code\":42"), "stdout: {stdout}");
}

// Issue #148: pybun run must propagate the child Python process exit code.

#[test]
fn run_script_propagates_nonzero_exit_code() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("fail.py");
    fs::write(&script, "import sys; sys.exit(42)").unwrap();

    let output = bin()
        .args(["run", script.to_str().unwrap()])
        .output()
        .expect("run pybun");
    assert_eq!(
        output.status.code(),
        Some(42),
        "pybun must exit with the script's exit code"
    );
}

#[test]
fn run_inline_code_propagates_nonzero_exit_code() {
    let output = bin()
        .args(["run", "-c", "--", "import sys; sys.exit(7)"])
        .output()
        .expect("run pybun");
    assert_eq!(
        output.status.code(),
        Some(7),
        "pybun must exit with the inline code's exit code"
    );
}

#[test]
fn run_script_exit_zero_still_succeeds() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("ok.py");
    fs::write(&script, "print('ok')").unwrap();

    bin()
        .args(["run", script.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn run_script_propagates_exit_code_json_mode() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("fail_json.py");
    fs::write(&script, "import sys; sys.exit(5)").unwrap();

    let output = bin()
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun");
    // JSON output must be valid and contain exit_code
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));
    assert_eq!(value["detail"]["exit_code"], 5);
    // JSON envelope status must be "error" when child exits non-zero (#155)
    assert_eq!(value["status"], "error");
    // pybun process must exit with the script's code
    assert_eq!(output.status.code(), Some(5));
}

#[test]
fn run_pep723_uses_uv_backend_when_forced() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("pep723_uv.py");
    let content = r#"# /// script
# dependencies = ["requests>=2.28.0"]
# ///
print("hello")
"#;
    fs::write(&script, content).unwrap();

    // Create a fake `uv` executable on PATH.
    let uv_dir = temp.path().join("uv-bin");
    fs::create_dir_all(&uv_dir).unwrap();
    let uv_path = if cfg!(windows) {
        uv_dir.join("uv.bat")
    } else {
        uv_dir.join("uv")
    };

    if cfg!(windows) {
        fs::write(&uv_path, "@echo off\r\necho UV_RUN_OK\r\nexit /b 0\r\n").unwrap();
    } else {
        fs::write(&uv_path, "#!/usr/bin/env sh\necho UV_RUN_OK\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&uv_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&uv_path, perms).unwrap();
        }
    }

    let mut path_entries = vec![uv_dir.clone()];
    if let Some(existing) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&existing));
    }
    let new_path = std::env::join_paths(path_entries).unwrap();

    let output = bin()
        .env("PYBUN_PEP723_BACKEND", "uv")
        .env("PATH", new_path)
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun with uv backend");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout).expect("valid JSON output");
    assert_eq!(value["status"], "ok");
    assert_eq!(value["detail"]["pep723_backend"], "uv_run");
    assert_eq!(value["detail"]["exit_code"], 0);
}

// =============================================================================
// PR1.9: PEP 723 dependencies auto-install in isolated environment
// =============================================================================

#[test]
fn run_pep723_auto_installs_dependencies() {
    // Test that PEP 723 dependencies are auto-installed in a temp env
    // Note: This test uses dry-run mode for faster execution
    let temp = tempdir().unwrap();
    let script = temp.path().join("pep723_with_deps.py");

    // Create a PEP 723 script with dependencies
    let content = r#"# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "cowsay",
# ]
# ///
print("Hello with deps")
"#;
    fs::write(&script, content).unwrap();

    // Set dry-run mode for testing
    bin()
        .env("PYBUN_PEP723_DRY_RUN", "1")
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("pep723_dependencies"))
        .stdout(predicate::str::contains("cowsay"))
        .stdout(predicate::str::contains("temp_env"));
}

#[test]
fn run_pep723_json_shows_auto_install_info() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("pep723_info.py");

    let content = r#"# /// script
# dependencies = ["requests>=2.28.0", "rich"]
# ///
print("test")
"#;
    fs::write(&script, content).unwrap();

    bin()
        .env("PYBUN_PEP723_DRY_RUN", "1")
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"pep723_dependencies\""))
        .stdout(predicate::str::contains("requests>=2.28.0"))
        .stdout(predicate::str::contains("rich"))
        // Should indicate temp env was created (in dry-run mode, shows it would be)
        .stdout(predicate::str::contains("temp_env").or(predicate::str::contains("isolated")));
}

#[test]
fn run_pep723_empty_deps_no_temp_env() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("pep723_empty.py");

    // PEP 723 block but no dependencies
    let content = r#"# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
print("no deps needed")
"#;
    fs::write(&script, content).unwrap();

    // Should run directly without creating temp env
    bin()
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"exit_code\":0"));
}

#[test]
fn run_without_pep723_uses_system_env() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("simple_script.py");
    fs::write(&script, "print('no pep723')").unwrap();

    // Should run with system/project env, no temp env created
    bin()
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"exit_code\":0"))
        // Should have empty pep723_dependencies
        .stdout(predicate::str::contains("\"pep723_dependencies\":[]"));
}

// =============================================================================
// PR-OPT1: PEP 723 venv cache tests
// =============================================================================

#[test]
fn run_pep723_cache_hit_json_output() {
    // Test that cache_hit field is present in JSON output
    let temp = tempdir().unwrap();
    let script = temp.path().join("pep723_cache.py");

    let content = r#"# /// script
# dependencies = ["cowsay"]
# ///
print("test cache")
"#;
    fs::write(&script, content).unwrap();

    // Dry-run mode to check JSON structure
    bin()
        .env("PYBUN_PEP723_DRY_RUN", "1")
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"cache_hit\""));
}

#[test]
fn run_pep723_no_cache_mode() {
    // Test PYBUN_PEP723_NO_CACHE environment variable
    let temp = tempdir().unwrap();
    let script = temp.path().join("pep723_no_cache.py");

    let content = r#"# /// script
# dependencies = ["cowsay"]
# ///
print("test no cache")
"#;
    fs::write(&script, content).unwrap();

    // With NO_CACHE mode, should still work (in dry-run)
    bin()
        .env("PYBUN_PEP723_DRY_RUN", "1")
        .env("PYBUN_PEP723_NO_CACHE", "1")
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("pep723_dependencies"));
}

#[test]
fn run_pep723_cache_shows_cleanup_false_when_cached() {
    // When cached, cleanup should be false (venv is reused)
    let temp = tempdir().unwrap();
    let script = temp.path().join("pep723_cleanup.py");

    let content = r#"# /// script
# dependencies = ["cowsay"]
# ///
print("test cleanup field")
"#;
    fs::write(&script, content).unwrap();

    bin()
        .env("PYBUN_PEP723_DRY_RUN", "1")
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success()
        // cleanup should be false with caching (venv not cleaned up)
        .stdout(predicate::str::contains("\"cleanup\":false"));
}

// =============================================================================
// Issue #155: --format=json must report status "error" when child exits non-zero
// =============================================================================

#[test]
fn run_json_mode_nonzero_exit_reports_error_status() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("fail155.py");
    fs::write(&script, "import sys; sys.exit(3)").unwrap();

    let output = bin()
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));

    assert_eq!(
        value["status"], "error",
        "JSON status must be 'error' when child exits non-zero"
    );
    assert_eq!(value["detail"]["exit_code"], 3);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn run_json_mode_inline_nonzero_reports_error_status() {
    let output = bin()
        .args([
            "--format=json",
            "run",
            "-c",
            "--",
            "import sys; sys.exit(7)",
        ])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));

    assert_eq!(
        value["status"], "error",
        "JSON status must be 'error' for -c mode with non-zero exit"
    );
    assert_eq!(value["detail"]["exit_code"], 7);
    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn run_json_mode_zero_exit_reports_ok_status() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("ok155.py");
    fs::write(&script, "print('success')").unwrap();

    let output = bin()
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));

    assert_eq!(
        value["status"], "ok",
        "JSON status must be 'ok' when child exits 0"
    );
    assert_eq!(value["detail"]["exit_code"], 0);
    assert!(output.status.success());
}

// =============================================================================
// Issue #172: validate locked wheel Python tags against the active interpreter
// =============================================================================

#[cfg(unix)]
fn write_fake_python(dir: &std::path::Path, version: &str) -> std::path::PathBuf {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let path = dir.join("fake_python.sh");
    let mut file = fs::File::create(&path).unwrap();
    writeln!(file, "#!/bin/sh").unwrap();
    writeln!(file, "echo 'Python {version}'").unwrap();
    let mut perms = file.metadata().unwrap().permissions();
    perms.set_mode(0o755);
    file.set_permissions(perms).unwrap();
    path
}

fn write_lockfile_with_wheel(path: &std::path::Path, wheel_filename: &str) {
    use pybun::lockfile::{Lockfile, Package, PackageSource};

    let mut lock = Lockfile::new(vec!["3.10".into()], vec!["macos-arm64".into()]);
    lock.add_package(Package {
        name: "numpy".to_string(),
        version: "1.26.4".to_string(),
        source: PackageSource::Registry {
            index: "https://pypi.org/simple".to_string(),
            url: "https://files.pythonhosted.org/packages/numpy/".to_string(),
        },
        wheel: wheel_filename.to_string(),
        hash: "sha256:deadbeef".to_string(),
        dependencies: Vec::new(),
    });
    lock.save_to_path(path).unwrap();
}

#[cfg(unix)]
#[test]
fn run_warns_on_locked_wheel_python_version_mismatch() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("main.py");
    fs::write(&script, "print('hello')").unwrap();

    write_lockfile_with_wheel(
        &temp.path().join("pybun.lockb"),
        "numpy-1.26.4-cp310-cp310-macosx_11_0_arm64.whl",
    );

    let fake_python = write_fake_python(temp.path(), "3.12.7");

    let output = bin()
        .current_dir(temp.path())
        .env_remove("PYBUN_ENV")
        .env("PYBUN_PYTHON", &fake_python)
        .args(["--format=json", "run", "main.py"])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));

    let diags = value["diagnostics"].as_array().expect("diagnostics array");
    let mismatch = diags
        .iter()
        .find(|d| d.get("code") == Some(&Value::from("W_LOCK_PYTHON_VERSION_MISMATCH")))
        .unwrap_or_else(|| {
            panic!("expected W_LOCK_PYTHON_VERSION_MISMATCH diagnostic, got: {diags:?}")
        });

    let message = mismatch["message"].as_str().expect("message string");
    assert!(message.contains("Python 3.10"), "message: {message}");
    assert!(message.contains("Python 3.12.7"), "message: {message}");
    assert!(message.contains("pybun install"), "message: {message}");
    assert_eq!(mismatch["level"], "warning");
}

#[cfg(unix)]
#[test]
fn run_no_warning_when_locked_wheel_matches_active_interpreter() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("main.py");
    fs::write(&script, "print('hello')").unwrap();

    write_lockfile_with_wheel(
        &temp.path().join("pybun.lockb"),
        "numpy-1.26.4-cp312-cp312-macosx_11_0_arm64.whl",
    );

    let fake_python = write_fake_python(temp.path(), "3.12.7");

    let output = bin()
        .current_dir(temp.path())
        .env_remove("PYBUN_ENV")
        .env("PYBUN_PYTHON", &fake_python)
        .args(["--format=json", "run", "main.py"])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));

    let diags = value["diagnostics"].as_array().expect("diagnostics array");
    assert!(
        !diags
            .iter()
            .any(|d| d.get("code") == Some(&Value::from("W_LOCK_PYTHON_VERSION_MISMATCH"))),
        "expected no version mismatch diagnostic, got: {diags:?}"
    );
}
