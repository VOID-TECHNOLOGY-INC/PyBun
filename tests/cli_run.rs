use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

fn network_enabled() -> bool {
    std::env::var_os("PYBUN_E2E_NETWORK").is_some()
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
        .args(["run", "-c", "print('inline')"])
        .assert()
        .success()
        .stdout(predicate::str::contains("inline"));
}

#[test]
fn run_inline_code_long_flag() {
    bin()
        .args(["run", "--code", "print('inline-long')"])
        .assert()
        .success()
        .stdout(predicate::str::contains("inline-long"));
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
fn run_json_traceback_diagnostic_matches_mcp_shape() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("main.py");
    fs::write(&script, "import pybun_missing_package_for_traceback_test").unwrap();

    let output = bin()
        .current_dir(temp.path())
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));
    let diagnostics = value["diagnostics"].as_array().expect("diagnostics array");
    let diagnostic = diagnostics
        .first()
        .unwrap_or_else(|| panic!("expected traceback diagnostic, got: {value}"));

    assert_eq!(diagnostic["level"], "error");
    assert_eq!(diagnostic["code"], "runtime.module_not_found");
    assert_eq!(diagnostic["exception_type"], "ModuleNotFoundError");
    assert_eq!(diagnostic["location"]["file"], "main.py");
    assert_eq!(diagnostic["location"]["line"], 1);
    assert_eq!(diagnostic["location"]["function"], "<module>");
    assert_eq!(diagnostic["next_action"]["tool"], "pybun_add");
    assert_eq!(
        diagnostic["next_action"]["args"]["package"],
        "pybun_missing_package_for_traceback_test"
    );
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
        .args(["run", "-c", "import sys; sys.exit(7)"])
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

#[test]
fn run_pep723_self_heals_from_corrupt_deps_json_cache_entry() {
    // Regression test for issue #299 (same bug class as #262): a corrupt
    // `deps.json` cache entry (e.g. truncated by a crash mid-write) must be
    // treated as a cache miss and trigger a rebuild-from-scratch, not crash
    // `pybun run script.py` with a fatal error.
    //
    // This reproduces the live repro from the issue:
    // ```text
    // echo "not valid json{{{" > <pep723-envs>/<hash>/deps.json
    // pybun run script.py
    // ```
    if !network_enabled() {
        eprintln!(
            "Skipping run_pep723_self_heals_from_corrupt_deps_json_cache_entry \
             (PYBUN_E2E_NETWORK not set)"
        );
        return;
    }

    let temp = tempdir().unwrap();
    let home = temp.path().join("pybun-home");
    fs::create_dir_all(&home).unwrap();
    let script = temp.path().join("pep723_corrupt_cache.py");

    let content = r#"# /// script
# dependencies = ["cowsay"]
# ///
print("test corrupt cache self-heal")
"#;
    fs::write(&script, content).unwrap();

    // First run: builds a fresh cached environment and records deps.json.
    bin()
        .env("PYBUN_HOME", &home)
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success();

    let envs_dir = home.join("pep723-envs");
    let mut entries: Vec<_> = fs::read_dir(&envs_dir)
        .expect("pep723-envs dir should exist after first run")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one cached env after first run"
    );
    let env_root = entries.remove(0).path();
    let deps_json = env_root.join("deps.json");
    assert!(deps_json.exists(), "deps.json should exist after caching");

    // Corrupt the cache entry to simulate a crash mid-write.
    fs::write(&deps_json, "not valid json{{{").unwrap();

    // Second run: must self-heal (rebuild) rather than crash.
    let output = bin()
        .env("PYBUN_HOME", &home)
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("command runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "pybun run should self-heal past a corrupt PEP 723 cache entry, not fail: \
         stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stderr.contains("discarded unreadable PEP 723 cache entry"),
        "expected a self-heal notice on stderr: {stderr}"
    );

    // The cache entry should have been rebuilt with valid JSON.
    let rebuilt = fs::read_to_string(&deps_json).expect("deps.json should exist again");
    assert!(
        serde_json::from_str::<Value>(&rebuilt).is_ok(),
        "rebuilt deps.json should be valid JSON: {rebuilt}"
    );
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
        .args(["--format=json", "run", "-c", "import sys; sys.exit(7)"])
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

// --- Profile integration tests (Issue #124) ---

#[test]
fn run_with_prod_profile_json_includes_profile_info() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("main.py");
    fs::write(&script, "print('hello')").unwrap();

    let output = bin()
        .args([
            "--format=json",
            "run",
            "--profile=prod",
            script.to_str().unwrap(),
        ])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));

    let profile = &value["detail"]["profile"];
    assert!(
        !profile.is_null(),
        "expected profile in JSON detail, got: {value}"
    );
    assert_eq!(
        profile["name"].as_str().unwrap_or(""),
        "prod",
        "expected profile name=prod, got: {profile}"
    );
    assert_eq!(
        profile["optimization_level"].as_u64().unwrap_or(0),
        2,
        "expected optimization_level=2 for prod, got: {profile}"
    );
}

#[test]
fn run_with_prod_profile_applies_python_optimization() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("check_opt.py");
    // sys.flags.optimize is 2 when Python is run with -OO (PYTHONOPTIMIZE=2)
    fs::write(
        &script,
        "import sys; print('optimize:', sys.flags.optimize)",
    )
    .unwrap();

    let output = bin()
        .args(["run", "--profile=prod", script.to_str().unwrap()])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("optimize: 2"),
        "expected optimize: 2 in output, got: {stdout}"
    );
}

#[test]
fn run_with_dev_profile_does_not_set_optimization() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("check_opt.py");
    fs::write(
        &script,
        "import sys; print('optimize:', sys.flags.optimize)",
    )
    .unwrap();

    let output = bin()
        .args(["run", "--profile=dev", script.to_str().unwrap()])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("optimize: 0"),
        "expected optimize: 0 in output for dev profile, got: {stdout}"
    );
}

#[test]
fn run_with_benchmark_profile_json_includes_profile_timing_flag() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("main.py");
    fs::write(&script, "print('hello')").unwrap();

    let output = bin()
        .args([
            "--format=json",
            "run",
            "--profile=benchmark",
            script.to_str().unwrap(),
        ])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));

    let profile = &value["detail"]["profile"];
    assert!(
        !profile.is_null(),
        "expected profile in JSON detail, got: {value}"
    );
    assert_eq!(
        profile["name"].as_str().unwrap_or(""),
        "benchmark",
        "expected profile name=benchmark, got: {profile}"
    );
    assert!(
        profile["timing"].as_bool().unwrap_or(false),
        "expected timing=true for benchmark profile, got: {profile}"
    );
}

#[test]
fn run_default_profile_is_dev() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("main.py");
    fs::write(&script, "print('hello')").unwrap();

    let output = bin()
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected valid JSON, got: {stdout}"));

    let profile = &value["detail"]["profile"];
    assert_eq!(
        profile["name"].as_str().unwrap_or(""),
        "dev",
        "default profile should be dev, got: {profile}"
    );
}

#[test]
fn run_with_prod_profile_lazy_imports_injected() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("check_lazy.py");
    // When lazy imports are injected, the LazyFinder will be in sys.meta_path
    fs::write(
        &script,
        "import sys; finders = [type(f).__name__ for f in sys.meta_path]; print('finders:', finders)",
    )
    .unwrap();

    let output = bin()
        .args(["run", "--profile=prod", script.to_str().unwrap()])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("LazyFinder"),
        "expected LazyFinder in sys.meta_path for prod profile with lazy_imports=true, got: {stdout}"
    );
}

#[test]
fn run_with_dev_profile_no_lazy_imports() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("check_lazy.py");
    fs::write(
        &script,
        "import sys; finders = [type(f).__name__ for f in sys.meta_path]; print('finders:', finders)",
    )
    .unwrap();

    let output = bin()
        .args(["run", "--profile=dev", script.to_str().unwrap()])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("LazyFinder"),
        "expected no LazyFinder in sys.meta_path for dev profile, got: {stdout}"
    );
}

// =============================================================================
// Issue #234: PEP 723 script lockfile collides with uv run backend
// When a PyBun script lockfile (<script>.lock) exists, the uv backend must be
// bypassed to prevent uv from attempting to parse the binary lockfile as TOML.
// =============================================================================

#[test]
fn run_pep723_with_script_lock_bypasses_uv_backend() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("locked.py");

    // Script with a dep from the fixture index so the lock step succeeds.
    let lock_script_content = r#"# /// script
# dependencies = ["app==1.0.0"]
# ///
print("hello locked")
"#;
    fs::write(&script, lock_script_content).unwrap();

    // Fake uv that fails only when called as "uv run" (the collision case).
    // It must succeed for "uv pip install" so the pybun backend can use it for
    // fast package installation after bypassing the uv run backend.
    let uv_dir = temp.path().join("uv-bin");
    fs::create_dir_all(&uv_dir).unwrap();
    let uv_path = if cfg!(windows) {
        uv_dir.join("uv.bat")
    } else {
        uv_dir.join("uv")
    };

    if cfg!(windows) {
        fs::write(
            &uv_path,
            "@echo off\r\nif \"%1\"==\"run\" (\r\n  echo UV_RUN_WAS_CALLED_UNEXPECTEDLY 1>&2\r\n  exit /b 1\r\n)\r\nexit /b 0\r\n",
        )
        .unwrap();
    } else {
        fs::write(
            &uv_path,
            "#!/usr/bin/env sh\nif [ \"$1\" = \"run\" ]; then\n  echo UV_RUN_WAS_CALLED_UNEXPECTEDLY >&2\n  exit 1\nfi\nexit 0\n",
        )
        .unwrap();
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

    // Create the PyBun binary lockfile next to the script.
    let index_path = std::path::PathBuf::from("tests/fixtures/index.json");
    bin()
        .env("PATH", &new_path)
        .args([
            "--format=json",
            "lock",
            "--script",
            script.to_str().unwrap(),
            "--index",
            index_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock_path = {
        let mut p = script.as_os_str().to_os_string();
        p.push(".lock");
        std::path::PathBuf::from(p)
    };
    assert!(lock_path.exists(), "lockfile must exist before running");

    // Run the script WITHOUT dry-run so the uv-selection path is fully exercised.
    // With the fix, pybun must choose the built-in backend (lockfile present) and
    // must NOT call "uv run" even though fake uv is on PATH with PYBUN_PEP723_BACKEND=auto.
    let output = bin()
        .env("PATH", &new_path)
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("UV_RUN_WAS_CALLED_UNEXPECTEDLY"),
        "uv run must not be invoked when a PyBun script lockfile exists, stderr: {stderr}"
    );

    let value: Value =
        serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("valid JSON, got: {stdout}"));
    assert_eq!(
        value["status"], "ok",
        "run should succeed; stdout: {stdout}"
    );
    assert_ne!(
        value["detail"]["pep723_backend"], "uv_run",
        "pep723_backend must not be uv_run when a script lockfile exists; output: {stdout}"
    );
}

#[test]
fn run_pep723_explicit_uv_backend_with_lockfile_emits_warning() {
    // When PYBUN_PEP723_BACKEND=uv is explicitly set but a PyBun lockfile exists,
    // pybun must warn the user and fall back to the pybun backend (Issue #234).
    let temp = tempdir().unwrap();
    let script = temp.path().join("locked_explicit_uv.py");
    let content = r#"# /// script
# dependencies = ["app==1.0.0"]
# ///
print("hello explicit uv lockfile")
"#;
    fs::write(&script, content).unwrap();

    // Fake uv: succeeds for all subcommands (install), fails only for run.
    let uv_dir = temp.path().join("uv-bin");
    fs::create_dir_all(&uv_dir).unwrap();
    let uv_path = if cfg!(windows) {
        uv_dir.join("uv.bat")
    } else {
        uv_dir.join("uv")
    };
    if cfg!(windows) {
        fs::write(
            &uv_path,
            "@echo off\r\nif \"%1\"==\"run\" (\r\n  echo UV_RUN_WAS_CALLED_UNEXPECTEDLY 1>&2\r\n  exit /b 1\r\n)\r\nexit /b 0\r\n",
        )
        .unwrap();
    } else {
        fs::write(
            &uv_path,
            "#!/usr/bin/env sh\nif [ \"$1\" = \"run\" ]; then\n  echo UV_RUN_WAS_CALLED_UNEXPECTEDLY >&2\n  exit 1\nfi\nexit 0\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&uv_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&uv_path, perms).unwrap();
        }
    }

    let mut path_entries = vec![uv_dir];
    if let Some(existing) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&existing));
    }
    let new_path = std::env::join_paths(path_entries).unwrap();

    let index_path = std::path::PathBuf::from("tests/fixtures/index.json");
    bin()
        .env("PATH", &new_path)
        .args([
            "--format=json",
            "lock",
            "--script",
            script.to_str().unwrap(),
            "--index",
            index_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let output = bin()
        .env("PYBUN_PEP723_BACKEND", "uv")
        .env("PATH", new_path)
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun with explicit uv backend and lockfile");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Must NOT invoke uv run.
    assert!(
        !stderr.contains("UV_RUN_WAS_CALLED_UNEXPECTEDLY"),
        "uv run must not be called when a lockfile exists; stderr: {stderr}"
    );
    // Must emit a warning so the user knows their setting was overridden.
    assert!(
        stderr.contains("warning:") && stderr.contains("lockfile"),
        "expected a warning about uv being bypassed due to lockfile; stderr: {stderr}"
    );
    // Must succeed.
    let value: Value =
        serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("valid JSON, got: {stdout}"));
    assert_eq!(value["status"], "ok", "stdout: {stdout}");
    assert_ne!(value["detail"]["pep723_backend"], "uv_run");
}

// =============================================================================
// Issue #238: warm cache speedup — uv backend must NOT pass --python <venv>
// =============================================================================

/// When pybun delegates PEP 723 execution to uv, it must call `uv run --script`
/// WITHOUT a `--python` argument.  Passing `--python <venv_python>` causes uv to
/// create a brand-new environment on every warm run (cache never reused), so
/// warm latency equals cold latency (~600 ms instead of the expected ~120 ms).
#[test]
fn run_pep723_uv_backend_does_not_pass_python_flag() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("pep723_no_python_flag.py");
    fs::write(
        &script,
        "# /// script\n# dependencies = [\"requests>=2.28.0\"]\n# ///\nprint('ok')\n",
    )
    .unwrap();

    // Fake uv that records its argv to a file and exits 0.
    let args_log = temp.path().join("uv_args.txt");
    let uv_dir = temp.path().join("uv-bin");
    fs::create_dir_all(&uv_dir).unwrap();
    let uv_path = uv_dir.join("uv");

    let args_log_str = args_log.to_str().unwrap();
    // Write argv (one arg per line) to the log file.
    let script_body = format!(
        "#!/usr/bin/env sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\"; done > {}\necho 'ok'\nexit 0\n",
        args_log_str
    );
    fs::write(&uv_path, &script_body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&uv_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&uv_path, perms).unwrap();
    }

    let mut path_entries = vec![uv_dir];
    if let Some(existing) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&existing));
    }
    let new_path = std::env::join_paths(path_entries).unwrap();

    let output = bin()
        .env("PATH", &new_path)
        // Ensure pybun backend is not forced — we want the auto/uv path
        .env("PYBUN_PEP723_BACKEND", "auto")
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun with auto (uv) backend");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value =
        serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("valid JSON, got: {stdout}"));
    assert_eq!(value["status"], "ok", "pybun run failed: {stdout}");
    assert_eq!(
        value["detail"]["pep723_backend"], "uv_run",
        "expected uv_run backend: {stdout}"
    );

    // Read the recorded uv argv
    let uv_args = fs::read_to_string(&args_log)
        .unwrap_or_else(|_| panic!("uv args log not written to {args_log_str}"));
    let args: Vec<&str> = uv_args.lines().collect();

    // uv must be called as `uv run --script <path>` — NOT `uv run --python ...`
    assert!(
        args.contains(&"run"),
        "uv must be called with 'run' subcommand; args: {args:?}"
    );
    assert!(
        args.contains(&"--script"),
        "uv must be called with '--script' flag; args: {args:?}"
    );
    assert!(
        !args.contains(&"--python"),
        "uv must NOT be called with '--python' (causes cache miss on every warm run); args: {args:?}"
    );
}

// =============================================================================
// Issue #301: CLI `run` path must self-heal a corrupt script lockfile
//
// `Lockfile::from_bytes` is used both by the MCP `pybun_doctor` path (which
// already treats a decode failure as a non-fatal "corrupt" status) and by the
// CLI `run` path via `load_script_lock`. Before this fix, `load_script_lock`
// propagated a decode failure via `?`, so a corrupt `<script>.py.lock` file
// (e.g. truncated by a crash mid-write) made `pybun run` fail hard instead of
// falling back to the script's declared PEP 723 dependencies — the same bug
// class as issue #299 (Pep723Cache::read_cache_entry) and issue #262 (PyPI
// legacy cache).
// =============================================================================

#[test]
fn run_self_heals_from_corrupt_script_lockfile() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("plain.py");
    fs::write(&script, "print('cli self-heal ok')\n").unwrap();

    // Simulate a `<script>.py.lock` corrupted by a crash mid-write.
    let lock_path = {
        let mut p = script.as_os_str().to_os_string();
        p.push(".lock");
        std::path::PathBuf::from(p)
    };
    fs::write(&lock_path, b"not a valid lockfile{{{").unwrap();
    assert!(lock_path.exists(), "corrupt lockfile must exist before run");

    let output = bin()
        .args(["--format=json", "run", script.to_str().unwrap()])
        .output()
        .expect("run pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "pybun run should self-heal past a corrupt script lockfile, not fail: \
         stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stderr.contains("discarded unreadable script lockfile"),
        "expected a self-heal notice on stderr: {stderr}"
    );

    let value: Value =
        serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("valid JSON, got: {stdout}"));
    assert_eq!(
        value["status"], "ok",
        "run should succeed despite the corrupt lockfile; stdout: {stdout}"
    );

    // The corrupt lockfile is left in place by `run` (it only reads script
    // locks, it does not rewrite `<script>.py.lock`) — running `pybun lock
    // --script` afterward is how a user regenerates it. What matters here is
    // that `run` treats the decode failure as "no lock" rather than a fatal
    // error, mirroring the MCP doctor path's self-heal behavior.
    assert!(
        lock_path.exists(),
        "corrupt lockfile should still be present on disk after a self-healed run"
    );
}
