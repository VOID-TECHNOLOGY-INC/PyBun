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

    bin()
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success() // pybun itself succeeds, reports script exit code
        .stdout(predicate::str::contains("\"exit_code\":42"));
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
