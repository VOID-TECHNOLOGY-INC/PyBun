use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
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
        .stdout(predicate::str::contains("executed").and(predicate::str::contains("successfully")));
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
        .stdout(predicate::str::contains(
            "executed inline code successfully",
        ));
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

    bin()
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"exit_code\":0"))
        .stdout(predicate::str::contains("\"status\":\"ok\""));
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
