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
        .stderr(predicate::str::contains("script not found"));
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
