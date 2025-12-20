use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn sandbox_blocks_subprocess_spawns() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("spawn.py");
    fs::write(
        &script,
        r#"
import subprocess
subprocess.run(["echo", "hello from child"])
"#,
    )
    .unwrap();

    bin()
        .args([
            "--format=json",
            "run",
            "--sandbox",
            script.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sandbox\""))
        .stdout(predicate::str::contains("\"allow_network\":false"))
        .stdout(predicate::str::contains("\"exit_code\":1"))
        .stdout(predicate::str::contains("sandbox"));
}

#[test]
fn sandbox_can_opt_in_network_access() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("network.py");
    fs::write(
        &script,
        r#"
import socket
socket.socket()
print("network allowed")
"#,
    )
    .unwrap();

    // Without opt-in, socket creation should be blocked and exit_code should be non-zero.
    bin()
        .args([
            "--format=json",
            "run",
            "--sandbox",
            script.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"exit_code\":1"));

    // With opt-in, the script should run successfully and report the sandbox policy in JSON.
    bin()
        .args([
            "--format=json",
            "run",
            "--sandbox",
            "--allow-network",
            script.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"exit_code\":0"))
        .stdout(predicate::str::contains("\"sandbox\""))
        .stdout(predicate::str::contains("\"allow_network\":true"));
}
