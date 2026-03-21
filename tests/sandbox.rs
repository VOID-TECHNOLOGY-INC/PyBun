use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn run_sandbox(args: &[&str]) -> assert_cmd::assert::Assert {
    bin().args(args).assert()
}

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

#[test]
fn sandbox_allow_read_blocks_unauthorized_path() {
    let temp = tempdir().unwrap();
    let allowed_dir = tempdir().unwrap();
    let secret_dir = tempdir().unwrap();

    // Write a "secret" file in the non-allowed dir
    let secret_file = secret_dir.path().join("secret.txt");
    fs::write(&secret_file, "top secret").unwrap();

    // Script attempts to read the secret file (outside --allow-read)
    let script = temp.path().join("read_secret.py");
    let secret_path = secret_file.to_str().unwrap().replace('\\', "/");
    fs::write(
        &script,
        format!("open({path:?}).read()\n", path = secret_path),
    )
    .unwrap();

    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        &format!("--allow-read={}", allowed_dir.path().display()),
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("\"exit_code\":1"));
}

#[test]
fn sandbox_allow_read_blocks_sibling_prefix_bypass() {
    let temp = tempdir().unwrap();
    let allowed_dir = temp.path().join("allowed");
    let sibling_dir = temp.path().join("allowed_evil");
    fs::create_dir_all(&allowed_dir).unwrap();
    fs::create_dir_all(&sibling_dir).unwrap();

    let secret_file = sibling_dir.join("secret.txt");
    fs::write(&secret_file, "top secret").unwrap();

    let script = temp.path().join("read_prefix_bypass.py");
    let secret_path = secret_file.to_str().unwrap().replace('\\', "/");
    fs::write(
        &script,
        format!("open({path:?}).read()\n", path = secret_path),
    )
    .unwrap();

    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        &format!("--allow-read={}", allowed_dir.display()),
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("\"exit_code\":1"))
    .stdout(predicate::str::contains("\"blocked_file_reads\":"));
}

#[test]
fn sandbox_allow_read_permits_allowed_path() {
    let temp = tempdir().unwrap();

    // Write a readable file inside the temp dir (which is --allow-read)
    let data_file = temp.path().join("data.txt");
    fs::write(&data_file, "hello data").unwrap();

    let script = temp.path().join("read_ok.py");
    let data_path = data_file.to_str().unwrap().replace('\\', "/");
    fs::write(
        &script,
        format!(
            "content = open({path:?}).read()\nprint('ok:', content)\n",
            path = data_path
        ),
    )
    .unwrap();

    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        &format!("--allow-read={}", temp.path().display()),
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("\"exit_code\":0"));
}

#[test]
fn sandbox_allow_read_blocks_update_mode_bypass() {
    let temp = tempdir().unwrap();
    let allowed_dir = tempdir().unwrap();
    let secret_dir = tempdir().unwrap();
    let secret_file = secret_dir.path().join("secret.txt");
    fs::write(&secret_file, "top secret").unwrap();

    let script = temp.path().join("read_update_mode.py");
    let secret_path = secret_file.to_str().unwrap().replace('\\', "/");
    fs::write(
        &script,
        format!(
            "handle = open({path:?}, 'r+')\nprint(handle.read())\n",
            path = secret_path
        ),
    )
    .unwrap();

    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        &format!("--allow-read={}", allowed_dir.path().display()),
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("\"exit_code\":1"))
    .stdout(predicate::str::contains("\"blocked_file_reads\":"));
}

#[test]
fn sandbox_allow_write_blocks_unauthorized_path() {
    let temp = tempdir().unwrap();
    let secret_dir = tempdir().unwrap();
    let target_file = secret_dir.path().join("output.txt");

    // Script tries to write to a path outside --allow-write
    let script = temp.path().join("write_secret.py");
    let target_path = target_file.to_str().unwrap().replace('\\', "/");
    fs::write(
        &script,
        format!("open({path:?}, 'w').write('hacked')\n", path = target_path),
    )
    .unwrap();

    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        &format!("--allow-write={}", temp.path().display()),
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("\"exit_code\":1"));
}

#[test]
fn sandbox_allow_write_permits_allowed_path() {
    let temp = tempdir().unwrap();
    let output_file = temp.path().join("out.txt");

    let script = temp.path().join("write_ok.py");
    let out_path = output_file.to_str().unwrap().replace('\\', "/");
    fs::write(
        &script,
        format!(
            "open({path:?}, 'w').write('written')\nprint('ok')\n",
            path = out_path
        ),
    )
    .unwrap();

    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        &format!("--allow-write={}", temp.path().display()),
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("\"exit_code\":0"));
}

#[test]
fn sandbox_json_output_includes_audit() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("blocked.py");
    fs::write(
        &script,
        r#"
import subprocess
try:
    subprocess.run(["echo", "hi"])
except PermissionError:
    pass
"#,
    )
    .unwrap();

    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("\"audit\""))
    .stdout(predicate::str::contains("\"blocked_subprocesses\""));
}

#[test]
fn sandbox_json_output_includes_policy() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("noop.py");
    fs::write(&script, "print('hello')\n").unwrap();

    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        &format!("--allow-read={}", temp.path().display()),
        &format!("--allow-write={}", temp.path().display()),
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("\"allow_read\""))
    .stdout(predicate::str::contains("\"allow_write\""));
}
