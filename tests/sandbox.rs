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
        .code(1)
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
        .code(1)
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
    .code(1)
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
    .code(1)
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
    .code(1)
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
    .code(1)
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

// --- Default write restriction tests (Issue #150) ---

#[test]
fn sandbox_default_blocks_write_to_etc() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("write_etc.py");
    // Attempt to write to /etc (should be blocked by sandbox default policy even without --allow-write)
    // Catches OSError broadly since the sandbox raises PermissionError (subclass of OSError)
    fs::write(
        &script,
        r#"
try:
    open('/etc/pybun_sandbox_test_DO_NOT_CREATE', 'w').write('hacked')
    print('WRITE ALLOWED')
except OSError as e:
    print('WRITE BLOCKED')
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
    .stdout(predicate::str::contains("WRITE BLOCKED"));
}

#[test]
fn sandbox_default_allows_write_to_tmp() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("write_tmp.py");
    let output_file = temp.path().join("sandbox_output.txt");
    let out_path = output_file.to_str().unwrap().replace('\\', "/");
    // Write to a temp dir path (which is in /tmp or equivalent) — should be allowed
    fs::write(
        &script,
        format!(
            r#"
import os
open({path:?}, 'w').write('ok')
print('WRITE OK')
"#,
            path = out_path
        ),
    )
    .unwrap();

    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("WRITE OK"));
}

#[test]
fn sandbox_default_write_restriction_audit_counts_blocked_writes() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("write_audit.py");
    // This test verifies that the SANDBOX (not the OS) is blocking writes by checking
    // the audit counter. The sandbox intercepts open() before the OS syscall and
    // increments blocked_file_writes.
    fs::write(
        &script,
        r#"
try:
    open('/etc/pybun_sandbox_test_DO_NOT_CREATE', 'w').write('x')
except OSError:
    pass
try:
    open('/usr/pybun_sandbox_test_DO_NOT_CREATE', 'w').write('x')
except OSError:
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
    .stdout(predicate::str::contains("\"blocked_file_writes\":2"));
}

#[test]
fn sandbox_explicit_allow_write_overrides_default_restriction() {
    let temp = tempdir().unwrap();
    let output_file = temp.path().join("out.txt");
    let script = temp.path().join("write_explicit.py");
    let out_path = output_file.to_str().unwrap().replace('\\', "/");
    fs::write(
        &script,
        format!(
            "open({path:?}, 'w').write('explicit')\nprint('WRITE OK')\n",
            path = out_path
        ),
    )
    .unwrap();

    // With --allow-write, explicit paths are allowed (existing behavior preserved)
    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        &format!("--allow-write={}", temp.path().display()),
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("WRITE OK"));
}

#[test]
fn sandbox_json_output_includes_default_deny_write_paths() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("noop.py");
    fs::write(&script, "print('hello')\n").unwrap();

    // When --sandbox is used without --allow-write, JSON output should include non-empty default_deny_write
    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("\"default_deny_write\""))
    .stdout(predicate::str::contains("\"/etc\"").or(predicate::str::contains("\"/usr\"")));
}

// --- Environment variable filtering tests (Issue #153) ---

#[test]
fn sandbox_default_filters_sensitive_env_vars() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("read_env.py");
    // Script tries to read a fake secret env var; sandbox should have filtered it out
    fs::write(
        &script,
        r#"
import os
val = os.environ.get("PYBUN_TEST_SECRET_KEY", "NOT_PRESENT")
print("SECRET:", val)
"#,
    )
    .unwrap();

    // Set a fake secret in parent env for the test process, then run sandbox
    bin()
        .env("PYBUN_TEST_SECRET_KEY", "super_secret_value_12345")
        .args([
            "--format=json",
            "run",
            "--sandbox",
            script.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("SECRET: NOT_PRESENT"));
}

#[test]
fn sandbox_default_preserves_basic_env_vars() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("check_env.py");
    // PATH should always be available so Python can find executables
    fs::write(
        &script,
        r#"
import os
path = os.environ.get("PATH", "")
print("PATH_PRESENT:", bool(path))
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
    .stdout(predicate::str::contains("PATH_PRESENT: True"));
}

#[test]
fn sandbox_allow_env_passes_specific_var_through() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("read_allowed_env.py");
    fs::write(
        &script,
        r#"
import os
val = os.environ.get("MY_ALLOWED_KEY", "NOT_PRESENT")
print("KEY:", val)
"#,
    )
    .unwrap();

    bin()
        .env("MY_ALLOWED_KEY", "allowed_value_xyz")
        .args([
            "--format=json",
            "run",
            "--sandbox",
            "--allow-env=MY_ALLOWED_KEY",
            script.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("KEY: allowed_value_xyz"));
}

#[test]
fn sandbox_allow_env_does_not_pass_unlisted_var() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("check_unlisted.py");
    fs::write(
        &script,
        r#"
import os
unlisted = os.environ.get("ANOTHER_SECRET", "NOT_PRESENT")
print("UNLISTED:", unlisted)
"#,
    )
    .unwrap();

    bin()
        .env("ANOTHER_SECRET", "secret_that_must_not_leak")
        .env("MY_ALLOWED_KEY", "allowed")
        .args([
            "--format=json",
            "run",
            "--sandbox",
            "--allow-env=MY_ALLOWED_KEY",
            script.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("UNLISTED: NOT_PRESENT"));
}

#[test]
fn sandbox_json_output_includes_allow_env() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("noop.py");
    fs::write(&script, "print('hello')\n").unwrap();

    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        "--allow-env=MY_KEY",
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("\"allow_env\""))
    .stdout(predicate::str::contains("\"MY_KEY\""));
}

#[test]
fn sandbox_non_sandbox_mode_does_not_filter_env() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("read_env_no_sandbox.py");
    // Without --sandbox, the env var must be visible to the child process
    fs::write(
        &script,
        r#"
import os
val = os.environ.get("PYBUN_TEST_SECRET_KEY", "NOT_PRESENT")
print("SECRET:", val)
"#,
    )
    .unwrap();

    bin()
        .env("PYBUN_TEST_SECRET_KEY", "visible_value")
        .args(["--format=json", "run", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("SECRET: visible_value"));
}

#[test]
fn sandbox_explicit_allow_write_yields_empty_default_deny_write_in_json() {
    let temp = tempdir().unwrap();
    let script = temp.path().join("noop.py");
    fs::write(&script, "print('hello')\n").unwrap();

    // When --allow-write is specified, default_deny_write must be [] in JSON
    // (the explicit allowlist already restricts all other paths)
    run_sandbox(&[
        "--format=json",
        "run",
        "--sandbox",
        &format!("--allow-write={}", temp.path().display()),
        script.to_str().unwrap(),
    ])
    .success()
    .stdout(predicate::str::contains("\"default_deny_write\":[]"));
}
