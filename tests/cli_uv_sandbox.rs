#![cfg(unix)]

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use tempfile::TempDir;

// Stub preparation only; the runtime and sandbox execute a real CPython venv.
fn project() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='demo'\nversion='0.1.0'\ndependencies=[]\n",
    )
    .unwrap();
    let output = Command::new("python3")
        .args(["-m", "venv", "--without-pip", ".venv"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let uv = dir.path().join("uv");
    fs::write(&uv, "#!/bin/sh\ncase \"$1\" in\n--version) echo 'uv 0.12.13';;\nworkspace) pwd;;\nlock) printf \"version=1\\nrequires-python='>=3.10'\\n\" > uv.lock;;\nsync) exit 0;;\n*) exit 2;;\nesac\n").unwrap();
    fs::set_permissions(&uv, fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

fn cli(dir: &TempDir, args: &[&str]) -> (bool, Value) {
    let output = cargo_bin_cmd!("pybun")
        .current_dir(dir.path())
        .env("PYBUN_BACKEND", "uv")
        .env("PYBUN_UV", dir.path().join("uv"))
        .env("PYBUN_HISTORY", "0")
        .args(["run", "--sandbox", "--format=json"])
        .args(args)
        .output()
        .unwrap();
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

#[test]
fn sandboxed_uv_launcher_runs_inline_and_script_without_exposing_guard() {
    let dir = project();
    let source = "import sys\nassert not hasattr(sys.modules.get('sitecustomize'), '_DENY_WRITE')\nprint('guarded-ok')\n";
    fs::write(dir.path().join("hello.py"), source).unwrap();
    for args in [vec!["--code", source], vec!["hello.py"]] {
        let (ok, value) = cli(&dir, &args);
        assert!(ok, "{value}");
        assert_eq!(value["detail"]["stdout"], "guarded-ok\n");
        assert_eq!(value["detail"]["sandboxed"], true);
    }
}

#[test]
fn sandboxed_uv_launcher_preserves_resource_denials() {
    let dir = project();
    let outside = TempDir::new().unwrap();
    let sentinel = outside.path().join("sentinel");
    fs::write(&sentinel, "original").unwrap();
    let path = serde_json::to_string(&sentinel).unwrap();
    let scripts = [
        "import socket; socket.create_connection(('127.0.0.1', 1))".to_string(),
        "import subprocess; subprocess.run(['echo', 'escaped'])".to_string(),
        format!("open({path}).read()"),
        format!("open({path}, 'w').write('escaped')"),
        "import sitecustomize; sitecustomize._DENY_WRITE.clear()".to_string(),
    ];
    for source in scripts {
        let root = dir.path().to_str().unwrap();
        let (ok, value) = cli(
            &dir,
            &[
                "--code",
                &source,
                "--allow-read",
                root,
                "--allow-write",
                root,
            ],
        );
        assert!(!ok, "{source}: {value}");
        let stderr = value["detail"]["stderr"].as_str().unwrap();
        assert!(
            if source.starts_with("import sitecustomize") {
                stderr.contains("No module named") || stderr.contains("has no attribute")
            } else {
                stderr.contains("blocked")
            },
            "{source}: {value}"
        );
        assert!(!stderr.contains("KeyError"), "{value}");
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "original");
    }
}

#[test]
fn sandboxed_uv_launcher_guards_pth_hooks_before_running_user_code() {
    let dir = project();
    let outside = TempDir::new().unwrap();
    let sentinel = outside.path().join("startup-escaped");
    let output = Command::new(dir.path().join(".venv/bin/python"))
        .args([
            "-I",
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let site = String::from_utf8(output.stdout).unwrap();
    fs::write(
        std::path::Path::new(site.trim()).join("startup.pth"),
        format!(
            "import builtins; builtins.open({}, 'w').write('escaped')\n",
            serde_json::to_string(&sentinel).unwrap()
        ),
    )
    .unwrap();
    let root = dir.path().to_str().unwrap();
    let (ok, value) = cli(&dir, &["--code", "print('user-ok')", "--allow-write", root]);
    assert!(ok, "{value}");
    assert_eq!(value["detail"]["stdout"], "user-ok\n");
    assert!(
        value["detail"]["stderr"]
            .as_str()
            .unwrap()
            .contains("blocked"),
        "{value}"
    );
    assert!(!sentinel.exists());
}

#[test]
fn sandboxed_uv_pep723_runs_with_an_external_interpreter_under_read_policy() {
    let dir = project();
    let outside = TempDir::new().unwrap();
    let venv = outside.path().join("venv");
    fs::rename(dir.path().join(".venv"), &venv).unwrap();
    fs::write(
        dir.path().join("external.py"),
        "# /// script\n# dependencies = []\n# ///\nprint('external-ok')\n",
    )
    .unwrap();
    fs::write(dir.path().join("uv"), "#!/bin/sh\ncase \"$1\" in\n--version) echo 'uv 0.12.13';;\nlock) printf \"version=1\\nrequires-python='>=3.10'\\n\" > external.py.lock;;\nsync) exit 0;;\npython) printf '%s/bin/python\\n' \"$UV_PROJECT_ENVIRONMENT\";;\n*) exit 2;;\nesac\n").unwrap();
    let output = cargo_bin_cmd!("pybun")
        .current_dir(dir.path())
        .env("PYBUN_BACKEND", "uv")
        .env("PYBUN_UV", dir.path().join("uv"))
        .env("UV_PROJECT_ENVIRONMENT", &venv)
        .env("PYBUN_HISTORY", "0")
        .args([
            "run",
            "external.py",
            "--sandbox",
            "--format=json",
            "--allow-read",
        ])
        .arg(dir.path())
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output.status.success(), "{value}");
    assert_eq!(value["detail"]["stdout"], "external-ok\n");
}

#[test]
fn mcp_uv_sandbox_runs_inline_and_script() {
    let dir = project();
    let home = TempDir::new().unwrap();
    fs::write(dir.path().join("hello.py"), "print('mcp-ok')\n").unwrap();
    let policy = dir.path().join("policy.toml");
    fs::write(&policy, "[tool.pybun.mcp.policy]\nrequire_sandbox=false\nallow_network=true\nmax_execution_time_s=0\nallowed_working_directories=['.']\n").unwrap();
    for args in [
        json!({"code":"print('mcp-ok')"}),
        json!({"script":"hello.py"}),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .current_dir(dir.path())
            .env("PYBUN_BACKEND", "uv")
            .env("PYBUN_UV", dir.path().join("uv"))
            .env("PYBUN_MCP_POLICY", &policy)
            .env("PYBUN_HOME", home.path())
            .env("PYBUN_HISTORY", "0")
            .args(["mcp", "serve", "--stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}})
        )
        .unwrap();
        writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pybun_run","arguments":args}})).unwrap();
        drop(stdin);
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let reply: Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
        assert_ne!(reply["result"]["isError"], true, "{reply}");
        let value: Value =
            serde_json::from_str(reply["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(value["status"], "success", "{value}");
        assert_eq!(value["sandboxed"], true);
        assert_eq!(value["stdout"], "mcp-ok\n");
    }
}

#[test]
fn uv_cpu_kill_has_signal_exit_and_ignores_partial_python_errors() {
    let dir = project();
    let (ok, value) = cli(
        &dir,
        &[
            "--sandbox-cpu=1",
            "--sandbox-timeout=20",
            "-c",
            "import sys\nsys.stderr.write(\"KeyError: 'sitecustomize'\\n\")\nwhile True: pass",
        ],
    );
    assert!(!ok, "{value}");
    assert_eq!(value["detail"]["exit_code"], 128 + libc::SIGXCPU, "{value}");
    assert_eq!(value["diagnostics"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(
        value["diagnostics"][0]["code"], "E_SANDBOX_CPU_LIMIT",
        "{value}"
    );
}
