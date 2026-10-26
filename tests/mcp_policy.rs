use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn call(root: &Path, tool: &str, arguments: Value) -> Value {
    rpc(
        root,
        "tools/call",
        json!({"name":tool,"arguments":arguments}),
    )
}
fn rpc(root: &Path, method: &str, params: Value) -> Value {
    rpc_backend(root, method, params, "native")
}
fn rpc_backend(root: &Path, method: &str, params: Value, backend: &str) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(root)
        .env_remove("PYBUN_MCP_POLICY")
        .env("PYBUN_BACKEND", backend)
        .env("PYBUN_UV", root.join("uv"))
        .env("PYBUN_HOME", root.join("home"))
        .env("PYBUN_HISTORY", "0")
        .env("PYBUN_PEP723_DRY_RUN", "1")
        .env("PYBUN_AUDIT_LOG", "/dev/null")
        .args(["mcp", "serve", "--stdio", "--allow-unsafe-no-sandbox"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
    )
    .unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    serde_json::from_str(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap()
}
fn content(reply: &Value) -> Value {
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text.strip_prefix("Error: ").unwrap_or(text)).unwrap()
}
fn configure(root: &Path, policy: &str) {
    std::fs::write(
        root.join("pyproject.toml"),
        format!("[tool.pybun.mcp.policy]\n{policy}\n"),
    )
    .unwrap();
}

#[test]
fn missing_and_malformed_policy_deny_before_execution() {
    let temp = tempfile::tempdir().unwrap();
    for policy in [None, Some("allow_network = 'private-secret'\n")] {
        if let Some(policy) = policy {
            configure(temp.path(), policy);
        }
        let reply = call(
            temp.path(),
            "pybun_run",
            json!({"code":"open('marker','w').write('executed')","unsafe_no_sandbox":true}),
        );
        assert_eq!(reply["result"]["isError"], true, "{reply}");
        assert!(!temp.path().join("marker").exists());
        assert!(!reply.to_string().contains("private-secret"));
        assert!(
            content(&reply)["diagnostics"][0]["code"]
                .as_str()
                .unwrap()
                .starts_with("E_MCP_POLICY_")
        );
    }
}

#[test]
fn server_policy_clamps_run_requests_and_exposes_effective_policy() {
    let temp = tempfile::tempdir().unwrap();
    configure(
        temp.path(),
        "default_sandbox=true\nrequire_sandbox=true\nallow_network=false\nmax_execution_time_s=2\n",
    );
    let reply = call(
        temp.path(),
        "pybun_run",
        json!({"code":"print('preview')","dry_run":true,"unsafe_no_sandbox":true,"sandbox_policy":{"allow_network":true,"timeout_secs":0}}),
    );
    let result = content(&reply);
    assert_eq!(result["sandboxed"], true, "{result}");
    assert_eq!(result["policy_applied"]["allow_network"], false);
    assert_eq!(result["sandbox_policy"]["timeout_secs"], 2);
    assert!(!temp.path().join(".pybun/receipts").exists());
}

#[test]
fn denied_tools_and_outside_paths_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    configure(temp.path(), "denied_tools=['pybun_gc']\n");
    let denied = content(&call(temp.path(), "pybun_gc", json!({})));
    assert_eq!(denied["diagnostics"][0]["code"], "E_MCP_POLICY_TOOL_DENIED");
    let outside = content(&call(
        temp.path(),
        "pybun_run",
        json!({"code":"print(1)","sandbox_policy":{"allow_write":["/etc"]}}),
    ));
    assert_eq!(
        outside["diagnostics"][0]["code"],
        "E_MCP_POLICY_PATH_DENIED"
    );
}

#[test]
fn active_limits_cannot_be_disabled_by_unsafe_flags() {
    let temp = tempfile::tempdir().unwrap();
    configure(
        temp.path(),
        "default_sandbox=false\nrequire_sandbox=false\nallow_network=true\nmax_execution_time_s=1\n",
    );
    let result = content(&call(
        temp.path(),
        "pybun_run",
        json!({"code":"print(1)","dry_run":true,"unsafe_no_sandbox":true}),
    ));
    assert_eq!(result["sandboxed"], true, "{result}");
}

#[test]
fn resource_aliases_cannot_bypass_denied_tools() {
    let temp = tempfile::tempdir().unwrap();
    configure(temp.path(), "denied_tools=['pybun_context']\n");
    let reply = rpc(
        temp.path(),
        "resources/read",
        json!({"uri":"pybun://project/snapshot"}),
    );
    assert!(reply["error"].is_object(), "{reply}");
    assert!(
        reply.to_string().contains("E_MCP_POLICY_TOOL_DENIED"),
        "{reply}"
    );
}

#[test]
fn effective_timeout_and_network_policy_are_enforced_during_real_execution() {
    let temp = tempfile::tempdir().unwrap();
    configure(temp.path(), "allow_network=false\nmax_execution_time_s=1\n");
    let start = std::time::Instant::now();
    let reply = call(
        temp.path(),
        "pybun_run",
        json!({"code":"import time; time.sleep(5)","unsafe_no_sandbox":true,"sandbox_policy":{"timeout_secs":0}}),
    );
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    let result = content(&reply);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(4),
        "{result}"
    );
    assert!(result.to_string().contains("E_SANDBOX_TIMEOUT"), "{result}");
    let reply = call(
        temp.path(),
        "pybun_run",
        json!({"code":"import socket; socket.socket().connect(('127.0.0.1',1))","sandbox_policy":{"allow_network":true,"allow_net":["127.0.0.1:1"]}}),
    );
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    let result = content(&reply);
    assert_eq!(result["exit_code"], 1, "{result}");
    assert!(
        result.to_string().contains("E_SANDBOX_NET_DENIED"),
        "{result}"
    );
    assert_eq!(result["policy_applied"]["allow_network"], false);
}

#[test]
fn native_script_lock_cannot_bypass_bounded_preparation() {
    use pybun::lockfile::{Lockfile, Package, PackageSource};
    let temp = tempfile::tempdir().unwrap();
    configure(temp.path(), "allow_network=false\nmax_execution_time_s=1\n");
    std::fs::write(temp.path().join("script.py"), "print('must not run')").unwrap();
    let mut lock = Lockfile::new(vec![], vec![]);
    lock.add_package(Package {
        name: "demo".into(),
        version: "1".into(),
        source: PackageSource::Url {
            url: "https://example.invalid/demo.whl".into(),
        },
        wheel: "demo.whl".into(),
        hash: "unused".into(),
        dependencies: vec![],
    });
    lock.save_to_path(temp.path().join("script.py.lock"))
        .unwrap();
    let result = content(&call(
        temp.path(),
        "pybun_run",
        json!({"script":"script.py"}),
    ));
    assert_eq!(
        result["diagnostics"][0]["code"], "E_MCP_POLICY_UNSUPPORTED",
        "{result}"
    );
    assert!(!temp.path().join(".pybun").exists());
}

#[cfg(unix)]
#[test]
fn backend_derived_roots_and_flag_injection_cannot_escape_policy() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join("pyproject.toml"),
        "[project]\nname='outside'\nversion='1'\n",
    )
    .unwrap();
    configure(
        temp.path(),
        "default_sandbox=false\nrequire_sandbox=false\nallow_network=true\nmax_execution_time_s=0\n",
    );
    let fake = temp.path().join("uv");
    std::fs::write(&fake,format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> calls\ncase \"$*\" in\n*--version*) echo 'uv 0.12.13';;\n*workspace*dir*) echo '{}';;\n*) touch mutation; exit 9;;\nesac\n",outside.path().display())).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let request =
        json!({"name":"pybun_lock","arguments":{"packages":["--script","/outside/script.py"]}});
    let denied = content(&rpc_backend(temp.path(), "tools/call", request, "uv"));
    assert_eq!(
        denied["diagnostics"][0]["code"], "E_MCP_POLICY_ARGUMENT",
        "{denied}"
    );
    assert!(!temp.path().join("calls").exists());
    let request = json!({"name":"pybun_lock","arguments":{"_authorized_roots":["/"]}});
    let denied = content(&rpc_backend(temp.path(), "tools/call", request, "uv"));
    assert_eq!(
        denied["diagnostics"][0]["code"], "E_MCP_POLICY_PATH_DENIED",
        "{denied}"
    );
    assert!(!temp.path().join("mutation").exists());
    assert!(!outside.path().join("uv.lock").exists());
    assert!(!temp.path().join(".pybun/receipts").exists());
}

#[cfg(unix)]
#[test]
fn authorization_rejects_fifo_before_reading_script_source() {
    let temp = tempfile::tempdir().unwrap();
    configure(temp.path(), "max_execution_time_s=1");
    assert!(
        Command::new("mkfifo")
            .arg(temp.path().join("blocked.py"))
            .status()
            .unwrap()
            .success()
    );
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pybun_run","arguments":{"script":"blocked.py"}}});
    let mut command = assert_cmd::Command::new(env!("CARGO_BIN_EXE_pybun"));
    command
        .current_dir(temp.path())
        .env_remove("PYBUN_MCP_POLICY")
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_HISTORY", "0")
        .env("PYBUN_HOME", temp.path().join("home"))
        .env("PYBUN_AUDIT_LOG", "/dev/null")
        .args(["mcp", "serve", "--stdio"])
        .write_stdin(format!("{request}\n"))
        .timeout(std::time::Duration::from_secs(3));
    command
        .assert()
        .success()
        .stdout(predicates::str::contains("E_MCP_POLICY_UNSUPPORTED"));
}

#[test]
fn sandboxed_run_cannot_rewrite_the_operator_policy() {
    let temp = tempfile::tempdir().unwrap();
    configure(
        temp.path(),
        "default_sandbox=true\nrequire_sandbox=true\nallow_network=false\nmax_execution_time_s=5\n",
    );
    let pyproject = temp.path().join("pyproject.toml");
    let before = std::fs::read_to_string(&pyproject).unwrap();
    let reply = call(
        temp.path(),
        "pybun_run",
        json!({
            "code": "from pathlib import Path; Path('pyproject.toml').write_text('denied_tools = []\\n')",
            "sandbox_policy": {}
        }),
    );
    let value = content(&reply);
    assert_ne!(value["status"], "success", "{value}");
    assert_eq!(std::fs::read_to_string(&pyproject).unwrap(), before);
}

#[test]
fn script_argument_cannot_be_smuggled_as_a_tool_option() {
    let temp = tempfile::tempdir().unwrap();
    configure(
        temp.path(),
        "default_sandbox=false\nrequire_sandbox=false\nallow_network=true\nmax_execution_time_s=0\n",
    );
    for tool in [
        "pybun_lint",
        "pybun_type_check",
        "pybun_profile",
        "pybun_fix",
    ] {
        let reply = call(
            temp.path(),
            tool,
            json!({"script": "--output-file=outside/pwned.txt"}),
        );
        let text = reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(
            text.contains("must be a path") || text.contains("Script not found"),
            "{tool}: {reply}"
        );
        assert!(
            !temp.path().join("outside/pwned.txt").exists(),
            "{tool} wrote outside the allowed root"
        );
    }
}

#[cfg(unix)]
#[test]
fn script_arguments_must_be_regular_files() {
    let temp = tempfile::tempdir().unwrap();
    configure(
        temp.path(),
        "default_sandbox=false\nrequire_sandbox=false\nallow_network=true\nmax_execution_time_s=0\n",
    );
    let fifo = temp.path().join("pipe.py");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|status| status.success())
            .unwrap_or(false),
        "mkfifo unavailable"
    );
    let reply = call(
        temp.path(),
        "pybun_lint",
        json!({"script": fifo.to_string_lossy()}),
    );
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.contains("regular file"), "{reply}");
}

#[test]
fn executed_tool_failures_set_is_error_without_changing_payloads() {
    let temp = tempfile::tempdir().unwrap();
    configure(
        temp.path(),
        "default_sandbox=false\nrequire_sandbox=false\nallow_network=true\nmax_execution_time_s=0\n",
    );
    for (code, expected_exit) in [("print('ok')", 0), ("import sys; sys.exit(3)", 3)] {
        let reply = call(
            temp.path(),
            "pybun_run",
            json!({"code":code,"unsafe_no_sandbox":true}),
        );
        let result = content(&reply);
        assert_eq!(result["exit_code"], expected_exit, "{reply}");
        assert_eq!(
            reply["result"]["isError"].as_bool().unwrap_or(false),
            expected_exit != 0,
            "{reply}"
        );
    }
    // Test failures are returned as a summary rather than a top-level status.
    std::fs::write(
        temp.path().join("test_demo.py"),
        "def test_failure():\n    assert False\n",
    )
    .unwrap();
    let reply = call(temp.path(), "pybun_test", json!({}));
    assert_eq!(content(&reply)["summary"]["failed"], 1, "{reply}");
    assert_eq!(reply["result"]["isError"], true, "{reply}");
}

#[cfg(unix)]
#[test]
fn v2_backend_failure_sets_is_error_and_preserves_envelope() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    configure(
        temp.path(),
        "default_sandbox=false\nrequire_sandbox=false\nallow_network=true\nmax_execution_time_s=0\n",
    );
    let uv = temp.path().join("uv");
    std::fs::write(&uv, "#!/bin/sh\nif [ \"$1\" = '--version' ]; then echo 'uv 0.12.13'; exit 0; fi\nif [ \"$1\" = 'workspace' ]; then pwd; exit 0; fi\nexit 0\n").unwrap();
    std::fs::write(
        temp.path().join("uv.lock"),
        "version=1\n[[package]]\nname='demo'\nversion='0.1.0'\nsource={virtual='.'}\n",
    )
    .unwrap();
    let venv = Command::new("python3")
        .args(["-m", "venv", "--without-pip"])
        .arg(temp.path().join(".venv"))
        .output()
        .unwrap();
    assert!(
        venv.status.success(),
        "{}",
        String::from_utf8_lossy(&venv.stderr)
    );
    std::fs::set_permissions(&uv, std::fs::Permissions::from_mode(0o755)).unwrap();
    let reply = rpc_backend(
        temp.path(),
        "tools/call",
        json!({"name":"pybun_run","arguments":{"code":"import sys; sys.exit(3)","unsafe_no_sandbox":true}}),
        "uv",
    );
    let result = content(&reply);
    assert_eq!(result["contract_version"], "2", "{reply}");
    assert_eq!(result["exit_code"], 3, "{reply}");
    assert!(result["receipt_id"].is_string(), "{reply}");
    assert_eq!(result["status"], "error", "{reply}");
    assert_eq!(reply["result"]["isError"], true, "{reply}");
}

#[cfg(unix)]
#[test]
fn mcp_cpu_kill_reports_only_cpu_failure_with_signal_exit() {
    let temp = tempfile::tempdir().unwrap();
    configure(temp.path(), "max_cpu_time_s=1\nmax_execution_time_s=20\n");
    let reply = call(
        temp.path(),
        "pybun_run",
        json!({"code":"import sys\nsys.stderr.write(\"KeyError: 'sitecustomize'\\n\")\nwhile True: pass", "sandbox_policy":{"cpu_limit_secs":1}}),
    );
    let value = content(&reply);
    assert_eq!(value["exit_code"], 128 + libc::SIGXCPU, "{reply}");
    let errors: Vec<_> = value["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["level"] == "error")
        .collect();
    assert_eq!(errors.len(), 1, "{reply}");
    assert_eq!(errors[0]["code"], "E_SANDBOX_CPU_LIMIT", "{reply}");
}
