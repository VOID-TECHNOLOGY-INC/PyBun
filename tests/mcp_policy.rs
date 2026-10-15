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
    let result = content(&call(
        temp.path(),
        "pybun_run",
        json!({"code":"import time; time.sleep(5)","unsafe_no_sandbox":true,"sandbox_policy":{"timeout_secs":0}}),
    ));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(4),
        "{result}"
    );
    assert!(result.to_string().contains("E_SANDBOX_TIMEOUT"), "{result}");
    let result = content(&call(
        temp.path(),
        "pybun_run",
        json!({"code":"import socket; socket.socket().connect(('127.0.0.1',1))","sandbox_policy":{"allow_network":true,"allow_net":["127.0.0.1:1"]}}),
    ));
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
