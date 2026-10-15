#![cfg(unix)]
use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;

fn run(code: &str, permissions: &[&str]) -> Value {
    let mut cmd = cargo_bin_cmd!("pybun");
    let output = cmd
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_HISTORY", "0")
        .args(["--format=json", "run", "--sandbox", "-c", code])
        .args(permissions)
        .output()
        .unwrap();
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)))
}

#[test]
fn run_allowlist_permits_only_selected_executable() {
    let allowed = run(
        "import subprocess; subprocess.run(['/bin/echo', 'allowed'], check=True)",
        &["--allow-run=/bin/echo"],
    );
    assert_eq!(allowed["detail"]["exit_code"], 0, "{allowed}");
    let denied = run(
        "import subprocess; subprocess.run(['/bin/sh', '-c', 'echo forbidden'])",
        &["--allow-run=/bin/echo"],
    );
    assert_eq!(denied["detail"]["exit_code"], 1, "{denied}");
    assert!(denied.to_string().contains("E_SANDBOX_RUN_DENIED"));
    assert!(denied.to_string().contains("/bin/sh"));
}

#[test]
fn network_allowlist_checks_host_and_port() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let permission = format!("--allow-net=127.0.0.1:{port}");
    let allowed = run(
        &format!(
            "import socket; socket.create_connection(('127.0.0.1', {port}), timeout=2).close()"
        ),
        &[&permission],
    );
    assert_eq!(allowed["detail"]["exit_code"], 0, "{allowed}");
    let denied = run(
        "import socket; socket.socket().connect(('127.0.0.1', 1))",
        &[&permission],
    );
    assert_eq!(denied["detail"]["exit_code"], 1, "{denied}");
    assert!(denied.to_string().contains("E_SANDBOX_NET_DENIED"));
    assert!(denied.to_string().contains("127.0.0.1:1"));
}

#[test]
fn hostname_permission_supports_direct_connect_and_udp() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let allowed = run(
        &format!("import socket; socket.socket().connect(('localhost', {port}))"),
        &[&format!("--allow-net=localhost:{port}")],
    );
    assert_eq!(allowed["detail"]["exit_code"], 0, "{allowed}");
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = receiver.local_addr().unwrap().port();
    let allowed = run(
        &format!(
            "import socket; socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'x',('127.0.0.1',{port}))"
        ),
        &[&format!("--allow-net=127.0.0.1:{port}")],
    );
    assert_eq!(allowed["detail"]["exit_code"], 0, "{allowed}");
    let by_name = run(
        &format!(
            "import socket; socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'x',('localhost',{port}))"
        ),
        &[&format!("--allow-net=localhost:{port}")],
    );
    assert_eq!(by_name["detail"]["exit_code"], 0, "{by_name}");
    let denied = run(
        "import socket; socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'x',('127.0.0.1',1))",
        &[&format!("--allow-net=127.0.0.1:{port}")],
    );
    assert!(denied.to_string().contains("E_SANDBOX_NET_DENIED"));
}

#[test]
fn alternate_spawn_and_exec_paths_use_the_same_allowlist() {
    for code in [
        "import os; os.execv('/bin/sh', ['sh','-c','echo forbidden'])",
        "import os; os.posix_spawn('/bin/sh', ['sh','-c','echo forbidden'], os.environ)",
        "import os; os.system('echo forbidden')",
        "import os; os.fork()",
    ] {
        let denied = run(code, &["--allow-run=/bin/echo"]);
        assert_eq!(denied["detail"]["exit_code"], 1, "{denied}");
        assert!(
            denied.to_string().contains("E_SANDBOX_RUN_DENIED"),
            "{denied}"
        );
    }
    let allowed = run(
        "import os; pid=os.posix_spawn('/bin/echo', ['echo','allowed'], os.environ); os.waitpid(pid,0)",
        &["--allow-run=/bin/echo"],
    );
    assert_eq!(allowed["detail"]["exit_code"], 0, "{allowed}");
}

#[test]
fn executable_checks_match_bytes_path_cwd_and_direct_exec_semantics() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let fake = temp.path().join("echo");
    std::fs::write(&fake, "#!/bin/sh\necho UNAUTHORIZED\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let directory = serde_json::to_string(temp.path().to_str().unwrap()).unwrap();
    for code in [
        format!(
            "import os,subprocess; subprocess.run(['echo'],env={{b'PATH':os.fsencode({directory})}})"
        ),
        format!("import os; os.chdir({directory}); os.execv('echo',['echo'])"),
    ] {
        let result = run(&code, &["--allow-run=/bin/echo"]);
        assert_eq!(result["detail"]["exit_code"], 1, "{result}");
        assert!(
            !result["detail"]["stdout"]
                .as_str()
                .unwrap_or("")
                .contains("UNAUTHORIZED")
        );
    }
}

#[test]
fn relative_path_is_resolved_in_the_child_working_directory() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let good = temp.path().join("good");
    let bad = temp.path().join("bad");
    for root in [&good, &bad] {
        std::fs::create_dir_all(root.join("bin")).unwrap();
    }
    symlink("/bin/echo", good.join("bin/echo")).unwrap();
    std::fs::write(bad.join("bin/echo"), "#!/bin/sh\necho UNAUTHORIZED\n").unwrap();
    std::fs::set_permissions(bad.join("bin/echo"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let code = format!(
        "import os,subprocess; os.chdir({}); subprocess.run(['echo'],cwd={},env={{'PATH':'bin'}})",
        serde_json::to_string(&good).unwrap(),
        serde_json::to_string(&bad).unwrap()
    );
    let result = run(&code, &["--allow-run=echo"]);
    assert_eq!(result["detail"]["exit_code"], 1, "{result}");
    assert!(
        !result["detail"]["stdout"]
            .as_str()
            .unwrap_or("")
            .contains("UNAUTHORIZED")
    );
}

#[test]
fn mcp_uses_the_same_granular_permissions() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .env("PYBUN_HOME", temp.path())
        .env("PYBUN_AUDIT_LOG", "/dev/null")
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_HISTORY", "0")
        .env(
            "PYBUN_MCP_POLICY",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mcp-permissive-policy.toml"),
        )
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for (id, executable) in [(1, "/bin/echo"), (2, "/bin/sh")] {
        let request = serde_json::json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"pybun_run","arguments":{"code":format!("import subprocess; subprocess.run(['{executable}','allowed'],check=True)"),"sandbox_policy":{"allow_run":["/bin/echo"]}}}});
        writeln!(input, "{request}").unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    let replies: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect();
    assert_eq!(replies.len(), 2);
    let allowed: Value =
        serde_json::from_str(replies[0]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(allowed["exit_code"], 0, "{allowed}");
    assert!(replies[1].to_string().contains("E_SANDBOX_RUN_DENIED"));
}

#[test]
fn ambiguous_spawnp_name_cannot_use_cwd_authorization_for_path_search() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let good = temp.path().join("good");
    let evil = temp.path().join("evil");
    for directory in [&good, &evil] {
        std::fs::create_dir(directory).unwrap();
        std::fs::write(
            directory.join("echo"),
            "#!/bin/sh\necho UNAUTHORIZED_SPAWNP\n",
        )
        .unwrap();
        std::fs::set_permissions(
            directory.join("echo"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let code = format!(
        "import os; os.chdir({}); os.environ['PATH']={}; pid=os.posix_spawnp('echo',['echo'],os.environ); os.waitpid(pid,0)",
        serde_json::to_string(&good).unwrap(),
        serde_json::to_string(&evil).unwrap()
    );
    let permission = format!("--allow-run={}", good.join("echo").display());
    let result = run(&code, &[&permission]);
    assert_eq!(result["detail"]["exit_code"], 1, "{result}");
    assert!(
        !result["detail"]["stdout"]
            .as_str()
            .unwrap_or("")
            .contains("UNAUTHORIZED_SPAWNP")
    );
}
