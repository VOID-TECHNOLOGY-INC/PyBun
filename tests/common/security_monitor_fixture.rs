#![allow(dead_code)]
#[path = "security_check_fixture.rs"]
mod check_fixture;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

pub fn fixture(
    server: &httpmock::MockServer,
    installed: bool,
) -> (tempfile::TempDir, tempfile::TempDir, String) {
    let (root, config) = check_fixture::fixture(server, installed);
    let state = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let config=config.replace("config_version=1",&format!("config_version=1\nmonitor_state_root={:?}",state.path().canonicalize().unwrap().join("state").to_string_lossy()))
        .replace("\"authorized_target_metadata_read\",\"approved_provider_http\"","\"authorized_target_metadata_read\",\"approved_provider_http\",\"authorized_state_read\",\"authorized_state_write\"");
    assert!(
        toml::from_str::<toml::Value>(&config).is_ok(),
        "fixture TOML"
    );
    pybun::security_assessment::config::SecurityAuthority::from_toml(&config, root.path()).unwrap();
    (root, state, config)
}

pub struct Session {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    id: u64,
    pub last_wire_bytes: usize,
}
impl Session {
    pub fn start(root: &Path, config: &str) -> Self {
        let policy = root.join("operator.toml");
        std::fs::write(&policy, config).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .current_dir(root)
            .env("PYBUN_MCP_POLICY", policy)
            .env("PYBUN_HOME", root.join("home"))
            .env("PYBUN_AUDIT_LOG", root.join("forbidden-audit/events.jsonl"))
            .env("PYBUN_BACKEND", "native")
            .env("PYBUN_ENV", root.join("ambient-env"))
            .args(["mcp", "serve", "--stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
            id: 0,
            last_wire_bytes: 0,
        }
    }
    pub fn call(&mut self, arguments: Value) -> Value {
        self.id += 1;
        writeln!(self.input.as_mut().unwrap(),"{}",serde_json::json!({"jsonrpc":"2.0","id":self.id,"method":"tools/call","params":{"name":"pybun_security_monitor","arguments":arguments}})).unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
        let mut line = String::new();
        assert!(self.output.read_line(&mut line).unwrap() > 0);
        self.last_wire_bytes = line.trim_end().len();
        let response: Value = serde_json::from_str(&line).unwrap();
        let body = serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
            .unwrap();
        capture("mcp-reply", &response);
        capture("mcp-body", &body);
        body
    }
    pub fn finish(mut self) {
        drop(self.input.take());
        let output = self.child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    pub fn lose_response(self, arguments: Value) {
        let Self {
            mut child,
            mut input,
            output,
            id,
            ..
        } = self;
        // Close the actual stdio response pipe before this explicit check. The
        // server cannot publish a prompt, but its guarded commit must finish.
        drop(output);
        writeln!(input.as_mut().unwrap(),"{}",serde_json::json!({"jsonrpc":"2.0","id":id+1,"method":"tools/call","params":{"name":"pybun_security_monitor","arguments":arguments}})).unwrap();
        input.as_mut().unwrap().flush().unwrap();
        drop(input);
        child.wait().unwrap();
    }
}

pub fn cli(root: &Path, config: &str, args: &[&str]) -> Value {
    let policy = root.join("operator.toml");
    std::fs::write(&policy, config).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(root)
        .env("PYBUN_HOME", root.join("home"))
        .args(["audit", "monitor"])
        .args(args)
        .arg("--security-config")
        .arg(policy)
        .arg("--format=json")
        .output()
        .unwrap();
    let response: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    capture("cli-envelope", &response);
    assert_eq!(
        output.status.code().unwrap(),
        response["detail"]["exit_code"].as_i64().unwrap() as i32,
        "{response}"
    );
    response["detail"].clone()
}

fn capture(kind: &str, value: &Value) {
    if let Some(path) = std::env::var_os("PYBUN_MONITOR_CAPTURE_DIR") {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir_all(&path).unwrap();
        let action = value["detail"]["action"]
            .as_str()
            .or_else(|| value["action"].as_str())
            .unwrap_or("rpc");
        std::fs::write(
            path.join(format!("{kind}-{id:04}-{action}.json")),
            serde_json::to_vec_pretty(value).unwrap(),
        )
        .unwrap();
    }
}
