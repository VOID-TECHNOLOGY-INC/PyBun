use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn serve(root: &Path, rates: &str, requests: &[Value]) -> (Vec<Value>, String) {
    std::fs::write(root.join("pyproject.toml"),format!("[tool.pybun.mcp.policy]\ndefault_sandbox=false\nrequire_sandbox=false\nallow_network=true\nmax_execution_time_s=0\n[tool.pybun.mcp.rate_limit]\n{rates}\n")).unwrap();
    let audit = tempfile::tempdir().unwrap();
    let audit_file = audit.path().join("audit.jsonl");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(root)
        .env_remove("PYBUN_MCP_POLICY")
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_HOME", root.join("home"))
        .env("PYBUN_HISTORY", "0")
        .env("PYBUN_AUDIT_LOG", &audit_file)
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for request in requests {
        writeln!(input, "{request}").unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    let replies = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    (
        replies,
        std::fs::read_to_string(audit_file).unwrap_or_default(),
    )
}
fn request(id: u64, tool: &str, args: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}})
}
fn content(reply: &Value) -> Value {
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text.strip_prefix("Error: ").unwrap_or(text)).unwrap()
}

#[test]
fn rejected_calls_do_not_execute_or_consume_other_budgets_and_are_audited() {
    let temp = tempfile::tempdir().unwrap();
    let requests = [
        request(1, "pybun_run", json!({"code":"print('allowed')"})),
        request(
            2,
            "pybun_run",
            json!({"code":"open('denied-marker','w').write('bad')","session_id":"spoofed-session"}),
        ),
        request(3, "pybun_environment_diff", json!({"before":{},"after":{}})),
        request(4, "pybun_environment_diff", json!({"before":{},"after":{}})),
    ];
    let (replies, audit) = serve(
        temp.path(),
        "calls_per_minute=10\nglobal_calls_per_minute=2\npybun_run_per_minute=1",
        &requests,
    );
    assert_eq!(replies.len(), 4);
    assert_eq!(content(&replies[0])["exit_code"], 0, "{}", replies[0]);
    for index in [1, 3] {
        assert_eq!(
            replies[index]["result"]["isError"], true,
            "{}",
            replies[index]
        );
        let result = content(&replies[index]);
        assert_eq!(result["diagnostics"][0]["code"], "mcp.rate_limit_exceeded");
        assert!(result["retry_after_ms"].as_u64().unwrap() > 0);
    }
    assert_ne!(replies[2]["result"]["isError"], true, "{}", replies[2]);
    assert!(!temp.path().join("denied-marker").exists());
    assert!(!temp.path().join(".pybun/receipts").exists());
    assert!(audit.contains("mcp.rate_limit_exceeded"), "{audit}");
    let sessions: Vec<_> = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["session_id"].clone())
        .collect();
    assert_eq!(sessions.len(), 4);
    assert!(
        sessions
            .iter()
            .all(|session| session == &sessions[0] && session != "spoofed-session")
    );
}

#[test]
fn malformed_rate_configuration_fails_closed_before_execution() {
    let temp = tempfile::tempdir().unwrap();
    let (replies, _) = serve(
        temp.path(),
        "calls_per_minute=0",
        &[request(
            1,
            "pybun_run",
            json!({"code":"open('marker','w').write('bad')"}),
        )],
    );
    assert_eq!(replies[0]["result"]["isError"], true, "{}", replies[0]);
    assert!(!temp.path().join("marker").exists());
}

#[test]
fn resource_alias_uses_the_same_tool_bucket() {
    let temp = tempfile::tempdir().unwrap();
    let requests = [
        request(1, "pybun_gc", json!({"dry_run":true})),
        json!({"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"pybun://cache/info"}}),
    ];
    let (replies, _) = serve(
        temp.path(),
        "[tool.pybun.mcp.rate_limit.per_tool.pybun_gc]\ncalls=1\nwindow_secs=60",
        &requests,
    );
    assert_ne!(replies[0]["result"]["isError"], true, "{}", replies[0]);
    assert!(replies[1]["error"].is_object(), "{}", replies[1]);
    assert!(replies[1].to_string().contains("mcp.rate_limit_exceeded"));
}

#[test]
fn stdio_session_limit_cannot_be_reset_by_client_identity() {
    let temp = tempfile::tempdir().unwrap();
    let requests = [
        request(1, "pybun_environment_diff", json!({"before":{},"after":{}})),
        request(
            2,
            "pybun_environment_diff",
            json!({"before":{},"after":{},"session_id":"new-client"}),
        ),
    ];
    let (replies, _) = serve(
        temp.path(),
        "calls_per_minute=1\nglobal_calls_per_minute=100",
        &requests,
    );
    assert_ne!(replies[0]["result"]["isError"], true);
    assert_eq!(
        content(&replies[0])["rate_limit_applied"]["limits"]["session"]["calls"],
        1
    );
    assert_eq!(
        content(&replies[1])["rate_limit_applied"]["scope"],
        "session"
    );
}
