use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

fn state() -> Value {
    json!({"schema_version":1,"python":{"implementation":"cpython","version":"3.12.1","abi":"cpython-312","executable":"/python","executable_digest":"abc"},"backend":{"name":"uv","version":"0.11.0"},"lock":{"source":"uv.lock","digest":"aaa"},"installed_packages":[{"name":"Demo_pkg","version":"1","artifact_hashes":["sha256:a"]}],"effective_policy":{"allow_network":false,"max_memory_mb":512},"profile":{"name":"dev"},"project":{"path":"/project"}})
}
fn cli(before: &Value, after: &Value) -> Value {
    let temp = tempfile::tempdir().unwrap();
    let left = temp.path().join("before.json");
    let right = temp.path().join("after.json");
    fs::write(&left, before.to_string()).unwrap();
    fs::write(&right, after.to_string()).unwrap();
    let output = cargo_bin_cmd!("pybun")
        .env("PYBUN_HISTORY", "0")
        .env("DIFF_SECRET_TOKEN", "credentialpkg")
        .args(["--format=json", "environment", "diff"])
        .arg(&left)
        .arg(&right)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["detail"].clone()
}
fn mcp(before: &Value, after: &Value) -> Value {
    let temp = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(temp.path())
        .env("PYBUN_HISTORY", "0")
        .env("DIFF_SECRET_TOKEN", "credentialpkg")
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}})
    )
    .unwrap();
    writeln!(input,"{}",json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pybun_environment_diff","arguments":{"before":before,"after":after}}})).unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    let rpc = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["id"] == 2)
        .unwrap();
    serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}
#[test]
fn cli_and_mcp_share_deterministic_complete_diffs() {
    let before = state();
    let mut after = state();
    after["python"]["version"] = json!("3.13.0");
    after["backend"]["version"] = json!("0.12.0");
    after["lock"]["digest"] = json!("bbb");
    after["effective_policy"]["allow_network"] = json!(true);
    after["installed_packages"] = json!([{"name":"demo-pkg","version":"2","artifact_hashes":["sha256:b"]},{"name":"extra","version":"1"}]);
    let result = cli(&before, &after);
    assert_eq!(result, mcp(&before, &after));
    let changes = result["changes"].as_array().unwrap();
    for field in [
        "python.version",
        "backend.version",
        "lock.digest",
        "effective_policy.allow_network",
        "installed_packages.demo-pkg",
        "installed_packages.extra",
    ] {
        assert!(
            changes.iter().any(|change| change["field"] == field),
            "missing {field}: {result}"
        );
    }
    assert!(
        changes
            .iter()
            .any(|change| change["reason_code"] == "PACKAGE_ADDED")
    );
    assert!(
        changes
            .iter()
            .any(|change| change["reason_code"] == "PACKAGE_CHANGED")
    );
    assert_eq!(result, cli(&before, &after));
}
#[test]
fn equal_and_partial_evidence_are_distinct_and_private() {
    let before = state();
    assert!(
        cli(&before, &before)["changes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let result = cli(&json!({}), &json!({}));
    assert!(result["changes"].as_array().unwrap().is_empty());
    assert!(!result["unavailable"].as_array().unwrap().is_empty());
    assert_eq!(result["complete"], false);
    let mut private = state();
    private["environment_variables"] = json!({"CUSTOM":"private-secret"});
    private["effective_policy"]["token"] = json!("private-secret");
    private["lock"]["source"] =
        json!("https://username:password@example.org/uv.lock?token=private-secret");
    let result = cli(&before, &private).to_string();
    for secret in ["private-secret", "username:password"] {
        assert!(!result.contains(secret), "{result}");
    }
    assert!(!result.contains("environment_variables"));
}
#[test]
fn package_removal_and_missing_evidence_do_not_claim_equality() {
    let before = state();
    let mut after = state();
    after["installed_packages"] = json!([]);
    after["python"]["abi"] = Value::Null;
    let result = cli(&before, &after);
    assert!(
        result["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["reason_code"] == "PACKAGE_REMOVED")
    );
    assert!(
        result["unavailable"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["field"] == "python.abi")
    );
}

#[test]
fn unknown_names_and_redacted_package_identity_are_unavailable() {
    let unknown = json!({"backend":{"name":"unknown"}});
    let result = cli(&unknown, &unknown);
    assert!(
        result["unavailable"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["field"] == "backend.name")
    );
    let private = json!({"installed_packages":[{"name":"credentialpkg","version":"1"}]});
    let empty = json!({"installed_packages":[]});
    let result = cli(&private, &empty);
    assert!(result["changes"].as_array().unwrap().is_empty(), "{result}");
    assert!(
        result["unavailable"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["field"] == "installed_packages")
    );
    assert_eq!(result, mcp(&private, &empty));
}
#[test]
fn native_receipt_resource_limits_are_compared() {
    let before = json!({"effective_policy":{"resource_limits":{"memory_limit_mb":512,"cpu_limit_secs":1,"max_processes":0,"file_size_limit_mb":1,"unsupported":[]}}});
    let after = json!({"effective_policy":{"resource_limits":{"memory_limit_mb":1024,"cpu_limit_secs":2,"max_processes":1,"file_size_limit_mb":2,"unsupported":["memory_limit_mb"]}}});
    let result = cli(&before, &after);
    for key in [
        "memory_limit_mb",
        "cpu_limit_secs",
        "max_processes",
        "file_size_limit_mb",
        "unsupported",
    ] {
        let field = format!("effective_policy.resource_limits.{key}");
        assert!(
            result["changes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["field"] == field),
            "{result}"
        );
    }
}
