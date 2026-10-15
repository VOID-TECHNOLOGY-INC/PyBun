use serde_json::{Value, json};
use std::path::Path;

fn preview(root: &Path, args: Value) -> Value {
    preview_backend(root, args, "native")
}
fn preview_backend(root: &Path, mut args: Value, backend: &str) -> Value {
    std::fs::write(
        root.join("pyproject.toml"),
        "[tool.pybun.mcp.policy]\nmax_execution_time_s=5\n",
    )
    .unwrap();
    args["dry_run"] = json!(true);
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pybun_run","arguments":args}});
    let mut command = assert_cmd::Command::new(env!("CARGO_BIN_EXE_pybun"));
    command
        .current_dir(root)
        .env_remove("PYBUN_MCP_POLICY")
        .env("PYBUN_BACKEND", backend)
        .env("PYBUN_UV", root.join("backend-must-not-start"))
        .env("PYBUN_HISTORY", "0")
        .env("PYBUN_HOME", root.join("home"))
        .env("PYBUN_AUDIT_LOG", "/dev/null")
        .args(["mcp", "serve", "--stdio"])
        .write_stdin(format!("{request}\n"))
        .timeout(std::time::Duration::from_secs(10));
    let output = command.assert().success();
    let rpc: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_ne!(rpc["result"]["isError"], true, "{rpc}");
    let value: Value =
        serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(value["dry_run"], true);
    assert!(!root.join("executed").exists());
    assert!(!root.join(".pybun/receipts").exists());
    value
}
fn assert_contract(value: &Value, risk: &str) {
    assert_eq!(value["estimated_risk"], risk, "{value}");
    assert_eq!(value["risk_level"], value["estimated_risk"]);
    assert_eq!(
        value["sandbox_policy_that_would_apply"],
        value["sandbox_policy"]
    );
    assert_eq!(
        value["sandbox_policy_that_would_apply"]["allow_network"],
        false
    );
    assert_eq!(value["sandbox_policy_that_would_apply"]["timeout_secs"], 5);
    assert!(value["risk_reasons"].is_array());
}
#[test]
fn dry_run_exposes_approval_contract_without_executing_inline_code() {
    for (code, risk) in [
        ("print('preview')", "low"),
        (
            "import socket\nopen('executed','w').write('bad')\nsocket.socket()",
            "medium",
        ),
        (
            "import shutil\nopen('executed','w').write('bad')\nshutil.rmtree('victim')",
            "high",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        assert_contract(&preview(temp.path(), json!({"code":code})), risk);
    }
}
#[test]
fn script_risk_uses_bounded_source_instead_of_filename() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("ordinary.py"),
        "import shutil\nopen('executed','w').write('bad')\nshutil.rmtree('victim')",
    )
    .unwrap();
    let value = preview(temp.path(), json!({"script":"ordinary.py"}));
    assert_eq!(value["risk_level"], "high", "{value}");
    assert_contract(&value, "high");
    std::fs::write(temp.path().join("socket.py"), "print('harmless')").unwrap();
    assert_contract(&preview(temp.path(), json!({"script":"socket.py"})), "low");
    let inline = preview(
        temp.path(),
        json!({"script":"ordinary.py","code":"print('inline')"}),
    );
    assert_contract(&inline, "low");
    assert!(
        inline["would_execute"]
            .as_str()
            .unwrap()
            .contains("Python inline code")
    );
}

#[test]
fn bounded_uv_dry_run_needs_no_backend_preparation() {
    let temp = tempfile::tempdir().unwrap();
    let value = preview_backend(
        temp.path(),
        json!({"code":"import shutil; shutil.rmtree('victim')"}),
        "uv",
    );
    assert_contract(&value, "high");
    assert_eq!(value["policy_applied"]["execution_supported"], false);
    assert!(!temp.path().join("uv.lock").exists());
    assert!(!temp.path().join(".venv").exists());
}
#[test]
fn uninspected_script_source_is_explicitly_uncertain() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::File::create(temp.path().join("large.py"))
        .unwrap()
        .set_len(3 * 1024 * 1024)
        .unwrap();
    let value = preview(temp.path(), json!({"script":"large.py"}));
    assert_eq!(value["risk_level"], "medium", "{value}");
    assert_contract(&value, "medium");
    assert!(
        value["risk_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason.as_str().unwrap().contains("not inspected"))
    );
}
