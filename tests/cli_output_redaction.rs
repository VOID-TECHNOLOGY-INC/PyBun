use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn command(root: &TempDir) -> assert_cmd::Command {
    let mut command = cargo_bin_cmd!("pybun");
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .current_dir(root.path())
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_HISTORY", "0")
        .env("PYBUN_HOME", root.path().join("home"))
        .env("AWS_PROFILE", "default")
        .env("AWS_PAGER", "a")
        .env("AWS_DEFAULT_OUTPUT", "json")
        .env("SECRET_API_KEY", "x");
    command
}

#[test]
fn ordinary_aws_settings_and_short_secrets_do_not_corrupt_run_output() {
    let root = TempDir::new().unwrap();
    for sandbox in [false, true] {
        let mut command = command(&root);
        command.args(["--format=json", "run"]);
        if sandbox {
            command.arg("--sandbox");
        }
        let output = command
            .args(["-c", "print('a json default database sandbox')"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            value["detail"]["stdout"], "a json default database sandbox\n",
            "{value}"
        );
        if sandbox {
            assert_eq!(
                value["diagnostics"][0]["message"],
                "sandbox enabled for inline code (allow_network=false)",
                "{value}"
            );
        }
    }
}

#[test]
fn actual_credentials_are_still_redacted_in_output_and_errors() {
    let root = TempDir::new().unwrap();
    let output = command(&root)
        .env("AWS_ACCESS_KEY_ID", "aws-access-credential")
        .env("AWS_BEARER_TOKEN_BEDROCK", "bedrock-private-value")
        .env("AWS_SECRET_ACCESS_KEY", "long-private-value")
        .env("AWS_SESSION_TOKEN", "aws-session-credential")
        .env("UV_INDEX_PRIVATE_PASSWORD", "index-password-value")
        .args(["--format=json", "run", "-c", "print('x prefixlong-private-valuesuffix aws-access-credential aws-session-credential index-password-value bedrock-private-value'); raise ValueError('long-private-value')"])
        .output().unwrap();
    assert!(!output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["detail"]["stdout"],
        "<redacted> prefix<redacted>suffix <redacted> <redacted> <redacted> <redacted>\n",
        "{value}"
    );
    for secret in [
        "long-private-value",
        "bedrock-private-value",
        "aws-access-credential",
        "aws-session-credential",
        "index-password-value",
    ] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    }
}

#[test]
fn mcp_redaction_preserves_normal_stdout_and_masks_short_credentials() {
    let root = TempDir::new().unwrap();
    std::fs::write(root.path().join("pyproject.toml"), "[tool.pybun.mcp.policy]\nrequire_sandbox=false\ndefault_sandbox=false\nallow_network=true\nmax_execution_time_s=0\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .current_dir(root.path())
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_HISTORY", "0")
        .env("PYBUN_HOME", root.path().join("home"))
        .env("PYBUN_AUDIT_LOG", root.path().join("audit.jsonl"))
        .env("AWS_PROFILE", "default")
        .env("AWS_PAGER", "a")
        .env("AWS_DEFAULT_OUTPUT", "json")
        .env("SECRET_API_KEY", "x")
        .args(["mcp", "serve", "--stdio", "--allow-unsafe-no-sandbox"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    writeln!(input, "{}", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pybun_run","arguments":{"code":"print('a json default database sandbox x')","unsafe_no_sandbox":true}}})).unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    let value: Value =
        serde_json::from_str(reply["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        value["stdout"], "a json default database sandbox <redacted>\n",
        "{reply}"
    );
    assert_eq!(value["status"], "success", "{reply}");
}
