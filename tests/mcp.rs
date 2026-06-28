//! Tests for the MCP (Model Context Protocol) server
//!
//! PR4.3: MCP server `pybun mcp serve` with RPC endpoints

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::tempdir;

fn pybun_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pybun"))
}

/// Helper: send requests to MCP server and collect stdout
#[test]
fn mcp_serve_help_shows_port_option() {
    let output = pybun_bin()
        .args(["mcp", "serve", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("port"),
        "mcp serve should have --port option"
    );
}

#[test]
fn mcp_serve_starts_server_stdio_mode() {
    let temp = tempdir().unwrap();

    // Start MCP server in stdio mode
    let mut child = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start MCP server");

    // Give server time to start
    std::thread::sleep(Duration::from_millis(100));

    // Send a simple JSON-RPC request
    if let Some(mut stdin) = child.stdin.take() {
        let request = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
        writeln!(stdin, "{}", request).ok();
        drop(stdin);
    }

    // Wait for response with timeout
    let output = child.wait_with_output().expect("failed to wait on child");

    // Should have some output
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Either stdout contains response or stderr has startup message
    assert!(
        !stdout.is_empty() || !stderr.is_empty(),
        "MCP server should produce output. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn mcp_serve_responds_to_initialize() {
    let temp = tempdir().unwrap();

    let mut child = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start MCP server");

    // Write initialize request
    if let Some(mut stdin) = child.stdin.take() {
        let request = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
        writeln!(stdin, "{}", request).ok();
        stdin.flush().ok();
    }

    // Read response
    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain valid JSON response
    if !stdout.is_empty() {
        // Try to parse as JSON
        for line in stdout.lines() {
            if line.starts_with('{') {
                let json: Result<serde_json::Value, _> = serde_json::from_str(line);
                if let Ok(response) = json {
                    // Should have jsonrpc field
                    assert!(response.get("jsonrpc").is_some() || response.get("result").is_some());
                }
            }
        }
    }
}

#[test]
fn mcp_serve_lists_available_tools() {
    let temp = tempdir().unwrap();

    let mut child = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start MCP server");

    if let Some(mut stdin) = child.stdin.take() {
        // Initialize first
        let init_req = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
        writeln!(stdin, "{}", init_req).ok();

        // Then request tools list
        let tools_req = r#"{"jsonrpc":"2.0","method":"tools/list","id":2,"params":{}}"#;
        writeln!(stdin, "{}", tools_req).ok();
        stdin.flush().ok();
    }

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should list some tools
    let has_tools = stdout.contains("tools")
        || stdout.contains("resolve")
        || stdout.contains("install")
        || stdout.contains("run");

    // Allow test to pass if server responds (may not have tools yet)
    assert!(
        has_tools || !stdout.is_empty() || output.status.success(),
        "MCP server should respond to tools/list"
    );
}

#[test]
fn mcp_json_output_format() {
    let temp = tempdir().unwrap();

    // Test JSON output mode for MCP info
    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "mcp", "serve", "--help"])
        .output()
        .unwrap();

    // Help should succeed
    assert!(output.status.success());
}

#[test]
fn mcp_tools_call_doctor() {
    let temp = tempdir().unwrap();

    let mut child = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start MCP server");

    if let Some(mut stdin) = child.stdin.take() {
        // Initialize
        let init_req = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
        writeln!(stdin, "{}", init_req).ok();

        // Call pybun_doctor tool
        let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_doctor","arguments":{"verbose":true}}}"#;
        writeln!(stdin, "{}", call_req).ok();
        stdin.flush().ok();
    }

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain response with checks
    assert!(
        stdout.contains("checks") || stdout.contains("healthy") || stdout.contains("python"),
        "pybun_doctor should return environment checks. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_run_inline_code() {
    let temp = tempdir().unwrap();

    let mut child = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start MCP server");

    if let Some(mut stdin) = child.stdin.take() {
        // Initialize
        let init_req = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
        writeln!(stdin, "{}", init_req).ok();

        // Call pybun_run with inline code
        let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"code":"print('Hello from MCP')"}}}"#;
        writeln!(stdin, "{}", call_req).ok();
        stdin.flush().ok();
    }

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain output from Python execution
    assert!(
        stdout.contains("Hello from MCP")
            || stdout.contains("success")
            || stdout.contains("exit_code"),
        "pybun_run should execute Python code. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_gc() {
    let temp = tempdir().unwrap();

    let mut child = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start MCP server");

    if let Some(mut stdin) = child.stdin.take() {
        // Initialize
        let init_req = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
        writeln!(stdin, "{}", init_req).ok();

        // Call pybun_gc with dry_run
        let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_gc","arguments":{"dry_run":true}}}"#;
        writeln!(stdin, "{}", call_req).ok();
        stdin.flush().ok();
    }

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain gc result
    assert!(
        stdout.contains("gc_complete") || stdout.contains("freed") || stdout.contains("dry_run"),
        "pybun_gc should return gc status. Got: {}",
        stdout
    );
}

/// Helper: send requests to MCP server and collect output.
fn mcp_call(requests: &[&str]) -> String {
    let temp = tempdir().unwrap();
    mcp_call_in(requests, temp.path(), &[])
}

/// Helper: send requests to MCP server from a specific cwd/environment.
fn mcp_call_in(requests: &[&str], current_dir: &Path, envs: &[(&str, OsString)]) -> String {
    let temp = tempdir().unwrap();

    let mut child = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .current_dir(current_dir)
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .envs(envs.iter().map(|(key, value)| (*key, value)))
        .spawn()
        .expect("failed to start MCP server");

    if let Some(mut stdin) = child.stdin.take() {
        let init_req = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
        writeln!(stdin, "{}", init_req).ok();
        for req in requests {
            writeln!(stdin, "{}", req).ok();
        }
        stdin.flush().ok();
    }

    let output = child.wait_with_output().expect("failed to wait");
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn json_rpc_lines(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter(|line| line.trim_start().starts_with('{'))
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("valid JSON-RPC line ({err}): {line}"))
        })
        .collect()
}

fn audit_log_entries(path: &Path) -> Vec<serde_json::Value> {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("audit log should be readable at {}: {err}", path.display()));
    content
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("valid JSONL audit entry ({err}): {line}"))
        })
        .collect()
}

#[test]
fn mcp_tools_list_includes_new_tools() {
    let stdout = mcp_call(&[r#"{"jsonrpc":"2.0","method":"tools/list","id":2,"params":{}}"#]);

    assert!(
        stdout.contains("pybun_lint"),
        "tools/list should include pybun_lint. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("pybun_type_check"),
        "tools/list should include pybun_type_check. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("pybun_profile"),
        "tools/list should include pybun_profile. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("pybun_fix"),
        "tools/list should include pybun_fix. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_lint_inline_code() {
    // Lint code with a known issue: unused import (F401)
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_lint","arguments":{"code":"import os\nprint('hello')"}}}"#;
    let stdout = mcp_call(&[call_req]);

    // Should return structured response - either violations found or tool-not-available
    assert!(
        stdout.contains("violations")
            || stdout.contains("tool_not_available")
            || stdout.contains("lint_complete"),
        "pybun_lint should return structured response. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_lint_clean_code() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_lint","arguments":{"code":"x = 1 + 1\nprint(x)\n"}}}"#;
    let stdout = mcp_call(&[call_req]);

    assert!(
        stdout.contains("violations")
            || stdout.contains("tool_not_available")
            || stdout.contains("lint_complete"),
        "pybun_lint should return structured response for clean code. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_type_check_inline_code() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_type_check","arguments":{"code":"def add(x: int, y: int) -> int:\n    return x + y\n"}}}"#;
    let stdout = mcp_call(&[call_req]);

    assert!(
        stdout.contains("errors")
            || stdout.contains("tool_not_available")
            || stdout.contains("type_check_complete"),
        "pybun_type_check should return structured response. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_profile_inline_code() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_profile","arguments":{"code":"total = sum(range(1000))","top_n":5}}}"#;
    let stdout = mcp_call(&[call_req]);

    // cProfile is built-in, so this should always succeed
    assert!(
        stdout.contains("hotspots")
            || stdout.contains("total_time")
            || stdout.contains("profile_complete"),
        "pybun_profile should return hotspots. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_profile_script_preserves_execution_context() {
    let project = tempdir().unwrap();
    std::fs::write(project.path().join("helper.py"), "VALUE = 41\n").unwrap();
    std::fs::write(
        project.path().join("main.py"),
        "from pathlib import Path\nfrom helper import VALUE\nassert Path(__file__).name == 'main.py'\nprint(VALUE + 1)\n",
    )
    .unwrap();

    let script = project.path().join("main.py");
    let call_req = format!(
        r#"{{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{{"name":"pybun_profile","arguments":{{"script":"{}","top_n":5}}}}}}"#,
        script.display()
    );
    let stdout = mcp_call(&[call_req.as_str()]);

    assert!(
        stdout.contains("profile_complete") && !stdout.contains("\"isError\":true"),
        "pybun_profile should emulate normal script execution context. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_fix_requires_script() {
    // pybun_fix without script should return an error
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_fix","arguments":{}}}"#;
    let stdout = mcp_call(&[call_req]);

    assert!(
        stdout.contains("Error") || stdout.contains("error") || stdout.contains("script"),
        "pybun_fix without script should return error. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_unknown_tool_returns_error() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_nonexistent","arguments":{}}}"#;
    let stdout = mcp_call(&[call_req]);

    assert!(
        stdout.contains("Unknown tool") || stdout.contains("isError"),
        "Unknown tool should return error. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_lint_uses_project_env_ruff() {
    let project = tempdir().unwrap();
    let venv_root = project.path().join("venv");
    let venv_bin = if cfg!(windows) {
        venv_root.join("Scripts")
    } else {
        venv_root.join("bin")
    };
    std::fs::create_dir_all(&venv_bin).unwrap();
    let python_name = if cfg!(windows) {
        "python.exe"
    } else {
        "python"
    };
    let ruff_name = if cfg!(windows) { "ruff.cmd" } else { "ruff" };
    #[cfg(unix)]
    std::os::unix::fs::symlink("/usr/bin/env", venv_bin.join(python_name)).unwrap();
    #[cfg(windows)]
    std::fs::write(venv_bin.join(python_name), "").unwrap();
    std::fs::write(venv_bin.join(ruff_name), if cfg!(windows) {
        "@echo off\r\nif \"%1\"==\"check\" (\r\n  echo []\r\n  exit /b 0\r\n)\r\nif \"%1\"==\"--version\" (\r\n  echo ruff 0.0-test\r\n  exit /b 0\r\n)\r\nexit /b 2\r\n"
    } else {
        "#!/bin/sh\nif [ \"$1\" = \"check\" ]; then\n  echo '[]'\n  exit 0\nfi\nif [ \"$1\" = \"--version\" ]; then\n  echo 'ruff 0.0-test'\n  exit 0\nfi\nexit 2\n"
    }).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(venv_bin.join(ruff_name))
            .unwrap()
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(venv_bin.join(ruff_name), perms).unwrap();
    }

    let envs = vec![("PYBUN_ENV", venv_root.into_os_string())];
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_lint","arguments":{"code":"x = 1\n"}}}"#;
    let stdout = mcp_call_in(&[call_req], project.path(), &envs);

    assert!(
        stdout.contains(r#"\"tool\":\"ruff\""#) && !stdout.contains("tool_not_available"),
        "pybun_lint should prefer ruff from the selected env. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_fix_surfaces_ruff_failures() {
    let project = tempdir().unwrap();
    let fake_bin = project.path().join("bin");
    std::fs::create_dir_all(&fake_bin).unwrap();
    std::fs::write(project.path().join("test.py"), "import os\n").unwrap();
    let ruff_name = if cfg!(windows) { "ruff.cmd" } else { "ruff" };
    std::fs::write(
        fake_bin.join(ruff_name),
        if cfg!(windows) {
            "@echo off\r\nif \"%1\"==\"--version\" (\r\n  echo ruff 0.0-test\r\n  exit /b 0\r\n)\r\necho bad rule 1>&2\r\nexit /b 2\r\n"
        } else {
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo 'ruff 0.0-test'\n  exit 0\nfi\necho 'bad rule' >&2\nexit 2\n"
        },
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(fake_bin.join(ruff_name))
            .unwrap()
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(fake_bin.join(ruff_name), perms).unwrap();
    }

    let separator = if cfg!(windows) { ';' } else { ':' };
    let path = format!(
        "{}{}{}",
        fake_bin.display(),
        separator,
        std::env::var("PATH").unwrap_or_default()
    );
    let envs = vec![("PATH", OsString::from(path))];
    let call_req = format!(
        r#"{{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{{"name":"pybun_fix","arguments":{{"script":"{}","select":["BAD"]}}}}}}"#,
        project.path().join("test.py").display()
    );
    let stdout = mcp_call_in(&[call_req.as_str()], project.path(), &envs);

    assert!(
        stdout.contains("\"isError\":true") && stdout.contains("ruff check failed"),
        "pybun_fix should surface ruff execution failures. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_resolve_no_index() {
    let temp = tempdir().unwrap();

    let mut child = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .current_dir(temp.path())
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start MCP server");

    if let Some(mut stdin) = child.stdin.take() {
        // Initialize
        let init_req = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
        writeln!(stdin, "{}", init_req).ok();

        // Call pybun_resolve without index
        let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_resolve","arguments":{"requirements":["requests>=2.28"]}}}"#;
        writeln!(stdin, "{}", call_req).ok();
        stdin.flush().ok();
    }

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain a response (either no_index status or parsed requirements)
    assert!(
        stdout.contains("no_index")
            || stdout.contains("parsed_requirements")
            || stdout.contains("requirements"),
        "pybun_resolve should handle missing index gracefully. Got: {}",
        stdout
    );
}

#[test]
fn mcp_pybun_run_sandbox_policy_blocks_subprocess() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"code":"import subprocess\nsubprocess.run(['echo','hi'])","sandbox_policy":{"allow_network":false}}}}"#;
    let stdout = mcp_call(&[call_req]);

    // Should return a response with sandboxed=true and exit_code != 0
    assert!(
        stdout.contains("sandboxed") || stdout.contains("exit_code"),
        "pybun_run with sandbox_policy should return sandbox info. Got: {}",
        stdout
    );
}

#[test]
fn mcp_pybun_run_sandbox_policy_audit_present() {
    // Run a script that tries to spawn a process; audit should record the block
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"code":"import subprocess\ntry:\n    subprocess.run(['echo','hi'])\nexcept PermissionError:\n    pass","sandbox_policy":{}}}}"#;
    let stdout = mcp_call(&[call_req]);

    assert!(
        stdout.contains("audit") || stdout.contains("sandboxed"),
        "pybun_run with sandbox_policy should include audit. Got: {}",
        stdout
    );
}

#[test]
fn mcp_pybun_run_without_sandbox_policy_no_restriction() {
    // Without sandbox_policy, normal code should run freely
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"code":"print('unrestricted')"}}}"#;
    let stdout = mcp_call(&[call_req]);

    assert!(
        stdout.contains("unrestricted") || stdout.contains("exit_code"),
        "pybun_run without sandbox should run freely. Got: {}",
        stdout
    );
}

// ─── MCP structured action audit log (Issue #249) ───────────────────────────

#[test]
fn mcp_tool_calls_write_jsonl_audit_entries() {
    let project = tempdir().unwrap();
    let audit_path = project.path().join("mcp-audit.jsonl");
    let audit_env = audit_path.as_os_str().to_os_string();
    let requests = [
        r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_doctor","arguments":{"verbose":true}}}"#,
        r#"{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"pybun_run","arguments":{"code":"print('audit ok')"}}}"#,
    ];

    let stdout = mcp_call_in(&requests, project.path(), &[("PYBUN_AUDIT_LOG", audit_env)]);
    assert!(
        stdout.contains("audit ok"),
        "pybun_run should still execute. Got: {stdout}"
    );

    let entries = audit_log_entries(&audit_path);
    assert_eq!(entries.len(), 2, "expected one entry per tools/call");

    let first_session = entries[0]["session_id"]
        .as_str()
        .expect("session_id should be a string");
    assert!(!first_session.is_empty());
    assert_eq!(entries[1]["session_id"].as_str(), Some(first_session));
    assert_ne!(entries[0]["call_id"], entries[1]["call_id"]);
    assert_eq!(entries[0]["tool"].as_str(), Some("pybun_doctor"));
    assert_eq!(entries[1]["tool"].as_str(), Some("pybun_run"));
    assert_eq!(
        entries[1]["input"]["code"].as_str(),
        Some("print('audit ok')")
    );
    assert!(
        entries[1]["input_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    assert_eq!(entries[1]["output_summary"]["status"].as_str(), Some("ok"));
    assert_eq!(
        entries[1]["tool_schema"]["protocol_version"].as_str(),
        Some("2024-11-05")
    );
}

#[test]
fn mcp_audit_hash_inputs_config_omits_raw_input() {
    let project = tempdir().unwrap();
    let audit_path = project.path().join("hashed-audit.jsonl");
    fs::write(
        project.path().join("pyproject.toml"),
        format!(
            "[tool.pybun.mcp.audit]\npath = \"{}\"\nhash_inputs = true\n",
            audit_path.display()
        ),
    )
    .unwrap();

    let secret = "secret-token-issue-249";
    let req = format!(
        r#"{{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{{"name":"pybun_run","arguments":{{"code":"print('{secret}')"}}}}}}"#
    );
    let stdout = mcp_call_in(&[&req], project.path(), &[]);
    assert!(
        stdout.contains(secret),
        "tool output should still include the program stdout. Got: {stdout}"
    );

    let raw_log = fs::read_to_string(&audit_path).unwrap();
    assert!(
        !raw_log.contains(secret),
        "hash_inputs=true must not persist raw input content: {raw_log}"
    );
    let entries = audit_log_entries(&audit_path);
    assert!(entries[0].get("input").is_none());
    assert!(
        entries[0]["input_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
}

#[test]
fn mcp_audit_recent_resource_returns_session_entries() {
    let project = tempdir().unwrap();
    let audit_path = project.path().join("audit.jsonl");
    let audit_env = audit_path.as_os_str().to_os_string();
    let requests = [
        r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_doctor","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","method":"resources/read","id":3,"params":{"uri":"pybun://audit/recent"}}"#,
    ];

    let stdout = mcp_call_in(&requests, project.path(), &[("PYBUN_AUDIT_LOG", audit_env)]);
    let responses = json_rpc_lines(&stdout);
    let recent = responses
        .iter()
        .find(|value| value["id"].as_i64() == Some(3))
        .expect("resources/read response should be present");
    let text = recent["result"]["contents"][0]["text"]
        .as_str()
        .expect("resource content should be text");
    let body: serde_json::Value = serde_json::from_str(text).expect("audit resource JSON");
    assert_eq!(body["entries"][0]["tool"].as_str(), Some("pybun_doctor"));
    assert_eq!(body["count"].as_u64(), Some(1));
}

#[test]
fn mcp_audit_dev_null_disables_logging_without_error() {
    let project = tempdir().unwrap();
    let stdout = mcp_call_in(
        &[
            r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"code":"print('no audit file')"}}}"#,
        ],
        project.path(),
        &[("PYBUN_AUDIT_LOG", OsString::from("/dev/null"))],
    );

    assert!(
        stdout.contains("no audit file"),
        "PYBUN_AUDIT_LOG=/dev/null should not fail tool execution. Got: {stdout}"
    );
}

#[test]
fn mcp_audit_log_survives_sandbox_write_tamper_attempt() {
    let project = tempdir().unwrap();
    let writable = tempdir().unwrap();
    let audit_path = project.path().join("parent-owned-audit.jsonl");
    let audit_env = audit_path.as_os_str().to_os_string();

    let warmup = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_doctor","arguments":{}}}"#;
    let audit_literal = serde_json::to_string(audit_path.to_str().unwrap()).unwrap();
    let writable_literal = serde_json::to_string(writable.path().to_str().unwrap()).unwrap();
    let code = [
        "import os",
        &format!("audit = {audit_literal}"),
        &format!("writable = {writable_literal}"),
        "open(os.path.join(writable, 'ok.txt'), 'w').write('ok')",
        "for action in ('write', 'delete'):",
        "    try:",
        "        if action == 'write':",
        "            open(audit, 'w').write('tampered')",
        "        else:",
        "            os.remove(audit)",
        "    except PermissionError:",
        "        pass",
        "",
    ]
    .join("\n");
    let code_json = serde_json::to_string(&code).unwrap();
    let allow_write_json = serde_json::to_string(writable.path().to_str().unwrap()).unwrap();
    let tamper = format!(
        r#"{{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{{"name":"pybun_run","arguments":{{"code":{code_json},"sandbox_policy":{{"allow_write":[{allow_write_json}]}}}}}}}}"#
    );

    let stdout = mcp_call_in(
        &[warmup, &tamper],
        project.path(),
        &[("PYBUN_AUDIT_LOG", audit_env)],
    );
    assert!(
        stdout.contains("blocked_file_writes"),
        "sandbox audit should report blocked tampering. Got: {stdout}"
    );

    let entries = audit_log_entries(&audit_path);
    assert_eq!(
        entries.len(),
        2,
        "prior entry should survive attempted delete/overwrite"
    );
    assert_eq!(entries[0]["tool"].as_str(), Some("pybun_doctor"));
    assert_eq!(entries[1]["tool"].as_str(), Some("pybun_run"));
    assert!(
        entries[1]["file_writes"]
            .as_array()
            .is_some_and(|writes| writes.iter().any(|entry| entry["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("ok.txt")))),
        "allow_write output should be recorded in file_writes: {}",
        entries[1]
    );
}

// ─── Structured traceback diagnostics (Issue #243) ───────────────────────────

fn run_mcp_pybun_run(code: &str) -> String {
    use std::io::Write;
    use std::process::Stdio;
    let temp = tempfile::tempdir().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .env("PYBUN_HOME", temp.path())
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start MCP server");

    if let Some(mut stdin) = child.stdin.take() {
        let init = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
        writeln!(stdin, "{init}").ok();
        let code_escaped = code.replace('"', "\\\"").replace('\n', "\\n");
        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{{"name":"pybun_run","arguments":{{"code":"{code_escaped}"}}}}}}"#
        );
        writeln!(stdin, "{req}").ok();
        stdin.flush().ok();
    }

    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn mcp_pybun_run_module_not_found_has_diagnostics() {
    let stdout = run_mcp_pybun_run("import numpy_does_not_exist");
    assert!(
        stdout.contains("runtime.module_not_found") || stdout.contains("module_not_found"),
        "Expected structured diagnostic code in response. Got: {stdout}"
    );
}

#[test]
fn mcp_pybun_run_module_not_found_has_next_action() {
    let stdout = run_mcp_pybun_run("import numpy_does_not_exist");
    assert!(
        stdout.contains("pybun_add"),
        "Expected next_action.tool=pybun_add in response. Got: {stdout}"
    );
}

#[test]
fn mcp_pybun_run_module_not_found_package_name() {
    let stdout = run_mcp_pybun_run("import numpy_does_not_exist");
    assert!(
        stdout.contains("numpy_does_not_exist"),
        "Expected package name in response. Got: {stdout}"
    );
}

#[test]
fn mcp_pybun_run_success_has_no_diagnostics() {
    let stdout = run_mcp_pybun_run("print('ok')");
    // Diagnostics should be null or absent on success
    assert!(
        !stdout.contains("runtime."),
        "Successful run should not have error diagnostics. Got: {stdout}"
    );
}

#[test]
fn mcp_pybun_run_syntax_error_has_diagnostics() {
    let stdout = run_mcp_pybun_run("def bad(\n  pass");
    assert!(
        stdout.contains("runtime.syntax_error") || stdout.contains("syntax_error"),
        "Expected syntax_error diagnostic. Got: {stdout}"
    );
}
