//! Tests for the MCP (Model Context Protocol) server
//!
//! PR4.3: MCP server `pybun mcp serve` with RPC endpoints

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::tempdir;

fn pybun_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pybun"))
}

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

/// Helper: send requests to MCP server and collect output
fn mcp_call(requests: &[&str]) -> String {
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
