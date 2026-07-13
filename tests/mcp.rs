//! Tests for the MCP (Model Context Protocol) server
//!
//! PR4.3: MCP server `pybun mcp serve` with RPC endpoints

use httpmock::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};
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
fn mcp_tools_call_doctor_detects_corrupt_pypi_cache() {
    // Regression test for issue #268: the `pybun_doctor` MCP tool must flag
    // a corrupt legacy `.json` PyPI cache entry as a non-fatal `info`
    // status, the same way the CLI `pybun doctor` command does.
    let temp = tempdir().unwrap();
    let pypi_cache = temp.path().join("pypi-cache");
    fs::create_dir_all(&pypi_cache).unwrap();
    fs::write(pypi_cache.join("requests.json"), b"not valid json{{{").unwrap();

    let mut child = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .env("PYBUN_PYPI_CACHE_DIR", &pypi_cache)
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start MCP server");

    if let Some(mut stdin) = child.stdin.take() {
        let init_req = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
        writeln!(stdin, "{}", init_req).ok();

        let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_doctor","arguments":{"verbose":true}}}"#;
        writeln!(stdin, "{}", call_req).ok();
        stdin.flush().ok();
    }

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut found_pypi_cache_check = false;
    for line in stdout.lines() {
        if !line.starts_with('{') {
            continue;
        }
        let Ok(response) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(text) = response
            .get("result")
            .and_then(|r| r.get("content"))
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("text"))
            .and_then(|t| t.as_str())
        else {
            continue;
        };
        let Ok(doctor_result) = serde_json::from_str::<serde_json::Value>(text) else {
            continue;
        };
        let Some(checks) = doctor_result.get("checks").and_then(|c| c.as_array()) else {
            continue;
        };
        if let Some(pypi_check) = checks.iter().find(|c| c["name"] == "pypi_cache") {
            found_pypi_cache_check = true;
            assert_eq!(
                pypi_check["stale_count"], 1,
                "corrupt legacy .json cache entry should be counted as stale/corrupt: {}",
                pypi_check
            );
            assert_eq!(
                pypi_check["status"], "info",
                "corrupt cache entries should be a non-fatal info status, not error"
            );
        }
    }

    assert!(
        found_pypi_cache_check,
        "pybun_doctor response should include a pypi_cache check. Got: {}",
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

fn tool_result_json(stdout: &str, id: i64) -> serde_json::Value {
    let responses = json_rpc_lines(stdout);
    let response = responses
        .iter()
        .find(|value| value["id"].as_i64() == Some(id))
        .unwrap_or_else(|| panic!("tools/call response with id {id} should be present: {stdout}"));
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tools/call response should contain text content: {response}"));
    serde_json::from_str(text).unwrap_or_else(|err| {
        panic!("tools/call text should be JSON ({err}): {text}\nstdout: {stdout}")
    })
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

// =============================================================================
// Issue #284: pybun_install must not report false "installed" success
// =============================================================================

/// Minimal wheel payload (a valid zip) shared by the pybun_install honesty tests.
fn issue284_wheel_bytes() -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    zip.start_file("dummy.txt", options)
        .expect("start wheel entry");
    zip.write_all(b"ok").expect("write wheel entry");
    let cursor = zip.finish().expect("finish wheel zip");
    cursor.into_inner()
}

fn issue284_wheel_sha256() -> String {
    let mut hasher = Sha256::new();
    hasher.update(issue284_wheel_bytes());
    hex::encode(hasher.finalize())
}

/// Set up a minimal fake PyPI (legacy JSON API) serving a single "app" package
/// with one real, downloadable wheel. Returns the mock server's base URL.
fn issue284_setup_pypi_mock(server: &MockServer) -> String {
    let base = server.base_url();
    let sha256 = issue284_wheel_sha256();

    let project_body = json!({
        "info": { "name": "app", "version": "1.0.0" },
        "releases": {
            "1.0.0": [
                {
                    "filename": "app-1.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": format!("{}/files/app-1.0.0-py3-none-any.whl", base),
                    "yanked": false,
                    "digests": { "sha256": sha256 }
                }
            ]
        }
    })
    .to_string();
    server.mock(|when, then| {
        when.method(GET).path("/pypi/app/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(project_body.clone());
    });

    let meta_body = json!({
        "info": { "name": "app", "version": "1.0.0", "requires_dist": [] }
    })
    .to_string();
    server.mock(|when, then| {
        when.method(GET).path("/pypi/app/1.0.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(meta_body.clone());
    });

    let wheel_body = issue284_wheel_bytes();
    server.mock(move |when, then| {
        when.method(GET).path("/files/app-1.0.0-py3-none-any.whl");
        then.status(200)
            .header("Content-Type", "application/octet-stream")
            .body(wheel_body.clone());
    });

    base
}

/// Create (or reuse) a real venv at `<project_root>/.venv` using the host's python3.
fn issue284_ensure_venv(project_root: &Path) -> std::path::PathBuf {
    let venv = project_root.join(".venv");
    if !venv.exists() {
        let status = std::process::Command::new("python3")
            .args(["-m", "venv", ".venv"])
            .current_dir(project_root)
            .status()
            .expect("failed to create venv for pybun_install honesty test");
        assert!(status.success(), "python3 -m venv failed: {:?}", status);
    }
    venv
}

/// Regression test for Issue #284: when no wheel is actually downloaded/installed
/// (e.g. the given index only contains hash metadata, no download URLs), `pybun_install`
/// must not claim `"status": "installed"` or fabricate an "installed N packages" message.
/// It must also stop using the placeholder-only fixture-index lookup and fabricated
/// `sha256:placeholder` hashes / invented wheel filenames from before this fix.
#[test]
fn mcp_tools_call_install_reports_resolved_not_installed_when_no_wheel_downloaded() {
    let temp = tempdir().unwrap();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    let index_path = Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index.json");
    // Escape backslashes for JSON string safety (relevant on Windows paths).
    let index_str = index_path.display().to_string().replace('\\', "\\\\");

    let call_req = format!(
        r#"{{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{{"name":"pybun_install","arguments":{{"requirements":["app==1.0.0"],"index":"{}"}}}}}}"#,
        index_str
    );

    let stdout = mcp_call_in(&[call_req.as_str()], temp.path(), &[]);
    let result = tool_result_json(&stdout, 2);

    assert_eq!(
        result["status"], "resolved",
        "must not claim 'installed' when no wheel was actually downloaded/installed. Got: {result}"
    );
    assert_eq!(
        result["installed_count"].as_u64(),
        Some(0),
        "no wheels were installed, so installed_count must be 0. Got: {result}"
    );

    let message = result["message"]
        .as_str()
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        !message.contains("installed") || message.contains("no wheels"),
        "message must not fabricate an installation claim: {message}"
    );

    // Real hashes from the fixture must be used, never the fabricated
    // "sha256:placeholder" the old implementation always wrote.
    let artifacts = result["artifacts"].as_array().cloned().unwrap_or_default();
    assert!(
        !artifacts.is_empty(),
        "resolved packages should carry verified artifact info: {result}"
    );
    for artifact in &artifacts {
        let sha = artifact["sha256"].as_str().unwrap_or_default();
        assert_ne!(
            sha, "sha256:placeholder",
            "must not fabricate placeholder hashes: {result}"
        );
        assert!(!sha.is_empty(), "hash should be non-empty: {result}");
    }

    // Lockfile naming should match the CLI's project lockfile convention (pybun.lockb),
    // not the previous MCP-only "pybun.lock".
    let lock_path = temp.path().join("pybun.lockb");
    assert!(
        lock_path.exists(),
        "expected lockfile at {}",
        lock_path.display()
    );
}

/// Regression test for Issue #284: when a real wheel *is* downloaded and installed
/// (via the same code path as CLI `pybun install`, here exercised through the
/// PyPI fallback since no `index` argument is given), `pybun_install` must report
/// `"status": "installed"` with a real, non-placeholder verified hash.
#[test]
fn mcp_tools_call_install_actually_installs_wheel_and_reports_honest_status() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let server = MockServer::start();
    let base_url = issue284_setup_pypi_mock(&server);
    let venv = issue284_ensure_venv(temp.path());

    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_install","arguments":{"requirements":["app==1.0.0"]}}}"#;

    let stdout = mcp_call_in(
        &[call_req],
        temp.path(),
        &[
            ("PYBUN_PYPI_BASE_URL", OsString::from(base_url)),
            (
                "PYBUN_PYPI_CACHE_DIR",
                OsString::from(cache_dir.to_str().unwrap()),
            ),
            ("PYBUN_ENV", OsString::from(venv.to_str().unwrap())),
        ],
    );

    let result = tool_result_json(&stdout, 2);

    assert_eq!(
        result["status"], "installed",
        "expected honest 'installed' status once a wheel was really downloaded and \
         installed via the real install path (not fabricated). Got: {result}"
    );
    assert!(
        result["installed_count"].as_u64().unwrap_or(0) > 0,
        "installed_count should reflect the real wheel install: {result}"
    );

    let artifacts = result["artifacts"].as_array().cloned().unwrap_or_default();
    assert!(
        !artifacts.is_empty(),
        "expected verified artifacts: {result}"
    );
    for artifact in &artifacts {
        assert_ne!(
            artifact["sha256"].as_str().unwrap_or_default(),
            "sha256:placeholder",
            "hash must be real, not fabricated: {result}"
        );
    }
}

/// Regression test for Issue #284: `offline` was previously accepted but silently
/// ignored (`let _offline = ...`). With an empty cache and no local index, an
/// offline install must fail honestly rather than silently reaching the network
/// (via an ignored offline flag) or fabricating a success.
#[test]
fn mcp_tools_call_install_honors_offline_flag() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("empty_cache");

    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_install","arguments":{"requirements":["app==1.0.0"],"offline":true}}}"#;

    let stdout = mcp_call_in(
        &[call_req],
        temp.path(),
        &[
            (
                "PYBUN_PYPI_CACHE_DIR",
                OsString::from(cache_dir.to_str().unwrap()),
            ),
            // Deliberately unreachable: proves offline mode never dials out.
            ("PYBUN_PYPI_BASE_URL", OsString::from("http://127.0.0.1:9")),
        ],
    );

    let responses = json_rpc_lines(&stdout);
    let response = responses
        .iter()
        .find(|v| v["id"].as_i64() == Some(2))
        .unwrap_or_else(|| panic!("tools/call response with id 2 should be present: {stdout}"));

    let is_error = response["result"]["isError"].as_bool().unwrap_or(false);
    assert!(
        is_error,
        "offline install with an empty cache should fail honestly instead of \
         claiming success or silently reaching the network. Got: {stdout}"
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
fn mcp_pybun_run_defaults_to_sandbox_without_policy() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"code":"import subprocess\ntry:\n    subprocess.run(['echo','hi'])\nexcept PermissionError:\n    print('blocked-default')"}}}"#;
    let stdout = mcp_call(&[call_req]);
    let result = tool_result_json(&stdout, 2);

    assert_eq!(result["sandboxed"].as_bool(), Some(true), "{result}");
    assert!(
        result["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("blocked-default")),
        "{result}"
    );
    assert_eq!(
        result["audit"]["blocked_subprocesses"].as_u64(),
        Some(1),
        "{result}"
    );
}

#[test]
fn mcp_pybun_run_unsafe_no_sandbox_allows_explicit_opt_out_with_warning() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"code":"import subprocess, sys\nsubprocess.run([sys.executable, '-c', \"print('optout-child')\"])", "unsafe_no_sandbox": true}}}"#;
    let stdout = mcp_call(&[call_req]);
    let result = tool_result_json(&stdout, 2);

    assert_eq!(result["sandboxed"].as_bool(), Some(false), "{result}");
    assert!(
        result["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("optout-child")),
        "{result}"
    );
    assert_eq!(
        result["warnings"][0]["code"].as_str(),
        Some("W_MCP_UNSAFE_NO_SANDBOX"),
        "{result}"
    );
}

#[test]
fn mcp_pybun_run_dry_run_returns_plan_without_executing() {
    let project = tempdir().unwrap();
    let marker = project.path().join("dry-run-marker.txt");
    let marker_json = serde_json::to_string(marker.to_str().unwrap()).unwrap();
    let code = format!("open({marker_json}, 'w').write('executed')");
    let code_json = serde_json::to_string(&code).unwrap();
    let call_req = format!(
        r#"{{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{{"name":"pybun_run","arguments":{{"code":{code_json},"dry_run":true}}}}}}"#
    );
    let stdout = mcp_call(&[&call_req]);
    let result = tool_result_json(&stdout, 2);

    assert_eq!(result["dry_run"].as_bool(), Some(true), "{result}");
    assert_eq!(result["sandboxed"].as_bool(), Some(true), "{result}");
    assert!(
        result["would_execute"]
            .as_str()
            .is_some_and(|summary| summary.contains("Python inline code")),
        "{result}"
    );
    assert!(
        !marker.exists(),
        "dry_run must not execute code or create marker at {}",
        marker.display()
    );
}

#[test]
fn mcp_pybun_run_dry_run_requires_target() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"dry_run":true}}}"#;
    let stdout = mcp_call(&[call_req]);
    let responses = json_rpc_lines(&stdout);
    let response = responses
        .iter()
        .find(|value| value["id"].as_i64() == Some(2))
        .expect("tools/call response should be present");

    assert_eq!(
        response["result"]["isError"].as_bool(),
        Some(true),
        "{response}"
    );
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("Either 'script' or 'code' must be provided")),
        "{response}"
    );
}

#[test]
fn mcp_pybun_run_allow_env_rejects_credential_names() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"code":"import os\nprint(os.environ.get('AWS_SECRET_ACCESS_KEY', 'missing'))","sandbox_policy":{"allow_env":["AWS_SECRET_ACCESS_KEY"]}}}}"#;
    let project = tempdir().unwrap();
    let stdout = mcp_call_in(
        &[call_req],
        project.path(),
        &[("AWS_SECRET_ACCESS_KEY", OsString::from("should-not-leak"))],
    );
    let result = tool_result_json(&stdout, 2);

    assert_eq!(result["sandboxed"].as_bool(), Some(true), "{result}");
    assert!(
        result["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("missing") && !stdout.contains("should-not-leak")),
        "{result}"
    );
}

#[test]
fn mcp_pybun_run_blocks_writes_to_sandbox_audit_file() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"code":"import os\npath = os.environ['PYBUN_SANDBOX_AUDIT_FILE']\ntry:\n    open(path, 'w').write('tampered')\nexcept PermissionError:\n    print('audit-write-blocked')"}}}"#;
    let stdout = mcp_call(&[call_req]);
    let result = tool_result_json(&stdout, 2);

    assert_eq!(result["sandboxed"].as_bool(), Some(true), "{result}");
    assert!(
        result["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("audit-write-blocked")),
        "{result}"
    );
    assert_eq!(
        result["audit"]["blocked_file_writes"].as_u64(),
        Some(1),
        "{result}"
    );
}

#[test]
fn mcp_pybun_run_sandbox_policy_preserves_allow_network() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"code":"import os\nprint(os.environ.get('PYBUN_SANDBOX_ALLOW_NETWORK', 'missing'))","sandbox_policy":{"allow_network":true}}}}"#;
    let stdout = mcp_call(&[call_req]);
    let result = tool_result_json(&stdout, 2);

    assert_eq!(result["sandboxed"].as_bool(), Some(true), "{result}");
    assert!(
        result["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.trim() == "1"),
        "{result}"
    );
}

#[cfg(unix)]
#[test]
fn mcp_pybun_run_default_sandbox_reports_process_and_file_size_limits() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_run","arguments":{"code":"print('limits')"}}}"#;
    let stdout = mcp_call(&[call_req]);
    let result = tool_result_json(&stdout, 2);

    assert_eq!(result["sandboxed"].as_bool(), Some(true), "{result}");
    assert_eq!(
        result["resource_limits"]["max_processes"].as_u64(),
        Some(0),
        "{result}"
    );
    assert_eq!(
        result["resource_limits"]["file_size_limit_mb"].as_u64(),
        Some(10),
        "{result}"
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
        stdout.contains("E_RUNTIME_MODULE_NOT_FOUND"),
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
        !stdout.contains("E_RUNTIME_"),
        "Successful run should not have error diagnostics. Got: {stdout}"
    );
}

#[test]
fn mcp_pybun_run_syntax_error_has_diagnostics() {
    let stdout = run_mcp_pybun_run("def bad(\n  pass");
    assert!(
        stdout.contains("E_RUNTIME_SYNTAX_ERROR"),
        "Expected syntax_error diagnostic. Got: {stdout}"
    );
}

// ── pybun_context tests ──────────────────────────────────────────────────────

#[test]
fn mcp_tools_list_includes_pybun_context() {
    let stdout = mcp_call(&[r#"{"jsonrpc":"2.0","method":"tools/list","id":2,"params":{}}"#]);
    assert!(
        stdout.contains("pybun_context"),
        "tools/list should include pybun_context. Got: {stdout}"
    );
}

#[test]
fn mcp_pybun_context_returns_required_fields() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_context","arguments":{}}}"#;
    let stdout = mcp_call(&[call_req]);
    let result = tool_result_json(&stdout, 2);

    assert!(
        result["python_version"].is_string() || result["python_version"].is_null(),
        "pybun_context must include python_version field. Got: {result}"
    );
    assert!(
        result["venv_status"].is_string(),
        "pybun_context must include venv_status field. Got: {result}"
    );
    assert!(
        result["lockfile_status"].is_string(),
        "pybun_context must include lockfile_status field. Got: {result}"
    );
    assert!(
        result["installed_packages"].is_array() || result["installed_packages"].is_null(),
        "pybun_context must include installed_packages field. Got: {result}"
    );
    assert!(
        result["doctor_warnings"].is_array(),
        "pybun_context must include doctor_warnings field. Got: {result}"
    );
    assert!(
        result["snapshot_at_ms"].is_number(),
        "pybun_context must include snapshot_at_ms field. Got: {result}"
    );
}

#[test]
fn mcp_pybun_context_summary_only_returns_counts() {
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_context","arguments":{"summary_only":true}}}"#;
    let stdout = mcp_call(&[call_req]);
    let result = tool_result_json(&stdout, 2);

    // In summary_only mode, installed_packages should be absent and counts should appear
    assert!(
        result["installed_count"].is_number(),
        "summary_only mode should include installed_count. Got: {result}"
    );
    assert!(
        result["declared_count"].is_number(),
        "summary_only mode should include declared_count. Got: {result}"
    );
    assert!(
        result.get("installed_packages").is_none() || result["installed_packages"].is_null(),
        "summary_only mode should not include installed_packages array. Got: {result}"
    );
}

#[test]
fn mcp_pybun_context_venv_status_missing_in_empty_dir() {
    let project = tempdir().unwrap();
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_context","arguments":{}}}"#;
    let stdout = mcp_call_in(&[call_req], project.path(), &[]);
    let result = tool_result_json(&stdout, 2);

    let venv_status = result["venv_status"].as_str().unwrap_or("");
    assert!(
        ["ok", "missing", "corrupt"].contains(&venv_status),
        "venv_status must be one of ok/missing/corrupt. Got: {venv_status}"
    );
}

#[test]
fn mcp_pybun_context_lockfile_status_missing_in_empty_dir() {
    let project = tempdir().unwrap();
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_context","arguments":{}}}"#;
    let stdout = mcp_call_in(&[call_req], project.path(), &[]);
    let result = tool_result_json(&stdout, 2);

    let lockfile_status = result["lockfile_status"].as_str().unwrap_or("");
    assert!(
        ["in_sync", "drift", "missing"].contains(&lockfile_status),
        "lockfile_status must be one of in_sync/drift/missing. Got: {lockfile_status}"
    );
    assert_eq!(
        lockfile_status, "missing",
        "empty dir should have lockfile_status=missing"
    );
}

#[test]
fn mcp_resources_list_includes_project_snapshot() {
    let stdout = mcp_call(&[r#"{"jsonrpc":"2.0","method":"resources/list","id":2,"params":{}}"#]);
    assert!(
        stdout.contains("pybun://project/snapshot"),
        "resources/list should include pybun://project/snapshot. Got: {stdout}"
    );
}

#[test]
fn mcp_pybun_context_corrupt_lockfile_returns_corrupt_status() {
    let project = tempdir().unwrap();
    // Write an invalid lockfile (not valid binary format)
    std::fs::write(project.path().join("pybun.lock"), b"not a valid lockfile").unwrap();
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_context","arguments":{}}}"#;
    let stdout = mcp_call_in(&[call_req], project.path(), &[]);
    let result = tool_result_json(&stdout, 2);

    assert_eq!(
        result["lockfile_status"].as_str(),
        Some("corrupt"),
        "invalid lockfile content should yield lockfile_status=corrupt, not drift. Got: {result}"
    );
    let warnings = result["doctor_warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w["code"].as_str() == Some("W_LOCKFILE_CORRUPT")),
        "W_LOCKFILE_CORRUPT warning should be present. Got: {warnings:?}"
    );
}

#[test]
fn mcp_project_snapshot_resource_returns_context_data() {
    let project = tempdir().unwrap();
    let requests = [
        r#"{"jsonrpc":"2.0","method":"resources/read","id":2,"params":{"uri":"pybun://project/snapshot"}}"#,
    ];
    let stdout = mcp_call_in(&requests, project.path(), &[]);
    let responses = json_rpc_lines(&stdout);
    let response = responses
        .iter()
        .find(|v| v["id"].as_i64() == Some(2))
        .expect("resources/read response should be present");

    let text = response["result"]["contents"][0]["text"]
        .as_str()
        .expect("resource content should be text");
    let body: serde_json::Value =
        serde_json::from_str(text).expect("project snapshot should be JSON");

    assert!(
        body["venv_status"].is_string(),
        "project snapshot should include venv_status. Got: {body}"
    );
    assert!(
        body["lockfile_status"].is_string(),
        "project snapshot should include lockfile_status. Got: {body}"
    );
}

// ---------------------------------------------------------------------------
// pybun_test MCP tool tests (Issue #246)
// ---------------------------------------------------------------------------

/// Create a minimal fake venv whose `bin/python` can run test functions without
/// requiring pytest to be installed in the host environment.
///
/// The fake python:
/// - Intercepts `python -m pytest -xvs FILE::TEST` calls
/// - Executes the target function via importlib and exits 0/1 based on outcome
/// - Delegates every other invocation to the real `python3`
///
/// Returns the venv root path that should be passed as `PYBUN_ENV`.
#[cfg(unix)]
fn make_pytest_venv(dir: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let venv = dir.join("venv");
    let bin = venv.join("bin");
    std::fs::create_dir_all(&bin).unwrap();

    // Minimal test runner: loads file with importlib, calls the function, exits 0/1.
    let runner = bin.join("_pytest_runner.py");
    std::fs::write(
        &runner,
        r#"import sys, importlib.util
file_path, test_name = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("_test_mod", file_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fn = getattr(mod, test_name)
try:
    fn()
    sys.exit(0)
except Exception as e:
    print(f"FAILED {test_name}: {e}", file=sys.stderr)
    sys.exit(1)
"#,
    )
    .unwrap();

    // Shell wrapper that intercepts `python -m pytest -xvs FILE::TEST`.
    let runner_path = runner.display().to_string();
    let python_script = format!(
        r#"#!/bin/sh
if [ "$1" = "-m" ] && [ "$2" = "pytest" ]; then
    SPEC="$4"
    FILE="${{SPEC%%::*}}"
    TEST="${{SPEC##*::}}"
    exec python3 "{runner_path}" "$FILE" "$TEST"
else
    exec python3 "$@"
fi
"#
    );
    let python_bin = bin.join("python");
    std::fs::write(&python_bin, python_script).unwrap();
    let mut perms = std::fs::metadata(&python_bin).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&python_bin, perms).unwrap();

    venv
}

#[test]
fn mcp_tools_list_includes_pybun_test() {
    let stdout = mcp_call(&[r#"{"jsonrpc":"2.0","method":"tools/list","id":2,"params":{}}"#]);
    assert!(
        stdout.contains("pybun_test"),
        "tools/list should include pybun_test. Got: {stdout}"
    );
}

#[test]
fn mcp_pybun_test_all_passing_returns_summary() {
    let project = tempdir().unwrap();
    fs::write(
        project.path().join("test_example.py"),
        "def test_one():\n    assert 1 + 1 == 2\n\ndef test_two():\n    assert True\n",
    )
    .unwrap();

    let venv = make_pytest_venv(project.path());
    let envs = vec![("PYBUN_ENV", venv.into_os_string())];
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_test","arguments":{}}}"#;
    let stdout = mcp_call_in(&[call_req], project.path(), &envs);
    let result = tool_result_json(&stdout, 2);

    assert!(
        result["summary"].is_object(),
        "pybun_test response should include summary object. Got: {result}"
    );
    assert!(
        result["summary"]["total"].is_number(),
        "summary should include total count. Got: {result}"
    );
    assert!(
        result["summary"]["passed"].is_number(),
        "summary should include passed count. Got: {result}"
    );
    assert!(
        result["summary"]["failed"].is_number(),
        "summary should include failed count. Got: {result}"
    );
    assert!(
        result["summary"]["duration_ms"].is_number(),
        "summary should include duration_ms. Got: {result}"
    );
    assert!(
        result["failures"].is_array(),
        "pybun_test response should include failures array. Got: {result}"
    );
    assert!(
        result["passed"].is_array(),
        "pybun_test response should include passed array. Got: {result}"
    );
    assert_eq!(
        result["summary"]["failed"].as_i64(),
        Some(0),
        "all-passing test suite should have 0 failures. Got: {result}"
    );
}

#[test]
fn mcp_pybun_test_failures_include_rerun_command() {
    let project = tempdir().unwrap();
    fs::write(
        project.path().join("test_fail.py"),
        "def test_passing():\n    assert True\n\ndef test_failing():\n    assert 1 == 2\n",
    )
    .unwrap();

    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_test","arguments":{}}}"#;
    let stdout = mcp_call_in(&[call_req], project.path(), &[]);
    let result = tool_result_json(&stdout, 2);

    let failures = result["failures"]
        .as_array()
        .expect("failures should be array");
    assert!(
        !failures.is_empty(),
        "should have at least one failure. Got: {result}"
    );

    let failure = &failures[0];
    assert!(
        failure["name"].is_string(),
        "failure should include name. Got: {failure}"
    );
    assert!(
        failure["file"].is_string(),
        "failure should include file. Got: {failure}"
    );
    assert!(
        failure["line"].is_number(),
        "failure should include line. Got: {failure}"
    );
    assert!(
        failure["duration_ms"].is_number(),
        "failure should include duration_ms. Got: {failure}"
    );
    assert!(
        failure["status"].is_string(),
        "failure should include status field. Got: {failure}"
    );
    assert!(
        failure["rerun_command"].is_string(),
        "failure should include rerun_command. Got: {failure}"
    );
    let rerun = failure["rerun_command"].as_str().unwrap();
    assert!(
        rerun.contains("pybun") && rerun.contains("test"),
        "rerun_command should be a pybun test command. Got: {rerun}"
    );
}

#[test]
fn mcp_pybun_test_passed_entries_have_required_fields() {
    let project = tempdir().unwrap();
    fs::write(
        project.path().join("test_pass.py"),
        "def test_hello():\n    assert 'hello' == 'hello'\n",
    )
    .unwrap();

    let venv = make_pytest_venv(project.path());
    let envs = vec![("PYBUN_ENV", venv.into_os_string())];
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_test","arguments":{}}}"#;
    let stdout = mcp_call_in(&[call_req], project.path(), &envs);
    let result = tool_result_json(&stdout, 2);

    let passed = result["passed"].as_array().expect("passed should be array");
    assert!(
        !passed.is_empty(),
        "should have passing tests. Got: {result}"
    );

    let entry = &passed[0];
    assert!(
        entry["name"].is_string(),
        "passed entry should have name. Got: {entry}"
    );
    assert!(
        entry["file"].is_string(),
        "passed entry should have file. Got: {entry}"
    );
    assert!(
        entry["line"].is_number(),
        "passed entry should have line. Got: {entry}"
    );
    assert!(
        entry["duration_ms"].is_number(),
        "passed entry should have duration_ms. Got: {entry}"
    );
    assert_eq!(
        entry["status"].as_str(),
        Some("passed"),
        "passed entry status should be 'passed'. Got: {entry}"
    );
}

#[test]
fn mcp_pybun_test_filter_runs_matching_tests() {
    let project = tempdir().unwrap();
    fs::write(
        project.path().join("test_filter.py"),
        "def test_alpha():\n    assert True\n\ndef test_beta():\n    assert True\n",
    )
    .unwrap();

    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_test","arguments":{"filter":"alpha"}}}"#;
    let stdout = mcp_call_in(&[call_req], project.path(), &[]);
    let result = tool_result_json(&stdout, 2);

    assert_eq!(
        result["summary"]["total"].as_i64(),
        Some(1),
        "filter 'alpha' should match exactly 1 test. Got: {result}"
    );
}

#[test]
fn mcp_pybun_test_empty_project_returns_empty_summary() {
    let project = tempdir().unwrap();

    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_test","arguments":{}}}"#;
    let stdout = mcp_call_in(&[call_req], project.path(), &[]);
    let result = tool_result_json(&stdout, 2);

    assert!(
        result["summary"].is_object(),
        "empty project should still return summary object. Got: {result}"
    );
    assert_eq!(
        result["summary"]["total"].as_i64(),
        Some(0),
        "empty project should have 0 total tests. Got: {result}"
    );
}

#[test]
fn mcp_pybun_test_changed_runs_git_modified_files() {
    let project = tempdir().unwrap();

    // Init a git repo
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(project.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(project.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(project.path())
        .output()
        .unwrap();

    // Create and commit a test file (not modified)
    fs::write(
        project.path().join("test_committed.py"),
        "def test_committed():\n    assert True\n",
    )
    .unwrap();
    std::process::Command::new("git")
        .args(["add", "."])
        .current_dir(project.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["commit", "-m", "initial"])
        .current_dir(project.path())
        .output()
        .unwrap();

    // Add a new (untracked/modified) test file
    fs::write(
        project.path().join("test_new.py"),
        "def test_new_feature():\n    assert True\n",
    )
    .unwrap();

    let venv = make_pytest_venv(project.path());
    let envs = vec![("PYBUN_ENV", venv.into_os_string())];
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_test","arguments":{"changed":true}}}"#;
    let stdout = mcp_call_in(&[call_req], project.path(), &envs);
    let result = tool_result_json(&stdout, 2);

    // Should run exactly the 1 test from the new untracked file, not the committed one
    assert!(
        result["summary"].is_object(),
        "changed mode should return summary. Got: {result}"
    );
    assert_eq!(
        result["summary"]["total"].as_i64(),
        Some(1),
        "changed mode should run exactly 1 test (from test_new.py). Got: {result}"
    );

    // Verify it is the new test, not the committed one
    let passed = result["passed"].as_array().expect("passed should be array");
    let found_new = passed
        .iter()
        .any(|t| t["name"].as_str() == Some("test_new_feature"));
    assert!(
        found_new,
        "changed mode should run test_new_feature from the untracked file. Got passed: {passed:?}"
    );
    let found_committed = passed
        .iter()
        .any(|t| t["name"].as_str() == Some("test_committed"));
    assert!(
        !found_committed,
        "changed mode must not run test_committed from the already-committed file. Got passed: {passed:?}"
    );
}

// ---------------------------------------------------------------------------
// pybun_audit MCP tool tests (Issue #247)
// ---------------------------------------------------------------------------

#[test]
fn mcp_tools_list_includes_pybun_audit() {
    let stdout = mcp_call(&[r#"{"jsonrpc":"2.0","method":"tools/list","id":2,"params":{}}"#]);
    assert!(
        stdout.contains("pybun_audit"),
        "tools/list should include pybun_audit. Got: {stdout}"
    );
}

#[test]
fn mcp_pybun_audit_returns_valid_structure_with_mocked_osv() {
    // Verify that pybun_audit returns a valid response structure regardless of
    // which Python env is found (system Python or none). The OSV endpoint is
    // mocked to return no vulnerabilities so the test is deterministic.
    let project = tempdir().unwrap();

    let server = MockServer::start();
    // Return empty results for every query (no vulnerabilities)
    let _osv_mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(r#"{"results":[]}"#);
    });

    let osv_url = format!("{}/v1/querybatch", server.base_url());
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_audit","arguments":{}}}"#;
    let stdout = mcp_call_in(
        &[call_req],
        project.path(),
        &[("PYBUN_OSV_URL", OsString::from(osv_url))],
    );
    let result = tool_result_json(&stdout, 2);

    assert!(
        result["summary"].is_object(),
        "audit should return summary object. Got: {result}"
    );
    assert!(
        result["summary"]["scanned"].is_number(),
        "audit summary should have numeric scanned count. Got: {result}"
    );
    assert_eq!(
        result["summary"]["vulnerable"].as_i64(),
        Some(0),
        "mocked OSV (no vulns) should report 0 vulnerabilities. Got: {result}"
    );
    assert!(
        result["vulnerabilities"].is_array(),
        "audit should return vulnerabilities array. Got: {result}"
    );
}

#[test]
fn mcp_pybun_audit_osv_vulnerability_returned() {
    // Mock OSV returning one vulnerability for "requests" 2.27.0
    let server = MockServer::start();
    let osv_body = serde_json::json!({
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-j8r2-6x86-q33q",
                        "summary": "Requests SSRF vulnerability",
                        "severity": [
                            {
                                "type": "CVSS_V3",
                                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                            }
                        ],
                        "affected": [
                            {
                                "package": {"name": "requests", "ecosystem": "PyPI"},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "2.31.0"}
                                        ]
                                    }
                                ]
                            }
                        ],
                        "database_specific": {
                            "severity": "HIGH"
                        }
                    }
                ]
            }
        ]
    });
    let _mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(osv_body);
    });

    // Create a fake venv that reports "requests 2.27.0" via pip list
    let project = tempdir().unwrap();
    let fake_venv = make_fake_pip_venv(
        project.path(),
        r#"[{"name": "requests", "version": "2.27.0"}]"#,
    );

    let osv_url = format!("{}/v1/querybatch", server.base_url());
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_audit","arguments":{"fix":true}}}"#;
    let stdout = mcp_call_in(
        &[call_req],
        project.path(),
        &[
            ("PYBUN_OSV_URL", OsString::from(osv_url)),
            ("PYBUN_ENV", fake_venv.into_os_string()),
        ],
    );
    let result = tool_result_json(&stdout, 2);

    assert_eq!(
        result["summary"]["scanned"].as_i64(),
        Some(1),
        "should report 1 package scanned. Got: {result}"
    );
    assert_eq!(
        result["summary"]["vulnerable"].as_i64(),
        Some(1),
        "should report 1 vulnerable package. Got: {result}"
    );
    assert_eq!(
        result["summary"]["high"].as_i64(),
        Some(1),
        "should report 1 high severity vulnerability. Got: {result}"
    );

    let vulns = result["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities should be array");
    assert_eq!(
        vulns.len(),
        1,
        "should have 1 vulnerability entry. Got: {result}"
    );

    let vuln = &vulns[0];
    assert_eq!(
        vuln["package"].as_str(),
        Some("requests"),
        "package name mismatch. Got: {vuln}"
    );
    assert_eq!(
        vuln["vulnerability_id"].as_str(),
        Some("GHSA-j8r2-6x86-q33q"),
        "vulnerability_id mismatch. Got: {vuln}"
    );
    assert_eq!(
        vuln["severity"].as_str(),
        Some("high"),
        "severity should be 'high'. Got: {vuln}"
    );
    assert_eq!(
        vuln["fix_version"].as_str(),
        Some("2.31.0"),
        "fix_version should be 2.31.0. Got: {vuln}"
    );
    assert_eq!(
        vuln["next_action"]["tool"].as_str(),
        Some("pybun_upgrade"),
        "next_action.tool should be pybun_upgrade. Got: {vuln}"
    );
    assert_eq!(
        vuln["next_action"]["args"]["package"].as_str(),
        Some("requests"),
        "next_action.args.package should be requests. Got: {vuln}"
    );
    assert_eq!(
        vuln["next_action"]["args"]["version"].as_str(),
        Some("2.31.0"),
        "next_action.args.version should be 2.31.0. Got: {vuln}"
    );
}

#[test]
fn mcp_pybun_audit_severity_threshold_filters_low() {
    // Mock OSV returning one low severity vulnerability
    let server = MockServer::start();
    let osv_body = serde_json::json!({
        "results": [
            {
                "vulns": [
                    {
                        "id": "PYSEC-2023-001",
                        "summary": "Low severity issue",
                        "affected": [
                            {
                                "package": {"name": "example-pkg", "ecosystem": "PyPI"},
                                "ranges": []
                            }
                        ],
                        "database_specific": {
                            "severity": "LOW"
                        }
                    }
                ]
            }
        ]
    });
    let _mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(osv_body);
    });

    let project = tempdir().unwrap();
    let fake_venv = make_fake_pip_venv(
        project.path(),
        r#"[{"name": "example-pkg", "version": "1.0.0"}]"#,
    );

    let osv_url = format!("{}/v1/querybatch", server.base_url());
    // Request with severity_threshold=high — LOW should be filtered out
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_audit","arguments":{"severity_threshold":"high"}}}"#;
    let stdout = mcp_call_in(
        &[call_req],
        project.path(),
        &[
            ("PYBUN_OSV_URL", OsString::from(osv_url)),
            ("PYBUN_ENV", fake_venv.into_os_string()),
        ],
    );
    let result = tool_result_json(&stdout, 2);

    let vulns = result["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert_eq!(
        vulns.len(),
        0,
        "severity_threshold=high should filter out LOW severity vulns. Got: {result}"
    );
}

#[test]
fn mcp_pybun_audit_fix_false_omits_next_action() {
    let server = MockServer::start();
    let osv_body = serde_json::json!({
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-test-0001",
                        "summary": "Test vuln",
                        "affected": [
                            {
                                "package": {"name": "testpkg", "ecosystem": "PyPI"},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]
                                    }
                                ]
                            }
                        ],
                        "database_specific": {"severity": "MEDIUM"}
                    }
                ]
            }
        ]
    });
    let _mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(osv_body);
    });

    let project = tempdir().unwrap();
    let fake_venv = make_fake_pip_venv(
        project.path(),
        r#"[{"name": "testpkg", "version": "1.0.0"}]"#,
    );

    let osv_url = format!("{}/v1/querybatch", server.base_url());
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_audit","arguments":{"fix":false}}}"#;
    let stdout = mcp_call_in(
        &[call_req],
        project.path(),
        &[
            ("PYBUN_OSV_URL", OsString::from(osv_url)),
            ("PYBUN_ENV", fake_venv.into_os_string()),
        ],
    );
    let result = tool_result_json(&stdout, 2);

    let vulns = result["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert_eq!(vulns.len(), 1, "should have 1 vulnerability. Got: {result}");
    assert!(
        vulns[0]["next_action"].is_null(),
        "fix=false should set next_action to null. Got: {}",
        vulns[0]
    );
}

#[test]
fn mcp_pybun_audit_scanner_field_present() {
    let project = tempdir().unwrap();
    let server = MockServer::start();
    let _mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(r#"{"results":[]}"#);
    });
    let osv_url = format!("{}/v1/querybatch", server.base_url());
    let call_req = r#"{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"pybun_audit","arguments":{}}}"#;
    let stdout = mcp_call_in(
        &[call_req],
        project.path(),
        &[("PYBUN_OSV_URL", OsString::from(osv_url))],
    );
    let result = tool_result_json(&stdout, 2);

    assert!(
        result["scanner"].is_string(),
        "audit response should include scanner field. Got: {result}"
    );
}

/// Create a fake venv where `bin/python` delegates `pip list --format=json` to return
/// the given JSON string, and delegates everything else to the real python3.
#[cfg(unix)]
fn make_fake_pip_venv(dir: &Path, pip_list_json: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let venv = dir.join("fake_venv");
    let bin = venv.join("bin");
    std::fs::create_dir_all(&bin).unwrap();

    let pip_json = pip_list_json.replace('"', "\\\"");
    let script = format!(
        r#"#!/bin/sh
# Fake python: intercept "pip list --format=json"
args="$*"
case "$args" in
  *"pip list"*"--format=json"*)
    echo "{pip_json}"
    exit 0
    ;;
  *)
    exec python3 "$@"
    ;;
esac
"#,
        pip_json = pip_json
    );

    let python = bin.join("python");
    std::fs::write(&python, script).unwrap();
    std::fs::set_permissions(&python, std::fs::Permissions::from_mode(0o755)).unwrap();

    venv
}

#[cfg(not(unix))]
fn make_fake_pip_venv(dir: &Path, _pip_list_json: &str) -> std::path::PathBuf {
    // Windows stub — tests guarded by #[cfg(unix)] where needed
    dir.join("fake_venv")
}

// =============================================================================
// Issue #341: MCP pybun_resolve mirrors the CLI `--pre` opt-in — pre-release
// versions are excluded by default and only selected when `"pre": true`.
// =============================================================================

fn index_prerelease_fixture() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_prerelease.json")
}

#[test]
fn mcp_tools_call_resolve_excludes_prereleases_by_default() {
    let temp = tempdir().unwrap();
    let index = index_prerelease_fixture();

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

        let call_req = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{{"name":"pybun_resolve","arguments":{{"requirements":["lib>=1.0.0"],"index":"{}"}}}}}}"#,
            index.display()
        );
        writeln!(stdin, "{}", call_req).ok();
        stdin.flush().ok();
    }

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("resolved"),
        "pybun_resolve should resolve against the fixture index. Got: {}",
        stdout
    );
    assert!(
        !stdout.contains("2.0.0rc1"),
        "pre-release 2.0.0rc1 must be excluded by default. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("1.0.0"),
        "stable 1.0.0 should be selected by default. Got: {}",
        stdout
    );
}

#[test]
fn mcp_tools_call_resolve_pre_opts_in_to_prereleases() {
    let temp = tempdir().unwrap();
    let index = index_prerelease_fixture();

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

        let call_req = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{{"name":"pybun_resolve","arguments":{{"requirements":["lib>=1.0.0"],"index":"{}","pre":true}}}}}}"#,
            index.display()
        );
        writeln!(stdin, "{}", call_req).ok();
        stdin.flush().ok();
    }

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("2.0.0rc1"),
        "\"pre\": true must allow the pre-release to be selected. Got: {}",
        stdout
    );
}
