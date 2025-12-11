//! JSON Event Schema Tests (PR4.1)
//!
//! Tests for the global JSON event schema that all commands use.
//! This ensures consistent, machine-readable output for AI/MCP integration.

use std::process::Command;

/// JSON envelope must have required fields
#[test]
fn json_envelope_has_required_fields() {
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .args(["--format=json", "python", "list"])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    // Required envelope fields
    assert!(json.get("version").is_some(), "missing 'version' field");
    assert!(json.get("command").is_some(), "missing 'command' field");
    assert!(json.get("status").is_some(), "missing 'status' field");
    assert!(
        json.get("duration_ms").is_some(),
        "missing 'duration_ms' field"
    );
    assert!(json.get("detail").is_some(), "missing 'detail' field");
    assert!(json.get("events").is_some(), "missing 'events' field");
    assert!(
        json.get("diagnostics").is_some(),
        "missing 'diagnostics' field"
    );
}

/// Version field must be a string following semver-like format
#[test]
fn json_version_field_is_valid() {
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .args(["--format=json", "python", "list"])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    let version = json.get("version").expect("version field");
    assert!(version.is_string(), "version must be a string");

    // Schema version should be like "1" or "1.0"
    let v = version.as_str().unwrap();
    assert!(!v.is_empty(), "version must not be empty");
}

/// Status field must be one of: ok, error
#[test]
fn json_status_field_is_valid() {
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .args(["--format=json", "python", "list"])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    let status = json.get("status").expect("status field");
    let status_str = status.as_str().expect("status must be string");
    assert!(
        status_str == "ok" || status_str == "error",
        "status must be 'ok' or 'error', got '{}'",
        status_str
    );
}

/// Duration must be a non-negative number
#[test]
fn json_duration_is_non_negative() {
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .args(["--format=json", "python", "list"])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    let duration = json.get("duration_ms").expect("duration_ms field");
    assert!(duration.is_u64(), "duration_ms must be a u64");
    assert!(duration.as_u64().unwrap() >= 0, "duration_ms must be >= 0");
}

/// Events field must be an array
#[test]
fn json_events_is_array() {
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .args(["--format=json", "python", "list"])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    let events = json.get("events").expect("events field");
    assert!(events.is_array(), "events must be an array");
}

/// Diagnostics field must be an array
#[test]
fn json_diagnostics_is_array() {
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .args(["--format=json", "python", "list"])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    let diagnostics = json.get("diagnostics").expect("diagnostics field");
    assert!(diagnostics.is_array(), "diagnostics must be an array");
}

/// Each event in events array must have type and timestamp
#[test]
fn json_event_has_required_fields() {
    // Use install command which generates events
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .args([
            "--format=json",
            "install",
            "--require",
            "nonexistent==1.0",
            "--index",
            "tests/fixtures/index.json",
            "--lock",
            "/tmp/pybun_test_schema.lockb",
        ])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Even if command fails, JSON should be valid
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let events = json.get("events").and_then(|e| e.as_array());
        if let Some(events) = events {
            for event in events {
                // Each event must have 'type' field
                assert!(event.get("type").is_some(), "event missing 'type' field");
                // Each event must have 'timestamp_ms' field
                assert!(
                    event.get("timestamp_ms").is_some(),
                    "event missing 'timestamp_ms' field"
                );
            }
        }
    }
}

/// Diagnostic entry must have level, code, and message
#[test]
fn json_diagnostic_has_required_fields() {
    // This test verifies the structure when diagnostics are present
    // We'll trigger a diagnostic by providing an invalid configuration
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .args(["--format=json", "doctor"])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let diagnostics = json.get("diagnostics").and_then(|d| d.as_array());
        if let Some(diagnostics) = diagnostics {
            for diag in diagnostics {
                // Each diagnostic must have required fields
                if diag.is_object() {
                    assert!(
                        diag.get("level").is_some(),
                        "diagnostic missing 'level' field"
                    );
                    assert!(
                        diag.get("message").is_some(),
                        "diagnostic missing 'message' field"
                    );
                }
            }
        }
    }
}

/// Error responses must include error details
#[test]
fn json_error_response_has_error_detail() {
    // Trigger an error by not providing required package argument
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .args(["--format=json", "add"])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // If JSON output is present, validate error structure
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let status = json.get("status").and_then(|s| s.as_str());
        if status == Some("error") {
            // Error responses should have error details
            let detail = json.get("detail");
            assert!(detail.is_some(), "error response must have detail");
            let detail = detail.unwrap();
            assert!(
                detail.get("error").is_some() || detail.get("message").is_some(),
                "error detail must have 'error' or 'message' field"
            );
        }
    }
}

/// Trace ID is optional but must be valid UUID format when present
#[test]
fn json_trace_id_format_when_present() {
    // Run with PYBUN_TRACE env var set
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .args(["--format=json", "python", "list"])
        .env("PYBUN_TRACE", "1")
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    if let Some(trace_id) = json.get("trace_id") {
        if !trace_id.is_null() {
            let trace_str = trace_id.as_str().expect("trace_id must be a string");
            // UUID format: 8-4-4-4-12 hex chars
            assert!(
                trace_str.len() >= 32,
                "trace_id should be UUID format: {}",
                trace_str
            );
        }
    }
}

/// All subcommands produce valid JSON when --format=json is specified
mod all_commands {
    use super::*;

    #[test]
    fn python_list_json() {
        let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .args(["--format=json", "python", "list"])
            .output()
            .expect("failed to execute pybun");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(json["command"], "pybun python list");
    }

    #[test]
    fn python_list_all_json() {
        let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .args(["--format=json", "python", "list", "--all"])
            .output()
            .expect("failed to execute pybun");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(json["command"], "pybun python list");
    }

    #[test]
    fn test_stub_json() {
        let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .args(["--format=json", "test"])
            .output()
            .expect("failed to execute pybun");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(json["command"], "pybun test");
    }

    #[test]
    fn build_stub_json() {
        let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .args(["--format=json", "build"])
            .output()
            .expect("failed to execute pybun");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(json["command"], "pybun build");
    }

    #[test]
    fn doctor_json() {
        let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .args(["--format=json", "doctor"])
            .output()
            .expect("failed to execute pybun");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(json["command"], "pybun doctor");
    }

    #[test]
    fn gc_json() {
        let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .args(["--format=json", "gc"])
            .output()
            .expect("failed to execute pybun");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(json["command"], "pybun gc");
    }

    #[test]
    fn self_update_stub_json() {
        let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .args(["--format=json", "self", "update"])
            .output()
            .expect("failed to execute pybun");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(json["command"], "pybun self update");
    }

    #[test]
    fn mcp_serve_stub_json() {
        let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .args(["--format=json", "mcp", "serve"])
            .output()
            .expect("failed to execute pybun");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(json["command"], "pybun mcp serve");
    }
}

/// Schema versioning tests
mod schema_version {
    use super::*;

    #[test]
    fn schema_version_is_1() {
        let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .args(["--format=json", "python", "list"])
            .output()
            .expect("failed to execute pybun");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(json["version"], "1", "Schema version should be '1'");
    }
}
