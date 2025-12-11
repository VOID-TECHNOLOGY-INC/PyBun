//! Tests for the Observability layer
//!
//! PR4.4: Observability layer with PYBUN_TRACE, structured logging, redaction

use std::process::Command;
use tempfile::tempdir;

fn pybun_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pybun"))
}

#[test]
fn trace_id_present_when_pybun_trace_set() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .env("PYBUN_TRACE", "1")
        .args(["--format=json", "gc"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    // trace_id should be present when PYBUN_TRACE=1
    assert!(
        json.get("trace_id").is_some(),
        "trace_id should be present when PYBUN_TRACE=1, got: {}",
        stdout
    );

    // trace_id should look like a UUID
    let trace_id = json["trace_id"].as_str().unwrap();
    assert!(
        trace_id.contains('-') && trace_id.len() >= 32,
        "trace_id should be a UUID-like string: {}",
        trace_id
    );
}

#[test]
fn trace_id_absent_when_pybun_trace_not_set() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .env_remove("PYBUN_TRACE")
        .args(["--format=json", "gc"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    // trace_id should be absent or null when PYBUN_TRACE not set
    assert!(
        json.get("trace_id").is_none() || json["trace_id"].is_null(),
        "trace_id should be absent when PYBUN_TRACE not set"
    );
}

#[test]
fn events_have_timestamps() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "gc"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let events = json["events"].as_array().expect("events should be array");

    // Should have at least command_start and command_end events
    assert!(
        events.len() >= 2,
        "should have at least 2 events (start/end)"
    );

    // Each event should have timestamp_ms
    for event in events {
        assert!(
            event.get("timestamp_ms").is_some(),
            "event should have timestamp_ms: {:?}",
            event
        );
    }
}

#[test]
fn duration_ms_in_response() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "gc"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert!(
        json.get("duration_ms").is_some(),
        "response should have duration_ms"
    );

    let duration = json["duration_ms"].as_u64().unwrap();
    // Duration should be reasonable (less than 30 seconds for gc)
    assert!(
        duration < 30000,
        "duration should be reasonable: {}",
        duration
    );
}

#[test]
fn schema_version_in_response() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "gc"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert_eq!(
        json["version"].as_str(),
        Some("1"),
        "schema version should be '1'"
    );
}

#[test]
fn diagnostics_array_present() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "gc"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert!(
        json["diagnostics"].is_array(),
        "diagnostics should be an array"
    );
}

#[test]
fn sensitive_env_vars_redacted() {
    // This test checks that sensitive environment variables are not leaked in logs
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .env("AWS_SECRET_ACCESS_KEY", "super-secret-key-12345")
        .env("GITHUB_TOKEN", "ghp_secret_token_12345")
        .env("PYBUN_TRACE", "1")
        .args(["--format=json", "doctor"])
        .output()
        .unwrap();

    // Check stdout doesn't contain the secrets
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stdout.contains("super-secret-key-12345"),
        "stdout should not contain AWS secret"
    );
    assert!(
        !stdout.contains("ghp_secret_token_12345"),
        "stdout should not contain GitHub token"
    );
    assert!(
        !stderr.contains("super-secret-key-12345"),
        "stderr should not contain AWS secret"
    );
    assert!(
        !stderr.contains("ghp_secret_token_12345"),
        "stderr should not contain GitHub token"
    );
}

#[test]
fn log_level_via_pybun_log() {
    let temp = tempdir().unwrap();

    // Test with PYBUN_LOG=debug
    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .env("PYBUN_LOG", "debug")
        .args(["gc"])
        .output()
        .unwrap();

    assert!(output.status.success());
    // Debug mode might produce more stderr output
    // We just check it doesn't crash
}

#[test]
fn event_types_are_valid() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "gc"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let events = json["events"].as_array().expect("events should be array");

    let valid_event_types = [
        "command_start",
        "command_end",
        "resolve_start",
        "resolve_progress",
        "resolve_complete",
        "install_start",
        "download_start",
        "download_progress",
        "download_complete",
        "extract_start",
        "extract_complete",
        "install_complete",
        "env_create",
        "env_activate",
        "script_start",
        "script_end",
        "cache_hit",
        "cache_miss",
        "cache_write",
        "python_list_start",
        "python_list_complete",
        "python_install_start",
        "python_install_complete",
        "python_remove_start",
        "python_remove_complete",
        "progress",
        "custom",
    ];

    for event in events {
        let event_type = event["type"].as_str().expect("event should have type");
        assert!(
            valid_event_types.contains(&event_type),
            "event type '{}' should be valid",
            event_type
        );
    }
}
