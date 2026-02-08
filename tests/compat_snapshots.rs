//! Compatibility snapshots for CLI help and JSON output (PR7.1).

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
}

fn snapshots_root() -> PathBuf {
    PathBuf::from("tests/snapshots/compat")
}

fn update_snapshots() -> bool {
    std::env::var("PYBUN_UPDATE_SNAPSHOTS").is_ok()
}

fn assert_snapshot(path: &Path, actual: &str) {
    if update_snapshots() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create snapshot dir");
        }
        fs::write(path, actual).expect("write snapshot");
        return;
    }

    let expected = fs::read_to_string(path).expect("read snapshot");
    assert_eq!(expected, actual, "snapshot mismatch: {}", path.display());
}

fn normalize_envelope(mut value: Value) -> Value {
    if let Some(obj) = value.as_object_mut() {
        if let Some(duration) = obj.get_mut("duration_ms") {
            *duration = json!(0);
        }

        if let Some(trace_id) = obj.get_mut("trace_id")
            && !trace_id.is_null()
        {
            *trace_id = json!("<trace_id>");
        }

        if let Some(events) = obj.get_mut("events").and_then(|v| v.as_array_mut()) {
            for event in events {
                if let Some(ts) = event
                    .as_object_mut()
                    .and_then(|event_obj| event_obj.get_mut("timestamp_ms"))
                {
                    *ts = json!(0);
                }
            }
        }

        if let Some(detail) = obj.get_mut("detail").and_then(|v| v.as_object_mut()) {
            if let Some(target) = detail.get_mut("target")
                && target.is_string()
            {
                *target = json!("<target>");
            }

            if let Some(manifest) = detail.get_mut("manifest").and_then(|v| v.as_object_mut()) {
                if let Some(target) = manifest.get_mut("target")
                    && target.is_string()
                {
                    *target = json!("<target>");
                }

                if let Some(asset) = manifest.get_mut("asset").and_then(|v| v.as_object_mut())
                    && let Some(target) = asset.get_mut("target")
                    && target.is_string()
                {
                    *target = json!("<target>");
                }
            }
        }
    }

    value
}

fn snapshot_json(name: &str, raw: &str) {
    let value: Value = serde_json::from_str(raw).expect("valid JSON output");
    let normalized = normalize_envelope(value);
    let pretty = serde_json::to_string_pretty(&normalized).expect("pretty JSON");
    let path = snapshots_root().join(format!("{}.json", name));
    assert_snapshot(&path, &pretty);
}

fn snapshot_text(name: &str, raw: &str) {
    let path = snapshots_root().join(format!("{}.txt", name));
    assert_snapshot(&path, raw);
}

#[test]
fn help_snapshots() {
    let cases: &[(&str, &[&str])] = &[
        ("help_root", &["--help"]),
        ("help_install", &["install", "--help"]),
        ("help_add", &["add", "--help"]),
        ("help_remove", &["remove", "--help"]),
        ("help_lock", &["lock", "--help"]),
        ("help_run", &["run", "--help"]),
        ("help_x", &["x", "--help"]),
        ("help_test", &["test", "--help"]),
        ("help_build", &["build", "--help"]),
        ("help_doctor", &["doctor", "--help"]),
        ("help_mcp", &["mcp", "--help"]),
        ("help_mcp_serve", &["mcp", "serve", "--help"]),
        ("help_self", &["self", "--help"]),
        ("help_self_update", &["self", "update", "--help"]),
        ("help_gc", &["gc", "--help"]),
        ("help_python", &["python", "--help"]),
        ("help_python_list", &["python", "list", "--help"]),
        ("help_python_install", &["python", "install", "--help"]),
        ("help_python_remove", &["python", "remove", "--help"]),
        ("help_python_which", &["python", "which", "--help"]),
        ("help_module_find", &["module-find", "--help"]),
        ("help_lazy_import", &["lazy-import", "--help"]),
        ("help_watch", &["watch", "--help"]),
        ("help_profile", &["profile", "--help"]),
        ("help_schema", &["schema", "--help"]),
        ("help_schema_print", &["schema", "print", "--help"]),
        ("help_schema_check", &["schema", "check", "--help"]),
    ];

    for (name, args) in cases {
        let output = pybun()
            .args(*args)
            .output()
            .expect("failed to run pybun help");
        assert!(output.status.success(), "help command failed: {}", name);
        let stdout = String::from_utf8_lossy(&output.stdout);
        snapshot_text(name, &stdout);
    }
}

#[test]
fn json_snapshots() {
    let cases: &[(&str, &[&str])] = &[
        ("json_schema_print", &["--format=json", "schema", "print"]),
        ("json_schema_check", &["--format=json", "schema", "check"]),
        (
            "json_self_update_dry_run",
            &["--format=json", "self", "update", "--dry-run"],
        ),
    ];

    for (name, args) in cases {
        let output = pybun()
            .args(*args)
            .output()
            .expect("failed to run pybun json");
        assert!(output.status.success(), "json command failed: {}", name);
        let stdout = String::from_utf8_lossy(&output.stdout);
        snapshot_json(name, &stdout);
    }
}
