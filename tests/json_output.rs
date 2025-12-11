use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn install_outputs_structured_json() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    let output = bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "app==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("utf8");
    let parsed: Value = serde_json::from_str(&stdout).expect("json output");

    assert_eq!(parsed["version"], "1");
    assert_eq!(parsed["command"], "pybun install");
    assert_eq!(parsed["status"], "ok");
    assert!(parsed["duration_ms"].as_u64().is_some());
    assert_eq!(parsed["detail"]["lockfile"], lock_path.to_str().unwrap());
    assert_eq!(
        parsed["detail"]["packages"]
            .as_array()
            .expect("packages array")
            .len(),
        4
    );
    // Events should be present (CommandStart, ResolveStart, InstallComplete, CommandEnd)
    let events = parsed["events"].as_array().expect("events array");
    assert!(
        !events.is_empty(),
        "events array should contain command lifecycle events"
    );

    // Check event structure if events exist
    for event in events {
        assert!(event.get("type").is_some(), "event should have type field");
        assert!(
            event.get("timestamp_ms").is_some(),
            "event should have timestamp_ms field"
        );
    }

    // Diagnostics array should be present (may be empty for successful commands)
    assert!(
        parsed["diagnostics"].as_array().is_some(),
        "diagnostics array should be present"
    );
}

fn index_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index.json")
}
