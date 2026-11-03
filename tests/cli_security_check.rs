use assert_cmd::cargo::cargo_bin_cmd;
use clap::Parser;
use pybun::cli::Cli;
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn new_check_parser_preserves_bare_audit_and_rejects_legacy_flag_mixing() {
    assert!(Cli::try_parse_from(["pybun", "audit", "--system", "--fail-on", "high"]).is_ok());
    assert!(
        Cli::try_parse_from([
            "pybun",
            "audit",
            "check-updates",
            "--target",
            "installed",
            "--format=json"
        ])
        .is_ok()
    );
    assert!(Cli::try_parse_from(["pybun", "audit", "--system", "check-updates"]).is_err());
    assert!(
        Cli::try_parse_from(["pybun", "audit", "check-updates", "--target", "system"]).is_err()
    );
    assert!(Cli::try_parse_from(["pybun", "audit", "check-updates", "--timeout-ms", "0"]).is_err());
}

#[test]
fn unconfigured_check_returns_operational_v2_failure_without_creating_project_files() {
    let project = tempdir().unwrap();
    let output = cargo_bin_cmd!("pybun")
        .current_dir(project.path())
        .args([
            "audit",
            "check-updates",
            "--target",
            "installed",
            "--format=json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["version"], "2");
    assert_eq!(value["status"], "error");
    assert_eq!(value["detail"]["contract_version"], "2");
    assert!(value["detail"]["assessment"].is_null());
    assert_eq!(value["detail"]["exit_code"], 3);
    assert!(value["detail"].get("next_action").is_none());
    assert_eq!(std::fs::read_dir(project.path()).unwrap().count(), 0);
}
