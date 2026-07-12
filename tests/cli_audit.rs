//! Tests for `pybun audit` — CLI exposure of OSV vulnerability scanning
//! (Issue #316). Mirrors the MCP `pybun_audit` tool tests in `tests/mcp.rs`,
//! since both surfaces delegate to the shared `src/audit.rs` scan logic.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use httpmock::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[cfg(unix)]
fn make_fake_pip_venv(dir: &std::path::Path, pip_list_json: &str) -> std::path::PathBuf {
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

/// A fake venv whose `python -m pip list --format=json` invocation always
/// fails (nonzero exit), simulating a broken/unusable environment.
#[cfg(unix)]
fn make_fake_pip_venv_with_broken_pip(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let venv = dir.join("broken_venv");
    let bin = venv.join("bin");
    std::fs::create_dir_all(&bin).unwrap();

    let script = r#"#!/bin/sh
args="$*"
case "$args" in
  *"pip list"*"--format=json"*)
    echo "pip: command not found" >&2
    exit 1
    ;;
  *)
    exec python3 "$@"
    ;;
esac
"#;

    let python = bin.join("python");
    std::fs::write(&python, script).unwrap();
    std::fs::set_permissions(&python, std::fs::Permissions::from_mode(0o755)).unwrap();

    venv
}

#[test]
fn audit_json_returns_valid_structure_with_mocked_osv() {
    let project = tempdir().unwrap();

    let server = MockServer::start();
    let _osv_mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(r#"{"results":[]}"#);
    });

    let osv_url = format!("{}/v1/querybatch", server.base_url());
    let output = bin()
        .current_dir(project.path())
        .env("PYBUN_OSV_URL", &osv_url)
        .args(["--format=json", "audit"])
        .output()
        .expect("failed to run pybun audit");

    assert!(
        output.status.success(),
        "audit should exit 0 when no vulnerabilities found. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout).expect("valid JSON output");

    assert_eq!(value["status"].as_str(), Some("ok"));
    assert!(value["detail"]["summary"].is_object());
    assert_eq!(value["detail"]["summary"]["vulnerable"].as_i64(), Some(0));
    assert!(value["detail"]["vulnerabilities"].is_array());
}

#[cfg(unix)]
#[test]
fn audit_json_reports_vulnerability_from_mocked_osv() {
    let server = MockServer::start();
    let osv_body = serde_json::json!({
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-j8r2-6x86-q33q",
                        "summary": "Requests SSRF vulnerability",
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

    let project = tempdir().unwrap();
    let fake_venv = make_fake_pip_venv(
        project.path(),
        r#"[{"name": "requests", "version": "2.27.0"}]"#,
    );

    let osv_url = format!("{}/v1/querybatch", server.base_url());
    let output = bin()
        .current_dir(project.path())
        .env("PYBUN_OSV_URL", &osv_url)
        .env("PYBUN_ENV", &fake_venv)
        .args(["--format=json", "audit"])
        .output()
        .expect("failed to run pybun audit");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout).expect("valid JSON output");

    assert_eq!(value["detail"]["summary"]["scanned"].as_i64(), Some(1));
    assert_eq!(value["detail"]["summary"]["vulnerable"].as_i64(), Some(1));
    assert_eq!(value["detail"]["summary"]["high"].as_i64(), Some(1));

    let vulns = value["detail"]["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities should be array");
    assert_eq!(vulns.len(), 1);
    assert_eq!(vulns[0]["package"].as_str(), Some("requests"));
    assert_eq!(
        vulns[0]["vulnerability_id"].as_str(),
        Some("GHSA-j8r2-6x86-q33q")
    );
    assert_eq!(vulns[0]["severity"].as_str(), Some("high"));
    assert_eq!(vulns[0]["fix_version"].as_str(), Some("2.31.0"));

    // Without --fail-on, a high-severity finding must not fail the process.
    assert!(
        output.status.success(),
        "audit without --fail-on should exit 0 even with vulnerabilities found"
    );
    assert_eq!(value["status"].as_str(), Some("ok"));

    // Diagnostics array should surface the finding for human/CI consumption.
    let diagnostics = value["diagnostics"]
        .as_array()
        .expect("diagnostics should be array");
    assert!(
        diagnostics
            .iter()
            .any(|d| d["code"].as_str() == Some("W_AUDIT_VULNERABILITY_FOUND")),
        "expected W_AUDIT_VULNERABILITY_FOUND diagnostic. Got: {diagnostics:?}"
    );
}

#[cfg(unix)]
#[test]
fn audit_fail_on_threshold_exits_nonzero_when_matched() {
    let server = MockServer::start();
    let osv_body = serde_json::json!({
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-j8r2-6x86-q33q",
                        "summary": "Requests SSRF vulnerability",
                        "affected": [],
                        "database_specific": {"severity": "HIGH"}
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
        r#"[{"name": "requests", "version": "2.27.0"}]"#,
    );

    let osv_url = format!("{}/v1/querybatch", server.base_url());
    let output = bin()
        .current_dir(project.path())
        .env("PYBUN_OSV_URL", &osv_url)
        .env("PYBUN_ENV", &fake_venv)
        .args(["--format=json", "audit", "--fail-on=high"])
        .output()
        .expect("failed to run pybun audit");

    assert!(
        !output.status.success(),
        "audit --fail-on=high should exit non-zero when a high vulnerability is found"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout).expect("valid JSON output");
    assert_eq!(value["status"].as_str(), Some("error"));
}

#[cfg(unix)]
#[test]
fn audit_fail_on_threshold_does_not_trigger_below_severity() {
    let server = MockServer::start();
    let osv_body = serde_json::json!({
        "results": [
            {
                "vulns": [
                    {
                        "id": "PYSEC-2021-0001",
                        "summary": "Low severity issue",
                        "affected": [],
                        "database_specific": {"severity": "LOW"}
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
        r#"[{"name": "somepkg", "version": "1.0.0"}]"#,
    );

    let osv_url = format!("{}/v1/querybatch", server.base_url());
    let output = bin()
        .current_dir(project.path())
        .env("PYBUN_OSV_URL", &osv_url)
        .env("PYBUN_ENV", &fake_venv)
        .args(["--format=json", "audit", "--fail-on=high"])
        .output()
        .expect("failed to run pybun audit");

    assert!(
        output.status.success(),
        "audit --fail-on=high should exit 0 when only a low severity vulnerability is found"
    );
}

#[cfg(unix)]
#[test]
fn audit_fail_on_still_triggers_when_below_severity_threshold() {
    // Regression test: --severity-threshold must only govern what is
    // *displayed*, not silently hide findings from --fail-on. A "high"
    // finding must still fail the process even when --severity-threshold is
    // set above it (here: critical).
    let server = MockServer::start();
    let osv_body = serde_json::json!({
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-j8r2-6x86-q33q",
                        "summary": "Requests SSRF vulnerability",
                        "affected": [],
                        "database_specific": {"severity": "HIGH"}
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
        r#"[{"name": "requests", "version": "2.27.0"}]"#,
    );

    let osv_url = format!("{}/v1/querybatch", server.base_url());
    let output = bin()
        .current_dir(project.path())
        .env("PYBUN_OSV_URL", &osv_url)
        .env("PYBUN_ENV", &fake_venv)
        .args([
            "--format=json",
            "audit",
            "--severity-threshold=critical",
            "--fail-on=high",
        ])
        .output()
        .expect("failed to run pybun audit");

    assert!(
        !output.status.success(),
        "--fail-on=high must still trigger even though --severity-threshold=critical would \
         otherwise hide the high-severity finding from the displayed list"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout).expect("valid JSON output");
    assert_eq!(value["status"].as_str(), Some("error"));

    let diagnostics = value["diagnostics"]
        .as_array()
        .expect("diagnostics should be array");
    assert!(
        diagnostics
            .iter()
            .any(|d| d["code"].as_str() == Some("E_AUDIT_FAIL_ON_THRESHOLD")),
        "expected E_AUDIT_FAIL_ON_THRESHOLD diagnostic. Got: {diagnostics:?}"
    );
}

#[cfg(unix)]
#[test]
fn audit_reports_error_when_pip_list_fails_instead_of_silently_passing() {
    // Regression test: a broken environment must not be treated as "zero
    // packages, scan succeeded" — that would let `--fail-on` pass silently
    // in CI even though nothing was actually scanned.
    let project = tempdir().unwrap();
    let broken_venv = make_fake_pip_venv_with_broken_pip(project.path());

    let output = bin()
        .current_dir(project.path())
        .env("PYBUN_ENV", &broken_venv)
        .args(["--format=json", "audit", "--fail-on=high"])
        .output()
        .expect("failed to run pybun audit");

    assert!(
        !output.status.success(),
        "audit should exit non-zero when pip list fails, not silently report a clean scan"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(&stdout).expect("valid JSON output");
    assert_eq!(value["status"].as_str(), Some("error"));

    let diagnostics = value["diagnostics"]
        .as_array()
        .expect("diagnostics should be array");
    assert!(
        diagnostics
            .iter()
            .any(|d| d["code"].as_str() == Some("E_AUDIT_PIP_LIST_FAILED")),
        "expected E_AUDIT_PIP_LIST_FAILED diagnostic. Got: {diagnostics:?}"
    );
}

#[test]
fn audit_severity_threshold_filters_low_severity_findings() {
    let project = tempdir().unwrap();

    let server = MockServer::start();
    let _osv_mock = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(r#"{"results":[]}"#);
    });

    let osv_url = format!("{}/v1/querybatch", server.base_url());
    bin()
        .current_dir(project.path())
        .env("PYBUN_OSV_URL", &osv_url)
        .args(["audit", "--severity-threshold=critical"])
        .assert()
        .success();
}

#[test]
fn audit_help_documents_severity_threshold_and_fail_on() {
    bin()
        .args(["audit", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--severity-threshold"))
        .stdout(predicates::str::contains("--fail-on"));
}
