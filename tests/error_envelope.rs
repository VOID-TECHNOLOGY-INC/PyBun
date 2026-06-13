//! Error envelope regression tests (Issue #191)
//!
//! For an agent-first tool, every error response must be machine-actionable:
//! when `status == "error"`, `diagnostics[]` must be non-empty and each
//! error-level entry must carry a stable `code` (starting with `E_`), a
//! `message`, and a `suggestion` hint.

use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::TempDir;

/// Assert the invariant from Issue #191: when `status == "error"`,
/// `diagnostics[]` is non-empty and each error-level diagnostic has a
/// non-empty `code` (starting with `E_`), `message`, and `suggestion`.
fn assert_error_envelope(json: &serde_json::Value, expected_code: &str) {
    assert_eq!(
        json.get("status").and_then(|s| s.as_str()),
        Some("error"),
        "expected status == \"error\", got: {json}"
    );

    let diagnostics = json
        .get("diagnostics")
        .and_then(|d| d.as_array())
        .expect("diagnostics field must be a non-null array");
    assert!(
        !diagnostics.is_empty(),
        "diagnostics[] must be non-empty when status == \"error\""
    );

    let mut found = false;
    for diag in diagnostics {
        if diag.get("level").and_then(|l| l.as_str()) != Some("error") {
            continue;
        }

        let code = diag
            .get("code")
            .and_then(|c| c.as_str())
            .unwrap_or_default();
        assert!(
            code.starts_with("E_"),
            "error diagnostic missing stable E_* code: {diag}"
        );

        let message = diag
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or_default();
        assert!(
            !message.is_empty(),
            "error diagnostic missing message: {diag}"
        );

        let suggestion = diag
            .get("suggestion")
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        assert!(
            !suggestion.is_empty(),
            "error diagnostic missing suggestion: {diag}"
        );

        if code == expected_code {
            found = true;
        }
    }

    assert!(
        found,
        "expected an error diagnostic with code {expected_code}, got: {diagnostics:?}"
    );
}

#[test]
fn outdated_without_lockfile_has_coded_diagnostic() {
    let temp = TempDir::new().unwrap();

    let output = cargo_bin_cmd!("pybun")
        .current_dir(&temp)
        .args(["--format=json", "outdated"])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    assert_error_envelope(&json, "E_LOCKFILE_NOT_FOUND");
}

#[test]
fn upgrade_without_lockfile_has_coded_diagnostic() {
    let temp = TempDir::new().unwrap();

    let output = cargo_bin_cmd!("pybun")
        .current_dir(&temp)
        .args(["--format=json", "upgrade"])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    assert_error_envelope(&json, "E_LOCKFILE_NOT_FOUND");
}

#[test]
fn remove_without_project_has_coded_diagnostic() {
    let temp = TempDir::new().unwrap();

    let output = cargo_bin_cmd!("pybun")
        .current_dir(&temp)
        .args(["--format=json", "remove", "somepkg"])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    assert_error_envelope(&json, "E_REMOVE_FAILED");
}

#[test]
fn schema_check_with_unreadable_path_has_coded_diagnostic() {
    let output = cargo_bin_cmd!("pybun")
        .args([
            "--format=json",
            "schema",
            "check",
            "--path",
            "/nonexistent/schema.json",
        ])
        .output()
        .expect("failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");

    assert_error_envelope(&json, "E_SCHEMA_FILE_READ");
}
