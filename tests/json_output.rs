use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use pybun::lockfile::{Lockfile, Package, PackageSource};
use serde_json::Value;
use std::fs;
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
    assert_eq!(parsed["detail"]["verified"], true);
    assert_eq!(
        parsed["detail"]["artifacts"]
            .as_array()
            .expect("artifacts array")
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

// ---------------------------------------------------------------------------
// Issue #285: PEP 508 extras (e.g. `typer[all]`) must not be silently
// dropped without a trace. `pybun install --require 'app[extra1,extra2]==1.0.0'`
// should still resolve and install the base package (honest degradation —
// full extras resolution is tracked separately as PR-A5) but must surface a
// `W_EXTRAS_IGNORED` diagnostic explaining that the extras were ignored.
// ---------------------------------------------------------------------------
#[test]
fn install_with_extras_outputs_w_extras_ignored_diagnostic() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    let output = bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "app[extra1,extra2]==1.0.0",
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

    assert_eq!(parsed["status"], "ok");

    // The base package should still be installed (honest degradation).
    let names: Vec<&str> = parsed["detail"]["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .filter_map(|p| p.as_str())
        .collect();
    assert!(
        names.contains(&"app"),
        "expected base package 'app' to be resolved: {names:?}"
    );

    let diags = parsed["diagnostics"].as_array().expect("diagnostics array");
    let extras_diag = diags
        .iter()
        .find(|d| d.get("code") == Some(&Value::from("W_EXTRAS_IGNORED")))
        .expect("expected W_EXTRAS_IGNORED diagnostic");

    assert_eq!(extras_diag["level"], "warning");
    let message = extras_diag["message"].as_str().expect("message string");
    assert!(
        message.contains("app") && message.contains("extra1") && message.contains("extra2"),
        "diagnostic message should name the package and dropped extras: {message}"
    );
    assert_eq!(extras_diag["context"]["package"], "app");
    let extras_ctx = extras_diag["context"]["extras"]
        .as_array()
        .expect("extras context array");
    let extras_ctx: Vec<&str> = extras_ctx.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(extras_ctx, vec!["extra1", "extra2"]);
}

#[test]
fn install_error_outputs_diagnostics_in_json() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    let output = bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "missing==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("utf8");
    let parsed: Value = serde_json::from_str(&stdout).expect("json output");

    assert_eq!(parsed["status"], "error");
    let diags = parsed["diagnostics"].as_array().expect("diagnostics array");
    assert!(
        !diags.is_empty(),
        "error responses should include at least one diagnostic"
    );

    // Self-healing diagnostics should include a structured code for resolution failures.
    assert!(
        diags
            .iter()
            .any(|d| d.get("code") == Some(&Value::from("E_RESOLVE_MISSING"))),
        "expected E_RESOLVE_MISSING diagnostic code"
    );
}

// ---------------------------------------------------------------------------
// Issue #270: diagnostics[].message / diagnostics[].suggestion must be
// locale-neutral (English) in --format=json, since diagnostics[].code is the
// stable machine-readable contract that agents/tooling key off of. Verify
// this holds even when the process runs under a Japanese locale (LANG/LC_ALL),
// which previously produced hardcoded Japanese text in these fields.
// ---------------------------------------------------------------------------
#[test]
fn install_error_json_diagnostics_are_locale_neutral_under_japanese_locale() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    let output = bin()
        .env("LANG", "ja_JP.UTF-8")
        .env("LC_ALL", "ja_JP.UTF-8")
        .env("LC_MESSAGES", "ja_JP.UTF-8")
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "missing==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("utf8");
    let parsed: Value = serde_json::from_str(&stdout).expect("json output");

    assert_eq!(parsed["status"], "error");
    let diags = parsed["diagnostics"].as_array().expect("diagnostics array");
    assert!(!diags.is_empty());

    for diag in diags {
        if let Some(message) = diag.get("message").and_then(|m| m.as_str()) {
            assert!(
                message.is_ascii(),
                "diagnostics[].message must be locale-neutral English even under LANG=ja_JP.UTF-8, got: {message:?}"
            );
        }
        if let Some(suggestion) = diag.get("suggestion").and_then(|s| s.as_str()) {
            assert!(
                suggestion.is_ascii(),
                "diagnostics[].suggestion must be locale-neutral English even under LANG=ja_JP.UTF-8, got: {suggestion:?}"
            );
        }
    }
}

#[test]
fn install_conflict_outputs_conflict_tree_diagnostics_in_json() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_conflict_path();

    let output = bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "root==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("utf8");
    let parsed: Value = serde_json::from_str(&stdout).expect("json output");

    assert_eq!(parsed["status"], "error");
    let diags = parsed["diagnostics"].as_array().expect("diagnostics array");
    assert!(
        diags
            .iter()
            .any(|d| d.get("code") == Some(&Value::from("E_RESOLVE_CONFLICT"))),
        "expected E_RESOLVE_CONFLICT diagnostic code"
    );

    // At least one diagnostic should include a conflict tree context payload.
    let has_tree = diags.iter().any(|d| {
        d.get("context")
            .and_then(|c| c.get("existing_chain"))
            .and_then(|v| v.as_array())
            .is_some()
            && d.get("context")
                .and_then(|c| c.get("requested_chain"))
                .and_then(|v| v.as_array())
                .is_some()
    });
    assert!(
        has_tree,
        "expected conflict diagnostics to include chains in context"
    );
}

#[test]
fn install_missing_hash_outputs_verification_diagnostic_in_json() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_missing_hash_path();

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
        .failure()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("utf8");
    let parsed: Value = serde_json::from_str(&stdout).expect("json output");

    assert_eq!(parsed["status"], "error");
    let diags = parsed["diagnostics"].as_array().expect("diagnostics array");
    assert!(
        diags
            .iter()
            .any(|d| d.get("code") == Some(&Value::from("E_VERIFY_MISSING_HASH"))),
        "expected E_VERIFY_MISSING_HASH diagnostic code"
    );
}

#[test]
fn lock_missing_script_and_no_pyproject_outputs_diagnostics_in_json() {
    // Without --script and without a pyproject.toml in the directory tree,
    // `lock` has no target to lock and must fail with an actionable diagnostic
    // (Issue #149: `lock` without --script locks the project when a
    // pyproject.toml is present, so this case is now scoped to "no target").
    let temp = tempdir().unwrap();

    let output = bin()
        .current_dir(temp.path())
        .args(["--format=json", "lock"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("utf8");
    let parsed: Value = serde_json::from_str(&stdout).expect("json output");

    assert_eq!(parsed["status"], "error");
    let diags = parsed["diagnostics"].as_array().expect("diagnostics array");
    assert!(
        diags
            .iter()
            .any(|d| d.get("code") == Some(&Value::from("E_LOCK_TARGET_REQUIRED"))),
        "expected E_LOCK_TARGET_REQUIRED diagnostic code"
    );
    assert!(
        diags.iter().any(|d| d
            .get("suggestion")
            .and_then(Value::as_str)
            .is_some_and(|hint| hint.contains("--script") && hint.contains("pyproject.toml"))),
        "expected suggestion mentioning --script and pyproject.toml"
    );
}

#[test]
fn upgrade_outputs_drift_warning_for_placeholder_hash_lockfiles() {
    let temp = tempdir().unwrap();
    let index_path = temp.path().join("index.json");
    let lock_path = temp.path().join("pybun.lockb");

    fs::write(
        temp.path().join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["pkg-a>=1.0.0"]
"#,
    )
    .unwrap();

    fs::write(
        &index_path,
        r#"[
  {
    "name": "pkg-a",
    "version": "1.0.0",
    "dependencies": [],
    "wheels": [
      {
        "file": "pkg_a-1.0.0-py3-none-any.whl",
        "hash": "sha256:hash1"
      }
    ]
  }
]"#,
    )
    .unwrap();

    let mut lock = Lockfile::new(vec!["3.11".into()], vec!["any".into()]);
    lock.add_package(Package {
        name: "pkg-a".into(),
        version: "1.0.0".into(),
        source: PackageSource::Registry {
            index: "pypi".into(),
            url: "https://pypi.org/simple".into(),
        },
        wheel: "pkg_a-1.0.0-py3-none-any.whl".into(),
        hash: "sha256:placeholder".into(),
        dependencies: vec![],
    });
    lock.save_to_path(&lock_path).unwrap();

    let output = bin()
        .current_dir(temp.path())
        .args([
            "upgrade",
            "--index",
            index_path.to_str().unwrap(),
            "--dry-run",
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
    let diags = parsed["diagnostics"].as_array().expect("diagnostics array");
    assert!(
        diags
            .iter()
            .any(|d| d.get("code") == Some(&Value::from("W_LOCK_PLACEHOLDER_HASH"))),
        "expected W_LOCK_PLACEHOLDER_HASH diagnostic code"
    );
}

fn index_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index.json")
}

fn index_conflict_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_conflict.json")
}

fn index_missing_hash_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_missing_hash.json")
}

// ---------------------------------------------------------------------------
// Issue #341: when only pre-release versions satisfy the constraints and the
// user did not opt in via `--pre`, the resolver falls back to the pre-release
// but the selection must be surfaced as a `W_PRERELEASE_SELECTED` warning
// diagnostic instead of being silent.
// ---------------------------------------------------------------------------

fn index_prerelease_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_prerelease.json")
}

#[test]
fn install_prerelease_fallback_outputs_w_prerelease_selected_diagnostic() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_prerelease_path();

    let output = bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "prelib",
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

    assert_eq!(parsed["status"], "ok");

    // The only available version (a pre-release) is still installed.
    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let prelib = lock.packages.get("prelib").expect("prelib entry");
    assert_eq!(prelib.version, "0.9.0b1");

    let diags = parsed["diagnostics"].as_array().expect("diagnostics array");
    let pre_diag = diags
        .iter()
        .find(|d| d.get("code") == Some(&Value::from("W_PRERELEASE_SELECTED")))
        .expect("expected W_PRERELEASE_SELECTED diagnostic");

    assert_eq!(pre_diag["level"], "warning");
    let message = pre_diag["message"].as_str().expect("message string");
    assert!(
        message.contains("prelib") && message.contains("0.9.0b1"),
        "diagnostic message should name the package and pre-release version: {message}"
    );
    assert_eq!(pre_diag["context"]["package"], "prelib");
    assert_eq!(pre_diag["context"]["version"], "0.9.0b1");
}

#[test]
fn install_with_pre_flag_does_not_emit_prerelease_diagnostic() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_prerelease_path();

    let output = bin()
        .args([
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "prelib",
            "--pre",
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

    assert_eq!(parsed["status"], "ok");
    let diags = parsed["diagnostics"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !diags
            .iter()
            .any(|d| d.get("code") == Some(&Value::from("W_PRERELEASE_SELECTED"))),
        "explicit --pre opt-in must not produce the fallback warning: {diags:?}"
    );
}
