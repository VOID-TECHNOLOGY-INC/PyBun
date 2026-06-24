//! Tests for `pybun doctor --fix` / `--apply` self-healing remediation (Issue #118)

use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn pybun_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pybun"))
}

/// Write a `.bin` file that fails to deserialize as a `CacheEntry`, matching
/// `pypi::is_stale_pypi_cache_entry`'s definition of a stale cache file.
fn write_stale_pypi_cache_entry(dir: &std::path::Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("stale-package.bin"),
        b"not a valid bincode payload",
    )
    .unwrap();
}

#[test]
fn doctor_fix_help_shows_fix_and_apply_flags() {
    let output = pybun_bin().args(["doctor", "--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--fix"),
        "doctor --help should mention --fix"
    );
    assert!(
        stdout.contains("--apply"),
        "doctor --help should mention --apply"
    );
}

#[test]
fn doctor_apply_without_fix_is_rejected() {
    let output = pybun_bin().args(["doctor", "--apply"]).output().unwrap();
    assert!(
        !output.status.success(),
        "--apply without --fix should fail"
    );
}

#[test]
fn doctor_fix_reports_empty_plan_when_healthy() {
    let temp = tempdir().unwrap();
    let pypi_cache = temp.path().join("pypi-cache");
    fs::create_dir_all(&pypi_cache).unwrap();

    let output = pybun_bin()
        .env("PYBUN_PYPI_CACHE_DIR", &pypi_cache)
        .args(["--format=json", "doctor", "--fix"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["command"], "pybun doctor");
    let fix_plan = json["detail"]["fix_plan"]
        .as_array()
        .expect("fix_plan should be an array");
    assert!(fix_plan.is_empty(), "no issues -> empty fix plan");
}

#[test]
fn doctor_fix_surfaces_stale_pypi_cache_remediation() {
    let temp = tempdir().unwrap();
    let pypi_cache = temp.path().join("pypi-cache");
    write_stale_pypi_cache_entry(&pypi_cache);

    let output = pybun_bin()
        .env("PYBUN_PYPI_CACHE_DIR", &pypi_cache)
        .args(["--format=json", "doctor", "--fix"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let fix_plan = json["detail"]["fix_plan"]
        .as_array()
        .expect("fix_plan should be an array");
    assert_eq!(
        fix_plan.len(),
        1,
        "stale cache entry should yield one fix-plan item"
    );

    let candidates = fix_plan[0]["fix_candidates"]
        .as_array()
        .expect("fix_candidates should be an array");
    assert_eq!(candidates[0]["command"], "pybun gc");
    assert_eq!(candidates[0]["risk"], "low");
    assert_eq!(candidates[0]["auto_applicable"], true);

    // The stale cache file must still exist: `--fix` alone never mutates state.
    assert!(
        pypi_cache.join("stale-package.bin").exists(),
        "dry-run --fix must not delete anything"
    );

    // Diagnostics array should also carry the structured fix candidate.
    let diagnostics = json["diagnostics"]
        .as_array()
        .expect("diagnostics should be an array");
    assert!(
        diagnostics
            .iter()
            .any(|d| d["code"] == "I_DOCTOR_STALE_PYPI_CACHE" && d["fix_candidates"].is_array()),
        "diagnostics should include the stale-cache fix candidate"
    );
}

#[test]
fn doctor_fix_apply_removes_stale_pypi_cache_entry() {
    let temp = tempdir().unwrap();
    let pypi_cache = temp.path().join("pypi-cache");
    write_stale_pypi_cache_entry(&pypi_cache);

    let output = pybun_bin()
        .env("PYBUN_PYPI_CACHE_DIR", &pypi_cache)
        .args(["--format=json", "doctor", "--fix", "--apply"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let applied = json["detail"]["applied_fixes"]
        .as_array()
        .expect("applied_fixes should be an array");
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0]["command"], "pybun gc");
    assert_eq!(applied[0]["applied"], true);
    assert_eq!(applied[0]["files_removed"], 1);

    assert!(
        !pypi_cache.join("stale-package.bin").exists(),
        "--fix --apply should have removed the stale cache entry"
    );
}
