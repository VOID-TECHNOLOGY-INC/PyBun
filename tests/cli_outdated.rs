use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use pybun::lockfile::{Lockfile, Package, PackageSource};
use std::fs;
use tempfile::TempDir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn outdated_fails_without_lockfile() {
    let temp = TempDir::new().unwrap();
    let mut cmd = bin();
    cmd.current_dir(&temp)
        .arg("outdated")
        .assert()
        .failure()
        .stdout(predicate::str::contains("pybun.lockb not found"));
}

#[test]
fn outdated_detects_updates() {
    let temp = TempDir::new().unwrap();
    let project_root = temp.path();

    // 1. Create pyproject.toml declaring a constraint that excludes the
    //    latest release, so "wanted" and "latest" diverge.
    let pyproject = r#"
[project]
name = "test-project"
version = "0.1.0"
dependencies = [
    "foo<2.0.0"
]
"#;
    fs::write(project_root.join("pyproject.toml"), pyproject).unwrap();

    // 2. Local JSON index (`load_index_from_path`) with an older and a newer
    //    release of "foo".
    let index_path = project_root.join("index.json");
    let index_json = serde_json::json!([
        {"name": "foo", "version": "1.0.0", "dependencies": []},
        {"name": "foo", "version": "1.5.0", "dependencies": []},
        {"name": "foo", "version": "2.0.0", "dependencies": []},
    ]);
    fs::write(&index_path, serde_json::to_string(&index_json).unwrap()).unwrap();

    // 3. A real binary lockfile pinning "foo" at 1.0.0 (older than both the
    //    constraint-satisfying 1.5.0 and the unconstrained latest 2.0.0).
    let mut lockfile = Lockfile::new(vec![], vec![]);
    lockfile.add_package(Package {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: PackageSource::Registry {
            index: "local".to_string(),
            url: "file:///index/foo".to_string(),
        },
        wheel: "foo-1.0.0-py3-none-any.whl".to_string(),
        hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        dependencies: vec![],
    });
    lockfile
        .save_to_path(project_root.join("pybun.lockb"))
        .unwrap();

    let output = bin()
        .current_dir(project_root)
        .args([
            "--format=json",
            "outdated",
            "--index",
            index_path.to_str().unwrap(),
        ])
        .output()
        .expect("pybun outdated runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "pybun outdated should succeed against a local index: stdout={stdout}\nstderr={stderr}"
    );

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("valid JSON output from outdated");
    assert_eq!(json["status"], "ok");

    let outdated = json["detail"]["outdated"]
        .as_array()
        .expect("outdated array present");
    assert_eq!(
        outdated.len(),
        1,
        "expected exactly one outdated package: {outdated:?}"
    );

    let entry = &outdated[0];
    assert_eq!(entry["package"], "foo");
    assert_eq!(entry["current"], "1.0.0");
    assert_eq!(
        entry["wanted"], "1.5.0",
        "wanted should respect the '<2.0.0' constraint: {entry:?}"
    );
    assert_eq!(
        entry["latest"], "2.0.0",
        "latest should ignore the constraint: {entry:?}"
    );
    // `type` classifies current vs. latest (unconstrained), so a 1.0.0 -> 2.0.0
    // jump is a major update even though the constrained "wanted" is 1.5.0.
    assert_eq!(entry["type"], "major");
}

/// Regression test for Issue #325 (same pattern as #301/#299/#262): a
/// `pybun.lockb` that exists but fails to decode (e.g. truncated by a crash
/// mid-write) must be self-healed - treated as "no current lock" - rather
/// than causing `pybun outdated` to hard-fail with a misleading "Run `pybun
/// install`" suggestion (which won't fix an existing corrupt lockfile).
#[test]
fn outdated_self_heals_from_corrupt_lockfile() {
    let temp = TempDir::new().unwrap();
    let project_root = temp.path();

    let pyproject = r#"
[project]
name = "test-outdated"
version = "0.1.0"
dependencies = ["requests"]
"#;
    fs::write(project_root.join("pyproject.toml"), pyproject).unwrap();

    // Simulate a lockfile corrupted/truncated by a crash mid-write.
    fs::write(
        project_root.join("pybun.lockb"),
        "this is not a valid bincode lockfile, truncated garbage",
    )
    .unwrap();

    let output = bin()
        .current_dir(project_root)
        .args(["--format=json", "outdated"])
        .output()
        .expect("pybun outdated runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "pybun outdated should self-heal past a corrupt pybun.lockb, not fail: \
         stdout={stdout}\nstderr={stderr}"
    );

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("valid JSON output from outdated");
    assert_eq!(json["status"], "ok");

    let diagnostics = json["diagnostics"]
        .as_array()
        .expect("diagnostics array present");
    assert!(
        diagnostics.iter().any(|d| {
            d["message"]
                .as_str()
                .is_some_and(|m| m.contains("pybun.lockb") && m.contains("no current lock"))
        }),
        "expected a self-heal diagnostic about the discarded corrupt lockfile: {diagnostics:?}"
    );

    // Must not claim the lockfile is simply missing.
    assert!(
        !stdout.contains("pybun.lockb not found"),
        "corrupt lockfile should not be reported as missing: {stdout}"
    );
}
