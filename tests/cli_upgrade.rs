use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use pybun::lockfile::{Lockfile, PackageSource};
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn upgrade_fails_without_lockfile() {
    let temp = TempDir::new().unwrap();
    let mut cmd = bin();
    cmd.current_dir(&temp)
        .arg("upgrade")
        .assert()
        .failure()
        .stdout(predicate::str::contains("lockfile not found"));
}

#[test]
fn upgrade_full() {
    let temp = TempDir::new().unwrap();
    let project_root = temp.path();

    // 1. Create pyproject.toml
    let pyproject = r#"
[project]
name = "test-project"
version = "0.1.0"
dependencies = [
    "pkg-a>=1.0.0"
]
"#;
    fs::write(project_root.join("pyproject.toml"), pyproject).unwrap();

    // 2. Create initial index.json with v1.0.0
    let index_v1 = r#"[
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
]"#;
    let index_path = project_root.join("index.json");
    fs::write(&index_path, index_v1).unwrap();

    // 3. Install v1.0.0
    let mut cmd = bin();
    cmd.current_dir(project_root)
        .arg("install")
        .arg("--index")
        .arg(&index_path)
        .assert()
        .success();

    // 4. Update index.json to include v2.0.0
    let index_v2 = r#"[
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
  },
  {
    "name": "pkg-a",
    "version": "2.0.0",
    "dependencies": [],
    "wheels": [
      {
        "file": "pkg_a-2.0.0-py3-none-any.whl",
        "hash": "sha256:hash2"
      }
    ]
  }
]"#;
    fs::write(&index_path, index_v2).unwrap();

    // 5. Upgrade
    let mut cmd = bin();
    cmd.current_dir(project_root)
        .arg("upgrade")
        .arg("--index")
        .arg(&index_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("pkg-a 1.0.0 -> 2.0.0"));
}

#[test]
fn upgrade_partial() {
    let temp = TempDir::new().unwrap();
    let project_root = temp.path();

    // 1. Create pyproject.toml with 2 deps
    let pyproject = r#"
[project]
name = "test-project"
version = "0.1.0"
dependencies = [
    "pkg-a",
    "pkg-b"
]
"#;
    fs::write(project_root.join("pyproject.toml"), pyproject).unwrap();

    // 2. Initial index with v1 for both
    let index_v1 = r#"[
  {
    "name": "pkg-a",
    "version": "1.0.0",
    "dependencies": [],
    "wheels": [{"file": "pkg_a-1.0.0.whl", "hash": "sha256:a1"}]
  },
  {
    "name": "pkg-b",
    "version": "1.0.0",
    "dependencies": [],
    "wheels": [{"file": "pkg_b-1.0.0.whl", "hash": "sha256:b1"}]
  }
]"#;
    let index_path = project_root.join("index.json");
    fs::write(&index_path, index_v1).unwrap();

    // 3. Install
    bin()
        .current_dir(project_root)
        .args(["install", "--index", index_path.to_str().unwrap()])
        .assert()
        .success();

    // 4. Update index with v2 for both
    let index_v2 = r#"[
  {
    "name": "pkg-a",
    "version": "1.0.0",
    "dependencies": [],
    "wheels": [{"file": "pkg_a-1.0.0.whl", "hash": "sha256:a1"}]
  },
  {
    "name": "pkg-b",
    "version": "1.0.0",
    "dependencies": [],
    "wheels": [{"file": "pkg_b-1.0.0.whl", "hash": "sha256:b1"}]
  },
  {
    "name": "pkg-a",
    "version": "2.0.0",
    "dependencies": [],
    "wheels": [{"file": "pkg_a-2.0.0.whl", "hash": "sha256:a2"}]
  },
  {
    "name": "pkg-b",
    "version": "2.0.0",
    "dependencies": [],
    "wheels": [{"file": "pkg_b-2.0.0.whl", "hash": "sha256:b2"}]
  }
]"#;
    fs::write(&index_path, index_v2).unwrap();

    // 5. Partial upgrade ONLY pkg-a
    bin()
        .current_dir(project_root)
        .args(["upgrade", "pkg-a", "--index", index_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("pkg-a 1.0.0 -> 2.0.0"))
        .stdout(predicate::str::contains("pkg-b").not()); // pkg-b should NOT be mentioned/upgraded
}

#[test]
fn upgrade_with_local_index_preserves_registry_source_url() {
    let temp = TempDir::new().unwrap();
    let project_root = temp.path();

    fs::write(
        project_root.join("pyproject.toml"),
        r#"
[project]
name = "test-project"
version = "0.1.0"
dependencies = [
    "pkg-a>=1.0.0"
]
"#,
    )
    .unwrap();

    let index_path = project_root.join("index.json");
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

    bin()
        .current_dir(project_root)
        .args(["install", "--index", index_path.to_str().unwrap()])
        .assert()
        .success();

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
  },
  {
    "name": "pkg-a",
    "version": "2.0.0",
    "dependencies": [],
    "wheels": [
      {
        "file": "pkg_a-2.0.0-py3-none-any.whl",
        "hash": "sha256:hash2"
      }
    ]
  }
]"#,
    )
    .unwrap();

    bin()
        .current_dir(project_root)
        .args(["upgrade", "--index", index_path.to_str().unwrap()])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(project_root.join("pybun.lockb")).unwrap();
    let pkg = lock.packages.get("pkg-a").expect("pkg-a in lockfile");
    assert_eq!(pkg.version, "2.0.0");
    match &pkg.source {
        PackageSource::Registry { index, url } => {
            assert_eq!(index, "pypi");
            assert_eq!(url, &index_path.display().to_string());
        }
        other => panic!("expected registry source, got {other:?}"),
    }
}

#[test]
fn upgrade_fails_when_new_artifact_is_missing_hash() {
    let temp = TempDir::new().unwrap();
    let project_root = temp.path();

    fs::write(
        project_root.join("pyproject.toml"),
        r#"
[project]
name = "test-project"
version = "0.1.0"
dependencies = [
    "pkg-a>=1.0.0"
]
"#,
    )
    .unwrap();

    let index_v1 = r#"[
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
]"#;
    let index_path = project_root.join("index.json");
    fs::write(&index_path, index_v1).unwrap();

    bin()
        .current_dir(project_root)
        .arg("install")
        .arg("--index")
        .arg(&index_path)
        .assert()
        .success();

    let before = fs::read(project_root.join("pybun.lockb")).unwrap();

    let index_v2_missing_hash = r#"[
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
  },
  {
    "name": "pkg-a",
    "version": "2.0.0",
    "dependencies": [],
    "wheels": [
      {
        "file": "pkg_a-2.0.0-py3-none-any.whl"
      }
    ]
  }
]"#;
    fs::write(&index_path, index_v2_missing_hash).unwrap();

    bin()
        .current_dir(project_root)
        .args(["upgrade", "--index", index_path.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("missing sha256"));

    let after = fs::read(project_root.join("pybun.lockb")).unwrap();
    assert_eq!(
        before, after,
        "upgrade should keep the existing lockfile when verification fails"
    );
}

/// Regression test for Issue #261: `pybun outdated` and `pybun upgrade --dry-run`
/// gave contradictory answers about which packages have available updates.
///
/// Root cause: `upgrade --dry-run`'s JSON `detail.artifacts` array listed every
/// resolved package (changed or not), while `outdated`'s `detail.outdated` array
/// (correctly) only lists packages whose version actually changed. An agent
/// gating on `outdated` before deciding whether to run `upgrade` could get a
/// false negative because `outdated` looked "up to date" while `upgrade
/// --dry-run`'s artifacts list contained unrelated, unchanged packages.
///
/// `artifacts` must only include packages that are actually part of the
/// `upgraded` set, matching `outdated`'s definition of "has an update".
#[test]
fn upgrade_dry_run_artifacts_only_list_changed_packages() {
    let temp = TempDir::new().unwrap();
    let project_root = temp.path();

    // Two direct dependencies: pkg-a will get a new version, pkg-c will not.
    fs::write(
        project_root.join("pyproject.toml"),
        r#"
[project]
name = "test-project"
version = "0.1.0"
dependencies = [
    "pkg-a",
    "pkg-c"
]
"#,
    )
    .unwrap();

    let index_path = project_root.join("index.json");
    fs::write(
        &index_path,
        r#"[
  {"name": "pkg-a", "version": "1.0.0", "dependencies": [], "wheels": [{"file": "pkg_a-1.0.0-py3-none-any.whl", "hash": "sha256:a1"}]},
  {"name": "pkg-c", "version": "1.0.0", "dependencies": [], "wheels": [{"file": "pkg_c-1.0.0-py3-none-any.whl", "hash": "sha256:c1"}]}
]"#,
    )
    .unwrap();

    bin()
        .current_dir(project_root)
        .args(["install", "--index", index_path.to_str().unwrap()])
        .assert()
        .success();

    // Only pkg-a gets a new version; pkg-c is unchanged.
    fs::write(
        &index_path,
        r#"[
  {"name": "pkg-a", "version": "1.0.0", "dependencies": [], "wheels": [{"file": "pkg_a-1.0.0-py3-none-any.whl", "hash": "sha256:a1"}]},
  {"name": "pkg-a", "version": "2.0.0", "dependencies": [], "wheels": [{"file": "pkg_a-2.0.0-py3-none-any.whl", "hash": "sha256:a2"}]},
  {"name": "pkg-c", "version": "1.0.0", "dependencies": [], "wheels": [{"file": "pkg_c-1.0.0-py3-none-any.whl", "hash": "sha256:c1"}]}
]"#,
    )
    .unwrap();

    // (A) upgrade --dry-run
    let upgrade_output = bin()
        .current_dir(project_root)
        .args([
            "--format=json",
            "upgrade",
            "--dry-run",
            "--index",
            index_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let upgrade_json: Value = serde_json::from_str(std::str::from_utf8(&upgrade_output).unwrap())
        .expect("valid JSON from upgrade --dry-run");

    let artifact_packages: Vec<&str> = upgrade_json["detail"]["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .map(|a| a["package"].as_str().unwrap())
        .collect();

    // (B) outdated
    let outdated_output = bin()
        .current_dir(project_root)
        .args([
            "--format=json",
            "outdated",
            "--index",
            index_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let outdated_json: Value = serde_json::from_str(std::str::from_utf8(&outdated_output).unwrap())
        .expect("valid JSON from outdated");

    let outdated_packages: Vec<&str> = outdated_json["detail"]["outdated"]
        .as_array()
        .expect("outdated array")
        .iter()
        .map(|o| o["package"].as_str().unwrap())
        .collect();

    // The two commands must agree on which packages have updates available.
    assert_eq!(
        outdated_packages,
        vec!["pkg-a"],
        "outdated should report pkg-a as having an update"
    );
    assert_eq!(
        artifact_packages,
        vec!["pkg-a"],
        "upgrade --dry-run artifacts should only include packages that actually \
         changed (pkg-c is unchanged and must not appear), so it matches `outdated`"
    );
}
