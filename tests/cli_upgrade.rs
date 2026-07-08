use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use pybun::lockfile::{Lockfile, Package, PackageSource};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
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

// =============================================================================
// Issue #295: `pybun upgrade` selected wheels via PATH python, ignoring the
// target venv — same root cause as #291 (fixed for `pybun install` in #292,
// `pybun lock` in #293, and `pybun run` in #294).
// =============================================================================

fn index_cp_tag_mismatch_path() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index_cp_tag_mismatch.json")
}

/// Create a fake venv whose `bin/python` (or `Scripts/python.exe` on Windows)
/// reports a controlled `--version` output, independent of any real Python
/// installation on the host or on PATH.
#[cfg(unix)]
fn fake_venv_reporting_version(root: &Path, version_line: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let venv_dir = root.join(".fake-venv");
    let bin_dir = venv_dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let python = bin_dir.join("python");
    let mut file = fs::File::create(&python).unwrap();
    use std::io::Write;
    writeln!(file, "#!/bin/sh\necho '{version_line}'").unwrap();
    let mut perms = file.metadata().unwrap().permissions();
    perms.set_mode(0o755);
    file.set_permissions(perms).unwrap();

    fs::write(venv_dir.join("pyvenv.cfg"), "version = 3.12.5\n").unwrap();

    venv_dir
}

#[cfg(unix)]
#[test]
fn upgrade_selects_wheel_for_target_venv_python_not_path_python() {
    // Regression test for Issue #295: `pybun upgrade` re-resolves dependencies and
    // rewrites pybun.lockb using select_artifact_for_platform(), which shells out to
    // whatever python3/python resolves on PATH, ignoring the project's actual venv.
    // Seed a lockfile that already recorded a (mismatched) cp311 wheel, then run
    // `upgrade` against a fake venv that reports Python 3.12.5 — a passing test
    // proves upgrade now consults the *venv's* interpreter, not PATH, when
    // re-selecting wheels to record.
    let temp = TempDir::new().unwrap();
    let project_root = temp.path();
    let index = index_cp_tag_mismatch_path();
    let lock_path = project_root.join("pybun.lockb");
    let venv = fake_venv_reporting_version(project_root, "Python 3.12.5");

    fs::write(
        project_root.join("pyproject.toml"),
        r#"
[project]
name = "cp-tag-test"
version = "0.1.0"
dependencies = [
    "verpkg==1.0.0"
]
"#,
    )
    .unwrap();

    // Seed an existing lockfile recording the (mismatched) cp311 wheel, as if a
    // prior `install`/`lock` had run against a PATH python reporting 3.11.
    let mut seed_lock = Lockfile::new(vec!["3.11".into()], vec!["any".into()]);
    seed_lock.add_package(Package {
        name: "verpkg".to_string(),
        version: "1.0.0".to_string(),
        source: PackageSource::Registry {
            index: "pypi".to_string(),
            url: index.display().to_string(),
        },
        wheel: "verpkg-1.0.0-cp311-cp311-any.whl".to_string(),
        hash: "sha256:verpkgcp311".to_string(),
        dependencies: vec![],
    });
    seed_lock.save_to_path(&lock_path).unwrap();

    bin()
        .current_dir(project_root)
        .env("PYBUN_ENV", &venv)
        .env_remove("PYBUN_FORCE_CP_TAG")
        .args([
            "--format=json",
            "upgrade",
            "--index",
            index.to_str().unwrap(),
        ])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(&lock_path).expect("lock loads");
    let pkg = lock.packages.get("verpkg").expect("entry exists");
    assert_eq!(
        pkg.wheel, "verpkg-1.0.0-cp312-cp312-any.whl",
        "should record the cp312 wheel matching the target venv's Python 3.12, \
         not whatever python3/python resolves to on PATH"
    );
}
