use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use pybun::lockfile::{Lockfile, PackageSource};
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
