use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn upgrade_fails_without_lockfile() {
    let temp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("pybun").unwrap();
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
    let mut cmd = Command::cargo_bin("pybun").unwrap();
    cmd.current_dir(&project_root)
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
    let mut cmd = Command::cargo_bin("pybun").unwrap();
    cmd.current_dir(&project_root)
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
    Command::cargo_bin("pybun")
        .unwrap()
        .current_dir(&project_root)
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
    Command::cargo_bin("pybun")
        .unwrap()
        .current_dir(&project_root)
        .args(["upgrade", "pkg-a", "--index", index_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("pkg-a 1.0.0 -> 2.0.0"))
        .stdout(predicate::str::contains("pkg-b").not()); // pkg-b should NOT be mentioned/upgraded
}
