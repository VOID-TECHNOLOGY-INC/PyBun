use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

fn write_pyproject(path: &Path, deps: &[&str]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let deps_toml = deps
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let content = format!(
        r#"[project]
name = "{name}"
version = "0.1.0"
dependencies = [{deps}]
"#,
        name = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("root"),
        deps = deps_toml
    );
    fs::write(path, content).unwrap();
}

#[test]
fn workspace_install_resolves_member_dependencies() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let root_pyproject = root.join("pyproject.toml");

    // Workspace with two member projects.
    let members = ["packages/app1", "packages/app2"];
    let members_toml = members
        .iter()
        .map(|m| format!("\"{m}\""))
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(
        &root_pyproject,
        format!(
            r#"[tool.pybun.workspace]
members = [{members}]
"#,
            members = members_toml
        ),
    )
    .unwrap();

    write_pyproject(
        &root.join("packages/app1/pyproject.toml"),
        &["lib-a==1.0.0"],
    );
    write_pyproject(
        &root.join("packages/app2/pyproject.toml"),
        &["lib-b==2.0.0"],
    );

    let index = Path::new("tests/fixtures/index.json")
        .canonicalize()
        .unwrap();

    bin()
        .current_dir(root)
        .args([
            "--format=json",
            "install",
            "--index",
            index.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"packages\""))
        .stdout(predicate::str::contains("lib-a"))
        .stdout(predicate::str::contains("lib-b"));

    assert!(
        root.join("pybun.lockb").exists(),
        "lockfile should be created"
    );
}

#[test]
fn workspace_install_handles_root_plus_member_deps() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let root_pyproject = root.join("pyproject.toml");

    fs::write(
        &root_pyproject,
        r#"[project]
name = "root"
version = "0.1.0"
dependencies = ["lib-c==1.0.0"]

[tool.pybun.workspace]
members = ["packages/app"]
"#,
    )
    .unwrap();

    write_pyproject(&root.join("packages/app/pyproject.toml"), &["lib-a==1.0.0"]);

    let index = Path::new("tests/fixtures/index.json")
        .canonicalize()
        .unwrap();

    let output = bin()
        .current_dir(root)
        .args([
            "--format=json",
            "install",
            "--index",
            index.to_str().unwrap(),
        ])
        .output()
        .expect("run pybun install");

    assert!(
        output.status.success(),
        "install should succeed: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("lib-a"),
        "member dependency should be resolved"
    );
    assert!(
        stdout.contains("lib-c"),
        "root dependency should be resolved"
    );
}
