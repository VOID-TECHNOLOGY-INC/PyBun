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

fn write_monorepo(root: &Path) {
    fs::write(
        root.join("pyproject.toml"),
        r#"[project]
name = "root"
version = "0.1.0"
dependencies = []

[tool.pybun.workspace]
members = ["packages/api", "packages/sdk"]

[dependency-groups]
dev = ["lib-c==1.0.0"]
"#,
    )
    .unwrap();

    fs::create_dir_all(root.join("packages/api")).unwrap();
    fs::write(
        root.join("packages/api/pyproject.toml"),
        r#"[project]
name = "api"
version = "0.1.0"
dependencies = ["lib-a==1.0.0"]

[project.optional-dependencies]
dev = ["lib-b==2.0.0"]
"#,
    )
    .unwrap();

    write_pyproject(&root.join("packages/sdk/pyproject.toml"), &["lib-b==2.0.0"]);
}

fn fixture_index() -> std::path::PathBuf {
    Path::new("tests/fixtures/index.json")
        .canonicalize()
        .unwrap()
}

#[test]
fn non_workspace_projects_report_workspace_as_null_in_json_detail() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_pyproject(&root.join("pyproject.toml"), &["lib-a==1.0.0"]);

    let index = fixture_index();

    // `install` on a plain (non-workspace) project should still include the
    // "workspace" key, set to null, so JSON consumers don't need to special
    // case "key present" vs "key absent" depending on subcommand.
    let install_output = bin()
        .current_dir(root)
        .args([
            "--format=json",
            "install",
            "--index",
            index.to_str().unwrap(),
        ])
        .output()
        .expect("run pybun install");
    assert!(install_output.status.success());
    let install_stdout = String::from_utf8_lossy(&install_output.stdout);
    assert!(
        install_stdout.contains("\"workspace\":null"),
        "non-workspace install detail should report workspace as null: {install_stdout}"
    );

    // `test` (dry-run) without --member should also emit "workspace": null.
    fs::write(
        root.join("test_sample.py"),
        "def test_ok():\n    assert True\n",
    )
    .unwrap();
    let test_output = bin()
        .current_dir(root)
        .env("PYBUN_TEST_DRY_RUN", "1")
        .args(["--format=json", "test"])
        .output()
        .expect("run pybun test");
    assert!(test_output.status.success());
    let test_stdout = String::from_utf8_lossy(&test_output.stdout);
    assert!(
        test_stdout.contains("\"workspace\":null"),
        "non-workspace test detail should report workspace as null: {test_stdout}"
    );
}

#[test]
fn workspace_install_with_member_selector_scopes_to_member() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_monorepo(root);

    let index = fixture_index();

    let output = bin()
        .current_dir(root)
        .args([
            "--format=json",
            "install",
            "--member",
            "api",
            "--index",
            index.to_str().unwrap(),
        ])
        .output()
        .expect("run pybun install --member");

    assert!(
        output.status.success(),
        "install --member should succeed: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"scope\":\"member\""),
        "json detail should report member scope: {stdout}"
    );
    assert!(
        stdout.contains("\"selected_members\":[\"api\"]"),
        "json detail should record the selected member: {stdout}"
    );
    assert!(
        stdout.contains("lib-a"),
        "member dependency should be resolved: {stdout}"
    );
    assert!(
        !stdout.contains("\"name\":\"lib-b\""),
        "non-selected member dependency should not be installed: {stdout}"
    );
}

#[test]
fn workspace_install_with_member_and_group_selectors_combine() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_monorepo(root);

    let index = fixture_index();

    let output = bin()
        .current_dir(root)
        .args([
            "--format=json",
            "install",
            "--member",
            "api",
            "--group",
            "dev",
            "--index",
            index.to_str().unwrap(),
        ])
        .output()
        .expect("run pybun install --member --group");

    assert!(
        output.status.success(),
        "install --member --group should succeed: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"scope\":\"member\""),
        "json detail should report member scope: {stdout}"
    );
    assert!(
        stdout.contains("\"group\":\"dev\""),
        "json detail should record the selected group: {stdout}"
    );
    assert!(
        stdout.contains("lib-b"),
        "member's optional-dependencies group should be resolved: {stdout}"
    );
}

#[test]
fn workspace_install_with_group_selector_merges_across_members() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_monorepo(root);

    let index = fixture_index();

    let output = bin()
        .current_dir(root)
        .args([
            "--format=json",
            "install",
            "--group",
            "dev",
            "--index",
            index.to_str().unwrap(),
        ])
        .output()
        .expect("run pybun install --group");

    assert!(
        output.status.success(),
        "install --group should succeed: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"scope\":\"group\""),
        "json detail should report group scope: {stdout}"
    );
    assert!(
        stdout.contains("\"selected_members\":[\"api\",\"sdk\"]"),
        "json detail should list every member contributing to the group: {stdout}"
    );
    assert!(
        stdout.contains("lib-b") && stdout.contains("lib-c"),
        "group dependencies from root and members should be merged: {stdout}"
    );
}

#[test]
fn workspace_install_with_workspace_flag_requires_workspace_config() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_pyproject(&root.join("pyproject.toml"), &["lib-a==1.0.0"]);

    let index = fixture_index();

    bin()
        .current_dir(root)
        .args([
            "--format=json",
            "install",
            "--workspace",
            "--index",
            index.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("[tool.pybun.workspace]"));
}

#[test]
fn workspace_install_with_unknown_member_reports_available_members() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_monorepo(root);

    let index = fixture_index();

    bin()
        .current_dir(root)
        .args([
            "--format=json",
            "install",
            "--member",
            "missing",
            "--index",
            index.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(
            predicate::str::contains("workspace member 'missing' not found")
                .and(predicate::str::contains("api"))
                .and(predicate::str::contains("sdk")),
        );
}

#[test]
fn test_command_with_member_selector_scopes_discovery_to_member_root() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_monorepo(root);

    // Add a test file inside the `api` member and a sibling member that
    // should be excluded when `--member api` scopes discovery.
    fs::write(
        root.join("packages/api/test_api.py"),
        "def test_ok():\n    assert True\n",
    )
    .unwrap();
    fs::write(
        root.join("packages/sdk/test_sdk.py"),
        "def test_ok():\n    assert True\n",
    )
    .unwrap();

    let output = bin()
        .current_dir(root)
        .env("PYBUN_TEST_DRY_RUN", "1")
        .args(["--format=json", "test", "--member", "api"])
        .output()
        .expect("run pybun test --member");

    assert!(
        output.status.success(),
        "test --member should succeed: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"scope\":\"member\""),
        "json detail should report member scope: {stdout}"
    );
    assert!(
        stdout.contains("\"selected_members\":[\"api\"]"),
        "json detail should record the selected member: {stdout}"
    );
    assert!(
        stdout.contains("test_api.py"),
        "discovery should include the member's own test file: {stdout}"
    );
    assert!(
        !stdout.contains("test_sdk.py"),
        "discovery should not include sibling member test files: {stdout}"
    );
}

#[test]
fn test_command_with_unknown_member_reports_available_members() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_monorepo(root);

    bin()
        .current_dir(root)
        .env("PYBUN_TEST_DRY_RUN", "1")
        .args(["--format=json", "test", "--member", "missing"])
        .assert()
        .failure()
        .stdout(
            predicate::str::contains("workspace member 'missing' not found")
                .and(predicate::str::contains("api"))
                .and(predicate::str::contains("sdk")),
        );
}

#[test]
fn outdated_with_member_selector_scopes_constraints_to_member() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_monorepo(root);

    let index = fixture_index();

    // Create a lockfile to check against.
    bin()
        .current_dir(root)
        .args(["install", "--index", index.to_str().unwrap()])
        .assert()
        .success();

    let output = bin()
        .current_dir(root)
        .args([
            "--format=json",
            "outdated",
            "--member",
            "api",
            "--index",
            index.to_str().unwrap(),
        ])
        .output()
        .expect("run pybun outdated --member");

    assert!(
        output.status.success(),
        "outdated --member should succeed: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"scope\":\"member\""),
        "json detail should report member scope: {stdout}"
    );
    assert!(
        stdout.contains("\"selected_members\":[\"api\"]"),
        "json detail should record the selected member: {stdout}"
    );
}

#[test]
fn outdated_with_group_selector_merges_across_members() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_monorepo(root);

    let index = fixture_index();

    bin()
        .current_dir(root)
        .args(["install", "--index", index.to_str().unwrap()])
        .assert()
        .success();

    let output = bin()
        .current_dir(root)
        .args([
            "--format=json",
            "outdated",
            "--group",
            "dev",
            "--index",
            index.to_str().unwrap(),
        ])
        .output()
        .expect("run pybun outdated --group");

    assert!(
        output.status.success(),
        "outdated --group should succeed: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"scope\":\"group\""),
        "json detail should report group scope: {stdout}"
    );
    assert!(
        stdout.contains("\"selected_members\":[\"api\",\"sdk\"]"),
        "json detail should list every member contributing to the group: {stdout}"
    );
}

#[test]
fn upgrade_with_member_selector_scopes_to_member_dependencies() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_monorepo(root);

    let index = fixture_index();

    bin()
        .current_dir(root)
        .args(["install", "--index", index.to_str().unwrap()])
        .assert()
        .success();

    let output = bin()
        .current_dir(root)
        .args([
            "--format=json",
            "upgrade",
            "--member",
            "api",
            "--index",
            index.to_str().unwrap(),
        ])
        .output()
        .expect("run pybun upgrade --member");

    assert!(
        output.status.success(),
        "upgrade --member should succeed: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"scope\":\"member\""),
        "json detail should report member scope: {stdout}"
    );
    assert!(
        stdout.contains("\"selected_members\":[\"api\"]"),
        "json detail should record the selected member: {stdout}"
    );
}

#[test]
fn upgrade_with_unknown_group_falls_back_to_empty_dependency_set() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    write_monorepo(root);

    let index = fixture_index();

    bin()
        .current_dir(root)
        .args(["install", "--index", index.to_str().unwrap()])
        .assert()
        .success();

    bin()
        .current_dir(root)
        .args([
            "--format=json",
            "upgrade",
            "--group",
            "missing",
            "--index",
            index.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"upgraded\":[]"))
        .stdout(predicate::str::contains("\"scope\":\"group\""));
}
