use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn bin() -> Command {
    let mut command = cargo_bin_cmd!("pybun");
    command.env("PYBUN_BACKEND", "native");
    command
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

#[test]
fn workspace_conflicts_preserve_every_member_constraint_and_provenance() {
    for root_conflict in [false, true] {
        for reversed in [false, true] {
            for group in [false, true] {
                let temp = tempdir().unwrap();
                let root = temp.path();
                let members = if reversed { "['b', 'a']" } else { "['a', 'b']" };
                let declarations = |name: &str, spec: &str| {
                    if group {
                        format!("[project]\nname='{name}'\n[dependency-groups]\ndev=['{spec}']\n")
                    } else {
                        format!("[project]\nname='{name}'\ndependencies=['{spec}']\n")
                    }
                };
                let root_spec = if root_conflict {
                    "demo==1.0"
                } else {
                    "other==1.0"
                };
                fs::write(
                    root.join("pyproject.toml"),
                    format!(
                        "{}\n[tool.pybun.workspace]\nmembers={members}\n",
                        declarations("root", root_spec)
                    ),
                )
                .unwrap();
                for (name, spec) in [("a", "demo==2.0"), ("b", "demo==1.0")] {
                    fs::create_dir(root.join(name)).unwrap();
                    fs::write(
                        root.join(name).join("pyproject.toml"),
                        declarations(name, spec),
                    )
                    .unwrap();
                }
                let index: Vec<_> = [("demo", "1.0"), ("demo", "2.0"), ("other", "1.0")].into_iter().map(|(name, version)| serde_json::json!({"name":name,"version":version,"dependencies":[],"wheels":[{"file":format!("{name}-{version}-py3-none-any.whl"),"hash":format!("sha256:{}", "0".repeat(64))}]})).collect();
                fs::write(root.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();
                let mut command = bin();
                command.current_dir(root).args([
                    "--format=json",
                    "install",
                    "--workspace",
                    "--index",
                    "index.json",
                ]);
                if group {
                    command.args(["--group", "dev"]);
                }
                let output = command.output().unwrap();
                assert!(!output.status.success(), "constraints must conflict");
                assert!(!root.join("pybun.lockb").exists());
                let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                let error = value["diagnostics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|d| d["code"] == "E_RESOLVE_CONFLICT")
                    .expect("conflict diagnostic");
                let context = error["context"].to_string();
                assert!(
                    context.contains("demo==1.0") && context.contains("demo==2.0"),
                    "{error}"
                );
                assert!(
                    context.contains("pyproject.toml"),
                    "must include declaration provenance: {error}"
                );
            }
        }
    }
}

#[test]
fn workspace_overlaps_normalized_names_markers_and_extras_resolve_together() {
    for group in [false, true] {
        let temp = tempdir().unwrap();
        let root = temp.path();
        for (name, deps) in [
            ("root", vec!["Demo_pkg>=1.0"]),
            ("a", vec!["demo.pkg[fast]>=2.0"]),
            (
                "b",
                vec!["demo-pkg<3.0", "demo-pkg==9.0; python_version < '0'"],
            ),
        ] {
            let dir = if name == "root" {
                root.to_path_buf()
            } else {
                root.join(name)
            };
            fs::create_dir_all(&dir).unwrap();
            let deps_toml = deps
                .iter()
                .map(|d| format!("\"{d}\""))
                .collect::<Vec<_>>()
                .join(",");
            let declaration = if group {
                format!("[dependency-groups]\ndev=[{deps_toml}]\n")
            } else {
                format!("dependencies=[{deps_toml}]\n")
            };
            let workspace = if name == "root" {
                "[tool.pybun.workspace]\nmembers=['b','a']\n"
            } else {
                ""
            };
            fs::write(
                dir.join("pyproject.toml"),
                format!("[project]\nname='{name}'\n{declaration}\n{workspace}"),
            )
            .unwrap();
        }
        let index:Vec<_>=["1.0","2.0","3.0"].into_iter().map(|v|serde_json::json!({"name":"demo-pkg","version":v,"dependencies":[],"wheels":[{"file":format!("demo_pkg-{v}-py3-none-any.whl"),"hash":format!("sha256:{}","0".repeat(64))}]})).collect();
        fs::write(root.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();
        let mut command = bin();
        command.current_dir(root).args([
            "--format=json",
            "install",
            "--workspace",
            "--index",
            "index.json",
        ]);
        if group {
            command.args(["--group", "dev"]);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let lock = pybun::lockfile::Lockfile::load_from_path(root.join("pybun.lockb")).unwrap();
        assert_eq!(lock.packages.len(), 1);
        assert_eq!(lock.packages["demo-pkg"].name, "demo-pkg");
        assert_eq!(lock.packages["demo-pkg"].version, "2.0");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            value["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["code"] == "W_EXTRAS_IGNORED")
        );
    }
}
