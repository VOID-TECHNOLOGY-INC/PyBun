use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn git(root: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .current_dir(root)
            .args(args)
            .status()
            .unwrap()
            .success()
    );
}

fn project() -> TempDir {
    let temp = tempfile::tempdir().unwrap();
    git(temp.path(), &["init", "-q"]);
    fs::write(temp.path().join("core.py"), "VALUE = 1\n").unwrap();
    fs::write(temp.path().join("bridge.py"), "from core import VALUE\n").unwrap();
    fs::write(
        temp.path().join("test_unexpected.py"),
        "import bridge\ndef test_relevant():\n    assert bridge.VALUE > 0\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("test_other.py"),
        "def test_unrelated():\n    assert False\n",
    )
    .unwrap();
    git(temp.path(), &["add", "."]);
    git(
        temp.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "baseline",
        ],
    );
    temp
}

fn cli(root: &Path, extra: &[&str]) -> (bool, Value) {
    let output = cargo_bin_cmd!("pybun")
        .current_dir(root)
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_PYTHON", "python3")
        .args(["--format=json", "test", "--affected", "--backend=pybun"])
        .args(extra)
        .output()
        .unwrap();
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

fn mcp(root: &Path) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(root)
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_PYTHON", "python3")
        .env(
            "PYBUN_MCP_POLICY",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mcp-permissive-policy.toml"),
        )
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    writeln!(input,"{}",json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}})).unwrap();
    writeln!(input,"{}",json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pybun_test","arguments":{"changed":true}}})).unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    let response: String = String::from_utf8(output.stdout).unwrap();
    let rpc: Value = response
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|v| v["id"] == 2)
        .unwrap();
    serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[test]
fn affected_selection_follows_transitive_imports_in_cli_and_mcp() {
    let temp = project();
    fs::write(temp.path().join("core.py"), "VALUE = 2\n").unwrap();
    let mcp = mcp(temp.path());
    assert_eq!(
        mcp["summary"]["total"], 1,
        "MCP must follow transitive imports: {mcp}"
    );
    let (success, cli) = cli(temp.path(), &[]);
    assert!(success, "{cli}");
    assert_eq!(cli["detail"]["summary"]["total"], 1);
    assert_eq!(
        cli["detail"]["results"][0]["selection_reason"],
        "transitive"
    );
    assert_eq!(mcp["summary"]["total"], 1, "{mcp}");
    assert_eq!(mcp["passed"][0]["selection_reason"], "transitive");
    assert_eq!(cli["detail"]["selection"], mcp["selection"]);
}

#[test]
fn affected_selection_reports_direct_changes_and_no_changes() {
    let temp = project();
    let (success, value) = cli(temp.path(), &["--discover"]);
    assert!(success, "{value}");
    assert!(value["detail"]["selection"].as_array().unwrap().is_empty());
    fs::write(
        temp.path().join("test_new spaced.py"),
        "def test_new():\n    pass\n",
    )
    .unwrap();
    let (success, value) = cli(temp.path(), &["--discover", "--since", "HEAD"]);
    assert!(success, "{value}");
    assert_eq!(
        value["detail"]["selection"][0]["selection_reason"],
        "direct"
    );
}

#[test]
fn affected_selection_falls_back_when_ast_evidence_is_incomplete() {
    let temp = project();
    fs::write(temp.path().join("core.py"), "def broken(\n").unwrap();
    let (success, value) = cli(temp.path(), &["--discover"]);
    assert!(success, "{value}");
    assert_eq!(value["detail"]["selection"].as_array().unwrap().len(), 2);
    assert!(
        value["detail"]["selection"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["selection_reason"] == "conservative")
    );
}

#[test]
fn affected_selection_rejects_invalid_references() {
    let temp = project();
    let (success, value) = cli(temp.path(), &["--since", "missing-reference"]);
    assert!(!success, "{value}");
    assert!(
        value["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "E_TEST_SELECTION")
    );
}

#[test]
fn affected_selection_tracks_fixture_import_closures_in_real_execution() {
    let temp = project();
    fs::write(
        temp.path().join("conftest.py"),
        "import pytest, bridge\n@pytest.fixture\ndef value():\n    return bridge.VALUE\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("test_unexpected.py"),
        "def test_relevant(value):\n    assert value > 0\n",
    )
    .unwrap();
    git(temp.path(), &["add", "."]);
    git(
        temp.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixtures",
        ],
    );
    fs::write(temp.path().join("core.py"), "VALUE=2\n").unwrap();
    let (success, value) = cli(temp.path(), &[]);
    assert!(!success, "{value}");
    assert_eq!(value["detail"]["summary"]["total"], 2);
    assert_eq!(value["detail"]["summary"]["passed"], 1);
    assert_eq!(value["detail"]["summary"]["failed"], 1);
    assert_eq!(
        value["detail"]["results"][0]["selection_reason"],
        "transitive"
    );
    assert!(
        value["detail"]["selection"][0]["chain"]
            .as_array()
            .unwrap()
            .contains(&json!("conftest.py"))
    );
}

#[test]
fn affected_selection_tracks_deleted_modules_and_configuration_changes() {
    let temp = project();
    fs::remove_file(temp.path().join("core.py")).unwrap();
    let (success, value) = cli(temp.path(), &["--discover"]);
    assert!(success, "{value}");
    assert_eq!(value["detail"]["selection"].as_array().unwrap().len(), 1);
    fs::write(temp.path().join("pytest.ini"), "[pytest]\n").unwrap();
    let (success, value) = cli(temp.path(), &["--discover"]);
    assert!(success, "{value}");
    assert_eq!(value["detail"]["selection"].as_array().unwrap().len(), 2);
}

#[test]
fn affected_selection_rejects_missing_git_evidence_and_option_like_refs() {
    let temp = tempfile::tempdir().unwrap();
    let (success, value) = cli(temp.path(), &["--discover"]);
    assert!(!success, "{value}");
    let temp = project();
    let (success, value) = cli(temp.path(), &["--since=--help"]);
    assert!(!success, "{value}");
}

#[cfg(unix)]
#[test]
fn affected_selection_does_not_read_symlinks_outside_the_repository() {
    let temp = project();
    let outside = tempfile::tempdir().unwrap();
    fs::write(
        outside.path().join("core.py"),
        "raise RuntimeError('private content')\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("core.py"),
        temp.path().join("outside.py"),
    )
    .unwrap();
    let (success, value) = cli(temp.path(), &["--discover"]);
    assert!(!success, "{value}");
    assert!(!value.to_string().contains("private content"));
}
