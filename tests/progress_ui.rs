use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::tempdir;

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
}

fn index_path() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    std::path::Path::new(&manifest_dir)
        .join("tests")
        .join("fixtures")
        .join("index.json")
}

#[test]
fn progress_is_suppressed_for_json_output() {
    let assert = pybun()
        .args(["--format=json", "--progress=always", "schema", "print"])
        .assert()
        .success();

    let output = assert.get_output();
    assert!(
        output.stderr.is_empty(),
        "progress UI should be disabled for JSON format"
    );
}

#[test]
fn no_progress_flag_disables_renderer() {
    let assert = pybun()
        .args(["--progress=always", "--no-progress", "schema", "print"])
        .assert()
        .success();

    let output = assert.get_output();
    assert!(
        output.stderr.is_empty(),
        "--no-progress should suppress UI output"
    );
}

#[test]
fn progress_renders_for_install_when_forced() {
    let temp = tempdir().unwrap();
    let lock_path = temp.path().join("pybun.lockb");
    let index = index_path();

    let assert = pybun()
        .args([
            "--progress=always",
            "install",
            "--index",
            index.to_str().unwrap(),
            "--require",
            "app==1.0.0",
            "--lock",
            lock_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("Resolving"),
        "progress should include resolve stage"
    );
    assert!(
        stderr.contains("Downloading"),
        "progress should include download stage"
    );
    assert!(
        stderr.contains("Installing"),
        "progress should include install stage"
    );
}
