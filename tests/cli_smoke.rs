use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn help_lists_core_commands() {
    let assert = bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("pybun"))
        .stdout(contains("run"))
        .stdout(contains("install"))
        .stdout(contains("add"))
        .stdout(contains("remove"))
        .stdout(contains("test"))
        .stdout(contains("build"))
        .stdout(contains("doctor"))
        .stdout(contains("mcp"))
        .stdout(contains("self"))
        .stdout(contains("gc"));

    assert.stdout(contains("sandbox").or(contains("--sandbox")));
}

#[test]
fn version_is_reported() {
    bin()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn subcommand_help_is_available() {
    for sub in [
        "install", "add", "remove", "run", "x", "test", "build", "doctor", "mcp", "self", "gc",
    ] {
        bin().args([sub, "--help"]).assert().success();
    }
}

#[test]
fn help_supports_json_format() {
    let assert = bin().args(["--help", "--format=json"]).assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON output");

    assert_eq!(value["version"], "1");
    assert_eq!(value["command"], "pybun --help");
    assert_eq!(value["status"], "ok");
    assert_eq!(value["detail"]["name"], "pybun");
    assert!(
        value["detail"]["subcommands"]
            .as_array()
            .expect("subcommands array")
            .iter()
            .any(|s| s["name"] == "install"),
        "expected install subcommand to be listed: {value}"
    );
}

#[test]
fn subcommand_help_supports_json_format() {
    let assert = bin()
        .args(["install", "--format", "json", "--help"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON output");

    assert_eq!(value["command"], "pybun install --help");
    assert_eq!(value["detail"]["name"], "install");
    assert!(
        value["detail"]["args"]
            .as_array()
            .expect("args array")
            .iter()
            .any(|a| a["name"] == "offline"),
        "expected offline arg to be listed: {value}"
    );
}

#[test]
fn text_format_help_is_unaffected() {
    bin()
        .args(["--help"])
        .assert()
        .success()
        .stdout(contains("Usage: pybun"))
        .stdout(contains("\"version\"").not());
}
