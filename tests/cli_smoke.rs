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
