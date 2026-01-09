use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use httpmock::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

fn parse_json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("valid JSON output")
}

#[test]
fn telemetry_status_defaults_to_disabled() {
    let temp = tempdir().unwrap();

    let output = bin()
        .env("PYBUN_HOME", temp.path())
        .args(["telemetry", "status", "--format=json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json = parse_json(&output.stdout);
    assert_eq!(json["detail"]["enabled"], false);
    assert_eq!(json["detail"]["source"], "default");
}

#[test]
fn telemetry_enable_persists_config() {
    let temp = tempdir().unwrap();

    bin()
        .env("PYBUN_HOME", temp.path())
        .args(["telemetry", "enable", "--format=json"])
        .assert()
        .success();

    let output = bin()
        .env("PYBUN_HOME", temp.path())
        .args(["telemetry", "status", "--format=json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json = parse_json(&output.stdout);
    assert_eq!(json["detail"]["enabled"], true);
    assert_eq!(json["detail"]["source"], "config");
}

#[test]
fn telemetry_disabled_by_default_does_not_send() {
    let temp = tempdir().unwrap();
    let server = MockServer::start();
    let endpoint = format!("{}/telemetry", server.base_url());

    let mock = server.mock(|when, then| {
        when.method(POST).path("/telemetry");
        then.status(200);
    });

    bin()
        .env("PYBUN_HOME", temp.path())
        .env("PYBUN_TELEMETRY_ENDPOINT", endpoint)
        .args(["--format=json", "gc"])
        .assert()
        .success();

    assert_eq!(mock.hits(), 0);
}

#[test]
fn telemetry_enabled_sends() {
    let temp = tempdir().unwrap();

    bin()
        .env("PYBUN_HOME", temp.path())
        .args(["telemetry", "enable"])
        .assert()
        .success();

    let server = MockServer::start();
    let endpoint = format!("{}/telemetry", server.base_url());
    let mock = server.mock(|when, then| {
        when.method(POST).path("/telemetry");
        then.status(200);
    });

    bin()
        .env("PYBUN_HOME", temp.path())
        .env("PYBUN_TELEMETRY_ENDPOINT", endpoint)
        .args(["--format=json", "gc"])
        .assert()
        .success();

    assert_eq!(mock.hits(), 1);
}

#[test]
fn telemetry_env_and_flag_precedence() {
    let temp = tempdir().unwrap();

    bin()
        .env("PYBUN_HOME", temp.path())
        .args(["telemetry", "enable"])
        .assert()
        .success();

    let server = MockServer::start();
    let endpoint = format!("{}/telemetry", server.base_url());
    let mock = server.mock(|when, then| {
        when.method(POST).path("/telemetry");
        then.status(200);
    });

    bin()
        .env("PYBUN_HOME", temp.path())
        .env("PYBUN_TELEMETRY_ENDPOINT", &endpoint)
        .env("PYBUN_TELEMETRY", "0")
        .args(["--format=json", "gc"])
        .assert()
        .success();

    assert_eq!(mock.hits(), 0);

    bin()
        .env("PYBUN_HOME", temp.path())
        .env("PYBUN_TELEMETRY_ENDPOINT", &endpoint)
        .env("PYBUN_TELEMETRY", "0")
        .args(["--telemetry", "--format=json", "gc"])
        .assert()
        .success();

    assert_eq!(mock.hits(), 1);
}

#[test]
fn telemetry_redacts_sensitive_tags() {
    let temp = tempdir().unwrap();
    let server = MockServer::start();
    let endpoint = format!("{}/telemetry", server.base_url());

    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/telemetry")
            .json_body_partial(r#"{"metadata":{"token":"[redacted]","team":"core"}}"#);
        then.status(200);
    });

    bin()
        .env("PYBUN_HOME", temp.path())
        .env("PYBUN_TELEMETRY_ENDPOINT", endpoint)
        .env("PYBUN_TELEMETRY", "1")
        .env("PYBUN_TELEMETRY_TAGS", "token=super-secret,team=core")
        .args(["--format=json", "gc"])
        .assert()
        .success();

    assert_eq!(mock.hits(), 1);
}
