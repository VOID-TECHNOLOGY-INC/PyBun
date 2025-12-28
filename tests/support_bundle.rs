//! E2E tests for support bundle creation and upload.
//!
//! PR7.3: Supportability bundle + crash report hook.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use httpmock::prelude::*;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn doctor_bundle_creates_bundle_and_redacts_env() {
    let temp = TempDir::new().unwrap();
    let bundle_path = temp.path().join("bundle");
    let home = temp.path().join("home");

    pybun()
        .env("PYBUN_HOME", &home)
        .env("PYBUN_TEST_TOKEN", "super-secret")
        .args([
            "--format=json",
            "doctor",
            "--bundle",
            bundle_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"bundle\""));

    let env_json = fs::read_to_string(bundle_path.join("env.json")).unwrap();
    assert!(env_json.contains("<redacted>"));
    assert!(!env_json.contains("super-secret"));
}

#[test]
fn doctor_upload_posts_bundle() {
    let server = MockServer::start();
    let upload = server.mock(|when, then| {
        when.method(POST).path("/upload");
        then.status(200).header("Content-Type", "application/json");
    });

    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let url = format!("{}/upload", server.base_url());

    pybun()
        .env("PYBUN_HOME", &home)
        .env("PYBUN_SUPPORT_UPLOAD_URL", &url)
        .args(["--format=json", "doctor", "--upload"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"upload\""))
        .stdout(predicate::str::contains("\"status\":\"uploaded\""));

    upload.assert_hits(1);
}
