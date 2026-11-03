use assert_cmd::cargo::cargo_bin_cmd;
use clap::Parser;
use pybun::cli::Cli;
use serde_json::Value;

#[cfg(unix)]
#[path = "common/security_monitor_fixture.rs"]
mod fixture;

#[test]
fn monitor_exposes_all_six_explicit_actions_without_legacy_audit_flags() {
    for arguments in [
        vec!["add", "--name", "app", "--profile", "app"],
        vec!["list"],
        vec!["check", "monitor-id", "--after", "cursor"],
        vec!["events", "monitor-id"],
        vec!["remove", "monitor-id"],
        vec![
            "configure",
            "monitor-id",
            "--expected-revision",
            "1",
            "--profile",
            "app",
        ],
    ] {
        let mut args = vec!["pybun", "audit", "monitor"];
        args.extend(arguments);
        args.push("--format=json");
        assert!(Cli::try_parse_from(&args).is_ok(), "{args:?}");
    }
    assert!(Cli::try_parse_from(["pybun", "audit", "--system", "monitor", "list"]).is_err());
    assert!(
        Cli::try_parse_from([
            "pybun",
            "audit",
            "monitor",
            "check",
            "id",
            "--provider-url",
            "https://example.com"
        ])
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn cli_configuration_actions_are_explicit_config_only_and_remove_exact_identity() {
    let server = httpmock::MockServer::start();
    let requests = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    let (root, _state, config) = fixture::fixture(&server, true);
    let added = fixture::cli(
        root.path(),
        &config,
        &["add", "--name", "app", "--profile", "app", "--project", "."],
    );
    assert_eq!(added["exit_code"], 0, "{added}");
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let epoch = added["registration"]["epoch_id"].clone();
    let listed = fixture::cli(root.path(), &config, &["list"]);
    assert_eq!(listed["registrations"].as_array().unwrap().len(), 1);
    let events = fixture::cli(root.path(), &config, &["events", id]);
    assert_eq!(events["exit_code"], 3, "{events}");
    let configured = fixture::cli(
        root.path(),
        &config,
        &[
            "configure",
            id,
            "--expected-revision",
            "1",
            "--profile",
            "app",
        ],
    );
    assert_eq!(configured["exit_code"], 0, "{configured}");
    assert_ne!(configured["registration"]["epoch_id"], epoch);
    let removed = fixture::cli(root.path(), &config, &["remove", id]);
    assert_eq!(removed["removed"], true);
    let successor = fixture::cli(
        root.path(),
        &config,
        &["add", "--name", "app", "--profile", "app"],
    );
    assert_ne!(successor["registration"]["monitor_id"], id);
    let retried = fixture::cli(root.path(), &config, &["remove", id]);
    assert_eq!(retried["removed"], false, "{retried}");
    assert_eq!(
        fixture::cli(root.path(), &config, &["list"])["registrations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    requests.assert_calls(0);
    assert!(!root.path().join("helper-ran").exists());
    for path in ["home", ".pybun", "forbidden-audit"] {
        assert!(!root.path().join(path).exists(), "{path}");
    }
}

#[cfg(unix)]
#[test]
fn stale_concurrent_commit_keeps_observed_high_matches_separate_from_durable_state() {
    use httpmock::prelude::*;
    use std::{
        process::{Command, Stdio},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    let config = config.replace("max_output_bytes=65536", "max_output_bytes=524288");
    let arrivals = Arc::new(AtomicUsize::new(0));
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        let arrivals = arrivals.clone();
        then.respond_with(move |_| {
            arrivals.fetch_add(1, Ordering::SeqCst);
            let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while arrivals.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < until {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            httpmock::HttpMockResponse::builder()
                .status(200)
                .body(serde_json::json!({"results":[{"vulns":[{"id":"COMMIT-HIGH"}]}]}).to_string())
                .build()
        });
    });
    server.mock(|when,then|{when.method(GET).path("/v1/vulns/COMMIT-HIGH");then.json_body(serde_json::json!({"id":"COMMIT-HIGH","modified":"2026-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}));});
    let added = fixture::cli(
        root.path(),
        &config,
        &["add", "--name", "app", "--profile", "app"],
    );
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let spawn = || {
        Command::new(env!("CARGO_BIN_EXE_pybun"))
            .current_dir(root.path())
            .args([
                "audit",
                "monitor",
                "check",
                id,
                "--fail-on",
                "high",
                "--security-config",
            ])
            .arg(root.path().join("operator.toml"))
            .arg("--format=json")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let first = spawn();
    let second = spawn();
    let results: Vec<Value> = [first, second]
        .into_iter()
        .map(|child| {
            let output = child.wait_with_output().unwrap();
            let body: Value = serde_json::from_slice(&output.stdout).unwrap();
            body["detail"].clone()
        })
        .collect();
    assert_eq!(arrivals.load(Ordering::SeqCst), 2);
    let failed = results
        .iter()
        .find(|result| result["commit_status"] != "committed")
        .expect("one stale ticket rejected");
    assert_eq!(failed["exit_code"], 3, "{failed}");
    assert_eq!(failed["check"]["threshold_match_count"], 1, "{failed}");
    assert_eq!(
        failed["check"]["assessment"]["packages"][0]["installed"]["clusters"][0]["severity"],
        "high",
        "{failed}"
    );
    assert!(
        failed.get("current").is_none(),
        "uncommitted observation must not claim durable current: {failed}"
    );
    let committed = results
        .iter()
        .find(|result| result["commit_status"] == "committed")
        .unwrap();
    let replay = fixture::cli(root.path(), &config, &["events", id]);
    assert_eq!(
        replay["current"]["generation"],
        committed["current"]["generation"]
    );
}

#[test]
fn unconfigured_monitor_returns_coded_failure_without_initializing_state() {
    let root = tempfile::tempdir().unwrap();
    let output = cargo_bin_cmd!("pybun")
        .current_dir(root.path())
        .env("PYBUN_HOME", root.path().join("home"))
        .args(["audit", "monitor", "list", "--format=json"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["detail"]["operation"], "security_monitor");
    assert_eq!(body["detail"]["commit_status"], "not_committed");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
