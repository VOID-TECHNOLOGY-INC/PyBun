//! Actual CLI/MCP parity over identical approved local metadata observations.
#![cfg(unix)]
#[path = "common/security_check_fixture.rs"]
mod security_fixture;
use httpmock::prelude::*;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn cli(root: &Path, config: &str, arguments: &[&str]) -> (i32, Value) {
    fs::write(root.join("operator.toml"), config).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(root)
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_HISTORY", "1")
        .env("PYBUN_HOME", root.join("forbidden-home"))
        .args([
            "audit",
            "check-updates",
            "--security-config",
            "operator.toml",
            "--format=json",
        ])
        .args(arguments)
        .output()
        .unwrap();
    let envelope: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)));
    assert_eq!(envelope["version"], "2");
    capture("cli", &envelope);
    no_ambient_writes(root);
    (output.status.code().unwrap(), envelope["detail"].clone())
}
fn mcp(root: &Path, config: &str, arguments: Value) -> Value {
    fs::write(root.join("operator.toml"), config).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(root)
        .env("PYBUN_MCP_POLICY", root.join("operator.toml"))
        .env("PYBUN_AUDIT_LOG", root.join("forbidden-audit/events.jsonl"))
        .env("PYBUN_HISTORY", "1")
        .env("PYBUN_HOME", root.join("forbidden-home"))
        .env("PYBUN_BACKEND", "native")
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(),"{}",json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pybun_security_check","arguments":arguments}})).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut body: Value =
        serde_json::from_str(reply["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        reply["result"]["isError"].as_bool().unwrap_or(false),
        body["exit_code"] != json!(0)
    );
    body.as_object_mut().unwrap().remove("policy_applied");
    body.as_object_mut().unwrap().remove("rate_limit_applied");
    capture("mcp", &body);
    no_ambient_writes(root);
    body
}
fn no_ambient_writes(root: &Path) {
    for name in [
        ".pybun",
        "forbidden-home",
        "forbidden-audit",
        "monitor-state",
    ] {
        assert!(!root.join(name).exists(), "unexpected check write: {name}");
    }
}

fn capture(label: &str, value: &Value) {
    if let Some(directory) = std::env::var_os("PYBUN_SECURITY_CAPTURE_DIR") {
        fs::create_dir_all(&directory).unwrap();
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("fixture");
        fs::write(
            std::path::PathBuf::from(directory).join(format!("{name}-{label}.json")),
            serde_json::to_vec_pretty(value).unwrap(),
        )
        .unwrap();
    }
}
fn capture_independent(body: &mut Value) {
    fn clear(object: &mut Value, key: &str) {
        if let Some(value) = object.get_mut(key) {
            if value.is_number() {
                *value = json!(0);
            } else if value.is_string() {
                *value = json!("capture-dependent");
            }
        }
    }
    fn freshness(object: &mut Value) {
        if let Some(value) = object.get_mut("freshness") {
            clear(value, "age_seconds");
        }
    }
    clear(body, "observation_id");
    let Some(assessment) = body.get_mut("assessment").filter(|value| value.is_object()) else {
        return;
    };
    clear(&mut assessment["inventory"], "observed_at");
    clear(&mut assessment["inventory"], "observation_id");
    for provider in assessment["providers"].as_array_mut().into_iter().flatten() {
        clear(provider, "observed_at");
        for instance in provider["instances"].as_array_mut().into_iter().flatten() {
            freshness(instance);
            for record in instance["records"].as_array_mut().into_iter().flatten() {
                clear(record, "fetched_at");
                freshness(record);
            }
        }
    }
    for package in assessment["packages"].as_array_mut().into_iter().flatten() {
        for cluster in package["installed"]["clusters"]
            .as_array_mut()
            .into_iter()
            .flatten()
        {
            for record in cluster["records"].as_array_mut().into_iter().flatten() {
                clear(record, "fetched_at");
            }
        }
        if let Some(registry) = package
            .get_mut("registry")
            .filter(|value| value.is_object())
        {
            clear(registry, "fetched_at");
            freshness(registry);
        }
        for candidate in package["candidates"].as_array_mut().into_iter().flatten() {
            freshness(&mut candidate["qualification"]);
        }
    }
}

fn assert_equal(mut cli: Value, mut mcp: Value) {
    assert_eq!(cli["assessment_id"], mcp["assessment_id"]);
    capture_independent(&mut cli);
    capture_independent(&mut mcp);
    assert_eq!(
        cli, mcp,
        "only capture clocks/observation identities may differ; all facts, coverage, diagnostics and traversal remain equal"
    );
}
fn setup(server: &MockServer, installed: bool) -> (tempfile::TempDir, String) {
    let (root, config) = security_fixture::fixture(server, installed);
    (
        root,
        config.replace("max_output_bytes=65536", "max_output_bytes=5242880"),
    )
}
fn public_advisories(server: &MockServer) {
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.respond_with(|request| {
            let body: Value = serde_json::from_slice(request.body_ref()).unwrap();
            let results: Vec<_> = body["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| {
                    if q["version"] == json!("1.0") {
                        json!({"vulns":[{"id":"FIX-SIX"}]})
                    } else {
                        json!({})
                    }
                })
                .collect();
            httpmock::HttpMockResponse::builder()
                .status(200)
                .body(json!({"results":results}).to_string())
                .build()
        });
    });
    server.mock(|when,then|{when.method(GET).path("/v1/vulns/FIX-SIX");then.json_body(json!({"id":"FIX-SIX","modified":"2026-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]}]}));});
}
#[test]
fn complete_published_candidate_and_constraint_facts_match_across_transports() {
    let server = MockServer::start();
    let (root, config) = setup(&server, true);
    server.reset();
    server.mock(|when,then|{when.method(GET).path("/simple/six/");then.json_body(json!({"meta":{"api-version":"1.4"},"name":"six","versions":["2"],"files":[{"filename":"six-2-py3-none-any.whl","url":"/archives/six-2.whl","hashes":{},"size":100}]}));});
    let archive = server.mock(|when, then| {
        when.path("/archives/six-2.whl");
        then.status(500);
    });
    public_advisories(&server);
    let before = fs::read(root.path().join("pyproject.toml")).unwrap();
    let (code, left) = cli(root.path(), &config, &[]);
    let right = mcp(root.path(), &config, json!({}));
    assert_eq!(code, 0);
    assert_eq!(right["exit_code"], 0);
    assert_eq!(
        left["assessment"]["packages"][0]["candidates"][0]["qualification"]["candidate_kind"],
        "published_remediation_candidate"
    );
    assert_equal(left, right);
    archive.assert_calls(0);
    assert_eq!(
        before,
        fs::read(root.path().join("pyproject.toml")).unwrap()
    );
    assert!(!root.path().join("startup-hook-ran").exists());
    assert!(!root.path().join("forbidden-audit").exists());
}
#[test]
fn validated_empty_inventory_is_complete_in_both_transports() {
    let server = MockServer::start();
    let (root, config) = setup(&server, false);
    let network = server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.status(500);
    });
    let (code, left) = cli(root.path(), &config, &[]);
    let right = mcp(root.path(), &config, json!({}));
    assert_eq!(code, 0);
    assert_eq!(left["assessment"]["inventory"]["packages"], json!([]));
    assert_equal(left, right);
    network.assert_calls(0);
}
#[test]
fn mixed_private_partial_keeps_complete_public_findings_without_disclosure() {
    let server = MockServer::start();
    let (root, config) = setup(&server, true);
    let site = fs::read_dir(root.path().join(".venv/lib"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("site-packages/private-pkg-1.dist-info");
    fs::create_dir(&site).unwrap();
    fs::write(
        site.join("METADATA"),
        "Metadata-Version: 2.1\nName: private-pkg\nVersion: 1\n",
    )
    .unwrap();
    let leak = server.mock(|when, then| {
        when.path("/v1/querybatch").body_includes("private-pkg");
        then.status(500);
    });
    let registry_leak = server.mock(|when, then| {
        when.path("/simple/private-pkg/");
        then.status(500);
    });
    public_advisories(&server);
    let (code, left) = cli(root.path(), &config, &["--fail-on", "high"]);
    let right = mcp(root.path(), &config, json!({"fail_on":"high"}));
    assert_eq!(code, 3);
    assert!(left["threshold_match_count"].as_u64().unwrap() > 0);
    assert_equal(left, right);
    leak.assert_calls(0);
    registry_leak.assert_calls(0);
}
#[test]
fn denied_profile_mode_has_identical_failure_and_no_helper_or_http() {
    let server = MockServer::start();
    let (root, config) = setup(&server, true);
    // Compare the same frozen profile-mode denial after transport grants.
    let config = config.replace(
        "allowed_modes=[\"online\",\"offline\",\"online_with_cache_fallback\"]",
        "allowed_modes=[\"online\"]",
    );
    let network = server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.status(500);
    });
    let (code, left) = cli(root.path(), &config, &["--mode", "offline"]);
    let right = mcp(root.path(), &config, json!({"mode":"offline"}));
    assert_eq!(code, 3);
    assert!(left["assessment"].is_null());
    assert_equal(left, right);
    assert!(!root.path().join("helper-ran").exists());
    network.assert_calls(0);
    assert_eq!(fs::read_dir(root.path().join("cache")).unwrap().count(), 0);
}
#[test]
fn offline_cached_payload_parity_includes_age_and_per_item_incompleteness() {
    let server = MockServer::start();
    let (root, config) = setup(&server, true);
    let network = server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    assert_eq!(cli(root.path(), &config, &[]).0, 0);
    let cache_before: Vec<_> = fs::read_dir(root.path().join("cache"))
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_owned(),
                fs::read(path).unwrap(),
            )
        })
        .collect();
    let (code, left) = cli(root.path(), &config, &["--mode", "offline"]);
    let right = mcp(root.path(), &config, json!({"mode":"offline"}));
    assert_eq!(code, 3);
    assert_equal(left, right);
    network.assert_calls(1);
    let cache_after: Vec<_> = fs::read_dir(root.path().join("cache"))
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_owned(),
                fs::read(path).unwrap(),
            )
        })
        .collect();
    assert_eq!(cache_before, cache_after);
}
