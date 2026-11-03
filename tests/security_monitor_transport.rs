//! Actual publication lifecycle through both transports, using identical state
//! identities rather than replacing semantic/event IDs to make equality pass.
#![cfg(unix)]
#[path = "common/security_monitor_fixture.rs"]
mod fixture;
use httpmock::prelude::*;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

fn capture_clocks(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(capture_clocks),
        Value::Object(object) => {
            for (key, value) in object {
                // Provider documents and their digests are facts, not clocks.
                if key == "payload" {
                    continue;
                }
                if matches!(
                    key.as_str(),
                    "observed_at" | "fetched_at" | "last_confirmed_at" | "age_seconds"
                ) && value.is_number()
                {
                    *value = json!(0);
                } else if key == "observation_id" && value.is_string() {
                    *value = json!("capture-dependent");
                } else {
                    capture_clocks(value);
                }
            }
        }
        _ => {}
    }
}
fn equal(mut cli: Value, mut mcp: Value) {
    if cli.get("check").is_some() && mcp.get("check").is_some() {
        assert_eq!(cli["check"]["assessment_id"], mcp["check"]["assessment_id"]);
    }
    mcp.as_object_mut().unwrap().remove("policy_applied");
    mcp.as_object_mut().unwrap().remove("rate_limit_applied");
    capture_clocks(&mut cli);
    capture_clocks(&mut mcp);
    fn difference(left: &Value, right: &Value, path: &str) -> Option<String> {
        if left == right {
            return None;
        }
        match (left, right) {
            (Value::Object(left), Value::Object(right)) if left.keys().eq(right.keys()) => left
                .iter()
                .find_map(|(key, value)| difference(value, &right[key], &format!("{path}.{key}"))),
            (Value::Array(left), Value::Array(right)) if left.len() == right.len() => left
                .iter()
                .zip(right)
                .enumerate()
                .find_map(|(index, (left, right))| {
                    difference(left, right, &format!("{path}[{index}]"))
                }),
            _ => Some(format!(
                "{path}: {:?} != {:?}",
                left.to_string().chars().take(180).collect::<String>(),
                right.to_string().chars().take(180).collect::<String>()
            )),
        }
    }
    assert!(
        cli == mcp,
        "semantic payload differs: {}",
        difference(&cli, &mcp, "body").unwrap()
    );
}
fn equal_with_lineages(cli: Value, mut mcp: Value, ids: &BTreeMap<String, String>) {
    fn remap(value: &mut Value, ids: &BTreeMap<String, String>) {
        match value {
            Value::Array(values) => values.iter_mut().for_each(|value| remap(value, ids)),
            Value::Object(object) => {
                for (key, value) in object {
                    if key == "payload" {
                        continue;
                    }
                    if key == "finding_id"
                        && let Some(replacement) = value.as_str().and_then(|id| ids.get(id))
                    {
                        *value = json!(replacement);
                    } else if key == "related_lineages"
                        && let Some(values) = value.as_array_mut()
                    {
                        for value in values {
                            if let Some(replacement) = value.as_str().and_then(|id| ids.get(id)) {
                                *value = json!(replacement);
                            }
                        }
                    } else {
                        remap(value, ids);
                    }
                }
            }
            _ => {}
        }
    }
    // Only the initial random lineage allocation is mapped, once. Subsequent
    // identity changes cannot acquire a new mapping and therefore fail parity.
    remap(&mut mcp, ids);
    equal(cli, mcp);
}
fn equal_allocated(mut cli: Value, mut mcp: Value) {
    for key in ["monitor_id", "epoch_id"] {
        assert!(
            cli["registration"][key]
                .as_str()
                .is_some_and(|id| !id.is_empty())
        );
        assert!(
            mcp["registration"][key]
                .as_str()
                .is_some_and(|id| !id.is_empty())
        );
        cli["registration"][key] = json!("new-random-identity");
        mcp["registration"][key] = json!("new-random-identity");
    }
    equal(cli, mcp);
}
fn clone_registry(source: &Path, target: &Path) {
    for entry in fs::read_dir(target).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
    }
}

#[test]
fn publication_lifecycle_and_all_six_actions_have_cli_mcp_payload_parity() {
    let server = MockServer::start();
    let (root, state, config) = fixture::fixture(&server, true);
    server.reset();
    let published = Arc::new(AtomicBool::new(false));
    let publication = published.clone();
    let index = server.mock(move |when, then| {
        when.method(GET).path("/simple/six/");
        then.respond_with(move |_| {
            let available = publication.load(Ordering::SeqCst);
            let body = if available {
                json!({"meta":{"api-version":"1.4"},"name":"six","versions":["2.0"],"files":[{"filename":"six-2.0-py3-none-any.whl","url":"six-2.0.whl","hashes":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"size":100}]})
            } else {
                json!({"meta":{"api-version":"1.4"},"name":"six","versions":[],"files":[]})
            };
            httpmock::HttpMockResponse::builder().status(200).body(body.to_string()).build()
        });
    });
    let provider_available = Arc::new(AtomicBool::new(true));
    let availability = provider_available.clone();
    let query = server.mock(move |when, then| {
        when.method(POST).path("/v1/querybatch");
        then.respond_with(move |request| {
            if !availability.load(Ordering::SeqCst) {
                return httpmock::HttpMockResponse::builder()
                    .status(503)
                    .body("{}")
                    .build();
            }
            let body: Value = serde_json::from_slice(request.body_ref()).unwrap();
            let results: Vec<_> = body["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|query| {
                    if query["version"] == "1.0" {
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
    let detail = server.mock(|when, then| {
        when.method(GET).path("/v1/vulns/FIX-SIX");
        then.json_body(json!({"id":"FIX-SIX","modified":"2026-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}));
    });
    let config = config.replace("max_output_bytes=65536", "max_output_bytes=1048576");
    let state_a = state.path().canonicalize().unwrap().join("state");
    let state_b = state.path().canonicalize().unwrap().join("state-mcp");
    fs::create_dir(&state_b).unwrap();
    fs::set_permissions(&state_b, fs::Permissions::from_mode(0o700)).unwrap();
    let config_b = config.replace(state_a.to_str().unwrap(), state_b.to_str().unwrap());
    let added = fixture::cli(
        root.path(),
        &config,
        &["add", "--name", "app", "--profile", "app"],
    );
    let id = added["registration"]["monitor_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut initial_mcp = fixture::Session::start(root.path(), &config_b);
    let added_b = initial_mcp.call(json!({"action":"add","name":"app","profile":"app"}));
    equal_allocated(added, added_b);
    initial_mcp.finish();
    query.assert_calls(0);
    assert!(!root.path().join("helper-ran").exists());
    clone_registry(&state_a, &state_b);
    let mut mcp = fixture::Session::start(root.path(), &config_b);
    // Complete startup before CLI rewrites the shared policy filename; MCP
    // deliberately freezes its configuration at startup.
    let listed_b = mcp.call(json!({"action":"list"}));
    equal(fixture::cli(root.path(), &config, &["list"]), listed_b);
    let before = fs::read(root.path().join("pyproject.toml")).unwrap();
    let first = fixture::cli(root.path(), &config, &["check", &id]);
    assert_eq!(first["exit_code"], 0, "{first}");
    assert_eq!(first["current"]["findings"].as_array().unwrap().len(), 1);
    assert!(first["current"]["findings"][0]["candidate"].is_null());
    assert_eq!(
        first["newly_committed_events"][0]["event_type"],
        "baseline_observed"
    );
    let first_b = mcp.call(json!({"action":"check","monitor_id":id}));
    let mut lineages = BTreeMap::new();
    for finding in first["current"]["findings"].as_array().unwrap() {
        let counterpart = first_b["current"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|other| other["package_key"] == finding["package_key"])
            .unwrap();
        lineages.insert(
            counterpart["finding_id"].as_str().unwrap().to_owned(),
            finding["finding_id"].as_str().unwrap().to_owned(),
        );
    }
    equal_with_lineages(first.clone(), first_b, &lineages);
    published.store(true, Ordering::SeqCst);
    let fix = fixture::cli(root.path(), &config, &["check", &id]);
    assert!(
        fix["current"]["findings"][0]["candidate"]["qualified_remediation"]
            .as_bool()
            .unwrap()
    );
    assert!(
        fix["newly_committed_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_type"] == "fix_candidate_available")
    );
    equal_with_lineages(
        fix,
        mcp.call(json!({"action":"check","monitor_id":id})),
        &lineages,
    );
    let unchanged = fixture::cli(root.path(), &config, &["check", &id]);
    assert_eq!(unchanged["newly_committed_count"], 0, "{unchanged}");
    equal_with_lineages(
        unchanged,
        mcp.call(json!({"action":"check","monitor_id":id})),
        &lineages,
    );
    provider_available.store(false, Ordering::SeqCst);
    let failed = fixture::cli(root.path(), &config, &["check", &id]);
    assert_eq!(failed["exit_code"], 3, "{failed}");
    assert_eq!(failed["current"]["findings"].as_array().unwrap().len(), 1);
    equal_with_lineages(
        failed,
        mcp.call(json!({"action":"check","monitor_id":id})),
        &lineages,
    );
    provider_available.store(true, Ordering::SeqCst);
    let calls = (index.calls(), query.calls(), detail.calls());
    let offline = fixture::cli(root.path(), &config, &["check", &id, "--mode", "offline"]);
    assert_eq!(offline["exit_code"], 3, "{offline}");
    assert_eq!(offline["current"]["findings"].as_array().unwrap().len(), 1);
    equal_with_lineages(
        offline,
        mcp.call(json!({"action":"check","monitor_id":id,"mode":"offline"})),
        &lineages,
    );
    assert_eq!((index.calls(), query.calls(), detail.calls()), calls);
    let metadata = fs::read_dir(root.path().join(".venv/lib"))
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .path()
                .join("site-packages/six-1.0.dist-info/METADATA")
        })
        .find(|path| path.exists())
        .unwrap();
    let old = fs::read_to_string(&metadata).unwrap();
    fs::write(&metadata, old.replace("Version: 1.0", "Version: 2.0")).unwrap();
    let changed = fs::read(&metadata).unwrap();
    let resolved = fixture::cli(root.path(), &config, &["check", &id]);
    assert_eq!(
        resolved["current"]["epoch_id"],
        first["current"]["epoch_id"]
    );
    assert!(
        resolved["current"]["findings"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{resolved}"
    );
    assert!(
        resolved["newly_committed_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_type"] == "finding_resolved")
    );
    equal_with_lineages(
        resolved,
        mcp.call(json!({"action":"check","monitor_id":id})),
        &lineages,
    );
    equal_with_lineages(
        fixture::cli(root.path(), &config, &["events", &id]),
        mcp.call(json!({"action":"events","monitor_id":id})),
        &lineages,
    );
    let configured = fixture::cli(
        root.path(),
        &config,
        &[
            "configure",
            &id,
            "--profile",
            "app",
            "--expected-revision",
            "1",
        ],
    );
    assert_eq!(configured["registration"]["config_revision"], 2);
    equal_allocated(
        configured,
        mcp.call(
            json!({"action":"configure","monitor_id":id,"profile":"app","expected_revision":1}),
        ),
    );
    equal(
        fixture::cli(root.path(), &config, &["remove", &id]),
        mcp.call(json!({"action":"remove","monitor_id":id})),
    );
    equal(
        fixture::cli(root.path(), &config, &["remove", &id]),
        mcp.call(json!({"action":"remove","monitor_id":id})),
    );
    mcp.finish();
    assert_eq!(
        fs::read(root.path().join("pyproject.toml")).unwrap(),
        before
    );
    assert_eq!(fs::read(metadata).unwrap(), changed);
    for path in [
        "uv.lock",
        ".pybun",
        "home",
        "forbidden-audit",
        "startup-hook-ran",
    ] {
        assert!(
            !root.path().join(path).exists(),
            "unexpected mutation: {path}"
        );
    }
}

#[test]
fn operator_provider_change_resets_without_old_evidence_or_resolution() {
    let old_provider = MockServer::start();
    let (root, _state, config) = fixture::fixture(&old_provider, true);
    let old_query = old_provider.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{"vulns":[{"id":"FIX"}]}]}));
    });
    old_provider.mock(|when, then| {
        when.method(GET).path("/v1/vulns/FIX");
        then.json_body(json!({"id":"FIX","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"six","ecosystem":"PyPI"},"versions":["1.0"]}]}));
    });
    let config = config.replace("max_output_bytes=65536", "max_output_bytes=1048576");
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let baseline = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(baseline["current"]["findings"].as_array().unwrap().len(), 1);
    let old_cursor = baseline["replay"]["next_cursor"].clone();
    session.finish();
    let new_provider = MockServer::start();
    let new_query = new_provider.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let old_id_leak = new_provider.mock(|when, then| {
        when.method(GET);
        then.status(500);
    });
    let config = config.replace(
        &old_provider.url("/v1/querybatch"),
        &new_provider.url("/v1/querybatch"),
    );
    let mut session = fixture::Session::start(root.path(), &config);
    let reset = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(
        reset["exit_code"], 3,
        "a new epoch requires explicit consumer resynchronization: {reset}"
    );
    assert_eq!(reset["current"]["complete"], true);
    assert_ne!(
        reset["current"]["epoch_id"],
        baseline["current"]["epoch_id"]
    );
    assert!(reset["current"]["findings"].as_array().unwrap().is_empty());
    let events = reset["newly_committed_events"].as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "observation_reset")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["event_type"] == "finding_resolved"
                || event["event_type"] == "new_advisory")
    );
    let scoped = session.call(json!({"action":"events","monitor_id":id,"after":old_cursor}));
    assert_eq!(scoped["exit_code"], 3);
    assert!(
        scoped["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "E_MONITOR_CURSOR_SCOPE")
    );
    assert_eq!(scoped["current"]["epoch_id"], reset["current"]["epoch_id"]);
    assert!(!scoped.to_string().contains("\"FIX\""));
    session.finish();
    old_query.assert_calls(1);
    new_query.assert_calls(1);
    old_id_leak.assert_calls(0);
}

#[test]
fn lost_checkpoint_recovery_returns_its_authorized_new_epoch_not_a_stale_ticket() {
    let server = MockServer::start();
    let (root, state, config) = fixture::fixture(&server, true);
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let baseline = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(baseline["exit_code"], 0, "{baseline}");
    let checkpoints: Vec<_> = fs::read_dir(state.path().join("state"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
                && path.file_name().unwrap() != "registry.json"
        })
        .collect();
    assert_eq!(checkpoints.len(), 1);
    fs::remove_file(&checkpoints[0]).unwrap();
    let recovered = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(recovered["exit_code"], 3, "{recovered}");
    assert_eq!(recovered["commit_status"], "committed", "{recovered}");
    assert_ne!(
        recovered["current"]["epoch_id"],
        baseline["current"]["epoch_id"]
    );
    assert_eq!(recovered["current"]["complete"], true);
    assert!(
        recovered["newly_committed_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_type"] == "observation_reset")
    );
    assert!(
        !recovered["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "E_MONITOR_STALE_CHECK")
    );
    session.finish();
}
