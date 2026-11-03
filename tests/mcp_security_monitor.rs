use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[cfg(unix)]
#[path = "common/security_monitor_fixture.rs"]
mod fixture;

fn call(arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pybun_security_monitor","arguments":arguments}})
}

#[cfg(unix)]
#[test]
fn explicit_mcp_check_commits_once_and_replays_durable_events_without_scanning_again() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let query = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let (root, _state, config) = fixture::fixture(&server, true);
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    assert_eq!(added["exit_code"], 0, "{added}");
    assert!(!root.path().join("helper-ran").exists());
    query.assert_calls(0);
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let first = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(first["exit_code"], 0, "{first}");
    assert_eq!(first["commit_status"], "committed");
    assert_eq!(first["newly_committed_count"], 1, "{first}");
    let event = first["newly_committed_events"][0].clone();
    let helper_calls = std::fs::read_to_string(root.path().join("helper-ran")).unwrap();
    let replay = session.call(json!({"action":"events","monitor_id":id}));
    assert_eq!(replay["replay"]["events"][0], event);
    assert_eq!(
        std::fs::read_to_string(root.path().join("helper-ran")).unwrap(),
        helper_calls
    );
    query.assert_calls(1);
    let second = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(second["newly_committed_count"], 0, "{second}");
    assert_eq!(second["current"]["epoch_id"], first["current"]["epoch_id"]);
    session.finish();
    for path in [
        "home",
        "forbidden-audit",
        ".pybun",
        "ambient-env",
        "startup-hook-ran",
    ] {
        assert!(!root.path().join(path).exists(), "{path}");
    }
}

#[cfg(unix)]
#[test]
fn configure_cannot_rebind_a_monitor_to_a_different_even_granted_profile() {
    let server = httpmock::MockServer::start();
    let calls = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    let (root, _state, config) = fixture::fixture(&server, true);
    let start = config.find("[[security_assessment.profiles]]").unwrap();
    let end = config.find("[[security_assessment.providers]]").unwrap();
    let second = config[start..end].replace("id=\"app\"", "id=\"other\"");
    let config = config
        .replacen(
            "[[security_assessment.providers]]",
            &format!("{second}[[security_assessment.providers]]"),
            1,
        )
        .replace(
            "allowed_security_profiles=[\"app\"]",
            "allowed_security_profiles=[\"app\",\"other\"]",
        );
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    assert_eq!(added["exit_code"], 0, "{added}");
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let rejected = session.call(
        json!({"action":"configure","monitor_id":id,"expected_revision":1,"profile":"other"}),
    );
    assert_eq!(rejected["exit_code"], 3, "{rejected}");
    assert_eq!(rejected["commit_status"], "not_committed");
    let listed = session.call(json!({"action":"list"}));
    assert_eq!(listed["registrations"][0], added["registration"]);
    calls.assert_calls(0);
    assert!(!root.path().join("helper-ran").exists());
    session.finish();
}

#[cfg(unix)]
#[test]
fn output_bound_is_applied_after_full_durable_baseline_and_preserves_match_counts() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    let config = config.replace("max_output_bytes=65536", "max_output_bytes=4096");
    let ids: Vec<_> = (0..24)
        .map(|index| format!("MONITOR-SIX-{index}"))
        .collect();
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(
            json!({"results":[{"vulns":ids.iter().map(|id|json!({"id":id})).collect::<Vec<_>>()}]}),
        );
    });
    for id in &ids {
        server.mock(|when,then|{when.method(GET).path(format!("/v1/vulns/{id}"));then.json_body(json!({"id":id,"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}));});
    }
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    assert_eq!(added["exit_code"], 0, "{added}");
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let observed = session.call(json!({"action":"check","monitor_id":id,"fail_on":"high"}));
    assert_eq!(observed["exit_code"], 3, "{observed}");
    assert_eq!(observed["commit_status"], "committed");
    assert_eq!(observed["omitted"]["current_findings"], 24, "{observed}");
    assert_eq!(observed["omitted"]["threshold_matches"], 24, "{observed}");
    assert!(
        session.last_wire_bytes <= 4096,
        "{} bytes: {observed}",
        session.last_wire_bytes
    );
    session.finish();
    let calls = std::fs::read_to_string(root.path().join("helper-ran")).unwrap();
    let replay = fixture::cli(
        root.path(),
        &config.replace("max_output_bytes=4096", "max_output_bytes=65536"),
        &["events", id],
    );
    assert_eq!(
        replay["current"]["findings"].as_array().unwrap().len(),
        24,
        "{replay}"
    );
    let head = replay["replay"]["next_cursor"].as_str().unwrap();
    let mut bounded = fixture::Session::start(root.path(), &config);
    let empty = bounded.call(json!({"action":"events","monitor_id":id,"after":head}));
    assert_eq!(empty["exit_code"], 3, "{empty}");
    assert_eq!(empty["omitted"]["replay_events"], 0, "{empty}");
    assert_eq!(empty["replay"]["events"], json!([]), "{empty}");
    assert_eq!(empty["replay"]["next_cursor"], head, "{empty}");
    assert_eq!(empty["replay"]["has_more"], false, "{empty}");
    assert!(bounded.last_wire_bytes <= 4096);
    bounded.finish();
    assert_eq!(
        std::fs::read_to_string(root.path().join("helper-ran")).unwrap(),
        calls
    );
}

#[cfg(unix)]
#[test]
fn late_provider_timeout_keeps_known_high_facts_and_durable_partial_progress() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{"vulns":[{"id":"A-HIGH"},{"id":"Z-LATE"}]}]}));
    });
    server.mock(|when,then|{when.method(GET).path("/v1/vulns/A-HIGH");then.json_body(json!({"id":"A-HIGH","modified":"2026-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}));});
    server.mock(|when, then| {
        when.method(GET).path("/v1/vulns/Z-LATE");
        then.delay(std::time::Duration::from_secs(4))
            .json_body(json!({"id":"Z-LATE","modified":"2026-01-01T00:00:00Z","affected":[]}));
    });
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let limits = pybun::security_assessment::ObservationLimits {
        total_timeout_ms: 2000,
        http_timeout_ms: 1800,
        max_attempts: 1,
        ..Default::default()
    };
    let observed =
        session.call(json!({"action":"check","monitor_id":id,"fail_on":"high","limits":limits}));
    assert_eq!(observed["exit_code"], 3, "{observed}");
    assert_eq!(observed["commit_status"], "committed", "{observed}");
    let findings = observed["current"]["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding["active"] == true && finding["severity"] == "high"),
        "{observed}"
    );
    assert!(
        observed["newly_committed_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_type"] == "check_incomplete"),
        "{observed}"
    );
    let replay = session.call(json!({"action":"events","monitor_id":id}));
    assert!(
        replay["current"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["active"] == true && finding["severity"] == "high"),
        "{replay}"
    );
    session.finish();
}

#[cfg(unix)]
#[test]
fn known_record_omitted_from_query_is_refreshed_and_only_explicit_withdrawal_transitions() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    let config = config.replace("max_output_bytes=65536", "max_output_bytes=262144");
    let mut query = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{"vulns":[{"id":"KNOWN-HIGH"}]}]}));
    });
    let mut detail=server.mock(|when,then|{when.method(GET).path("/v1/vulns/KNOWN-HIGH");then.json_body(json!({"id":"KNOWN-HIGH","modified":"2026-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}));});
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let first = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(first["exit_code"], 0, "{first}");
    assert!(first["current"]["findings"][0]["active"] == true, "{first}");
    query.delete();
    detail.delete();
    let empty = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let mut missing = server.mock(|when, then| {
        when.method(GET).path("/v1/vulns/KNOWN-HIGH");
        then.status(404);
    });
    let uncertain = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(uncertain["exit_code"], 3, "{uncertain}");
    assert_eq!(
        uncertain["current"]["findings"][0]["active"], true,
        "{uncertain}"
    );
    assert!(
        !uncertain["newly_committed_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_type"] == "advisory_withdrawn"
                || event["event_type"] == "finding_resolved")
    );
    missing.delete();
    let withdrawn=server.mock(|when,then|{when.method(GET).path("/v1/vulns/KNOWN-HIGH");then.json_body(json!({"id":"KNOWN-HIGH","modified":"2026-01-02T00:00:00Z","withdrawn":"2026-01-02T00:00:00Z","affected":[]}));});
    let corrected = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(corrected["commit_status"], "committed", "{corrected}");
    assert!(
        corrected["newly_committed_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_type"] == "advisory_withdrawn"),
        "{corrected}"
    );
    assert_eq!(
        corrected["current"]["epoch_id"],
        first["current"]["epoch_id"]
    );
    assert!(
        !corrected["current"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["active"] == true),
        "{corrected}"
    );
    empty.assert_calls(2);
    withdrawn.assert_calls(1);
    session.finish();
}

#[cfg(unix)]
#[test]
fn ordinary_inventory_change_restarts_saved_traversal_without_resetting_epoch_or_scanning_twice() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let first = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(first["exit_code"], 0, "{first}");
    let site = std::fs::read_dir(root.path().join(".venv/lib"))
        .unwrap()
        .map(|entry| entry.unwrap().path().join("site-packages"))
        .find(|path| path.exists())
        .unwrap();
    let metadata = site.join("six-1.0.dist-info/METADATA");
    let old = std::fs::read_to_string(&metadata).unwrap();
    std::fs::write(metadata, old.replace("Version: 1.0", "Version: 1.1")).unwrap();
    let second = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(second["exit_code"], 0, "{second}");
    assert_eq!(second["current"]["epoch_id"], first["current"]["epoch_id"]);
    assert!(
        second["check"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "E_MONITOR_TRAVERSAL_RESTARTED"),
        "{second}"
    );
    assert!(
        !second["newly_committed_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_type"] == "observation_reset"),
        "{second}"
    );
    assert_eq!(
        second["check"]["assessment"]["inventory"]["packages"][0]["version"],
        "1.1"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("helper-ran"))
            .unwrap()
            .lines()
            .count(),
        2
    );
    session.finish();
}

#[cfg(unix)]
#[test]
fn durable_progress_reaches_more_than_ten_packages_across_explicit_checks() {
    use httpmock::prelude::*;
    use std::collections::BTreeSet;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    server.reset();
    let site = std::fs::read_dir(root.path().join(".venv/lib"))
        .unwrap()
        .map(|entry| entry.unwrap().path().join("site-packages"))
        .find(|path| path.exists())
        .unwrap();
    let mut names = vec!["six".to_string()];
    for index in 0..12 {
        let name = format!("pkg{index:02}");
        let metadata = site.join(format!("{name}-1.0.dist-info"));
        std::fs::create_dir(&metadata).unwrap();
        std::fs::write(
            metadata.join("METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n"),
        )
        .unwrap();
        names.push(name);
    }
    let mut document: toml::Value = toml::from_str(&config).unwrap();
    let policy = &mut document["security_assessment"]["source_policies"]["explicit"];
    policy["rules"]=toml::Value::try_from(names.iter().map(|name|json!({"name":name,"source_id":"public","upstream_name":name,"ecosystem":"PyPI","assumption":"Explicit operator mapping."})).collect::<Vec<_>>()).unwrap();
    policy["disclosure"] = toml::Value::try_from(
        ["advisory", "registry"]
            .iter()
            .map(|id| json!({"provider_id":id,"source_id":"public","packages":names}))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    document["security_assessment"]["limits"]["max_output_bytes"] = toml::Value::Integer(1048576);
    let config = toml::to_string(&document).unwrap();
    server.mock(|when,then|{when.method(GET).path_includes("/simple/");then.respond_with(|request|{
        let name=request.uri().path().trim_end_matches('/').rsplit('/').next().unwrap().to_string();
        httpmock::HttpMockResponse::builder().status(200).body(json!({"meta":{"api-version":"1.4"},"name":name,"versions":["2.0"],"files":[{"filename":format!("{name}-2.0-py3-none-any.whl"),"url":format!("{name}-2.0.whl"),"hashes":{},"size":100}]}).to_string()).build()
    });});
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.respond_with(|request| {
            let body: Value = serde_json::from_slice(request.body_ref()).unwrap();
            let results = vec![json!({}); body["queries"].as_array().unwrap().len()];
            httpmock::HttpMockResponse::builder()
                .status(200)
                .body(json!({"results":results}).to_string())
                .build()
        });
    });
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let limits = pybun::security_assessment::ObservationLimits {
        total_timeout_ms: 5000,
        http_timeout_ms: 1000,
        max_candidate_checks: 10,
        ..Default::default()
    };
    let mut seen = BTreeSet::new();
    let mut epoch = None;
    for _ in 0..3 {
        let result = session.call(json!({"action":"check","monitor_id":id,"limits":limits}));
        assert_eq!(result["commit_status"], "committed", "{result}");
        if let Some(epoch) = &epoch {
            assert_eq!(&result["current"]["epoch_id"], epoch);
        } else {
            epoch = Some(result["current"]["epoch_id"].clone());
        }
        for package in result["check"]["assessment"]["packages"]
            .as_array()
            .expect("bounded fixture assessment")
        {
            if !package["candidates"].as_array().unwrap().is_empty() {
                seen.insert(package["instance_id"].as_str().unwrap().to_string());
            }
        }
    }
    assert_eq!(
        seen.len(),
        13,
        "durable round-robin progress must reach every current instance"
    );
    session.finish();
}

#[cfg(unix)]
#[test]
fn durable_progress_reaches_twenty_first_candidate_and_emits_only_qualified_fix() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    server.reset();
    let config = config.replace("max_output_bytes=65536", "max_output_bytes=1048576");
    let versions: Vec<_> = (2..=31).map(|value| format!("{value}.0")).collect();
    server.mock(|when,then|{when.method(GET).path("/simple/six/");then.json_body(json!({"meta":{"api-version":"1.4"},"name":"six","versions":versions,"files":versions.iter().map(|version|json!({"filename":format!("six-{version}-py3-none-any.whl"),"url":format!("six-{version}.whl"),"hashes":{},"size":100})).collect::<Vec<_>>()}));});
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.respond_with(|request| {
            let body: Value = serde_json::from_slice(request.body_ref()).unwrap();
            let results =
                vec![json!({"vulns":[{"id":"FIX-22"}]}); body["queries"].as_array().unwrap().len()];
            httpmock::HttpMockResponse::builder()
                .status(200)
                .body(json!({"results":results}).to_string())
                .build()
        });
    });
    server.mock(|when,then|{when.method(GET).path("/v1/vulns/FIX-22");then.json_body(json!({"id":"FIX-22","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"22.0"}]}]}]}));});
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let first = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(first["commit_status"], "committed", "{first}");
    assert!(
        !first["newly_committed_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_type"] == "fix_candidate_available"),
        "first20 must not invent fix: {first}"
    );
    let second = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(second["commit_status"], "committed", "{second}");
    assert_eq!(second["current"]["epoch_id"], first["current"]["epoch_id"]);
    assert!(
        second["newly_committed_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_type"] == "fix_candidate_available"
                && event["candidate_version"] == "22"),
        "21st candidate must be durably reached: {second}"
    );
    session.finish();
}

#[cfg(unix)]
#[test]
fn stored_registration_never_grants_visibility_or_checks_after_profile_revocation() {
    let server = httpmock::MockServer::start();
    let requests = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    let (root, _state, config) = fixture::fixture(&server, true);
    let added = fixture::cli(
        root.path(),
        &config,
        &["add", "--name", "private-name", "--profile", "app"],
    );
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let revoked = config.replace(
        "allowed_security_profiles=[\"app\"]",
        "allowed_security_profiles=[]",
    );
    let mut session = fixture::Session::start(root.path(), &revoked);
    let listed = session.call(json!({"action":"list"}));
    assert!(!listed.to_string().contains("private-name"));
    assert!(!listed.to_string().contains(id));
    let hidden = session.call(json!({"action":"events","monitor_id":id}));
    let missing = session.call(json!({"action":"events","monitor_id":"nonexistent-monitor"}));
    assert_eq!(
        hidden, missing,
        "missing and invisible monitors must be indistinguishable"
    );
    let denied = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(denied["exit_code"], 3);
    assert!(denied.get("current").is_none());
    requests.assert_calls(0);
    assert!(!root.path().join("helper-ran").exists());
    session.finish();
}

#[cfg(unix)]
#[test]
fn offline_checks_retain_known_findings_without_network_or_authoritative_transitions() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    let config = config.replace("max_output_bytes=65536", "max_output_bytes=262144");
    let query = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{"vulns":[{"id":"OFFLINE-HIGH"}]}]}));
    });
    let detail=server.mock(|when,then|{when.method(GET).path("/v1/vulns/OFFLINE-HIGH");then.json_body(json!({"id":"OFFLINE-HIGH","modified":"2026-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}));});
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let online = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(online["current"]["findings"][0]["active"], true);
    for _ in 0..2 {
        let offline = session.call(json!({"action":"check","monitor_id":id,"mode":"offline"}));
        assert_eq!(offline["exit_code"], 3, "{offline}");
        assert_eq!(offline["current"]["findings"][0]["active"], true);
        assert!(
            !offline["newly_committed_events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| matches!(
                    event["event_type"].as_str(),
                    Some(
                        "finding_resolved"
                            | "advisory_withdrawn"
                            | "severity_increased"
                            | "fix_candidate_available"
                    )
                )),
            "{offline}"
        );
    }
    query.assert_calls(1);
    detail.assert_calls(1);
    session.finish();
}

#[cfg(unix)]
#[test]
fn unsupported_or_mismatched_add_target_does_not_even_initialize_state() {
    for extra in [
        json!({"target":"locked"}),
        json!({"project":"/unapproved-target"}),
    ] {
        let server = httpmock::MockServer::start();
        let (root, state, config) = fixture::fixture(&server, true);
        let mut session = fixture::Session::start(root.path(), &config);
        let mut args = json!({"action":"add","name":"app","profile":"app"});
        for (key, value) in extra.as_object().unwrap() {
            args[key] = value.clone();
        }
        let rejected = session.call(args);
        assert_eq!(rejected["exit_code"], 3, "{rejected}");
        assert!(
            !state.path().join("state").exists(),
            "invalid target must not create an empty state root"
        );
        assert!(!root.path().join("helper-ran").exists());
        session.finish();
    }
}

#[cfg(unix)]
#[test]
fn replay_scope_error_after_commit_keeps_new_event_receipt_and_stable_ids() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let mut session = fixture::Session::start(root.path(), &config);
    let a = session.call(json!({"action":"add","name":"a","profile":"app"}));
    let aid = a["registration"]["monitor_id"].as_str().unwrap();
    let first = session.call(json!({"action":"check","monitor_id":aid}));
    let cursor = first["replay"]["next_cursor"].clone();
    let b = session.call(json!({"action":"add","name":"b","profile":"app"}));
    let bid = b["registration"]["monitor_id"].as_str().unwrap();
    let committed = session.call(json!({"action":"check","monitor_id":bid,"after":cursor}));
    assert_eq!(committed["exit_code"], 3, "{committed}");
    assert_eq!(committed["commit_status"], "committed");
    assert_eq!(committed["newly_committed_count"], 1, "{committed}");
    assert_eq!(committed["newly_committed_events"][0]["monitor_id"], bid);
    let events = session.call(json!({"action":"events","monitor_id":bid}));
    assert_eq!(
        events["replay"]["events"],
        committed["newly_committed_events"]
    );
    let repeated = session.call(json!({"action":"check","monitor_id":bid}));
    assert_eq!(repeated["newly_committed_count"], 0, "{repeated}");
    session.finish();
}

#[cfg(unix)]
#[test]
fn malformed_bounded_cursor_returns_authorized_current_scope_without_observation() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    let query = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let first = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(first["exit_code"], 0);
    let calls = std::fs::read_to_string(root.path().join("helper-ran")).unwrap();
    for action in ["events", "check"] {
        let rejected =
            session.call(json!({"action":action,"monitor_id":id,"after":"not-a-cursor"}));
        assert_eq!(rejected["exit_code"], 3, "{rejected}");
        assert_eq!(rejected["diagnostics"][0]["code"], "E_MONITOR_CURSOR_SCOPE");
        assert_eq!(rejected["current"]["monitor_id"], id, "{rejected}");
        assert!(rejected["replay"]["resync_cursor"].is_string());
        assert_eq!(
            std::fs::read_to_string(root.path().join("helper-ran")).unwrap(),
            calls
        );
    }
    query.assert_calls(1);
    session.finish();
}

#[cfg(unix)]
#[test]
fn lost_stdio_response_after_check_replays_same_committed_ids_without_new_generation() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    let query = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    session.lose_response(json!({"action":"check","monitor_id":id}));
    let replay = fixture::cli(root.path(), &config, &["events", id]);
    assert_eq!(replay["exit_code"], 0, "{replay}");
    assert_eq!(replay["replay"]["events"].as_array().unwrap().len(), 1);
    let repeated = fixture::cli(root.path(), &config, &["events", id]);
    assert_eq!(repeated["replay"]["events"], replay["replay"]["events"]);
    assert_eq!(
        repeated["current"]["generation"],
        replay["current"]["generation"]
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("helper-ran"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    query.assert_calls(1);
}

#[cfg(unix)]
#[test]
fn malformed_cursor_summary_respects_selected_profile_output_cap() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    let config = config.replace("max_output_bytes=65536", "max_output_bytes=1048576");
    let ids: Vec<_> = (0..4)
        .map(|index| format!("PROFILE-BOUND-{index}"))
        .collect();
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(
            json!({"results":[{"vulns":ids.iter().map(|id|json!({"id":id})).collect::<Vec<_>>()}]}),
        );
    });
    for id in &ids {
        server.mock(|when,then|{when.method(GET).path(format!("/v1/vulns/{id}"));then.json_body(json!({"id":id,"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}));});
    }
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let first = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(first["current"]["findings"].as_array().unwrap().len(), 4);
    session.finish();
    let narrowed=config.replace("allowed_modes=[\"online\",\"offline\",\"online_with_cache_fallback\"]","allowed_modes=[\"online\",\"offline\",\"online_with_cache_fallback\"]\nlimits={max_output_bytes=4096}");
    let mut session = fixture::Session::start(root.path(), &narrowed);
    let result = session.call(json!({"action":"events","monitor_id":id,"after":"not-a-cursor"}));
    assert_eq!(result["exit_code"], 3, "{result}");
    assert!(
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["code"] == "E_MONITOR_CURSOR_SCOPE"),
        "{result}"
    );
    assert!(
        session.last_wire_bytes <= 4096,
        "selected profile cap exceeded: {}",
        session.last_wire_bytes
    );
    session.finish();
}

#[cfg(unix)]
#[test]
fn same_profile_operator_policy_change_is_adopted_before_check_without_configure() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    server.reset();
    let config = config.replace("max_output_bytes=65536", "max_output_bytes=524288");
    server.mock(|when,then|{when.method(GET).path("/simple/six/");then.json_body(json!({"meta":{"api-version":"1.4"},"name":"six","versions":["2rc1"],"files":[{"filename":"six-2rc1-py3-none-any.whl","url":"six-2rc1.whl","hashes":{},"size":100}]}));});
    server.mock(|when,then|{when.method(POST).path("/v1/querybatch");then.respond_with(|request|{let body:Value=serde_json::from_slice(request.body_ref()).unwrap();httpmock::HttpMockResponse::builder().status(200).body(json!({"results":vec![json!({"vulns":[{"id":"PRE-FIX"}]});body["queries"].as_array().unwrap().len()]}).to_string()).build()});});
    server.mock(|when,then|{when.method(GET).path("/v1/vulns/PRE-FIX");then.json_body(json!({"id":"PRE-FIX","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2rc1"}]}]}]}));});
    let mut session = fixture::Session::start(root.path(), &config);
    let added = session.call(json!({"action":"add","name":"app","profile":"app"}));
    let id = added["registration"]["monitor_id"].as_str().unwrap();
    let initial = session.call(json!({"action":"check","monitor_id":id}));
    session.finish();
    let updated=config.replace("allowed_modes=[\"online\",\"offline\",\"online_with_cache_fallback\"]","allowed_modes=[\"online\",\"offline\",\"online_with_cache_fallback\"]\ninclude_prereleases=true\nmax_cache_age_seconds=30");
    let mut session = fixture::Session::start(root.path(), &updated);
    let adopted = session.call(json!({"action":"check","monitor_id":id}));
    assert_eq!(adopted["commit_status"], "committed", "{adopted}");
    assert_ne!(
        adopted["current"]["epoch_id"],
        initial["current"]["epoch_id"]
    );
    let listed = session.call(json!({"action":"list"}));
    let stored = &listed["registrations"][0];
    assert_eq!(stored["config"]["include_prereleases"], true, "{stored}");
    assert_eq!(stored["config"]["freshness_ttl_seconds"], 30, "{stored}");
    assert_eq!(
        stored["config_revision"], 2,
        "one operator update must adopt once: {stored}"
    );
    assert_eq!(
        adopted["current"]["findings"][0]["candidate"]["version"], "2rc1",
        "{adopted}"
    );
    let repeated = session
        .call(json!({"action":"check","monitor_id":id,"after":adopted["replay"]["next_cursor"]}));
    assert_eq!(
        repeated["current"]["epoch_id"],
        adopted["current"]["epoch_id"]
    );
    assert_eq!(repeated["current"]["config_revision"], 2);
    assert!(
        repeated["check"]["assessment"]["packages"][0]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["qualification"]["version"] == "2rc1"),
        "{repeated}"
    );
    session.finish();
}

#[cfg(unix)]
#[test]
fn zero_freshness_ceiling_registers_and_checks_without_widening_authority() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, _state, config) = fixture::fixture(&server, true);
    let config=config.replace("allowed_modes=[\"online\",\"offline\",\"online_with_cache_fallback\"]","allowed_modes=[\"online\",\"offline\",\"online_with_cache_fallback\"]\nmax_cache_age_seconds=0");
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let added = fixture::cli(
        root.path(),
        &config,
        &["add", "--name", "zero-cli", "--profile", "app"],
    );
    assert_eq!(
        added["exit_code"], 0,
        "valid zero-ceiling profile must register: {added}"
    );
    assert_eq!(added["registration"]["config"]["freshness_ttl_seconds"], 0);
    let cli_id = added["registration"]["monitor_id"].as_str().unwrap();
    let observed = fixture::cli(
        root.path(),
        &config,
        &["check", cli_id, "--max-cache-age-seconds", "0"],
    );
    assert_eq!(observed["exit_code"], 0, "{observed}");
    assert_eq!(observed["commit_status"], "committed");
    let mut session = fixture::Session::start(root.path(), &config);
    let registered = session.call(json!({"action":"add","name":"zero-mcp","profile":"app"}));
    assert_eq!(registered["exit_code"], 0, "{registered}");
    assert_eq!(
        registered["registration"]["config"]["freshness_ttl_seconds"],
        0
    );
    let id = registered["registration"]["monitor_id"].as_str().unwrap();
    let observed =
        session.call(json!({"action":"check","monitor_id":id,"max_cache_age_seconds":0}));
    assert_eq!(observed["exit_code"], 0, "{observed}");
    assert_eq!(observed["current"]["complete"], true);
    session.finish();
}

fn exchange(requests: &[Value]) -> (tempfile::TempDir, Vec<Value>) {
    let root = tempfile::tempdir().unwrap();
    let policy = root.path().join("operator.toml");
    std::fs::write(&policy, "[mcp.policy]\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(root.path())
        .env("PYBUN_MCP_POLICY", policy)
        .env("PYBUN_HOME", root.path().join("home"))
        .env(
            "PYBUN_AUDIT_LOG",
            root.path().join("forbidden-audit/events.jsonl"),
        )
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for request in requests {
        writeln!(input, "{request}").unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let replies = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (root, replies)
}

fn body(reply: &Value) -> Value {
    serde_json::from_str(reply["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[test]
fn monitor_tool_advertises_strict_action_variants() {
    let (_, replies) = exchange(&[json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})]);
    let tools = replies[0]["result"]["tools"].as_array().unwrap();
    let monitor = tools
        .iter()
        .find(|tool| tool["name"] == "pybun_security_monitor")
        .expect("monitor tool");
    let variants = monitor["inputSchema"]["oneOf"].as_array().unwrap();
    for action in ["list", "add", "check", "events", "configure", "remove"] {
        assert!(
            variants
                .iter()
                .any(|variant| variant["properties"]["action"]["const"] == action
                    && variant["additionalProperties"] == false),
            "{action}"
        );
    }
    let configure = variants
        .iter()
        .find(|variant| variant["properties"]["action"]["const"] == "configure")
        .unwrap();
    assert_eq!(
        configure["properties"]["profile"]["type"], "string",
        "required profile assertion is not nullable"
    );
}

#[test]
fn monitor_default_denial_and_invalid_actions_never_initialize_state_or_audit() {
    let (root, replies) = exchange(&[
        call(json!({"action":"list"})),
        call(json!({"action":"daemon"})),
        call(json!({"action":"list","state_root":"/tmp/forbidden"})),
    ]);
    for (index, reply) in replies.iter().enumerate() {
        let detail = body(reply);
        assert_eq!(detail["operation"], "security_monitor");
        assert_eq!(detail["exit_code"], if index == 0 { 3 } else { 2 });
        assert_eq!(detail["commit_status"], "not_committed");
        assert_eq!(reply["result"]["isError"], true);
    }
    for path in ["home", "forbidden-audit", ".pybun", "monitor-state"] {
        assert!(!root.path().join(path).exists(), "{path}");
    }
}
