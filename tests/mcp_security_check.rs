//! Read-only MCP security checks must authorize before any observation side effect.
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, Command, Stdio},
};

fn request(id: u64, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"pybun_security_check","arguments":arguments}})
}

fn serve(root: &Path, policy: &str, requests: &[Value]) -> Vec<Value> {
    let mut child = start(root, policy);
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
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn start(root: &Path, policy: &str) -> Child {
    start_at(root, policy, &root.join("operator.toml"))
}

fn start_at(root: &Path, policy: &str, selected: &Path) -> Child {
    let policy_path = root.join("operator.toml");
    fs::write(&policy_path, policy).unwrap();
    Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(root)
        .env("PYBUN_MCP_POLICY", selected)
        .env("PYBUN_HOME", root.join("home"))
        .env("PYBUN_AUDIT_LOG", root.join("forbidden-audit/events.jsonl"))
        .env("PYBUN_HISTORY", "0")
        // The check must use its frozen uv profile, never ambient retargeting.
        .env("PYBUN_BACKEND", "native")
        .env("PYBUN_PYTHON", root.join("forbidden-python"))
        .env("PYBUN_ENV", root.join("ambient-environment"))
        .env("PYBUN_UV", root.join("forbidden-uv"))
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn body(reply: &Value) -> Value {
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .or_else(|| reply["result"]["contents"][0]["text"].as_str())
        .unwrap();
    serde_json::from_str(text.strip_prefix("Error: ").unwrap_or(text)).unwrap()
}

fn no_side_effects(root: &Path) {
    for path in [
        "home",
        "forbidden-audit",
        ".pybun",
        "helper-ran",
        "monitor-state",
    ] {
        assert!(
            !root.join(path).exists(),
            "unexpected observation side effect: {path}"
        );
    }
}

#[test]
fn security_check_is_advertised_with_strict_read_only_request_schema() {
    let temp = tempfile::tempdir().unwrap();
    let replies = serve(
        temp.path(),
        "[mcp.policy]\n",
        &[json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})],
    );
    let tools = replies[0]["result"]["tools"].as_array().unwrap();
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "pybun_security_check")
        .expect("new check tool");
    let schema = &tool["inputSchema"];
    assert_eq!(schema["additionalProperties"], false);
    for name in [
        "action",
        "trusted_python",
        "provider_url",
        "cache_root",
        "sandbox_policy",
        "environment",
    ] {
        assert!(schema["properties"].get(name).is_none(), "{name}");
    }
    assert_eq!(
        schema["properties"]["mode"]["enum"],
        json!(["online", "offline", "online_with_cache_fallback"])
    );
    no_side_effects(temp.path());
}

#[test]
fn default_check_denial_is_shared_coded_and_audited_only_in_memory() {
    let temp = tempfile::tempdir().unwrap();
    let replies = serve(
        temp.path(),
        "[mcp.policy]\n",
        &[
            request(1, json!({"mode":"offline"})),
            json!({"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"pybun://audit/recent"}}),
        ],
    );
    assert_eq!(replies[0]["result"]["isError"], true);
    let denied = body(&replies[0]);
    assert_eq!(denied["operation"], "security_check");
    assert_eq!(denied["exit_code"], 3);
    assert!(
        denied["diagnostics"][0]["code"]
            .as_str()
            .unwrap()
            .starts_with("E_MCP_POLICY_")
    );
    let recent = body(&replies[1]);
    assert_eq!(recent["count"], 1);
    assert_eq!(recent["entries"][0]["tool"], "pybun_security_check");
    no_side_effects(temp.path());
}

#[test]
fn strict_request_rejects_actions_retargeting_and_bad_continuations_before_authority() {
    let temp = tempfile::tempdir().unwrap();
    let requests = [
        json!({"action":"configure"}),
        json!({"trusted_python":"/bin/sh"}),
        json!({"provider_url":"http://127.0.0.1/"}),
        json!({"target":"system"}),
        json!({"mode":"automatic"}),
        json!({"continuation":"not-a-continuation"}),
        json!({"_authorized_roots":["/"]}),
        json!({"sandbox_policy":{"allow_network":true}}),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, args)| request(index as u64 + 1, args))
    .collect::<Vec<_>>();
    let replies = serve(temp.path(), "[mcp.policy]\n", &requests);
    for reply in replies {
        assert_eq!(reply["result"]["isError"], true);
        let denied = body(&reply);
        assert_eq!(denied["operation"], "security_check");
        assert_eq!(denied["exit_code"], 2, "{denied}");
    }
    no_side_effects(temp.path());
}

#[test]
fn denied_tool_precedes_new_capability_authority_lookup() {
    let temp = tempfile::tempdir().unwrap();
    let replies = serve(
        temp.path(),
        "[mcp.policy]\ndenied_tools=['pybun_security_check']\n",
        &[request(1, json!({}))],
    );
    assert_eq!(
        body(&replies[0])["diagnostics"][0]["code"],
        "E_MCP_POLICY_TOOL_DENIED"
    );
    no_side_effects(temp.path());
}

#[test]
fn malformed_continuation_has_the_identical_cli_and_mcp_failure_body() {
    let root = tempfile::tempdir().unwrap();
    let replies = serve(
        root.path(),
        "[mcp.policy]\n",
        &[request(1, json!({"continuation":"malformed"}))],
    );
    let cli = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(root.path())
        .env("PYBUN_HOME", root.path().join("home"))
        .env("PYBUN_HISTORY", "0")
        .args([
            "--format=json",
            "audit",
            "check-updates",
            "--continuation",
            "malformed",
        ])
        .output()
        .unwrap();
    assert_eq!(
        cli.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli: Value = serde_json::from_slice(&cli.stdout).unwrap();
    assert_eq!(body(&replies[0]), cli["detail"]);
    no_side_effects(root.path());
}

#[cfg(unix)]
#[path = "common/security_check_fixture.rs"]
mod security_fixture;
#[cfg(unix)]
use security_fixture::fixture;

#[cfg(unix)]
#[test]
fn compatible_opt_in_observes_frozen_target_with_local_http_and_no_durable_audit() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let advisory = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200).json_body(json!({"results":[{}]}));
    });
    let (root, config) = fixture(&server, true);
    let limits = pybun::security_assessment::ObservationLimits {
        total_timeout_ms: 2000,
        http_timeout_ms: 1000,
        ..Default::default()
    };
    let replies = serve(
        root.path(),
        &config,
        &[
            request(1, json!({"limits":limits})),
            json!({"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"pybun://audit/recent"}}),
        ],
    );
    let check = body(&replies[0]);
    assert_ne!(
        replies[0]["result"]["isError"], true,
        "{} {}",
        check["diagnostics"], check["assessment"]["coverage"]
    );
    assert_eq!(check["operation"], "security_check");
    assert_eq!(check["exit_code"], 0, "{}", check["diagnostics"]);
    assert_eq!(check["assessment"]["inventory"]["target"]["backend"], "uv");
    assert_eq!(check["profile_id"], "app");
    assert_eq!(check["policy_applied"]["sandboxed"], false);
    assert_eq!(check["policy_applied"]["effective_total_timeout_ms"], 2000);
    assert_eq!(check["policy_applied"]["effective_http_timeout_ms"], 1000);
    assert_eq!(body(&replies[1])["count"], 1);
    assert_eq!(
        body(&replies[1])["entries"][0]["file_snapshot_complete"],
        false
    );
    advisory.assert_calls(1);
    assert!(root.path().join("helper-ran").exists());
    for path in [
        "forbidden-audit",
        "home",
        ".pybun",
        "startup-hook-ran",
        "ambient-environment",
    ] {
        assert!(!root.path().join(path).exists(), "{path}");
    }
}

#[cfg(unix)]
#[test]
fn required_sandbox_cpu_and_memory_boundaries_deny_before_observation() {
    let server = httpmock::MockServer::start();
    let (root, config) = fixture(&server, true);
    for forbidden in [
        config.replace("require_sandbox=false", "require_sandbox=true"),
        config.replace(
            "max_execution_time_s=5",
            "max_execution_time_s=5\nmax_memory_mb=64",
        ),
        config.replace(
            "max_execution_time_s=5",
            "max_execution_time_s=5\nmax_cpu_time_s=1",
        ),
    ] {
        let reply = serve(root.path(), &forbidden, &[request(1, json!({}))]);
        assert_eq!(
            body(&reply[0])["diagnostics"][0]["code"],
            "E_MCP_POLICY_UNSUPPORTED"
        );
        no_side_effects(root.path());
        assert_eq!(fs::read_dir(root.path().join("cache")).unwrap().count(), 0);
    }
}

#[cfg(unix)]
#[test]
fn offline_opt_in_needs_no_http_grant_and_does_not_contact_provider() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let requests = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    let (root, config) = fixture(&server, true);
    let config = config
        .replace("allow_network=true", "allow_network=false")
        .replace(
            "\"authorized_target_metadata_read\",\"approved_provider_http\"",
            "\"authorized_target_metadata_read\"",
        );
    let replies = serve(
        root.path(),
        &config,
        &[request(1, json!({"mode":"offline"}))],
    );
    let check = body(&replies[0]);
    assert_eq!(check["exit_code"], 3, "{check}");
    assert_eq!(replies[0]["result"]["isError"], true);
    assert!(root.path().join("helper-ran").exists());
    requests.assert_calls(0);
    assert!(!root.path().join("forbidden-audit").exists());
    assert_eq!(fs::read_dir(root.path().join("cache")).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn backend_profile_and_network_grants_deny_without_disclosing_private_profile_ids() {
    let server = httpmock::MockServer::start();
    let (root, config) = fixture(&server, true);
    let outside = tempfile::tempdir().unwrap();
    for (policy, args, code) in [
        (
            config.replace("allowed_backends=[\"uv\"]", "allowed_backends=[\"native\"]"),
            json!({}),
            "E_MCP_POLICY_BACKEND_DENIED",
        ),
        (
            config.clone(),
            json!({"profile":"ungranted-profile"}),
            "E_MCP_POLICY_PROFILE_DENIED",
        ),
        (
            config.replace("allow_network=true", "allow_network=false"),
            json!({}),
            "E_MCP_POLICY_NETWORK_DENIED",
        ),
        (
            config.clone(),
            json!({"project":outside.path()}),
            "E_MCP_POLICY_PATH_DENIED",
        ),
        (
            config.replace(
                "authorized_target_metadata_read",
                "unknown_metadata_capability",
            ),
            json!({}),
            "E_MCP_POLICY_INVALID",
        ),
    ] {
        let replies = serve(root.path(), &policy, &[request(1, args)]);
        assert_eq!(
            body(&replies[0])["diagnostics"][0]["code"],
            code,
            "{}",
            replies[0]
        );
        no_side_effects(root.path());
    }
    let private = config.replace(
        "allowed_security_profiles=[\"app\"]",
        "allowed_security_profiles=[\"hidden-tenant-profile\"]",
    );
    let replies = serve(
        root.path(),
        &private,
        &[
            request(1, json!({})),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        ],
    );
    assert!(
        !serde_json::to_string(&replies)
            .unwrap()
            .contains("hidden-tenant-profile")
    );
}

#[cfg(unix)]
#[test]
fn rate_limited_checks_are_shared_failures_audited_only_in_memory() {
    let server = httpmock::MockServer::start();
    let (root, config) = fixture(&server, false);
    let config = format!(
        "{config}\n[mcp.rate_limit.per_tool.pybun_security_check]\ncalls=1\nwindow_secs=60\n"
    );
    let replies = serve(
        root.path(),
        &config,
        &[
            request(1, json!({})),
            request(2, json!({})),
            json!({"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"pybun://audit/recent"}}),
        ],
    );
    assert_eq!(
        body(&replies[0])["exit_code"],
        0,
        "{} {}",
        body(&replies[0])["diagnostics"],
        body(&replies[0])["assessment"]["coverage"]
    );
    let denied = body(&replies[1]);
    assert_eq!(denied["operation"], "security_check");
    assert_eq!(denied["exit_code"], 3);
    assert_eq!(denied["diagnostics"][0]["code"], "mcp.rate_limit_exceeded");
    assert!(denied["retry_after_ms"].as_u64().unwrap() > 0);
    assert_eq!(body(&replies[2])["count"], 2);
    assert_eq!(
        fs::read_to_string(root.path().join("helper-ran"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert!(!root.path().join("forbidden-audit").exists());
}

#[test]
fn server_does_not_accept_new_grants_from_an_edited_startup_policy() {
    let root = tempfile::tempdir().unwrap();
    let mut child = start(root.path(), "[mcp.policy]\n");
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})
    )
    .unwrap();
    input.flush().unwrap();
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    fs::write(root.path().join("operator.toml"),"[mcp.policy]\nrequire_sandbox=false\nallow_network=true\nallowed_security_capabilities=['authorized_target_metadata_read','approved_provider_http']\nallowed_security_profiles=['app']\n").unwrap();
    writeln!(input, "{}", request(2, json!({"mode":"offline"}))).unwrap();
    input.flush().unwrap();
    line.clear();
    output.read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        body(&reply)["diagnostics"][0]["code"],
        "E_MCP_POLICY_CAPABILITY_DENIED"
    );
    drop(input);
    assert!(child.wait().unwrap().success());
    no_side_effects(root.path());
}

#[cfg(unix)]
#[test]
fn server_freezes_approved_endpoints_with_the_startup_policy_snapshot() {
    use httpmock::prelude::*;
    let original = MockServer::start();
    let changed = MockServer::start();
    let approved = original.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.status(200).json_body(json!({"results":[{}]}));
    });
    let forbidden = changed.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    let (root, config) = fixture(&original, true);
    let mut child = start(root.path(), &config);
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})
    )
    .unwrap();
    input.flush().unwrap();
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let edited = config.replace(
        &original.url("/v1/querybatch"),
        &changed.url("/v1/querybatch"),
    );
    fs::write(root.path().join("operator.toml"), edited).unwrap();
    writeln!(input, "{}", request(2, json!({}))).unwrap();
    input.flush().unwrap();
    line.clear();
    output.read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        body(&reply)["exit_code"],
        0,
        "{} {}",
        body(&reply)["diagnostics"],
        body(&reply)["assessment"]["coverage"]
    );
    approved.assert_calls(1);
    forbidden.assert_calls(0);
    drop(input);
    assert!(child.wait().unwrap().success());
    assert!(!root.path().join("forbidden-audit").exists());
}

#[cfg(unix)]
#[test]
fn path_extension_metadata_remains_partial_without_executing_startup_hooks() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let (root, config) = fixture(&server, true);
    let site = fs::read_dir(root.path().join(".venv/lib"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("site-packages");
    fs::write(
        site.join("forbidden.pth"),
        format!(
            "import builtins; open({:?},'w').write('bad')\n",
            root.path().join("startup-hook-ran").to_string_lossy()
        ),
    )
    .unwrap();
    let replies = serve(root.path(), &config, &[request(1, json!({}))]);
    let check = body(&replies[0]);
    assert_eq!(check["exit_code"], 3);
    assert_eq!(check["status"], "partial");
    assert_eq!(replies[0]["result"]["isError"], true);
    assert!(
        check["assessment"]["inventory"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "E_SECURITY_UNSUPPORTED_PATH_EXTENSION")
    );
    assert!(!root.path().join("startup-hook-ran").exists());
    assert!(!root.path().join("forbidden-audit").exists());
}

#[cfg(unix)]
#[test]
fn complete_findings_are_successful_until_the_requested_threshold_matches() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, config) = fixture(&server, true);
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{"vulns":[{"id":"TEST-SIX-1"}]}]}));
    });
    server.mock(|when,then| {
        when.method(GET).path("/v1/vulns/TEST-SIX-1");
        then.json_body(json!({"id":"TEST-SIX-1","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}));
    });
    let replies = serve(
        root.path(),
        &config,
        &[request(1, json!({})), request(2, json!({"fail_on":"high"}))],
    );
    let observed = body(&replies[0]);
    let threshold = body(&replies[1]);
    assert_eq!(
        observed["status"], "complete",
        "{} {}",
        observed["diagnostics"], observed["assessment"]["coverage"]
    );
    assert_eq!(observed["exit_code"], 0);
    assert_ne!(replies[0]["result"]["isError"], true);
    assert_eq!(threshold["status"], "complete");
    assert_eq!(threshold["exit_code"], 1);
    assert!(
        !threshold["threshold_matches"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(replies[1]["result"]["isError"], true);
    assert!(!root.path().join("forbidden-audit").exists());
}

#[cfg(unix)]
#[test]
fn rate_rejection_precedes_executable_revalidation_and_target_reads() {
    let server = httpmock::MockServer::start();
    let (root, config) = fixture(&server, false);
    let config = format!(
        "{config}\n[mcp.rate_limit.per_tool.pybun_security_check]\ncalls=1\nwindow_secs=60\n"
    );
    let mut child = start(root.path(), &config);
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    writeln!(input, "{}", request(1, json!({}))).unwrap();
    input.flush().unwrap();
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let first: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        body(&first)["exit_code"],
        0,
        "{}",
        body(&first)["diagnostics"]
    );
    // A full authorizer would reject this changed executable. The rate-denied
    // request must not reach that filesystem revalidation at all.
    fs::write(root.path().join("trusted-python"), "#!/bin/sh\nexit 99\n").unwrap();
    fs::write(root.path().join("pyproject.toml"), "invalid = [metadata\n").unwrap();
    writeln!(input, "{}", request(2, json!({}))).unwrap();
    input.flush().unwrap();
    line.clear();
    output.read_line(&mut line).unwrap();
    let denied: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        body(&denied)["diagnostics"][0]["code"],
        "mcp.rate_limit_exceeded"
    );
    assert_eq!(
        fs::read_to_string(root.path().join("helper-ran"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    drop(input);
    assert!(child.wait().unwrap().success());
    assert!(!root.path().join("forbidden-audit").exists());
}

#[cfg(unix)]
#[test]
fn compatible_profile_loads_from_a_bare_relative_operator_override() {
    let server = httpmock::MockServer::start();
    let (root, config) = fixture(&server, false);
    let mut child = start_at(root.path(), &config, Path::new("operator.toml"));
    let mut input = child.stdin.take().unwrap();
    writeln!(input, "{}", request(1, json!({}))).unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        body(&reply)["exit_code"],
        0,
        "{}",
        body(&reply)["diagnostics"]
    );
    assert_ne!(reply["result"]["isError"], true);
    assert!(!root.path().join("forbidden-audit").exists());
}

#[cfg(unix)]
#[test]
fn swapped_environment_is_reauthorized_before_helper_cache_or_http_access() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let requests = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    let (root, config) = fixture(&server, true);
    let outside = tempfile::tempdir().unwrap();
    let mut child = start(root.path(), &config);
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})
    )
    .unwrap();
    input.flush().unwrap();
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    fs::rename(root.path().join(".venv"), root.path().join(".venv-old")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join(".venv")).unwrap();
    writeln!(input, "{}", request(2, json!({}))).unwrap();
    input.flush().unwrap();
    line.clear();
    output.read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(body(&reply)["exit_code"], 3);
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(
        body(&reply)["diagnostics"][0]["code"],
        "E_SECURITY_AUTHORITY"
    );
    requests.assert_calls(0);
    no_side_effects(root.path());
    assert_eq!(fs::read_dir(root.path().join("cache")).unwrap().count(), 0);
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[cfg(unix)]
#[test]
fn output_limit_bounds_actual_rpc_wire_and_retains_match_omission_counts() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, config) = fixture(&server, true);
    let config = config.replace("max_output_bytes=65536", "max_output_bytes=4096");
    let ids: Vec<_> = (0..24).map(|index| format!("BOUND-SIX-{index}")).collect();
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(
            json!({"results":[{"vulns":ids.iter().map(|id|json!({"id":id})).collect::<Vec<_>>()}]}),
        );
    });
    for id in &ids {
        server.mock(|when,then| {when.method(GET).path(format!("/v1/vulns/{id}"));
            then.json_body(json!({"id":id,"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}));
        });
    }
    let replies = serve(
        root.path(),
        &config,
        &[request(1, json!({"fail_on":"high"}))],
    );
    let check = body(&replies[0]);
    assert_eq!(check["exit_code"], 3);
    assert_eq!(check["diagnostics"][0]["code"], "E_SECURITY_OUTPUT_LIMIT");
    assert_eq!(check["threshold_match_count"], 24);
    assert_eq!(check["omitted"]["inventory_instances"], 1);
    assert_eq!(check["omitted"]["advisory_records"], 24);
    assert!(check["omitted"]["threshold_matches"].as_u64().unwrap() > 0);
    assert!(
        serde_json::to_vec(&replies[0]).unwrap().len() <= 4096,
        "RPC wire exceeded profile output bound"
    );
    assert!(!root.path().join("forbidden-audit").exists());
}

#[cfg(unix)]
#[test]
fn provider_declared_low_severity_does_not_match_a_high_threshold() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let (root, config) = fixture(&server, true);
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{"vulns":[{"id":"TEST-LOW"}]}]}));
    });
    server.mock(|when,then| {when.method(GET).path("/v1/vulns/TEST-LOW");
        then.json_body(json!({"id":"TEST-LOW","modified":"2026-01-01T00:00:00Z","database_specific":{"severity":"LOW"},"affected":[{"package":{"name":"six","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}));
    });
    let replies = serve(
        root.path(),
        &config,
        &[request(1, json!({"fail_on":"high"}))],
    );
    let check = body(&replies[0]);
    assert_eq!(
        check["status"], "complete",
        "{} {}",
        check["diagnostics"], check["assessment"]["coverage"]
    );
    assert_eq!(check["exit_code"], 0);
    assert_ne!(replies[0]["result"]["isError"], true);
    assert_eq!(check["threshold_match_count"], 0);
    assert_eq!(
        check["assessment"]["packages"][0]["installed"]["clusters"][0]["severity"],
        "low"
    );
    assert!(!root.path().join("forbidden-audit").exists());
}
