//! Central policy and rate admission before tool or resource side effects.
use super::*;
use std::time::Instant;

const SECURITY_FAILURE_BYTES: usize = 4096;
// Fixed JSON-RPC/content framing, excluding the caller-supplied request ID.
const SECURITY_RPC_RESERVE: usize = 128;

fn bounded_monitor_body(mut value: Value, max_bytes: usize) -> Value {
    use crate::security_assessment::check::check_wire_fits;
    if check_wire_fits(&value, max_bytes, SECURITY_RPC_RESERVE) {
        return value;
    }
    let count = |value: &Value| value.as_array().map_or(0, Vec::len);
    let omitted = json!({"current_findings":count(&value["current"]["findings"]),"newly_committed_events":count(&value["newly_committed_events"]),"replay_events":count(&value["replay"]["events"]),"registrations":count(&value["registrations"]),"threshold_matches":value["check"]["threshold_match_count"],"prior_omissions":value["omitted"]});
    if let Some(object) = value.as_object_mut() {
        for field in ["check", "registrations", "registration"] {
            object.remove(field);
        }
    }
    if value["current"].is_object() {
        value["current"]["findings"] = json!([]);
        value["current"]["diagnostics"] = json!([]);
    }
    if value["replay"].is_object() {
        value["replay"]["events"] = json!([]);
        value["replay"]["current"] = value["current"].clone();
        value["replay"]["next_cursor"] = Value::Null;
        value["replay"]["has_more"] = json!(true);
    }
    value["newly_committed_events"] = json!([]);
    value["newly_committed_truncated"] = json!(true);
    value["omitted"] = omitted;
    value["status"] = json!("partial");
    value["exit_code"] = json!(3);
    let mut diagnostics = value["diagnostics"].as_array().cloned().unwrap_or_default();
    if !diagnostics
        .iter()
        .any(|item| item["code"] == "E_SECURITY_OUTPUT_LIMIT")
    {
        diagnostics.push(json!({"code":"E_SECURITY_OUTPUT_LIMIT","message":"The observation exceeds the wire limit; retry the same input replay cursor for retained events."}));
    }
    value["diagnostics"] = json!(diagnostics);
    if !check_wire_fits(&value, max_bytes, SECURITY_RPC_RESERVE) {
        value.as_object_mut().unwrap().remove("replay");
    }
    value
}

fn bounded_security_body(value: Value, max_bytes: usize) -> Value {
    use crate::security_assessment::{
        ObservationDiagnostic,
        check::{CheckOmissions, check_json, check_wire_fits, failed_check},
    };
    let fits = |value: &Value| check_wire_fits(value, max_bytes, SECURITY_RPC_RESERVE);
    if fits(&value) {
        return value;
    }
    let len = |value: &Value| value.as_array().map_or(0, Vec::len);
    let omitted = |field: &str| value["omitted"][field].as_u64().unwrap_or(0) as usize;
    let packages = value["assessment"]["packages"]
        .as_array()
        .into_iter()
        .flatten();
    let total = value["threshold_match_count"].as_u64().unwrap_or(0) as usize;
    let mut summary = failed_check(
        ObservationDiagnostic::new(
            "E_SECURITY_OUTPUT_LIMIT",
            "The MCP output exceeded its authorized wire size; omitted evidence and matches are counted.",
        ),
        3,
    );
    summary.threshold_match_count = total;
    summary.omitted = Some(CheckOmissions {
        inventory_instances: omitted("inventory_instances")
            + len(&value["assessment"]["inventory"]["packages"]),
        advisory_records: omitted("advisory_records")
            + value["assessment"]["providers"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|provider| provider["instances"].as_array().into_iter().flatten())
                .map(|instance| len(&instance["records"]))
                .sum::<usize>(),
        finding_clusters: omitted("finding_clusters")
            + packages
                .clone()
                .map(|package| len(&package["installed"]["clusters"]))
                .sum::<usize>(),
        candidate_checks: omitted("candidate_checks")
            + packages
                .map(|package| len(&package["candidates"]))
                .sum::<usize>(),
        threshold_matches: total,
    });
    let mut summary = check_json(&summary);
    for field in [
        "assessment_id",
        "observation_id",
        "profile_id",
        "policy_digest",
        "policy_applied",
        "rate_limit_applied",
    ] {
        if let Some(metadata) = value.get(field) {
            let previous = summary.get(field).cloned();
            summary[field] = metadata.clone();
            if !fits(&summary) {
                if let Some(previous) = previous {
                    summary[field] = previous;
                } else {
                    summary.as_object_mut().unwrap().remove(field);
                }
            }
        }
    }
    for matched in value["threshold_matches"].as_array().into_iter().flatten() {
        summary["threshold_matches"]
            .as_array_mut()
            .unwrap()
            .push(matched.clone());
        let remaining = summary["omitted"]["threshold_matches"].as_u64().unwrap();
        summary["omitted"]["threshold_matches"] = json!(remaining.saturating_sub(1));
        if !fits(&summary) {
            summary["threshold_matches"].as_array_mut().unwrap().pop();
            summary["omitted"]["threshold_matches"] = json!(remaining);
            break;
        }
    }
    summary
}

// Tool handlers may return a failed execution inside an otherwise valid payload.
fn tool_content_failed(tool: &str, value: &Value) -> bool {
    value["status"] == "error"
        || (matches!(tool, "pybun_security_check" | "pybun_security_monitor")
            && (value["status"] != "complete" || value["exit_code"] != 0))
        || (matches!(tool, "pybun_run" | "pybun_test")
            && value["exit_code"].as_i64().is_some_and(|code| code != 0))
        || (tool == "pybun_test"
            && ["failed", "errors", "timeouts"].iter().any(|field| {
                value["summary"][field]
                    .as_u64()
                    .is_some_and(|count| count > 0)
            }))
}

impl McpServer {
    fn rate_config(&self) -> rate_limit::Config {
        self.policy
            .effective
            .as_ref()
            .map(|policy| policy.rate_limit.clone())
            .unwrap_or_default()
    }

    fn admit_tool(&mut self, tool: &str, args: &Value) -> Result<(), String> {
        let config = self.rate_config();
        let namespace = config.namespace(&self.policy.root);
        if let Err(rejected) =
            rate_limit::Limiter::global().admit(&namespace, &self.session_id, tool, &config)
        {
            let result = Err(rejected.value(&config, tool).to_string());
            // A rejected call may persist its security audit event, but never enters a tool.
            if !matches!(tool, "pybun_security_check" | "pybun_security_monitor")
                && let Err(error) = self.audit_log.prepare_for_call(&json!({}))
            {
                eprintln!("warning: failed to prepare rate-limit audit: {error}");
            }
            let entry = audit::build_audit_entry(
                &self.session_id,
                tool,
                args,
                &result,
                self.audit_log.config.hash_inputs,
                audit::AuditDiff {
                    complete: !matches!(tool, "pybun_security_check" | "pybun_security_monitor"),
                    ..Default::default()
                },
                0,
            );
            if matches!(tool, "pybun_security_check" | "pybun_security_monitor") {
                self.audit_log.record_memory(entry);
            } else {
                self.audit_log.record(entry);
            }
            return result.map(|_| ());
        }
        Ok(())
    }

    fn decorate_rate(&self, tool: &str, result: Result<String, String>) -> Result<String, String> {
        let decorate = |text: String| {
            if let Ok(mut value) = serde_json::from_str::<Value>(&text) {
                value["rate_limit_applied"] =
                    json!({"admitted":true,"limits":self.rate_config().describe(tool)});
                value.to_string()
            } else {
                text
            }
        };
        result.map(decorate).map_err(decorate)
    }
    pub(super) async fn handle_tools_call(&mut self, id: Value, params: Value) -> JsonRpcResponse {
        let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let tool_args = params.get("arguments").cloned().unwrap_or(json!({}));

        if tool_name == "pybun_security_check" {
            return self.handle_security_check(id, tool_args).await;
        }
        if tool_name == "pybun_security_monitor" {
            return self.handle_security_monitor(id, tool_args).await;
        }

        let backend = if crate::backend::native_selected() {
            "native"
        } else {
            "uv"
        };
        let requested_args = tool_args.clone();
        let authorized = match self.policy.authorize(tool_name, tool_args, backend) {
            Ok(authorized) => authorized,
            Err(denied) => {
                return JsonRpcResponse::success(
                    id,
                    json!({"content":[{"type":"text","text":self.policy.denial_value(&denied).to_string()}],"isError":true}),
                );
            }
        };
        if let Err(rejected) = self.admit_tool(tool_name, &requested_args) {
            return JsonRpcResponse::success(
                id,
                json!({"content":[{"type":"text","text":rejected}],"isError":true}),
            );
        }
        let tool_args = &authorized.args;
        let start = Instant::now();
        let before_snapshot = audit::snapshot_for_tool(tool_name, tool_args);
        let result = if let Err(err) = self.audit_log.prepare_for_call(tool_args) {
            Err(err)
        } else {
            match tool_name {
                "pybun_why" => {
                    crate::why::call(tool_args.clone(), policy::authorized_roots(tool_args))
                }
                "pybun_environment_diff" => crate::environment_diff::call(tool_args.clone()),
                "pybun_resolve" => tools::call_resolve(tool_args.clone()).await,
                "pybun_install" => tools::call_install(tool_args.clone()).await,
                "pybun_add" => tools::call_project("add", tool_args.clone()).await,
                "pybun_remove" => tools::call_project("remove", tool_args.clone()).await,
                "pybun_lock" => tools::call_project("lock", tool_args.clone()).await,
                "pybun_run" => tools::call_run(tool_args.clone()).await,
                "pybun_gc" => tools::call_gc(tool_args.clone()),
                "pybun_doctor" => tools::call_doctor(tool_args.clone()),
                "pybun_lint" => tools::call_lint(tool_args.clone()),
                "pybun_type_check" => tools::call_type_check(tool_args.clone()),
                "pybun_profile" => tools::call_profile(tool_args.clone()),
                "pybun_fix" => tools::call_fix(tool_args.clone()),
                "pybun_context" => tools::call_context(tool_args.clone()),
                "pybun_drift" => tools::call_drift(tool_args.clone()),
                "pybun_test" => tools::call_test(tool_args.clone()),
                "pybun_audit" => tools::call_audit(tool_args.clone()).await,
                "pybun_upgrade" if crate::backend::native_selected() => {
                    tools::call_upgrade(tool_args.clone())
                }
                "pybun_upgrade" => tools::call_project("upgrade", tool_args.clone()).await,
                _ => Err(format!("Unknown tool: {}", tool_name)),
            }
        };
        let result = self.decorate_rate(tool_name, authorized.decorate(result));
        let after_snapshot = audit::snapshot_for_tool(tool_name, tool_args);
        let file_writes = audit::diff_file_writes(&before_snapshot, &after_snapshot);
        let duration_ms = start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let result = result
            .map(|value| crate::support_bundle::redact_response(&value))
            .map_err(|value| crate::support_bundle::redact_response(&value));

        let audit_entry = audit::build_audit_entry(
            &self.session_id,
            tool_name,
            &requested_args,
            &result,
            self.audit_log.config.hash_inputs,
            file_writes,
            duration_ms,
        );
        self.audit_log.record(audit_entry);

        match result {
            Ok(content) => {
                let failed = serde_json::from_str::<Value>(&content)
                    .is_ok_and(|value| tool_content_failed(tool_name, &value));
                let mut result = json!({
                    "content": [{"type": "text", "text": content}]
                });
                if failed {
                    result["isError"] = json!(true);
                }
                JsonRpcResponse::success(id, result)
            }
            Err(e) => JsonRpcResponse::success(
                id,
                json!({
                    "content": [{
                        "type": "text",
                        "text": if serde_json::from_str::<Value>(&e).is_ok_and(|v| v["contract_version"] == "2") { e } else { format!("Error: {}", e) }
                    }],
                    "isError": true
                }),
            ),
        }
    }

    async fn handle_security_monitor(&mut self, id: Value, requested: Value) -> JsonRpcResponse {
        use crate::security_assessment::{
            ObservationDiagnostic,
            monitor::service::{MonitorRequest, MonitorResponse},
        };
        let started = Instant::now();
        let action = requested["action"]
            .as_str()
            .filter(|value| {
                matches!(
                    *value,
                    "list" | "add" | "check" | "events" | "configure" | "remove"
                )
            })
            .unwrap_or("invalid")
            .to_string();
        let failure = |error, code| MonitorResponse::failure(&action, error, code).json();
        let request = match serde_json::from_value::<MonitorRequest>(requested.clone()) {
            Ok(request) => request,
            Err(_) => {
                return self.finish_security_monitor(
                    id,
                    &requested,
                    failure(
                        ObservationDiagnostic::new(
                            "E_MONITOR_INPUT",
                            "Monitor arguments contain an unsupported action, field or value.",
                        ),
                        2,
                    ),
                    started.elapsed().as_millis() as u64,
                    SECURITY_FAILURE_BYTES,
                );
            }
        };
        if let Err(error) = request.validate() {
            return self.finish_security_monitor(
                id,
                &requested,
                failure(error, 2),
                started.elapsed().as_millis() as u64,
                SECURITY_FAILURE_BYTES,
            );
        }
        let prepared = match self.policy.prepare_security_monitor(&request) {
            Ok(prepared) => prepared,
            Err(error) => {
                let mut value = failure(error, 3);
                value["policy_applied"] = json!({"authorized":false});
                return self.finish_security_monitor(
                    id,
                    &requested,
                    value,
                    started.elapsed().as_millis() as u64,
                    SECURITY_FAILURE_BYTES,
                );
            }
        };
        if let Err(rejected) = self.admit_tool("pybun_security_monitor", &requested) {
            let mut value = failure(
                ObservationDiagnostic::new(
                    "mcp.rate_limit_exceeded",
                    "The MCP call rate limit was exceeded.",
                ),
                3,
            );
            if let Ok(rejected) = serde_json::from_str::<Value>(&rejected) {
                for field in ["retry_after_ms", "rate_limit_applied"] {
                    if let Some(decoration) = rejected.get(field) {
                        value[field] = decoration.clone();
                    }
                }
            }
            return JsonRpcResponse::success(
                id,
                json!({"content":[{"type":"text","text":bounded_monitor_body(value,prepared.max_output_bytes).to_string()}],"isError":true}),
            );
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let result = crate::security_assessment::monitor::service::execute(
            prepared.authority,
            request,
            prepared.scope,
            prepared.timeout,
            now,
        )
        .await;
        let max_output_bytes = prepared.max_output_bytes.min(result.output_limit());
        let mut value = result.json();
        value["policy_applied"] = prepared.applied;
        value["rate_limit_applied"] =
            json!({"admitted":true,"limits":self.rate_config().describe("pybun_security_monitor")});
        self.finish_security_monitor(
            id,
            &requested,
            value,
            started.elapsed().as_millis() as u64,
            max_output_bytes,
        )
    }

    fn finish_security_monitor(
        &mut self,
        id: Value,
        requested: &Value,
        value: Value,
        duration_ms: u64,
        max_bytes: usize,
    ) -> JsonRpcResponse {
        let value = bounded_monitor_body(value, max_bytes);
        let failed = tool_content_failed("pybun_security_monitor", &value);
        let text = value.to_string();
        let recorded = if failed {
            Err(text.clone())
        } else {
            Ok(text.clone())
        };
        let entry = audit::build_audit_entry(
            &self.session_id,
            "pybun_security_monitor",
            requested,
            &recorded,
            self.audit_log.config.hash_inputs,
            audit::AuditDiff {
                writes: vec![],
                complete: false,
            },
            duration_ms,
        );
        self.audit_log.record_memory(entry);
        let mut result = json!({"content":[{"type":"text","text":text}]});
        if failed {
            result["isError"] = json!(true);
        }
        JsonRpcResponse::success(id, result)
    }

    async fn handle_security_check(&mut self, id: Value, requested: Value) -> JsonRpcResponse {
        use crate::security_assessment::{
            ObservationDiagnostic,
            check::{CheckUpdatesRequest, check_json, failed_check},
            qualification::schedule::AssessmentContinuation,
        };
        let start = Instant::now();
        let request = serde_json::from_value::<CheckUpdatesRequest>(requested.clone());
        let request = match request {
            Ok(request) => request,
            Err(_) => {
                let value = check_json(&failed_check(
                    ObservationDiagnostic::new(
                        "E_SECURITY_REQUEST",
                        "Security-check arguments are invalid or contain unsupported fields.",
                    ),
                    2,
                ));
                return self.finish_security_check(
                    id,
                    &requested,
                    value,
                    start.elapsed().as_millis() as u64,
                    SECURITY_FAILURE_BYTES,
                );
            }
        };
        if let Some(cursor) = &request.continuation
            && let Err(diagnostic) = AssessmentContinuation::parse(cursor.as_str())
        {
            let value = check_json(&failed_check(diagnostic, 2));
            return self.finish_security_check(
                id,
                &requested,
                value,
                start.elapsed().as_millis() as u64,
                SECURITY_FAILURE_BYTES,
            );
        }
        let grant = match self.policy.security_check_grant(&request) {
            Ok(grant) => grant,
            Err(diagnostic) => {
                let mut value = check_json(&failed_check(diagnostic, 3));
                value["policy_applied"] = json!({"authorized":false});
                return self.finish_security_check(
                    id,
                    &requested,
                    value,
                    start.elapsed().as_millis() as u64,
                    SECURITY_FAILURE_BYTES,
                );
            }
        };
        let prepared = match self.policy.prepare_security_check(&request, grant) {
            Ok(prepared) => prepared,
            Err(diagnostic) => {
                let mut value = check_json(&failed_check(diagnostic, 3));
                value["policy_applied"] = json!({"authorized":false});
                return self.finish_security_check(
                    id,
                    &requested,
                    value,
                    start.elapsed().as_millis() as u64,
                    SECURITY_FAILURE_BYTES,
                );
            }
        };
        let max_output_bytes = prepared.check.max_output_bytes();
        if let Err(rejected) = self.admit_tool("pybun_security_check", &requested) {
            // admit_tool already retained this denial in memory, never on disk.
            let rejected: Value = serde_json::from_str(&rejected).expect("rate rejection is JSON");
            let mut value = check_json(&failed_check(
                ObservationDiagnostic::new(
                    "mcp.rate_limit_exceeded",
                    "The MCP call rate limit was exceeded.",
                ),
                3,
            ));
            for key in ["retry_after_ms", "rate_limit_applied"] {
                if let Some(decoration) = rejected.get(key) {
                    value[key] = decoration.clone();
                }
            }
            let value = bounded_security_body(value, max_output_bytes);
            return JsonRpcResponse::success(
                id,
                json!({"content":[{"type":"text","text":value.to_string()}],"isError":true}),
            );
        }
        let mut value = tools::call_security_check(prepared.check).await;
        value["policy_applied"] = prepared.applied;
        value["rate_limit_applied"] =
            json!({"admitted":true,"limits":self.rate_config().describe("pybun_security_check")});
        self.finish_security_check(
            id,
            &requested,
            value,
            start.elapsed().as_millis() as u64,
            max_output_bytes,
        )
    }

    fn finish_security_check(
        &mut self,
        id: Value,
        requested: &Value,
        value: Value,
        duration_ms: u64,
        max_output_bytes: usize,
    ) -> JsonRpcResponse {
        let value = bounded_security_body(value, max_output_bytes);
        let failed = tool_content_failed("pybun_security_check", &value);
        let text = value.to_string();
        let recorded = if failed {
            Err(text.clone())
        } else {
            Ok(text.clone())
        };
        let entry = audit::build_audit_entry(
            &self.session_id,
            "pybun_security_check",
            requested,
            &recorded,
            self.audit_log.config.hash_inputs,
            audit::AuditDiff {
                writes: vec![],
                complete: false,
            },
            duration_ms,
        );
        self.audit_log.record_memory(entry);
        let mut result = json!({"content":[{"type":"text","text":text}]});
        if failed {
            result["isError"] = json!(true);
        }
        JsonRpcResponse::success(id, result)
    }

    pub(super) fn handle_resources_read(&mut self, id: Value, params: Value) -> JsonRpcResponse {
        let uri = params.get("uri").and_then(|u| u.as_str()).unwrap_or("");

        let capability = match uri {
            "pybun://project/snapshot" => Some("pybun_context"),
            "pybun://env/info" => Some("pybun_doctor"),
            "pybun://cache/info" => Some("pybun_gc"),
            _ => None,
        };
        let authorized = if let Some(tool) = capability {
            match self.policy.authorize(
                tool,
                json!({}),
                if crate::backend::native_selected() {
                    "native"
                } else {
                    "uv"
                },
            ) {
                Ok(call) => Some(call),
                Err(denied) => {
                    return JsonRpcResponse::error(
                        id,
                        -32602,
                        self.policy.denial_value(&denied).to_string(),
                    );
                }
            }
        } else {
            None
        };
        if let Some(tool) = capability
            && let Err(rejected) = self.admit_tool(tool, &json!({"resource_uri":uri}))
        {
            return JsonRpcResponse::error(id, -32602, rejected);
        }
        let content = match uri {
            "pybun://cache/info" => tools::read_cache_info(),
            "pybun://env/info" => tools::read_env_info(),
            "pybun://audit/recent" => Ok(self.read_audit_recent()),
            "pybun://project/snapshot" => tools::call_context(json!({})),
            _ => Err(format!("Unknown resource: {}", uri)),
        };

        let content = if let Some(call) = authorized {
            self.decorate_rate(capability.unwrap(), call.decorate(content))
        } else {
            content
        };
        match content {
            Ok(text) => JsonRpcResponse::success(
                id,
                json!({
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": text
                    }]
                }),
            ),
            Err(e) => JsonRpcResponse::error(id, -32602, e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_failure_classification_preserves_successful_observations() {
        for value in [
            json!({"contract_version":"2","status":"error"}),
            json!({"status":"error","exit_code":0}),
        ] {
            assert!(tool_content_failed("pybun_doctor", &value));
        }
        for tool in ["pybun_run", "pybun_test"] {
            assert!(tool_content_failed(tool, &json!({"exit_code":3})));
            assert!(!tool_content_failed(tool, &json!({"exit_code":0})));
        }
        for field in ["failed", "errors", "timeouts"] {
            let value = json!({"summary":{field:1}});
            assert!(tool_content_failed("pybun_test", &value));
            assert!(!tool_content_failed("pybun_context", &value));
        }
        for value in [
            json!({"contract_version":"2","status":"success","exit_code":0}),
            json!({"status":"dry_run"}),
            json!({"status":"issues_found","checks":[{"status":"error"}]}),
            json!({"summary":{"failed":0,"errors":0,"timeouts":0,"skipped":1,"xfail":1,"xpass":1}}),
            json!({"stdout":"error"}),
        ] {
            assert!(!tool_content_failed("pybun_test", &value), "{value}");
        }
    }

    #[test]
    fn security_check_failure_classification_distinguishes_findings_and_incomplete_evidence() {
        assert!(!tool_content_failed(
            "pybun_security_check",
            &json!({"status":"complete","exit_code":0,"threshold_matches":[]})
        ));
        for value in [
            json!({"status":"complete","exit_code":1,"threshold_matches":[{}]}),
            json!({"status":"partial","exit_code":3,"threshold_matches":[{}]}),
            json!({"status":"error","exit_code":3}),
        ] {
            assert!(tool_content_failed("pybun_security_check", &value));
        }
        assert!(!tool_content_failed(
            "pybun_audit",
            &json!({"status":"partial","exit_code":3})
        ));
    }

    #[test]
    fn final_wire_fallback_keeps_match_totals_and_explicit_omissions() {
        let body = json!({"contract_version":"2","status":"complete","exit_code":1,
            "assessment_id":"semantic-id","threshold_match_count":2,
            "threshold_matches":[{"instance_id":"a","advisory_ids":["TEST-1"]},{"instance_id":"b","advisory_ids":["TEST-2"]}],
            "assessment":{"inventory":{"packages":[{},{}]},"providers":[{"instances":[{"records":[{},{},{}]}]}],"packages":[{"installed":{"clusters":[{},{}]},"candidates":[{}]}]},
            "policy_applied":{"large_metadata":"x".repeat(20_000)}});
        let bounded = bounded_security_body(body, 4096);
        assert_eq!(bounded["diagnostics"][0]["code"], "E_SECURITY_OUTPUT_LIMIT");
        assert_eq!(bounded["exit_code"], 3);
        assert_eq!(bounded["threshold_match_count"], 2);
        assert_eq!(bounded["omitted"]["inventory_instances"], 2);
        assert_eq!(bounded["omitted"]["advisory_records"], 3);
        assert_eq!(bounded["omitted"]["finding_clusters"], 2);
        assert_eq!(bounded["omitted"]["candidate_checks"], 1);
        assert_eq!(bounded["assessment_id"], "semantic-id");
        assert!(crate::security_assessment::check::check_wire_fits(
            &bounded,
            4096,
            SECURITY_RPC_RESERVE
        ));
    }
}
