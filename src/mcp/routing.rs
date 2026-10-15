//! Central policy and rate admission before tool or resource side effects.
use super::*;
use std::time::Instant;

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
            if let Err(error) = self.audit_log.prepare_for_call(&json!({})) {
                eprintln!("warning: failed to prepare rate-limit audit: {error}");
            }
            let entry = audit::build_audit_entry(
                &self.session_id,
                tool,
                args,
                &result,
                self.audit_log.config.hash_inputs,
                audit::AuditDiff::default(),
                0,
            );
            self.audit_log.record(entry);
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
            Ok(content) => JsonRpcResponse::success(
                id,
                json!({
                    "content": [{
                        "type": "text",
                        "text": content
                    }]
                }),
            ),
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
