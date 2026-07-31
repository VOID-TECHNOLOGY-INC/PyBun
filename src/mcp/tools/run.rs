//! `pybun_run` MCP tool implementation.
//!
//! Extracted from `mcp.rs` (Issue #344).

use super::super::audit::{
    describe_run_target, estimate_run_risk, mcp_sandbox_config_from_policy, sandbox_policy_json,
    unsafe_no_sandbox_warning,
};
use serde_json::{Value, json};
use std::path::PathBuf;

pub(crate) async fn call_run(args: Value) -> Result<String, String> {
    use crate::env::find_python_env;
    use crate::schema::EventCollector;

    let script = args.get("script").and_then(|s| s.as_str());
    let code = args.get("code").and_then(|c| c.as_str());
    let run_args: Vec<String> = args
        .get("args")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let unsafe_no_sandbox = args
        .get("unsafe_no_sandbox")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let use_sandbox = !unsafe_no_sandbox;
    let policy = args
        .get("sandbox_policy")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let effective_sandbox_config = mcp_sandbox_config_from_policy(&policy);
    let warnings = unsafe_no_sandbox_warning(unsafe_no_sandbox);

    let dry_run = args
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if script.is_none() && code.is_none() {
        return Err("Either 'script' or 'code' must be provided".to_string());
    }
    if let Some(script_path) = script
        && !PathBuf::from(script_path).exists()
    {
        return Err(format!("Script not found: {}", script_path));
    }
    if dry_run {
        let (risk_level, risk_reasons) = estimate_run_risk(script, code, use_sandbox);
        return Ok(json!({
            "status": "dry_run",
            "dry_run": true,
            "would_execute": describe_run_target(script, code),
            "sandboxed": use_sandbox,
            "sandbox_policy": use_sandbox.then(|| sandbox_policy_json(&effective_sandbox_config)),
            "risk_level": risk_level,
            "risk_reasons": risk_reasons,
            "warnings": warnings,
        })
        .to_string());
    }

    // Delegate to the same `commands::run_script` implementation the CLI's
    // `pybun run` uses, so PEP 723 dependency auto-install, sandboxing, and
    // interpreter discovery cannot silently diverge between the MCP and CLI
    // entry points (Issue #272). Interpreter discovery and sandboxed execution
    // were already shared via `env::find_python_env` /
    // `sandbox::execute_with_optional_sandbox`; this closes the remaining gap
    // where MCP skipped PEP 723 dependency install entirely.
    let run_args_struct = crate::cli::RunArgs {
        target: script.map(|s| s.to_string()),
        code: code.map(|s| s.to_string()),
        sandbox: use_sandbox,
        allow_network: effective_sandbox_config.allow_network,
        allow_read: effective_sandbox_config.allow_read.clone(),
        allow_write: effective_sandbox_config.allow_write.clone(),
        allow_env: effective_sandbox_config.allow_env.clone(),
        sandbox_timeout: effective_sandbox_config.timeout_secs,
        sandbox_memory: effective_sandbox_config.memory_limit_mb,
        sandbox_cpu: effective_sandbox_config.cpu_limit_secs,
        profile: "dev".to_string(),
        passthrough: run_args,
    };

    // Reported for informational purposes only; `run_script` performs its own
    // (identical) interpreter discovery internally.
    let working_dir = std::env::current_dir().map_err(|e| e.to_string())?;
    let python_path = find_python_env(&working_dir)
        .map(|env| env.python_path.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut collector = EventCollector::new();
    let result = crate::commands::run_script(
        &run_args_struct,
        &mut collector,
        crate::cli::OutputFormat::Json,
    )
    .await;

    match result {
        Ok(outcome) => {
            // Enrich diagnostics with a structured traceback when the script
            // failed, mirroring the CLI `pybun run` dispatcher (Issue #266).
            if outcome.exit_code != 0
                && let Some(tb) = outcome.stderr.as_deref().and_then(crate::traceback::parse)
            {
                let mut diag = crate::schema::Diagnostic::error(tb.message.clone());
                diag.code = Some(tb.code);
                diag.file = tb.location.as_ref().map(|l| l.file.clone());
                diag.line = tb.location.as_ref().map(|l| l.line);
                diag.exception_type = Some(tb.exception_type);
                diag.location = tb.location.as_ref().map(|loc| {
                    json!({
                        "file": loc.file,
                        "line": loc.line,
                        "function": loc.function,
                    })
                });
                diag.next_action = tb.next_action.map(|a| {
                    json!({
                        "tool": a.tool,
                        "args": a.args,
                    })
                });
                collector.diagnostic(diag);
            }
            let diagnostics =
                serde_json::to_value(collector.into_diagnostics()).unwrap_or(Value::Null);

            let sandboxed = outcome.sandbox.as_ref().map(|s| s.enabled).unwrap_or(false);
            let audit = outcome.sandbox.as_ref().and_then(|s| s.audit.clone());
            let resource_limits = outcome.sandbox.as_ref().map(|s| s.resource_limits.clone());
            let timed_out = outcome
                .sandbox
                .as_ref()
                .map(|s| s.timed_out)
                .unwrap_or(false);

            Ok(json!({
                "status": if outcome.exit_code == 0 { "success" } else { "error" },
                "target": outcome.target,
                "exit_code": outcome.exit_code,
                "stdout": outcome.stdout.unwrap_or_default(),
                "stderr": outcome.stderr.unwrap_or_default(),
                "python": python_path,
                "sandboxed": sandboxed,
                "audit": audit,
                "resource_limits": resource_limits,
                "timed_out": timed_out,
                "diagnostics": diagnostics,
                "warnings": warnings,
                "pep723_dependencies": outcome.pep723_deps,
                "pep723_backend": outcome.pep723_backend,
                "temp_env": outcome.temp_env,
                "cleanup": outcome.cleanup,
                "cache_hit": outcome.cache_hit,
            })
            .to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}
