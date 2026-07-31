//! `pybun_install` MCP tool implementation.
//!
//! Extracted from `mcp.rs` (Issue #344).

use serde_json::{Value, json};
use std::path::PathBuf;

/// Install packages by delegating to the same `install()` implementation
/// used by the CLI `pybun install` command (`crate::commands::install`).
///
/// This intentionally reuses the CLI's real index selection (with PyPI
/// fallback when no fixture/local `index` is given), real hash
/// verification (no `sha256:placeholder`), real wheel download, and real
/// wheel installation into the target environment's site-packages.
///
/// Issue #284: previously this method never downloaded or installed any
/// wheel, yet unconditionally reported `"status": "installed"` /
/// `"Resolved and installed N packages"`. It now reports `"installed"`
/// only when `InstallOutcome::installed_count > 0` (i.e. wheels were
/// actually fetched and installed); otherwise it reports an honest
/// `"resolved"` status describing exactly what happened (dependency
/// resolution and lockfile generation, without any wheel installation).
pub(crate) async fn call_install(args: Value) -> Result<String, String> {
    use crate::resolver::Requirement;
    use crate::schema::EventCollector;

    let requirements: Vec<String> = args
        .get("requirements")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let parsed_requirements: Vec<Requirement> = requirements
        .iter()
        .map(|s| s.parse().unwrap_or_else(|_| Requirement::any(s.trim())))
        .collect();

    // Honor `offline` (previously accepted but silently ignored).
    let offline = args
        .get("offline")
        .and_then(|o| o.as_bool())
        .unwrap_or(false);

    // Honor an explicit opt-in to installing into system Python, matching
    // the CLI's `--system` safety guard (defaults to creating an isolated
    // `.pybun/venv` rather than touching system Python).
    let system = args
        .get("system")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);

    let index = args
        .get("index")
        .and_then(|i| i.as_str())
        .map(PathBuf::from);

    // Default lockfile name matches the CLI project path (`pybun.lockb`),
    // not the previous MCP-only `pybun.lock` (see PR-A3 for the broader
    // MCP/CLI naming-unification track; this fix inherits the CLI
    // default as a side effect of delegating to the real install path).
    let lock = args
        .get("lock")
        .and_then(|l| l.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("pybun.lockb"));

    // Opt-in to pre-release versions (mirrors the CLI `--pre` flag).
    let pre = args.get("pre").and_then(|p| p.as_bool()).unwrap_or(false);

    let install_args = crate::cli::InstallArgs {
        offline,
        system,
        requirements: parsed_requirements,
        index,
        lock,
        workspace: false,
        member: None,
        group: None,
        pre,
    };

    let mut collector = EventCollector::new();
    let result = crate::commands::install(&install_args, &mut collector).await;
    let diagnostics = serde_json::to_value(collector.into_diagnostics()).unwrap_or(Value::Null);

    match result {
        Ok(outcome) => {
            let really_installed = outcome.installed_count > 0;
            let status = if really_installed {
                "installed"
            } else {
                "resolved"
            };
            let message = if really_installed {
                format!(
                    "Installed {} wheel(s) for {} resolved package(s) -> {}",
                    outcome.installed_count,
                    outcome.packages.len(),
                    outcome.lockfile.display()
                )
            } else {
                format!(
                    "Resolved {} package(s) and wrote {} (no wheels were downloaded or installed)",
                    outcome.packages.len(),
                    outcome.lockfile.display()
                )
            };

            Ok(json!({
                "status": status,
                "packages": outcome.packages,
                "lockfile": outcome.lockfile.display().to_string(),
                "count": outcome.packages.len(),
                "installed_count": outcome.installed_count,
                "verified": outcome.verified,
                "artifacts": outcome.artifacts,
                "message": message,
                "diagnostics": diagnostics,
            })
            .to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}
