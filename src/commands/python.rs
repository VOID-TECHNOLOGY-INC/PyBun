use super::RenderDetail;
use crate::cache::Cache;
use crate::cli::PythonCommands;
use crate::env::find_python_env;
use crate::runtime::{RuntimeManager, supported_versions};
use crate::schema::{EventCollector, EventType};
use color_eyre::eyre::{Result, eyre};
use serde_json::json;

// ---------------------------------------------------------------------------
// pybun python
// ---------------------------------------------------------------------------

pub(super) fn handle_python_command(
    cmd: &PythonCommands,
    collector: &mut EventCollector,
) -> Result<(String, RenderDetail)> {
    match cmd {
        PythonCommands::List(args) => {
            collector.event(EventType::PythonListStart);
            let result = python_list(args);
            collector.event(EventType::PythonListComplete);
            result
        }
        PythonCommands::Install(args) => {
            collector.event(EventType::PythonInstallStart);
            let result = python_install(args);
            collector.event(EventType::PythonInstallComplete);
            result
        }
        PythonCommands::Remove(args) => {
            collector.event(EventType::PythonRemoveStart);
            let result = python_remove(args);
            collector.event(EventType::PythonRemoveComplete);
            result
        }
        PythonCommands::Which(args) => python_which(args),
    }
}

fn python_list(args: &crate::cli::PythonListArgs) -> Result<(String, RenderDetail)> {
    let cache = Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
    let manager = RuntimeManager::new(cache);

    let installed = manager.list_installed()?;
    let available = supported_versions();

    let mut text_output = String::new();

    if args.all {
        text_output.push_str("Available Python versions:\n");
        for v in &available {
            let status = if installed.iter().any(|i| i == &v.version) {
                " (installed)"
            } else {
                ""
            };
            text_output.push_str(&format!("  {}{}\n", v.version, status));
        }
    } else {
        text_output.push_str("Installed Python versions:\n");
        if installed.is_empty() {
            text_output.push_str("  (none)\n");
            text_output
                .push_str("\nUse 'pybun python install <VERSION>' to install a Python version.");
        } else {
            for v in &installed {
                text_output.push_str(&format!("  {}\n", v));
            }
        }
    }

    let json = json!({
        "installed": installed,
        "available": available.iter().map(|v| &v.version).collect::<Vec<_>>(),
    });

    Ok((
        "list".to_string(),
        RenderDetail::with_json(text_output.trim(), json),
    ))
}

fn python_install(args: &crate::cli::PythonInstallArgs) -> Result<(String, RenderDetail)> {
    let cache = Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
    let manager = RuntimeManager::new(cache);

    // Check if already installed
    if manager.is_installed(&args.version) {
        let path = manager.python_binary(&args.version);
        let summary = format!(
            "Python {} is already installed at {}",
            args.version,
            path.display()
        );
        let json = json!({
            "version": args.version,
            "path": path.display().to_string(),
            "status": "already_installed",
        });
        return Ok((
            "install".to_string(),
            RenderDetail::with_json(summary, json),
        ));
    }

    // Install
    let python_path = manager.ensure_version(&args.version)?;

    let summary = format!(
        "Installed Python {} at {}",
        args.version,
        python_path.display()
    );
    let json = json!({
        "version": args.version,
        "path": python_path.display().to_string(),
        "status": "installed",
    });

    Ok((
        "install".to_string(),
        RenderDetail::with_json(summary, json),
    ))
}

fn python_remove(args: &crate::cli::PythonRemoveArgs) -> Result<(String, RenderDetail)> {
    let cache = Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
    let manager = RuntimeManager::new(cache);

    manager.remove_version(&args.version)?;

    let summary = format!("Removed Python {}", args.version);
    let json = json!({
        "version": args.version,
        "status": "removed",
    });

    Ok(("remove".to_string(), RenderDetail::with_json(summary, json)))
}

fn python_which(args: &crate::cli::PythonWhichArgs) -> Result<(String, RenderDetail)> {
    let cache = Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
    let manager = RuntimeManager::new(cache);

    if let Some(version) = &args.version {
        // Look up a specific version
        if manager.is_installed(version) {
            let path = manager.python_binary(version);
            let json = json!({
                "version": version,
                "path": path.display().to_string(),
                "managed": true,
            });
            return Ok((
                "which".to_string(),
                RenderDetail::with_json(path.display().to_string(), json),
            ));
        }

        // Check if we can find it via env discovery. Keep the discovery
        // error (rather than discarding it) so a real failure - e.g. a
        // malformed pyproject.toml or a permissions error - is surfaced
        // instead of being indistinguishable from "no Python found at all".
        let working_dir = std::env::current_dir()?;
        match find_python_env(&working_dir) {
            Ok(env) => {
                let json = json!({
                    "version": env.version,
                    "path": env.python_path.display().to_string(),
                    "source": format!("{}", env.source),
                    "managed": false,
                });
                return Ok((
                    "which".to_string(),
                    RenderDetail::with_json(env.python_path.display().to_string(), json),
                ));
            }
            Err(e) => {
                return Err(eyre!(
                    "Python {} is not installed and no environment Python could be found ({}). \
                     Use 'pybun python install {}' to install it.",
                    version,
                    e,
                    version
                ));
            }
        }
    }

    // No version specified - show the default Python that would be used
    let working_dir = std::env::current_dir()?;
    let env = find_python_env(&working_dir)?;

    let summary = format!("{} (from {})", env.python_path.display(), env.source);
    let json = json!({
        "version": env.version,
        "path": env.python_path.display().to_string(),
        "source": format!("{}", env.source),
        "managed": false,
    });

    Ok(("which".to_string(), RenderDetail::with_json(summary, json)))
}
