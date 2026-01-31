use crate::build::{BuildBackend, BuildCache};
use crate::cli::{
    Cli, Commands, InitArgs, InitTemplate, LazyImportArgs, LockArgs, McpCommands, ModuleFindArgs,
    OutdatedArgs, OutputFormat, ProfileArgs, ProgressMode, PythonCommands, SchemaCommands,
    SelfCommands, TelemetryCommands, UpgradeArgs, WatchArgs,
};
use crate::env::{EnvSource, find_python_env};
use crate::index::load_index_from_path;
use crate::installer;
use crate::lockfile::{Lockfile, Package, PackageSource};
use crate::pep723;
use crate::pep723_cache::{Pep723Cache, Pep723CacheKey};
use crate::progress::{ProgressConfig, ProgressDriver};
use crate::project::Project;
use crate::pypi::{PyPiClient, PyPiIndex};
use crate::release_manifest::{ReleaseManifest, current_release_target};
use crate::resolver::parse_version_relaxed;
use crate::resolver::{
    PackageIndex, Requirement, compare_versions, current_platform_tags, resolve,
    select_artifact_for_platform,
};
use crate::sandbox;
use crate::sbom;
use crate::schema::{Diagnostic, Event, EventCollector, EventType, JsonEnvelope, Status};
use crate::support_bundle::{BundleContext, BundleReport, build_support_bundle, upload_bundle};
use crate::wheel_cache::WheelCache;
use crate::workspace::Workspace;
use color_eyre::eyre::{Result, eyre};
use console::Style;
use dialoguer::{Input, theme::ColorfulTheme};
use futures::stream::{self, StreamExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs;
use std::io::IsTerminal;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

pub async fn execute(cli: Cli) -> Result<()> {
    let mut collector = EventCollector::new();

    let requested_progress = if cli.no_progress {
        ProgressMode::Never
    } else {
        cli.progress
    };
    let progress_mode = if matches!(cli.format, OutputFormat::Json) {
        ProgressMode::Never
    } else {
        requested_progress
    };
    let progress = ProgressDriver::new(ProgressConfig {
        mode: progress_mode,
        is_tty: std::io::stderr().is_terminal(),
    });
    if let Some(listener) = progress.listener() {
        collector.set_event_listener(listener);
    }

    // Record command start
    collector.event(EventType::CommandStart);

    let (command, detail) = match &cli.command {
        Commands::Install(args) => {
            collector.event(EventType::ResolveStart);
            let result = install(args, &mut collector).await;
            match result {
                Ok(InstallOutcome {
                    summary,
                    packages,
                    lockfile,
                }) => {
                    collector.event(EventType::InstallComplete);
                    (
                        "install".to_string(),
                        RenderDetail::with_json(
                            summary,
                            json!({
                                "lockfile": lockfile.display().to_string(),
                                "packages": packages,
                            }),
                        ),
                    )
                }
                Err(e) => (
                    "install".to_string(),
                    RenderDetail::error(
                        e.to_string(),
                        json!({
                            "error": e.to_string(),
                        }),
                    ),
                ),
            }
        }
        Commands::Add(args) => {
            let result = add_package(args);
            match result {
                Ok(AddOutcome {
                    summary,
                    package,
                    version,
                    added_deps,
                }) => {
                    // Chain install to ensure the environment is up-to-date
                    collector.info(format!("Installing dependencies including {}...", package));

                    let install_args = crate::cli::InstallArgs {
                        offline: args.offline,
                        requirements: Vec::new(), // install from pyproject.toml
                        index: None,
                        lock: std::path::PathBuf::from("pybun.lockb"),
                    };

                    match install(&install_args, &mut collector).await {
                        Ok(_) => (
                            "add".to_string(),
                            RenderDetail::with_json(
                                format!("{} and installed dependencies.", summary),
                                json!({
                                    "package": package,
                                    "version": version,
                                    "added_dependencies": added_deps,
                                    "installed": true,
                                }),
                            ),
                        ),
                        Err(e) => {
                            let err_msg = format!(
                                "Added {} to pyproject.toml but failed to install: {}",
                                package, e
                            );
                            collector.error(err_msg.clone());
                            (
                                "add".to_string(),
                                RenderDetail::error(
                                    err_msg,
                                    json!({
                                        "package": package,
                                        "error": e.to_string(),
                                        "installed": false,
                                    }),
                                ),
                            )
                        }
                    }
                }
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "add".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::Remove(args) => {
            let result = remove_package(args);
            match result {
                Ok(RemoveOutcome {
                    summary,
                    package,
                    removed,
                }) => (
                    "remove".to_string(),
                    RenderDetail::with_json(
                        summary,
                        json!({
                            "package": package,
                            "removed": removed,
                        }),
                    ),
                ),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "remove".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::Lock(args) => {
            collector.event(EventType::ResolveStart);
            let result = lock_dependencies(args, &mut collector).await;
            match result {
                Ok(LockOutcome {
                    summary,
                    lockfile,
                    packages,
                }) => {
                    collector.event(EventType::InstallComplete);
                    (
                        "lock".to_string(),
                        RenderDetail::with_json(
                            summary,
                            json!({
                                "lockfile": lockfile.display().to_string(),
                                "packages": packages,
                            }),
                        ),
                    )
                }
                Err(e) => (
                    "lock".to_string(),
                    RenderDetail::error(
                        e.to_string(),
                        json!({
                            "error": e.to_string(),
                        }),
                    ),
                ),
            }
        }
        Commands::Run(args) => {
            collector.event(EventType::ScriptStart);
            let result = run_script(args, &mut collector, cli.format).await;
            match result {
                Ok(RunOutcome {
                    summary,
                    target,
                    exit_code,
                    pep723_deps,
                    pep723_backend,
                    temp_env,
                    cleanup,
                    cache_hit,
                    stdout,
                    stderr,
                    sandbox,
                }) => {
                    collector.event(EventType::ScriptEnd);
                    let sandbox_detail = sandbox.as_ref().map(|s| {
                        json!({
                            "enabled": s.enabled,
                            "allow_network": s.allow_network,
                            "enforcement": s.enforcement,
                        })
                    });
                    (
                        "run".to_string(),
                        RenderDetail::with_json(
                            summary,
                            json!({
                                "target": target,
                                "exit_code": exit_code,
                                "pep723_dependencies": pep723_deps,
                                "pep723_backend": pep723_backend,
                                "temp_env": temp_env,
                                "cleanup": cleanup,
                                "cache_hit": cache_hit,
                                "stdout": stdout,
                                "stderr": stderr,
                                "sandbox": sandbox_detail,
                            }),
                        ),
                    )
                }
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "run".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::X(args) => {
            collector.event(EventType::EnvCreate);
            let result = execute_tool(args, &mut collector);
            match result {
                Ok(XOutcome {
                    summary,
                    package,
                    version,
                    passthrough,
                    temp_env,
                    python_version,
                    exit_code,
                    cleanup,
                }) => (
                    "x".to_string(),
                    RenderDetail::with_json(
                        summary,
                        json!({
                            "package": package,
                            "version": version,
                            "passthrough": passthrough,
                            "temp_env": temp_env,
                            "python_version": python_version,
                            "exit_code": exit_code,
                            "cleanup": cleanup,
                        }),
                    ),
                ),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "x".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::Test(args) => {
            collector.event(EventType::CommandStart);
            let result = run_tests(args, &mut collector);
            match result {
                Ok(detail) => ("test".to_string(), detail),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "test".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::Build(args) => (
            "build".to_string(),
            match run_build(args, &mut collector, cli.format) {
                Ok(outcome) => RenderDetail::with_json(outcome.summary, {
                    let backend = &outcome.backend;
                    let sbom_detail = if let Some(sbom) = &outcome.sbom {
                        json!({
                            "requested": args.sbom,
                            "path": sbom.path.display().to_string(),
                            "format": sbom.format,
                            "components": sbom.component_count,
                        })
                    } else {
                        json!({
                            "requested": args.sbom,
                            "status": if args.sbom { "skipped" } else { "not_requested" },
                        })
                    };
                    json!({
                    "builder": outcome.builder,
                    "python": outcome.python.display().to_string(),
                    "dist_dir": outcome.dist_dir.display().to_string(),
                    "artifacts": outcome.artifacts.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                    "backend": {
                        "name": backend.name.clone(),
                        "kind": backend.kind.as_str(),
                        "isolated": backend.isolated,
                        "requires": backend.requires.clone(),
                    },
                    "cache": {
                        "hit": outcome.cache_hit,
                        "key": outcome.cache_key,
                        "dir": outcome.cache_dir.display().to_string(),
                    },
                    "sbom": sbom_detail,
                    "stdout": outcome.stdout,
                    "stderr": outcome.stderr,
                    "exit_code": outcome.exit_code,
                    })
                }),
                Err(e) => {
                    collector.error(e.to_string());
                    RenderDetail::error(
                        e.to_string(),
                        json!({
                            "error": e.to_string(),
                        }),
                    )
                }
            },
        ),
        Commands::Doctor(args) => {
            collector.info("Running environment diagnostics");
            let detail = run_doctor(args, &mut collector);
            ("doctor".to_string(), detail)
        }
        Commands::Mcp(cmd) => match cmd {
            McpCommands::Serve(args) => {
                if args.stdio {
                    // Run MCP server in stdio mode - this blocks until shutdown
                    if let Err(e) = crate::mcp::run_stdio_server().await {
                        collector.error(e.to_string());
                        (
                            "mcp serve".to_string(),
                            RenderDetail::error(e.to_string(), json!({"error": e.to_string()})),
                        )
                    } else {
                        (
                            "mcp serve".to_string(),
                            RenderDetail::with_json(
                                "MCP server stopped",
                                json!({"status": "stopped", "mode": "stdio"}),
                            ),
                        )
                    }
                } else {
                    // HTTP mode (not yet implemented)
                    (
                        "mcp serve".to_string(),
                        stub_detail(
                            format!(
                                "port={} (HTTP mode not yet implemented, use --stdio)",
                                args.port
                            ),
                            json!({"port": args.port, "mode": "http", "status": "not_implemented"}),
                        ),
                    )
                }
            }
        },
        Commands::SelfCmd(cmd) => match cmd {
            SelfCommands::Update(args) => {
                let detail = run_self_update(args, &mut collector);
                ("self update".to_string(), detail)
            }
        },
        Commands::Gc(args) => {
            collector.event(EventType::CacheHit); // Reuse cache event
            let result = run_gc(args, &mut collector);
            match result {
                Ok(detail) => ("gc".to_string(), detail),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "gc".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::Python(cmd) => {
            match handle_python_command(cmd, &mut collector) {
                Ok((subcmd, detail)) => (format!("python {}", subcmd), detail),
                Err(e) => {
                    collector.error(e.to_string());
                    // Determine subcommand name for error reporting
                    let subcmd = match cmd {
                        PythonCommands::List(_) => "list",
                        PythonCommands::Install(_) => "install",
                        PythonCommands::Remove(_) => "remove",
                        PythonCommands::Which(_) => "which",
                    };
                    (
                        format!("python {}", subcmd),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::ModuleFind(args) => {
            collector.event(EventType::ModuleFindStart);
            let result = run_module_find(args, &mut collector);
            collector.event(EventType::ModuleFindComplete);
            match result {
                Ok(detail) => ("module-find".to_string(), detail),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "module-find".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::LazyImport(args) => {
            collector.event(EventType::LazyImportStart);
            let result = run_lazy_import(args, &mut collector);
            collector.event(EventType::LazyImportComplete);
            match result {
                Ok(detail) => ("lazy-import".to_string(), detail),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "lazy-import".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::Watch(args) => {
            collector.event(EventType::WatchStart);
            let result = run_watch(args, &mut collector);
            match result {
                Ok(detail) => ("watch".to_string(), detail),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "watch".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::Profile(args) => {
            let result = run_profile(args, &mut collector);
            match result {
                Ok(detail) => ("profile".to_string(), detail),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "profile".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::Schema(cmd) => match cmd {
            SchemaCommands::Print(_args) => {
                let schema_json = crate::schema::schema_v1_json();
                let schema_text = crate::schema::schema_v1_pretty();
                let detail = if matches!(cli.format, OutputFormat::Text) {
                    RenderDetail::with_json_raw_text(
                        schema_text,
                        json!({
                            "schema": schema_json,
                            "version": crate::schema::SCHEMA_VERSION,
                        }),
                    )
                } else {
                    RenderDetail::with_json(
                        format!("schema v{}", crate::schema::SCHEMA_VERSION),
                        json!({
                            "schema": schema_json,
                            "version": crate::schema::SCHEMA_VERSION,
                        }),
                    )
                };
                ("schema print".to_string(), detail)
            }
            SchemaCommands::Check(args) => {
                let detail = run_schema_check(args);
                ("schema check".to_string(), detail)
            }
        },
        Commands::Telemetry(cmd) => {
            let result = run_telemetry(cmd);
            match result {
                Ok(detail) => ("telemetry".to_string(), detail),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "telemetry".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::Init(args) => {
            let result = init_project(args);
            match result {
                Ok(detail) => ("init".to_string(), detail),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "init".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::Outdated(args) => {
            let result = run_outdated(args, &mut collector).await;
            match result {
                Ok(detail) => ("outdated".to_string(), detail),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "outdated".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
        Commands::Upgrade(args) => {
            let result = run_upgrade(args, &mut collector).await;
            match result {
                Ok(detail) => ("upgrade".to_string(), detail),
                Err(e) => {
                    collector.error(e.to_string());
                    (
                        "upgrade".to_string(),
                        RenderDetail::error(
                            e.to_string(),
                            json!({
                                "error": e.to_string(),
                            }),
                        ),
                    )
                }
            }
        }
    };

    // Record command end
    collector.event(EventType::CommandEnd);

    let duration = collector.elapsed();
    let (events, diagnostics, trace_id) = collector.into_parts();

    let is_error = detail.is_error;
    let rendered = render(
        &command,
        detail,
        cli.format,
        duration,
        events,
        diagnostics,
        trace_id,
    );

    progress.finish();
    println!("{rendered}");

    // Exit with error code if command failed
    if is_error {
        std::process::exit(1);
    }

    Ok(())
}

fn render(
    command: &str,
    detail: RenderDetail,
    format: OutputFormat,
    duration: Duration,
    events: Vec<Event>,
    diagnostics: Vec<Diagnostic>,
    trace_id: Option<String>,
) -> String {
    match format {
        OutputFormat::Text => {
            if detail.raw_text {
                detail.text
            } else {
                format!("pybun {command}: {}", detail.text)
            }
        }
        OutputFormat::Json => {
            let status = if detail.is_error {
                Status::Error
            } else {
                Status::Ok
            };
            let mut envelope =
                JsonEnvelope::new(format!("pybun {command}"), status, duration, detail.json);
            envelope.events = events;
            envelope.diagnostics = diagnostics;
            envelope.trace_id = trace_id;
            envelope.to_json()
        }
    }
}

fn stub_detail(message: String, payload: Value) -> RenderDetail {
    let message = format!("{message} (not implemented yet)");
    RenderDetail::with_json(
        message.clone(),
        json!({
            "status": "stub",
            "message": message,
            "payload": payload,
        }),
    )
}

fn schema_version_from(schema: &Value) -> Option<String> {
    schema
        .get("properties")
        .and_then(|v| v.get("version"))
        .and_then(|v| v.get("const").or_else(|| v.get("enum")))
        .and_then(|v| {
            if v.is_string() {
                v.as_str().map(|s| s.to_string())
            } else {
                v.get(0)
                    .and_then(|item| item.as_str().map(|s| s.to_string()))
            }
        })
}

fn run_schema_check(args: &crate::cli::SchemaCheckArgs) -> RenderDetail {
    let embedded = crate::schema::schema_v1_json();
    let embedded_version = schema_version_from(&embedded);
    let expected_version = crate::schema::SCHEMA_VERSION.to_string();

    let mut issues = Vec::new();
    if embedded_version.as_deref() != Some(expected_version.as_str()) {
        issues.push(format!(
            "embedded schema version mismatch (found {:?}, expected {})",
            embedded_version, expected_version
        ));
    }

    let default_path = PathBuf::from("schema/schema_v1.json");
    let path = args.path.clone().or_else(|| {
        if default_path.exists() {
            Some(default_path)
        } else {
            None
        }
    });

    let mut path_string = None;
    let mut file_error = None;
    let mut mismatch = None;

    if let Some(path) = path {
        path_string = Some(path.display().to_string());
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<Value>(&contents) {
                Ok(on_disk) => {
                    if on_disk != embedded {
                        mismatch = Some(true);
                        issues.push("schema file differs from embedded definition".to_string());
                    } else {
                        mismatch = Some(false);
                    }
                }
                Err(e) => {
                    file_error = Some(format!("failed to parse schema file: {}", e));
                    issues.push("schema file is not valid JSON".to_string());
                }
            },
            Err(e) => {
                file_error = Some(format!("failed to read schema file: {}", e));
                issues.push("schema file could not be read".to_string());
            }
        }
    }

    let status = if issues.is_empty() { "ok" } else { "error" };
    let summary = if issues.is_empty() {
        format!("schema v{} OK", expected_version)
    } else {
        format!("schema check failed ({} issue(s))", issues.len())
    };

    let detail = json!({
        "status": status,
        "schema_version": expected_version,
        "embedded_version": embedded_version,
        "path": path_string,
        "mismatch": mismatch,
        "error": file_error,
        "issues": issues,
    });

    if status == "ok" {
        RenderDetail::with_json(summary, detail)
    } else {
        RenderDetail::error(summary, detail)
    }
}

// ---------------------------------------------------------------------------
// pybun telemetry
// ---------------------------------------------------------------------------

fn run_telemetry(cmd: &TelemetryCommands) -> Result<RenderDetail> {
    use crate::paths::PyBunPaths;
    use crate::telemetry::TelemetryManager;

    let paths = PyBunPaths::new().map_err(|e| eyre!("failed to get config path: {}", e))?;
    let manager = TelemetryManager::new(paths.root());

    match cmd {
        TelemetryCommands::Status(_) => {
            let status = manager.status();
            let enabled_str = if status.enabled {
                "enabled"
            } else {
                "disabled"
            };
            let summary = format!("Telemetry: {} ({})", enabled_str, status.source);

            Ok(RenderDetail::with_json(
                summary,
                json!({
                    "enabled": status.enabled,
                    "source": status.source.to_string(),
                    "redaction_patterns": status.redaction_patterns,
                }),
            ))
        }
        TelemetryCommands::Enable(_) => {
            let status = manager.enable().map_err(|e| eyre!("{}", e))?;
            let summary = "Telemetry enabled".to_string();

            Ok(RenderDetail::with_json(
                summary,
                json!({
                    "enabled": status.enabled,
                    "source": status.source.to_string(),
                    "message": "Telemetry collection is now enabled. Thank you for helping improve PyBun!",
                }),
            ))
        }
        TelemetryCommands::Disable(_) => {
            let status = manager.disable().map_err(|e| eyre!("{}", e))?;
            let summary = "Telemetry disabled".to_string();

            Ok(RenderDetail::with_json(
                summary,
                json!({
                    "enabled": status.enabled,
                    "source": status.source.to_string(),
                    "message": "Telemetry collection is now disabled.",
                }),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// pybun doctor
// ---------------------------------------------------------------------------

fn run_doctor(args: &crate::cli::DoctorArgs, collector: &mut EventCollector) -> RenderDetail {
    let mut checks: Vec<Value> = Vec::new();
    let mut all_ok = true;
    let mut bundle_report: Option<BundleReport> = None;

    // Check pybun binary
    if let Ok(exe) = std::env::current_exe() {
        checks.push(json!({
            "name": "pybun_binary",
            "status": "ok",
            "path": exe.display().to_string(),
        }));
    }

    // Check Python availability
    let working_dir = std::env::current_dir().unwrap_or_default();
    match find_python_env(&working_dir) {
        Ok(env) => {
            checks.push(json!({
                "name": "python",
                "status": "ok",
                "message": format!("Python found at {}", env.python_path.display()),
                "source": format!("{}", env.source),
                "version": env.version,
            }));
            collector.info(format!("Python found: {}", env.python_path.display()));
        }
        Err(e) => {
            checks.push(json!({
                "name": "python",
                "status": "error",
                "message": format!("Python not found: {}", e),
            }));
            collector.warning(format!("Python not found: {}", e));
            all_ok = false;
        }
    }

    // Check cache directory
    match crate::cache::Cache::new() {
        Ok(cache) => {
            let cache_dir = cache.root();
            checks.push(json!({
                "name": "cache",
                "status": "ok",
                "message": format!("Cache directory: {}", cache_dir.display()),
                "path": cache_dir.display().to_string(),
            }));
        }
        Err(e) => {
            checks.push(json!({
                "name": "cache",
                "status": "error",
                "message": format!("Cache initialization failed: {}", e),
            }));
            collector.warning(format!("Cache initialization failed: {}", e));
            all_ok = false;
        }
    }

    // Check for pyproject.toml
    match Project::discover(&working_dir) {
        Ok(project) => {
            checks.push(json!({
                "name": "project",
                "status": "ok",
                "message": format!("Project found at {}", project.path().display()),
                "path": project.path().display().to_string(),
                "dependencies": project.dependencies(),
            }));
        }
        Err(_) => {
            checks.push(json!({
                "name": "project",
                "status": "info",
                "message": "No pyproject.toml found in current directory",
            }));
            collector.info("No pyproject.toml found");
        }
    }

    let status = if all_ok { "healthy" } else { "issues_found" };
    let summary = if all_ok {
        "All checks passed".to_string()
    } else {
        "Some issues found".to_string()
    };

    if args.verbose {
        collector.info("Verbose diagnostics enabled");
    }

    if args.bundle.is_some() || args.upload {
        let trace_id = collector.trace_id().map(|value| value.to_string());
        let context = BundleContext {
            checks: checks.clone(),
            verbose_logs: args.verbose,
            trace_id,
            command: "pybun doctor".to_string(),
        };

        let mut temp_bundle: Option<tempfile::TempDir> = None;
        let bundle_path = if let Some(path) = args.bundle.clone() {
            path
        } else if let Ok(temp) = tempfile::TempDir::new() {
            let path = temp.path().join("bundle");
            temp_bundle = Some(temp);
            path
        } else {
            std::env::temp_dir().join("pybun-support-bundle")
        };

        match build_support_bundle(&bundle_path, &context) {
            Ok(collection) => {
                let mut upload_outcome = None;
                let mut bundle_path_out = args.bundle.clone();

                if args.upload {
                    let upload_url = args
                        .upload_url
                        .clone()
                        .or_else(|| std::env::var("PYBUN_SUPPORT_UPLOAD_URL").ok());
                    match upload_url {
                        Some(url) => {
                            let outcome = upload_bundle(&collection, &url);
                            if outcome.status != "uploaded"
                                && bundle_path_out.is_none()
                                && let Some(temp) = temp_bundle.take()
                            {
                                let _ = temp.keep();
                                bundle_path_out = Some(collection.path.clone());
                            }
                            upload_outcome = Some(outcome);
                        }
                        None => {
                            upload_outcome = Some(crate::support_bundle::UploadOutcome {
                                url: "".to_string(),
                                status: "failed".to_string(),
                                http_status: None,
                                error: Some("upload endpoint not configured".to_string()),
                            });
                            if bundle_path_out.is_none()
                                && let Some(temp) = temp_bundle.take()
                            {
                                let _ = temp.keep();
                                bundle_path_out = Some(collection.path.clone());
                            }
                        }
                    }
                }

                bundle_report = Some(BundleReport {
                    bundle_path: bundle_path_out,
                    files: collection.files,
                    redactions: collection.redactions,
                    logs_included: collection.logs_included,
                    upload: upload_outcome,
                });
            }
            Err(err) => {
                collector.warning(format!("Support bundle failed: {:?}", err));
                return RenderDetail::error(
                    "Support bundle failed".to_string(),
                    json!({
                        "status": status,
                        "checks": checks,
                        "verbose": args.verbose,
                        "bundle_error": format!("{:?}", err),
                    }),
                );
            }
        }
    }

    let mut detail = json!({
        "status": status,
        "checks": checks,
        "verbose": args.verbose,
    });

    if let Some(bundle) = &bundle_report {
        detail["bundle"] = bundle.to_json();
    }

    let summary = if bundle_report.is_some() {
        format!("{}. Support bundle captured", summary)
    } else {
        summary
    };

    RenderDetail::with_json(summary, detail)
}

async fn install(
    args: &crate::cli::InstallArgs,
    collector: &mut EventCollector,
) -> Result<InstallOutcome> {
    // Gather requirements: either from --require flags or from pyproject.toml
    let requirements = if !args.requirements.is_empty() {
        // CLI --require flags take precedence
        args.requirements.clone()
    } else {
        // Try to load from pyproject.toml
        let working_dir = std::env::current_dir()?;
        let project = Project::discover(&working_dir).map_err(|_| {
            eyre!(
                "no requirements provided and no pyproject.toml found. \
                     Use --require or create a pyproject.toml with [project.dependencies]"
            )
        })?;

        // Workspace-aware dependency gathering.
        let deps = if let Ok(Some(workspace)) = Workspace::discover(&working_dir) {
            let merged = workspace.merged_dependencies();
            collector.info(format!(
                "Workspace detected at {} ({} members); merged {} dependencies",
                workspace.root.root().display(),
                workspace.members.len(),
                merged.len()
            ));
            merged
        } else {
            let deps = project.dependencies();
            if deps.is_empty() {
                collector.info("No dependencies found in pyproject.toml");
            } else {
                collector.info(format!(
                    "Found {} dependencies in {}",
                    deps.len(),
                    project.path().display()
                ));
            }
            deps
        };

        deps.into_iter()
            .map(|d| {
                d.parse::<Requirement>()
                    .unwrap_or_else(|_| Requirement::any(d.trim()))
            })
            .collect()
    };

    // If no requirements (empty pyproject dependencies), create empty lockfile
    if requirements.is_empty() {
        let lock = Lockfile::new(vec!["3.11".into()], vec!["unknown".into()]);
        lock.save_to_path(&args.lock)?;
        return Ok(InstallOutcome {
            summary: format!("no dependencies to install -> {}", args.lock.display()),
            packages: vec![],
            lockfile: args.lock.clone(),
        });
    }

    let offline = args.offline;
    let resolution = if let Some(index_path) = args.index.clone() {
        let index = load_index_from_path(&index_path).map_err(|e| eyre!(e))?;
        match resolve(requirements.clone(), &index).await {
            Ok(r) => r,
            Err(e) => {
                for d in crate::self_heal::diagnostics_for_resolve_error(&requirements, &e) {
                    collector.diagnostic(d);
                }
                return Err(eyre!(e.to_string()));
            }
        }
    } else {
        let client = PyPiClient::from_env(offline)
            .map_err(|e| eyre!("failed to init pypi client: {}", e))?;
        collector.info(format!(
            "Using PyPI index {} (offline: {})",
            client.index_url(),
            offline
        ));
        let index = PyPiIndex::new(client);
        match resolve(requirements.clone(), &index).await {
            Ok(r) => r,
            Err(e) => {
                for d in crate::self_heal::diagnostics_for_resolve_error(&requirements, &e) {
                    collector.diagnostic(d);
                }
                return Err(eyre!(e.to_string()));
            }
        }
    };
    collector.event_with(EventType::ResolveComplete, |event| {
        event.message = Some("Resolved dependencies".to_string());
        event.progress = Some(40);
    });

    let platform_tags = current_platform_tags();
    let mut lock = Lockfile::new(
        vec!["3.11".into()],
        vec![
            platform_tags
                .first()
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
        ],
    );
    for pkg in resolution.packages.values() {
        let selection = select_artifact_for_platform(pkg, &platform_tags);
        if selection.from_source {
            let message = format!(
                "no compatible pre-built wheel for {} {} on {}; source distributions are not supported for install",
                pkg.name,
                pkg.version,
                platform_tags.join(",")
            );
            eprintln!("warning: {}", message);
            collector.warning(message);
        }
        lock.add_package(Package {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            source: PackageSource::Registry {
                index: "pypi".into(),
                url: "https://pypi.org/simple".into(),
            },
            wheel: selection.filename,
            hash: selection
                .hash
                .clone()
                .unwrap_or_else(|| "sha256:placeholder".into()),
            dependencies: pkg.dependencies.iter().map(ToString::to_string).collect(),
        });
    }
    lock.save_to_path(&args.lock)?;

    // Download artifacts in parallel
    let cache_dir = dirs::cache_dir()
        .ok_or_else(|| eyre!("failed to determine cache directory"))?
        .join("pybun")
        .join("artifacts");

    collector.info(format!("Downloading artifacts to {}", cache_dir.display()));

    let mut download_items = Vec::new();
    let mut sdist_only_packages = Vec::new();
    for pkg in resolution.packages.values() {
        let selection = select_artifact_for_platform(pkg, &platform_tags);
        if let Some(url) = selection.url {
            // Construct filename from selection
            let filename = PathBuf::from(selection.filename);
            let dest = cache_dir.join(filename);
            // Include hash when available to verify downloads
            download_items.push((url, dest, selection.hash.clone()));
        } else if selection.from_source {
            // sdist-only package - no wheel available
            sdist_only_packages.push(format!("{}=={}", pkg.name, pkg.version));
        }
    }

    // Fail if there are sdist-only packages (source builds not yet supported)
    if !sdist_only_packages.is_empty() {
        let message = format!(
            "The following packages have no pre-built wheel for your platform and require source builds (not yet supported): {}",
            sdist_only_packages.join(", ")
        );
        collector.error(message.clone());
        return Err(eyre!(message));
    }

    collector.event_with(EventType::DownloadStart, |event| {
        event.message = Some(format!("Downloading {} artifacts", download_items.len()));
        event.progress = Some(50);
    });

    let outcome = InstallOutcome {
        summary: format!(
            "resolved {} packages -> {}",
            lock.packages.len(),
            args.lock.display()
        ),
        packages: lock.packages.keys().cloned().collect(),
        lockfile: args.lock.clone(),
    };

    if download_items.is_empty() {
        collector.event_with(EventType::InstallStart, |event| {
            event.message = Some("Installing 0 packages".to_string());
            event.progress = Some(85);
        });
        return Ok(outcome);
    }

    if !download_items.is_empty() {
        use crate::downloader::{DownloadRequest, Downloader};
        let downloader = Downloader::new();
        let concurrency = 10; // Default concurrency
        collector.info(format!(
            "Starting parallel download of {} artifacts...",
            download_items.len()
        ));

        // Keep track of paths to install
        let wheels_to_install: Vec<PathBuf> = download_items
            .iter()
            .map(|(_, path, _)| path.clone())
            .collect();

        let download_requests: Vec<DownloadRequest> =
            download_items.into_iter().map(Into::into).collect();
        let results = downloader
            .download_parallel(download_requests, concurrency)
            .await;

        // Check for failures
        let mut failures = 0;
        for res in results {
            if let Err(e) = res {
                eprintln!("warning: download failed: {}", e);
                failures += 1;
            }
        }

        if failures > 0 {
            collector.warning(format!("{} downloads failed", failures));
            return Err(eyre!("failed to download some artifacts"));
        }

        collector.event_with(EventType::DownloadComplete, |event| {
            event.message = Some("Downloads complete".to_string());
            event.progress = Some(70);
        });

        // Install wheels
        let working_dir = std::env::current_dir()?;
        let env = crate::env::find_python_env(&working_dir)?;

        // Warn if installing to system Python while in a project
        if matches!(env.source, crate::env::EnvSource::System)
            && Project::discover(&working_dir).is_ok()
        {
            let warning =
                "warning: PyBun is installing into system Python but a pyproject.toml exists.";
            eprintln!("{}", warning);
            eprintln!("hint: Create a .venv or set PYBUN_ENV to target a virtual environment.");
            collector.warning(warning.to_string());
        }

        collector.info(format!(
            "Installing packages into {}",
            env.python_path.display()
        ));

        // Determine site-packages path
        let output = std::process::Command::new(&env.python_path)
            .args([
                "-c",
                "import sysconfig; print(sysconfig.get_paths()['purelib'], end='')",
            ])
            .output()
            .map_err(|e| eyre!("failed to determine site-packages path: {}", e))?;

        if !output.status.success() {
            return Err(eyre!(
                "failed to determine site-packages path (python execution failed)"
            ));
        }
        let site_packages_str = String::from_utf8(output.stdout)
            .map_err(|e| eyre!("invalid utf8 in site-packages path: {}", e))?;
        let site_packages = PathBuf::from(site_packages_str);

        collector.info(format!("Target site-packages: {}", site_packages.display()));

        collector.event_with(EventType::InstallStart, |event| {
            event.message = Some(format!("Installing {} packages", wheels_to_install.len()));
            event.progress = Some(85);
        });

        for wheel in wheels_to_install {
            if wheel.exists() {
                crate::installer::install_wheel(&wheel, &site_packages)
                    .map_err(|e| eyre!("failed to install wheel {}: {}", wheel.display(), e))?;
            }
        }

        collector.event_with(EventType::InstallComplete, |event| {
            event.message = Some("Installation complete".to_string());
            event.progress = Some(100);
        });
    }

    Ok(outcome)
}

#[derive(Debug)]
struct InstallOutcome {
    summary: String,
    packages: Vec<String>,
    lockfile: PathBuf,
}

#[derive(Debug)]
struct LockOutcome {
    summary: String,
    lockfile: PathBuf,
    packages: Vec<String>,
}

async fn lock_dependencies(args: &LockArgs, collector: &mut EventCollector) -> Result<LockOutcome> {
    let script_path = args
        .script
        .as_ref()
        .ok_or_else(|| eyre!("--script is required for locking"))?;

    if !script_path.exists() {
        return Err(eyre!("script not found: {}", script_path.display()));
    }

    let pep723_metadata = match pep723::parse_script_metadata(script_path) {
        Ok(metadata) => metadata,
        Err(e) => {
            return Err(eyre!("failed to parse PEP 723 metadata: {}", e));
        }
    };

    let pep723_deps = pep723_metadata
        .as_ref()
        .map(|m| m.dependencies.clone())
        .unwrap_or_default();

    let lock_path = script_lock_path(script_path);

    let requirements: Vec<Requirement> = pep723_deps
        .iter()
        .map(|d| {
            d.parse::<Requirement>()
                .unwrap_or_else(|_| Requirement::any(d.trim()))
        })
        .collect();

    if pep723_deps.is_empty() {
        let lock = Lockfile::new(vec!["3.11".into()], vec!["unknown".into()]);
        lock.save_to_path(&lock_path)?;
        return Ok(LockOutcome {
            summary: format!("no dependencies to lock -> {}", lock_path.display()),
            lockfile: lock_path,
            packages: Vec::new(),
        });
    }

    let offline = args.offline;
    let resolution = if let Some(index_path) = args.index.clone() {
        let index = load_index_from_path(&index_path).map_err(|e| eyre!(e))?;
        match resolve(requirements.clone(), &index).await {
            Ok(r) => r,
            Err(e) => {
                for d in crate::self_heal::diagnostics_for_resolve_error(&requirements, &e) {
                    collector.diagnostic(d);
                }
                return Err(eyre!(e.to_string()));
            }
        }
    } else {
        let client = PyPiClient::from_env(offline)
            .map_err(|e| eyre!("failed to init pypi client: {}", e))?;
        collector.info(format!(
            "Using PyPI index {} (offline: {})",
            client.index_url(),
            offline
        ));
        let index = PyPiIndex::new(client);
        match resolve(requirements.clone(), &index).await {
            Ok(r) => r,
            Err(e) => {
                for d in crate::self_heal::diagnostics_for_resolve_error(&requirements, &e) {
                    collector.diagnostic(d);
                }
                return Err(eyre!(e.to_string()));
            }
        }
    };

    collector.event_with(EventType::ResolveComplete, |event| {
        event.message = Some("Resolved dependencies".to_string());
        event.progress = Some(40);
    });

    let platform_tags = current_platform_tags();
    let mut lock = Lockfile::new(
        vec!["3.11".into()],
        vec![
            platform_tags
                .first()
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
        ],
    );

    for pkg in resolution.packages.values() {
        let selection = select_artifact_for_platform(pkg, &platform_tags);
        if selection.from_source {
            let message = format!(
                "no compatible pre-built wheel for {} {} on {}; falling back to source build",
                pkg.name,
                pkg.version,
                platform_tags.join(",")
            );
            eprintln!("warning: {}", message);
            collector.warning(message);
        }
        lock.add_package(Package {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            source: PackageSource::Registry {
                index: "pypi".into(),
                url: "https://pypi.org/simple".into(),
            },
            wheel: selection.filename,
            hash: selection
                .hash
                .clone()
                .unwrap_or_else(|| "sha256:placeholder".into()),
            dependencies: pkg.dependencies.iter().map(ToString::to_string).collect(),
        });
    }

    lock.save_to_path(&lock_path)?;

    Ok(LockOutcome {
        summary: format!(
            "locked {} packages -> {}",
            lock.packages.len(),
            lock_path.display()
        ),
        lockfile: lock_path,
        packages: lock.packages.keys().cloned().collect(),
    })
}

#[derive(Debug)]
struct RenderDetail {
    text: String,
    json: Value,
    is_error: bool,
    raw_text: bool,
}

impl RenderDetail {
    fn with_json(text: impl Into<String>, json: Value) -> Self {
        Self {
            text: text.into(),
            json,
            is_error: false,
            raw_text: false,
        }
    }

    fn error(text: impl Into<String>, json: Value) -> Self {
        Self {
            text: text.into(),
            json,
            is_error: true,
            raw_text: false,
        }
    }

    fn with_json_raw_text(text: impl Into<String>, json: Value) -> Self {
        Self {
            text: text.into(),
            json,
            is_error: false,
            raw_text: true,
        }
    }
}

// ---------------------------------------------------------------------------
// pybun build
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BuildOutcome {
    summary: String,
    dist_dir: PathBuf,
    artifacts: Vec<PathBuf>,
    sbom: Option<sbom::SbomSummary>,
    stdout: String,
    stderr: String,
    exit_code: i32,
    builder: String,
    python: PathBuf,
    backend: BuildBackend,
    cache_hit: bool,
    cache_key: String,
    cache_dir: PathBuf,
}

fn run_build(
    args: &crate::cli::BuildArgs,
    collector: &mut EventCollector,
    format: OutputFormat,
) -> Result<BuildOutcome> {
    let cwd = std::env::current_dir()?;
    let project =
        Project::discover(&cwd).map_err(|e| eyre!("failed to locate pyproject.toml: {}", e))?;
    let project_root = project.root().to_path_buf();

    collector.info(format!("Building project in {}", project_root.display()));

    let python_env = find_python_env(&project_root)?;
    collector.info(format!(
        "Using Python from {} ({})",
        python_env.python_path.display(),
        python_env.source
    ));

    let backend = BuildBackend::from_build_system(project.build_system());
    let build_cache =
        BuildCache::new().map_err(|e| eyre!("failed to initialize build cache: {}", e))?;
    let cache_key = build_cache
        .compute_cache_key(&project_root, &python_env.python_path, &backend)
        .map_err(|e| eyre!("failed to compute build cache key: {}", e))?;
    let cache_dir = build_cache.cache_dir_for_key(&cache_key);
    let no_cache = std::env::var("PYBUN_BUILD_NO_CACHE").is_ok();

    let mut cache_hit = false;
    if !no_cache {
        cache_hit = build_cache
            .restore_dist(&cache_key, &project_root.join("dist"))
            .map_err(|e| eyre!("failed to restore build cache: {}", e))?;
        if cache_hit {
            collector.event(EventType::CacheHit);
        }
    }

    let builder = "python -m build".to_string();
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = 0;

    if !cache_hit {
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir).map_err(|e| {
                eyre!(
                    "failed to create build cache dir {}: {}",
                    cache_dir.display(),
                    e
                )
            })?;
        }
        collector.event_with(EventType::Progress, |event| {
            event.message = Some(format!(
                "invoking python -m build (backend: {})",
                backend.kind.as_str()
            ));
            event.progress = Some(30);
        });

        let mut cmd = ProcessCommand::new(&python_env.python_path);
        cmd.current_dir(&project_root).args(["-m", "build"]);
        for (key, value) in backend.env_overrides(&cache_dir) {
            cmd.env(key, value);
        }
        let output = cmd
            .output()
            .map_err(|e| eyre!("failed to execute python -m build: {}", e))?;

        exit_code = output.status.code().unwrap_or(-1);
        stdout = String::from_utf8_lossy(&output.stdout).to_string();
        stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if matches!(format, OutputFormat::Text) {
            if !stdout.trim().is_empty() {
                println!("{stdout}");
            }
            if !stderr.trim().is_empty() {
                eprintln!("{stderr}");
            }
        }

        if !output.status.success() {
            return Err(eyre!(
                "python -m build failed with exit code {}.\nstdout:\n{}\nstderr:\n{}",
                exit_code,
                stdout,
                stderr
            ));
        }
    }

    let dist_dir = project_root.join("dist");
    let artifacts = collect_artifacts(&dist_dir)?;
    if !cache_hit {
        build_cache
            .store_dist(&cache_key, &dist_dir)
            .map_err(|e| eyre!("failed to store build cache: {}", e))?;
    }

    let sbom = if args.sbom {
        fs::create_dir_all(&dist_dir).map_err(|e| eyre!("failed to create dist dir: {}", e))?;
        let sbom_path = dist_dir.join("pybun-sbom.json");
        let metadata = project.metadata();
        let summary = sbom::write_cyclonedx_sbom(&sbom_path, &metadata, &artifacts)
            .map_err(|e| eyre!("failed to write sbom: {}", e))?;
        Some(summary)
    } else {
        None
    };

    let summary = if cache_hit {
        format!(
            "Reused {} cached artifact{} from {}",
            artifacts.len(),
            if artifacts.len() == 1 { "" } else { "s" },
            dist_dir.display()
        )
    } else {
        format!(
            "Built {} artifact{} to {}",
            artifacts.len(),
            if artifacts.len() == 1 { "" } else { "s" },
            dist_dir.display()
        )
    };

    Ok(BuildOutcome {
        summary,
        dist_dir,
        artifacts,
        sbom,
        stdout,
        stderr,
        exit_code,
        builder,
        python: python_env.python_path,
        backend,
        cache_hit,
        cache_key,
        cache_dir,
    })
}

fn collect_artifacts(dist_dir: &Path) -> Result<Vec<PathBuf>> {
    if !dist_dir.exists() {
        return Ok(Vec::new());
    }

    let mut artifacts = Vec::new();
    let entries = fs::read_dir(dist_dir)
        .map_err(|e| eyre!("failed to read dist dir {}: {}", dist_dir.display(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| eyre!("failed to read dist entry: {}", e))?;
        if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            artifacts.push(entry.path());
        }
    }

    Ok(artifacts)
}

// ---------------------------------------------------------------------------
// pybun add
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct AddOutcome {
    summary: String,
    package: String,
    version: Option<String>,
    added_deps: Vec<String>,
}

fn add_package(args: &crate::cli::PackageArgs) -> Result<AddOutcome> {
    let package_spec = args
        .package
        .as_ref()
        .ok_or_else(|| eyre!("package name is required"))?;

    // Parse the requirement
    let req: Requirement = package_spec
        .parse()
        .map_err(|e: String| eyre!("invalid package spec: {}", e))?;

    // Find or create pyproject.toml
    let current_dir = std::env::current_dir()?;
    let mut project = match Project::discover(&current_dir) {
        Ok(p) => p,
        Err(_) => {
            // Create new pyproject.toml in current directory
            let path = current_dir.join("pyproject.toml");
            Project::new(&path)
        }
    };

    // Format the dependency string
    let dep_string = package_spec.clone();

    // Add to pyproject.toml
    project.add_dependency(&dep_string);
    project.save()?;

    let added_deps = project.dependencies();

    Ok(AddOutcome {
        summary: format!("added {} to {}", package_spec, project.path().display()),
        package: req.name.clone(),
        version: match &req.spec {
            crate::resolver::VersionSpec::Exact(v) => Some(v.clone()),
            crate::resolver::VersionSpec::Minimum(v) => Some(format!(">={}", v)),
            crate::resolver::VersionSpec::MinimumExclusive(v) => Some(format!(">{}", v)),
            crate::resolver::VersionSpec::MaximumInclusive(v) => Some(format!("<={}", v)),
            crate::resolver::VersionSpec::Maximum(v) => Some(format!("<{}", v)),
            crate::resolver::VersionSpec::NotEqual(v) => Some(format!("!={}", v)),
            crate::resolver::VersionSpec::Compatible(v) => Some(format!("~={}", v)),
            crate::resolver::VersionSpec::Any => None,
        },
        added_deps,
    })
}

// ---------------------------------------------------------------------------
// pybun remove
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RemoveOutcome {
    summary: String,
    package: String,
    removed: bool,
}

fn remove_package(args: &crate::cli::PackageArgs) -> Result<RemoveOutcome> {
    let package_name = args
        .package
        .as_ref()
        .ok_or_else(|| eyre!("package name is required"))?;

    // Find pyproject.toml
    let current_dir = std::env::current_dir()?;
    let mut project = Project::discover(&current_dir).map_err(|_| {
        eyre!(
            "pyproject.toml not found in {} or any parent directory",
            current_dir.display()
        )
    })?;

    // Remove from pyproject.toml
    let removed = project.remove_dependency(package_name);

    if removed {
        project.save()?;
    }

    let summary = if removed {
        format!("removed {} from {}", package_name, project.path().display())
    } else {
        format!("{} was not found in dependencies", package_name)
    };

    Ok(RemoveOutcome {
        summary,
        package: package_name.clone(),
        removed,
    })
}

// ---------------------------------------------------------------------------
// pybun run
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ScriptLockInfo {
    lock: Lockfile,
    lock_hash: String,
}

#[derive(Debug)]
struct RunOutcome {
    summary: String,
    target: Option<String>,
    exit_code: i32,
    pep723_deps: Vec<String>,
    /// Execution backend for PEP 723 scripts (system/pybun/uv_run).
    pep723_backend: String,
    /// Environment path used for PEP 723 dependencies (cached or temporary)
    temp_env: Option<String>,
    /// Whether the environment was cleaned up (only in no-cache mode)
    cleanup: bool,
    /// Whether the environment was a cache hit
    cache_hit: bool,
    /// Captured stdout (only when `--format=json`).
    stdout: Option<String>,
    /// Captured stderr (only when `--format=json`).
    stderr: Option<String>,
    /// Sandbox information when enabled
    sandbox: Option<SandboxInfo>,
}

#[derive(Debug, Clone)]
struct SandboxInfo {
    enabled: bool,
    allow_network: bool,
    enforcement: String,
}

#[derive(Debug)]
enum RunProgram {
    Python(String),
    Uv { uv_path: PathBuf, python: String },
}

fn script_lock_path(script_path: &Path) -> PathBuf {
    let mut lock_path = script_path.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

fn load_script_lock(script_path: &Path) -> Result<Option<ScriptLockInfo>> {
    let lock_path = script_lock_path(script_path);
    if !lock_path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(&lock_path)
        .map_err(|e| eyre!("failed to read script lock {}: {}", lock_path.display(), e))?;
    let lock = Lockfile::from_bytes(&bytes)
        .map_err(|e| eyre!("failed to parse script lock {}: {}", lock_path.display(), e))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let lock_hash = hex::encode(&digest[..16]);

    Ok(Some(ScriptLockInfo { lock, lock_hash }))
}

fn pep723_index_settings(metadata: Option<&pep723::ScriptMetadata>) -> Vec<String> {
    let mut settings = Vec::new();
    if let Some(metadata) = metadata {
        settings.extend(metadata.index_urls());
    }
    if let Ok(url) = std::env::var("PIP_INDEX_URL") {
        settings.extend(split_env_list(&url));
    }
    if let Ok(extra) = std::env::var("PIP_EXTRA_INDEX_URL") {
        settings.extend(split_env_list(&extra));
    }
    if let Ok(url) = std::env::var("UV_INDEX_URL") {
        settings.extend(split_env_list(&url));
    }
    if let Ok(extra) = std::env::var("UV_EXTRA_INDEX_URL") {
        settings.extend(split_env_list(&extra));
    }
    settings
}

fn split_env_list(raw: &str) -> Vec<String> {
    raw.split(|c: char| c.is_whitespace() || c == ',')
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect()
}

const MAX_RUN_STDIO_CAPTURE_BYTES: usize = 64 * 1024;

fn capture_stdio(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let truncated = bytes.len() > MAX_RUN_STDIO_CAPTURE_BYTES;
    let slice = if truncated {
        &bytes[..MAX_RUN_STDIO_CAPTURE_BYTES]
    } else {
        bytes
    };
    let mut out = String::from_utf8_lossy(slice).to_string();
    if truncated {
        out.push_str("\n...[truncated]");
    }
    Some(out)
}

async fn run_script(
    args: &crate::cli::RunArgs,
    collector: &mut EventCollector,
    format: OutputFormat,
) -> Result<RunOutcome> {
    let target = args
        .target
        .as_ref()
        .ok_or_else(|| eyre!("script target is required (e.g., pybun run script.py)"))?;

    // Check if it's a Python file
    let script_path = PathBuf::from(target);

    // Check for -c flag style execution
    if target == "-c" {
        return run_python_code(args, collector, format);
    }

    // Ensure the script exists
    if !script_path.exists() {
        return Err(eyre!("script not found: {}", script_path.display()));
    }

    // Check for PEP 723 metadata
    let pep723_metadata = match pep723::parse_script_metadata(&script_path) {
        Ok(metadata) => metadata,
        Err(e) => {
            // Log warning but continue
            eprintln!("warning: failed to parse PEP 723 metadata: {}", e);
            None
        }
    };

    let pep723_deps = pep723_metadata
        .as_ref()
        .map(|m| m.dependencies.clone())
        .unwrap_or_default();

    let script_lock = load_script_lock(&script_path)?;
    let (install_deps, lock_hash) = if let Some(lock_info) = &script_lock {
        let mut locked = lock_info
            .lock
            .packages
            .values()
            .map(|pkg| format!("{}=={}", pkg.name, pkg.version))
            .collect::<Vec<_>>();
        if locked.is_empty() {
            locked = pep723_deps.clone();
        }
        (locked, Some(lock_info.lock_hash.clone()))
    } else {
        (pep723_deps.clone(), None)
    };

    let has_pep723_deps = !install_deps.is_empty();

    // Shared wheel cache directory for PEP 723 installs (align with uv cache use).
    let wheel_cache_dir = if !has_pep723_deps {
        None
    } else {
        let cache = Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
        let dir = cache.packages_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| eyre!("failed to create wheel cache dir {}: {}", dir.display(), e))?;
        Some(dir)
    };

    // Check for dry-run mode (for testing)
    let dry_run = std::env::var("PYBUN_PEP723_DRY_RUN").is_ok();
    // Check for no-cache mode (force fresh venv)
    let no_cache = std::env::var("PYBUN_PEP723_NO_CACHE").is_ok();
    let pep723_backend_setting =
        std::env::var("PYBUN_PEP723_BACKEND").unwrap_or_else(|_| "auto".to_string());
    let pep723_backend_setting = pep723_backend_setting.trim().to_ascii_lowercase();

    let mut pep723_backend = "system".to_string();
    let mut temp_env_dir: Option<tempfile::TempDir> = None;

    // If there are PEP 723 dependencies, use cached or create environment
    let (runner, cached_env_path, cache_hit) = if has_pep723_deps {
        collector.info(format!(
            "PEP 723 script with {} dependencies",
            install_deps.len()
        ));

        match pep723_backend_setting.as_str() {
            "auto" | "pybun" | "uv" => {}
            other => {
                return Err(eyre!(
                    "invalid PYBUN_PEP723_BACKEND value: {other} (expected auto|pybun|uv)"
                ));
            }
        }

        if !dry_run && !no_cache && !args.sandbox && pep723_backend_setting != "pybun" {
            if let Some(uv_path) = crate::env::find_uv_executable() {
                let (base_python, env_source) = find_python_interpreter()?;
                eprintln!("info: using Python from {} for uv run backend", env_source);
                pep723_backend = "uv_run".to_string();
                (
                    RunProgram::Uv {
                        uv_path,
                        python: base_python,
                    },
                    None,
                    false,
                )
            } else if pep723_backend_setting == "uv" {
                return Err(eyre!(
                    "PYBUN_PEP723_BACKEND=uv requires `uv` to be available in PATH"
                ));
            } else {
                pep723_backend = "pybun".to_string();
                // Continue with the built-in runner below.
                let pep_cache =
                    Pep723Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
                let (base_python, env_source) = find_python_interpreter()?;
                let python_version = get_python_version(Path::new(&base_python))?;
                let index_settings = pep723_index_settings(pep723_metadata.as_ref());
                let cache_key = Pep723CacheKey::new(
                    &install_deps,
                    &python_version,
                    &index_settings,
                    lock_hash.as_deref(),
                );
                let install_no_deps = script_lock.is_some();
                let env_root = pep_cache
                    .script_env_root(&script_path)
                    .map_err(|e| eyre!("failed to resolve script env root: {}", e))?;
                let venv_path = pep_cache.venv_path_for_root(&env_root);
                let venv_python = pep_cache.python_path_for_venv(&venv_path);

                if dry_run {
                    collector.info(format!(
                        "Would use cached env at {} or create new one: {:?}",
                        venv_path.display(),
                        install_deps
                    ));
                    eprintln!("info: using Python from {} (dry-run)", env_source);
                    (
                        RunProgram::Python(base_python),
                        Some(venv_path.to_string_lossy().to_string()),
                        false,
                    )
                } else {
                    let _env_lock = pep_cache
                        .lock_script_env(&env_root)
                        .map_err(|e| eyre!("failed to lock script env: {}", e))?;

                    let mut cache_hit = false;
                    if venv_path.exists()
                        && venv_python.exists()
                        && let Some(info) = pep_cache
                            .read_cache_entry(&env_root)
                            .map_err(|e| eyre!("failed to read cache entry: {}", e))?
                        && Pep723Cache::cache_entry_matches_key(&info, &cache_key)
                    {
                        let _ = pep_cache.update_last_used_at(&env_root);
                        cache_hit = true;
                    }

                    if cache_hit {
                        collector.info(format!(
                            "Cache hit: reusing venv at {} (hash: {})",
                            venv_path.display(),
                            &cache_key.hash[..8]
                        ));
                        eprintln!(
                            "info: using cached environment {} (hash: {})",
                            venv_path.display(),
                            &cache_key.hash[..8]
                        );
                        (
                            RunProgram::Python(venv_python.to_string_lossy().to_string()),
                            Some(venv_path.to_string_lossy().to_string()),
                            true,
                        )
                    } else {
                        if venv_path.exists() {
                            fs::remove_dir_all(&venv_path).map_err(|e| {
                                eyre!("failed to remove stale venv {}: {}", venv_path.display(), e)
                            })?;
                        }
                        let info_path = env_root.join("deps.json");
                        let _ = fs::remove_file(&info_path);

                        eprintln!(
                            "info: using Python from {} for new cached env (hash: {})",
                            env_source,
                            &cache_key.hash[..8]
                        );

                        // Create virtual environment
                        eprintln!(
                            "info: creating cached environment at {}",
                            venv_path.display()
                        );

                        let mut venv_cmd = ProcessCommand::new(&base_python);
                        venv_cmd.args(["-m", "venv"]);
                        if crate::env::find_uv_executable().is_some() {
                            venv_cmd.arg("--without-pip");
                        }
                        venv_cmd.arg(&venv_path);
                        let venv_status = venv_cmd
                            .status()
                            .map_err(|e| eyre!("failed to create virtual environment: {}", e))?;

                        if !venv_status.success() {
                            return Err(eyre!("failed to create virtual environment"));
                        }

                        // Get pip path in venv (for fallback install)
                        let pip_path = if cfg!(windows) {
                            venv_path.join("Scripts").join("pip.exe")
                        } else {
                            venv_path.join("bin").join("pip")
                        };

                        // Install dependencies
                        eprintln!("info: installing {} dependencies...", install_deps.len());
                        if let Some(uv_path) = crate::env::find_uv_executable() {
                            eprintln!("info: using uv for fast installation");
                            let mut install_cmd = ProcessCommand::new(uv_path);
                            install_cmd.args(["pip", "install", "--quiet"]);
                            if install_no_deps {
                                install_cmd.arg("--no-deps");
                            }
                            install_cmd.arg("--python");
                            install_cmd.arg(&venv_path);
                            if let Some(dir) = &wheel_cache_dir {
                                if std::env::var_os("UV_CACHE_DIR").is_none() {
                                    install_cmd.env("UV_CACHE_DIR", dir);
                                }
                                if std::env::var_os("PIP_CACHE_DIR").is_none() {
                                    install_cmd.env("PIP_CACHE_DIR", dir);
                                }
                            }
                            install_cmd.args(&install_deps);

                            let install_status = install_cmd.status().map_err(|e| {
                                eyre!("failed to install dependencies with uv: {}", e)
                            })?;

                            if !install_status.success() {
                                collector
                                    .warning("failed to install dependencies with uv".to_string());
                                return Err(eyre!(
                                    "failed to install PEP 723 dependencies (uv backend)"
                                ));
                            }
                        } else {
                            // Fallback to standard pip
                            let mut install_cmd = ProcessCommand::new(&pip_path);
                            install_cmd.args(["install", "--quiet"]);
                            if install_no_deps {
                                install_cmd.arg("--no-deps");
                            }
                            if let Some(dir) = &wheel_cache_dir {
                                install_cmd.arg("--cache-dir");
                                install_cmd.arg(dir);
                            }
                            install_cmd.args(&install_deps);

                            let install_status = install_cmd
                                .status()
                                .map_err(|e| eyre!("failed to install dependencies: {}", e))?;

                            if !install_status.success() {
                                collector.warning("failed to install dependencies".to_string());
                                return Err(eyre!("failed to install PEP 723 dependencies"));
                            }
                        }

                        pep_cache
                            .record_cache_entry_at(&env_root, &cache_key)
                            .map_err(|e| eyre!("failed to record cache entry: {}", e))?;

                        eprintln!("info: cached environment ready");

                        (
                            RunProgram::Python(venv_python.to_string_lossy().to_string()),
                            Some(venv_path.to_string_lossy().to_string()),
                            false,
                        )
                    }
                }
            }
        } else {
            pep723_backend = "pybun".to_string();
            // Initialize PEP 723 cache
            let pep_cache =
                Pep723Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
            let (base_python, env_source) = find_python_interpreter()?;
            let python_version = get_python_version(Path::new(&base_python))?;
            let index_settings = pep723_index_settings(pep723_metadata.as_ref());
            let cache_key = Pep723CacheKey::new(
                &install_deps,
                &python_version,
                &index_settings,
                lock_hash.as_deref(),
            );
            let install_no_deps = script_lock.is_some();
            let env_root = pep_cache
                .script_env_root(&script_path)
                .map_err(|e| eyre!("failed to resolve script env root: {}", e))?;
            let venv_path = pep_cache.venv_path_for_root(&env_root);
            let venv_python = pep_cache.python_path_for_venv(&venv_path);

            if dry_run {
                collector.info(format!(
                    "Would use cached env at {} or create new one: {:?}",
                    venv_path.display(),
                    install_deps
                ));
                eprintln!("info: using Python from {} (dry-run)", env_source);
                (
                    RunProgram::Python(base_python),
                    Some(venv_path.to_string_lossy().to_string()),
                    false,
                )
            } else if !no_cache {
                let _env_lock = pep_cache
                    .lock_script_env(&env_root)
                    .map_err(|e| eyre!("failed to lock script env: {}", e))?;

                let mut cache_hit = false;
                if venv_path.exists()
                    && venv_python.exists()
                    && let Some(info) = pep_cache
                        .read_cache_entry(&env_root)
                        .map_err(|e| eyre!("failed to read cache entry: {}", e))?
                    && Pep723Cache::cache_entry_matches_key(&info, &cache_key)
                {
                    let _ = pep_cache.update_last_used_at(&env_root);
                    cache_hit = true;
                }

                if cache_hit {
                    collector.info(format!(
                        "Cache hit: reusing venv at {} (hash: {})",
                        venv_path.display(),
                        &cache_key.hash[..8]
                    ));
                    eprintln!(
                        "info: using cached environment {} (hash: {})",
                        venv_path.display(),
                        &cache_key.hash[..8]
                    );
                    (
                        RunProgram::Python(venv_python.to_string_lossy().to_string()),
                        Some(venv_path.to_string_lossy().to_string()),
                        true,
                    )
                } else {
                    if venv_path.exists() {
                        fs::remove_dir_all(&venv_path).map_err(|e| {
                            eyre!("failed to remove stale venv {}: {}", venv_path.display(), e)
                        })?;
                    }
                    let info_path = env_root.join("deps.json");
                    let _ = fs::remove_file(&info_path);

                    eprintln!(
                        "info: using Python from {} for new cached env (hash: {})",
                        env_source,
                        &cache_key.hash[..8]
                    );

                    // Create virtual environment
                    eprintln!(
                        "info: creating cached environment at {}",
                        venv_path.display()
                    );

                    let mut venv_cmd = ProcessCommand::new(&base_python);
                    venv_cmd.args(["-m", "venv"]);
                    if crate::env::find_uv_executable().is_some() {
                        venv_cmd.arg("--without-pip");
                    }
                    venv_cmd.arg(&venv_path);
                    let venv_status = venv_cmd
                        .status()
                        .map_err(|e| eyre!("failed to create virtual environment: {}", e))?;

                    if !venv_status.success() {
                        return Err(eyre!("failed to create virtual environment"));
                    }

                    // Get pip path in venv (for fallback install)
                    let _pip_path = if cfg!(windows) {
                        venv_path.join("Scripts").join("pip.exe")
                    } else {
                        venv_path.join("bin").join("pip")
                    };

                    eprintln!("info: installing {} dependencies...", install_deps.len());
                    if let Some(uv_path) = crate::env::find_uv_executable() {
                        eprintln!("info: using uv for fast installation");
                        let mut install_cmd = ProcessCommand::new(uv_path);
                        install_cmd.args(["pip", "install", "--quiet"]);
                        if install_no_deps {
                            install_cmd.arg("--no-deps");
                        }
                        install_cmd.arg("--python");
                        install_cmd.arg(&venv_path);
                        if let Some(dir) = &wheel_cache_dir {
                            if std::env::var_os("UV_CACHE_DIR").is_none() {
                                install_cmd.env("UV_CACHE_DIR", dir);
                            }
                            if std::env::var_os("PIP_CACHE_DIR").is_none() {
                                install_cmd.env("PIP_CACHE_DIR", dir);
                            }
                        }
                        install_cmd.args(&install_deps);

                        let install_status = install_cmd
                            .status()
                            .map_err(|e| eyre!("failed to install dependencies with uv: {}", e))?;

                        if !install_status.success() {
                            collector.warning("failed to install dependencies with uv".to_string());
                            return Err(eyre!(
                                "failed to install PEP 723 dependencies (uv backend)"
                            ));
                        }
                    } else {
                        // Native PyBun Installation
                        eprintln!("info: resolving dependencies (native)...");

                        let requirements: Vec<Requirement> = install_deps
                            .iter()
                            .map(|d| d.parse().unwrap_or_else(|_| Requirement::any(d)))
                            .collect();

                        // Use offline flag from args if available?
                        // run_script args doesn't strictly have offline flag passed down easily unless we parse it?
                        // But PyPiClient::from_env handles env vars.
                        let client = PyPiClient::from_env(false).map_err(|e| eyre!(e))?;
                        let index = PyPiIndex::new(client);
                        let resolution = resolve(requirements, &index)
                            .await
                            .map_err(|e: crate::resolver::ResolveError| eyre!(e))?;

                        // Prepare site-packages path
                        let major_minor = python_version
                            .split('.')
                            .take(2)
                            .collect::<Vec<_>>()
                            .join(".");
                        let site_packages = if cfg!(windows) {
                            venv_path.join("Lib").join("site-packages")
                        } else {
                            venv_path
                                .join("lib")
                                .join(format!("python{}", major_minor))
                                .join("site-packages")
                        };

                        let wheel_cache = WheelCache::new()
                            .map_err(|e| eyre!("failed to init wheel cache: {}", e))?;
                        eprintln!(
                            "info: downloading {} packages...",
                            resolution.packages.len()
                        );

                        let platform_tags = crate::resolver::current_platform_tags();
                        let mut download_futures = Vec::new();

                        for pkg in resolution.packages.values() {
                            let selection =
                                crate::resolver::select_artifact_for_platform(pkg, &platform_tags);
                            if selection.from_source {
                                return Err(eyre!(
                                    "native installer does not support sdist for {}",
                                    pkg.name
                                ));
                            }
                            if let Some(url) = &selection.url {
                                let name = pkg.name.clone();
                                let filename = selection.filename.clone();
                                let url = url.clone();
                                let wc = &wheel_cache;
                                download_futures.push(async move {
                                    wc.get_wheel(&name, &filename, &url, None).await
                                });
                            } else {
                                return Err(eyre!("no download URL for {}", pkg.name));
                            }
                        }

                        let results = futures::future::join_all(download_futures).await;
                        let mut wheels_to_install = Vec::new();
                        for res in results {
                            match res {
                                Ok(path) => wheels_to_install.push(path),
                                Err(e) => return Err(eyre!("download failed: {}", e)),
                            }
                        }

                        eprintln!("info: installing {} packages...", wheels_to_install.len());
                        for wheel in wheels_to_install {
                            installer::install_wheel(&wheel, &site_packages)
                                .map_err(|e| eyre!("failed to install wheel: {}", e))?;
                        }
                    }

                    pep_cache
                        .record_cache_entry_at(&env_root, &cache_key)
                        .map_err(|e| eyre!("failed to record cache entry: {}", e))?;

                    eprintln!("info: cached environment ready");

                    (
                        RunProgram::Python(venv_python.to_string_lossy().to_string()),
                        Some(venv_path.to_string_lossy().to_string()),
                        false,
                    )
                }
            } else {
                // No-cache mode: create temporary environment
                let temp_dir = tempfile::tempdir()
                    .map_err(|e| eyre!("failed to create temp directory: {}", e))?;
                let temp_env_str = temp_dir.path().to_string_lossy().to_string();

                eprintln!(
                    "info: using Python from {} for temp env (no-cache mode)",
                    env_source
                );

                let venv_path = temp_dir.path().join("venv");
                eprintln!(
                    "info: creating isolated environment at {}",
                    venv_path.display()
                );

                let mut venv_cmd = ProcessCommand::new(&base_python);
                venv_cmd.args(["-m", "venv"]);
                if crate::env::find_uv_executable().is_some() {
                    venv_cmd.arg("--without-pip");
                }
                venv_cmd.arg(&venv_path);
                let venv_status = venv_cmd
                    .status()
                    .map_err(|e| eyre!("failed to create virtual environment: {}", e))?;

                if !venv_status.success() {
                    return Err(eyre!("failed to create virtual environment"));
                }

                let pip_path = if cfg!(windows) {
                    venv_path.join("Scripts").join("pip.exe")
                } else {
                    venv_path.join("bin").join("pip")
                };
                let venv_python = if cfg!(windows) {
                    venv_path.join("Scripts").join("python.exe")
                } else {
                    venv_path.join("bin").join("python")
                };

                eprintln!("info: installing {} dependencies...", install_deps.len());

                if let Some(uv_path) = crate::env::find_uv_executable() {
                    eprintln!("info: using uv for fast installation (no-cache mode)");
                    let mut install_cmd = ProcessCommand::new(uv_path);
                    install_cmd.args(["pip", "install", "--quiet"]);
                    if install_no_deps {
                        install_cmd.arg("--no-deps");
                    }
                    install_cmd.arg("--python");
                    install_cmd.arg(&venv_path);
                    if let Some(dir) = &wheel_cache_dir {
                        if std::env::var_os("UV_CACHE_DIR").is_none() {
                            install_cmd.env("UV_CACHE_DIR", dir);
                        }
                        if std::env::var_os("PIP_CACHE_DIR").is_none() {
                            install_cmd.env("PIP_CACHE_DIR", dir);
                        }
                    }
                    install_cmd.args(&install_deps);

                    let install_status = install_cmd
                        .status()
                        .map_err(|e| eyre!("failed to install dependencies with uv: {}", e))?;

                    if !install_status.success() {
                        collector.warning("failed to install dependencies with uv".to_string());
                        return Err(eyre!("failed to install PEP 723 dependencies (uv)"));
                    }
                } else {
                    let mut install_cmd = ProcessCommand::new(&pip_path);
                    install_cmd.args(["install", "--quiet"]);
                    if install_no_deps {
                        install_cmd.arg("--no-deps");
                    }
                    if let Some(dir) = &wheel_cache_dir {
                        install_cmd.arg("--cache-dir");
                        install_cmd.arg(dir);
                    }
                    install_cmd.args(&install_deps);

                    let install_status = install_cmd
                        .status()
                        .map_err(|e| eyre!("failed to install dependencies: {}", e))?;

                    if !install_status.success() {
                        collector.warning("failed to install dependencies".to_string());
                        return Err(eyre!("failed to install PEP 723 dependencies"));
                    }
                }

                // Keep the temp dir alive until after execution.
                temp_env_dir = Some(temp_dir);
                (
                    RunProgram::Python(venv_python.to_string_lossy().to_string()),
                    Some(temp_env_str),
                    false,
                )
            }
        }
    } else {
        // No PEP 723 dependencies, use system/project Python
        let (python, env_source) = find_python_interpreter()?;

        if matches!(env_source, crate::env::EnvSource::System) {
            let current_dir = std::env::current_dir()?;
            if Project::discover(&current_dir).is_ok() {
                eprintln!("warning: PyBun is using system Python but a pyproject.toml exists.");
                eprintln!(
                    "hint: Ensure your virtual environment is at .venv, .pybun/venv, or set PYBUN_ENV."
                );
            }
        }

        eprintln!("info: using Python from {}", env_source);
        (RunProgram::Python(python), None, false)
    };

    // Build command
    let (mut cmd, is_uv_runner) = match runner {
        RunProgram::Python(python) => {
            let mut cmd = ProcessCommand::new(python);
            cmd.arg(&script_path);
            for arg in &args.passthrough {
                cmd.arg(arg);
            }
            (cmd, false)
        }
        RunProgram::Uv { uv_path, python } => {
            let mut cmd = ProcessCommand::new(uv_path);
            cmd.args(["run", "--python"]);
            cmd.arg(python);
            cmd.arg("--script");
            cmd.arg(&script_path);
            if let Some(dir) = &wheel_cache_dir {
                if std::env::var_os("UV_CACHE_DIR").is_none() {
                    cmd.env("UV_CACHE_DIR", dir);
                }
                if std::env::var_os("PIP_CACHE_DIR").is_none() {
                    cmd.env("PIP_CACHE_DIR", dir);
                }
            }
            if !args.passthrough.is_empty() {
                cmd.arg("--");
                for arg in &args.passthrough {
                    cmd.arg(arg);
                }
            }
            (cmd, true)
        }
    };

    // Enable sandbox if requested.
    let mut sandbox_guard: Option<sandbox::SandboxGuard> = None;
    let mut sandbox_info: Option<SandboxInfo> = None;
    if args.sandbox {
        if is_uv_runner {
            return Err(eyre!("--sandbox is not supported with uv run backend"));
        }
        let allow_network = args.allow_network
            || std::env::var("PYBUN_SANDBOX_ALLOW_NETWORK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        collector.info(format!("sandbox enabled (allow_network={})", allow_network));
        let guard =
            sandbox::apply_python_sandbox(&mut cmd, sandbox::SandboxConfig { allow_network })?;
        sandbox_info = Some(SandboxInfo {
            enabled: true,
            allow_network,
            enforcement: guard.enforcement().to_string(),
        });
        sandbox_guard = Some(guard);
    }

    let cleanup = temp_env_dir.is_some();

    // Execute
    // On Unix, use exec to replace the process if cleanup is not needed AND not in JSON mode
    // (JSON mode requires wrapping to emit final summary)
    #[cfg(unix)]
    if !cleanup && format != OutputFormat::Json && sandbox_guard.is_none() {
        let err = cmd.exec();
        return Err(eyre!("failed to exec runner: {}", err));
    }

    let (status, stdout, stderr) = match format {
        OutputFormat::Json => {
            let output = cmd
                .output()
                .map_err(|e| eyre!("failed to execute runner: {}", e))?;
            (
                output.status,
                capture_stdio(&output.stdout),
                capture_stdio(&output.stderr),
            )
        }
        OutputFormat::Text => (
            cmd.status()
                .map_err(|e| eyre!("failed to execute runner: {}", e))?,
            None,
            None,
        ),
    };
    // Drop guard after process exit to cleanup temporary sitecustomize dir.
    drop(sandbox_guard);

    let exit_code = status.code().unwrap_or(-1);

    let summary = if status.success() {
        format!("executed {} successfully", script_path.display())
    } else {
        format!(
            "script {} exited with code {}",
            script_path.display(),
            exit_code
        )
    };

    Ok(RunOutcome {
        summary,
        target: Some(target.clone()),
        exit_code,
        pep723_deps,
        pep723_backend,
        temp_env: cached_env_path,
        cleanup,
        cache_hit,
        stdout,
        stderr,
        sandbox: sandbox_info,
    })
}

/// Get Python version from a Python interpreter
fn get_python_version(python_path: &std::path::Path) -> Result<String> {
    let output = ProcessCommand::new(python_path)
        .args(["--version"])
        .output()
        .map_err(|e| eyre!("failed to get Python version: {}", e))?;

    let version_str = String::from_utf8_lossy(&output.stdout);
    // Parse "Python 3.11.0" -> "3.11.0"
    let version = version_str
        .trim()
        .strip_prefix("Python ")
        .unwrap_or(version_str.trim())
        .to_string();
    Ok(version)
}

fn run_python_code(
    args: &crate::cli::RunArgs,
    collector: &mut EventCollector,
    format: OutputFormat,
) -> Result<RunOutcome> {
    // pybun run -c "print('hello')" -- equivalent to python -c "..."
    let code = args
        .passthrough
        .first()
        .ok_or_else(|| eyre!("code argument required after -c"))?;

    let (python, env_source) = find_python_interpreter()?;
    eprintln!("info: using Python from {}", env_source);

    let mut cmd = ProcessCommand::new(&python);
    cmd.arg("-c").arg(code);

    let mut sandbox_info: Option<SandboxInfo> = None;
    let mut sandbox_guard: Option<sandbox::SandboxGuard> = None;
    if args.sandbox {
        let allow_network = args.allow_network
            || std::env::var("PYBUN_SANDBOX_ALLOW_NETWORK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        collector.info(format!(
            "sandbox enabled for inline code (allow_network={})",
            allow_network
        ));
        let guard =
            sandbox::apply_python_sandbox(&mut cmd, sandbox::SandboxConfig { allow_network })?;
        sandbox_info = Some(SandboxInfo {
            enabled: true,
            allow_network,
            enforcement: guard.enforcement().to_string(),
        });
        sandbox_guard = Some(guard);
    }

    // Add remaining passthrough arguments
    for arg in args.passthrough.iter().skip(1) {
        cmd.arg(arg);
    }

    #[cfg(unix)]
    if format != OutputFormat::Json && sandbox_guard.is_none() {
        let err = cmd.exec();
        return Err(eyre!("failed to exec Python: {}", err));
    }

    let (status, stdout, stderr) = match format {
        OutputFormat::Json => {
            let output = cmd
                .output()
                .map_err(|e| eyre!("failed to execute Python: {}", e))?;
            (
                output.status,
                capture_stdio(&output.stdout),
                capture_stdio(&output.stderr),
            )
        }
        OutputFormat::Text => (
            cmd.status()
                .map_err(|e| eyre!("failed to execute Python: {}", e))?,
            None,
            None,
        ),
    };
    drop(sandbox_guard);

    let exit_code = status.code().unwrap_or(-1);

    let summary = if status.success() {
        if args.sandbox {
            "executed inline code successfully (sandboxed)".to_string()
        } else {
            "executed inline code successfully".to_string()
        }
    } else {
        format!("inline code exited with code {}", exit_code)
    };

    Ok(RunOutcome {
        summary,
        target: Some("-c".to_string()),
        exit_code,
        pep723_deps: Vec::new(),
        pep723_backend: "system".to_string(),
        temp_env: None,
        cleanup: false,
        cache_hit: false,
        stdout,
        stderr,
        sandbox: sandbox_info,
    })
}

/// Find the Python interpreter to use.
/// Uses the new env module with full priority-based selection.
///
/// Priority:
/// 1. PYBUN_ENV environment variable (venv path)
/// 2. PYBUN_PYTHON environment variable (explicit binary)
/// 3. Project-local .pybun/venv directory
/// 4. .python-version file (pyenv-style)
/// 5. System Python (python3/python in PATH)
fn find_python_interpreter() -> Result<(String, EnvSource)> {
    let working_dir = std::env::current_dir()?;
    let env = find_python_env(&working_dir)?;
    Ok((env.python_path.to_string_lossy().to_string(), env.source))
}

// ---------------------------------------------------------------------------
// pybun python
// ---------------------------------------------------------------------------

use crate::cache::{Cache, format_size, parse_size};
use crate::runtime::{RuntimeManager, supported_versions};

fn handle_python_command(
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

// ---------------------------------------------------------------------------
// pybun x (execute tool ad-hoc)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct XOutcome {
    summary: String,
    package: String,
    version: Option<String>,
    passthrough: Vec<String>,
    temp_env: String,
    python_version: String,
    exit_code: i32,
    cleanup: bool,
}

fn execute_tool(args: &crate::cli::ToolArgs, _collector: &mut EventCollector) -> Result<XOutcome> {
    let package_spec = args
        .package
        .as_ref()
        .ok_or_else(|| eyre!("package name is required"))?;

    // Parse package name and version
    let (package_name, version) = parse_package_spec(package_spec);

    // Check for dry-run mode (for testing)
    let dry_run = std::env::var("PYBUN_X_DRY_RUN").is_ok();

    // Find Python interpreter
    let working_dir = std::env::current_dir()?;
    let env = find_python_env(&working_dir)?;
    let python_path = env.python_path.to_string_lossy().to_string();
    let python_version = env.version.clone().unwrap_or_else(|| "unknown".to_string());

    // Create temporary environment
    let temp_dir =
        tempfile::tempdir().map_err(|e| eyre!("failed to create temp directory: {}", e))?;
    let temp_env_path = temp_dir.path().to_string_lossy().to_string();

    if dry_run {
        // In dry-run mode, just return the planned actions
        return Ok(XOutcome {
            summary: format!("would execute {} (dry-run)", package_name),
            package: package_name,
            version,
            passthrough: args.passthrough.clone(),
            temp_env: temp_env_path,
            python_version,
            exit_code: 0,
            cleanup: true,
        });
    }

    // Create virtual environment in temp directory
    let venv_path = temp_dir.path().join("venv");
    eprintln!(
        "info: creating temporary environment at {}",
        venv_path.display()
    );

    let uv_available = crate::env::find_uv_executable().is_some();

    let mut venv_cmd = ProcessCommand::new(&python_path);
    venv_cmd.args(["-m", "venv"]);
    if uv_available {
        venv_cmd.arg("--without-pip");
    }
    venv_cmd.arg(&venv_path);
    let venv_status = venv_cmd
        .status()
        .map_err(|e| eyre!("failed to create virtual environment: {}", e))?;

    if !venv_status.success() {
        return Err(eyre!("failed to create virtual environment"));
    }

    // Get pip path in venv
    let pip_path = if cfg!(windows) {
        venv_path.join("Scripts").join("pip.exe")
    } else {
        venv_path.join("bin").join("pip")
    };

    // Get python path in venv
    let venv_python = if cfg!(windows) {
        venv_path.join("Scripts").join("python.exe")
    } else {
        venv_path.join("bin").join("python")
    };

    // Install the package using uv if available, otherwise pip
    eprintln!("info: installing {}...", package_spec);
    let install_status = if let Some(uv_path) = crate::env::find_uv_executable() {
        ProcessCommand::new(uv_path)
            .args(["pip", "install", "--quiet", "--python"])
            .arg(&venv_path)
            .arg(package_spec)
            .status()
            .map_err(|e| eyre!("failed to install package with uv: {}", e))?
    } else {
        ProcessCommand::new(&pip_path)
            .args(["install", "--quiet", package_spec])
            .status()
            .map_err(|e| eyre!("failed to install package: {}", e))?
    };

    if !install_status.success() {
        return Err(eyre!("failed to install package {}", package_spec));
    }

    // Find and execute the entry point
    // Most packages have a console script with the same name as the package
    let entry_point = if cfg!(windows) {
        venv_path
            .join("Scripts")
            .join(format!("{}.exe", package_name))
    } else {
        venv_path.join("bin").join(&package_name)
    };

    let exit_code = if entry_point.exists() {
        // Execute the console script directly
        eprintln!("info: executing {}...", entry_point.display());
        let mut cmd = ProcessCommand::new(&entry_point);
        for arg in &args.passthrough {
            cmd.arg(arg);
        }
        let status = cmd
            .status()
            .map_err(|e| eyre!("failed to execute {}: {}", package_name, e))?;
        status.code().unwrap_or(-1)
    } else {
        // Fallback: try to run as a module
        eprintln!("info: executing python -m {}...", package_name);
        let mut cmd = ProcessCommand::new(&venv_python);
        cmd.args(["-m", &package_name]);
        for arg in &args.passthrough {
            cmd.arg(arg);
        }
        let status = cmd
            .status()
            .map_err(|e| eyre!("failed to execute module {}: {}", package_name, e))?;
        status.code().unwrap_or(-1)
    };

    // Cleanup is automatic when temp_dir is dropped
    let summary = if exit_code == 0 {
        format!("executed {} successfully", package_name)
    } else {
        format!("{} exited with code {}", package_name, exit_code)
    };

    Ok(XOutcome {
        summary,
        package: package_name,
        version,
        passthrough: args.passthrough.clone(),
        temp_env: temp_env_path,
        python_version,
        exit_code,
        cleanup: true,
    })
}

/// Parse a package specification like "cowsay==6.1" into (name, version)
fn parse_package_spec(spec: &str) -> (String, Option<String>) {
    // Handle various specifier formats
    for sep in ["==", ">=", "<=", "!=", "~=", ">", "<"] {
        if let Some(idx) = spec.find(sep) {
            let name = spec[..idx].to_string();
            let version = spec[idx + sep.len()..].to_string();
            return (name, Some(version));
        }
    }
    (spec.to_string(), None)
}

// ---------------------------------------------------------------------------
// pybun self update
// ---------------------------------------------------------------------------

fn run_self_update(
    args: &crate::cli::SelfUpdateArgs,
    collector: &mut EventCollector,
) -> RenderDetail {
    let current_version = env!("CARGO_PKG_VERSION");
    let channel = &args.channel;

    collector.info(format!("Checking for updates on {} channel", channel));

    let manifest_source_env = std::env::var("PYBUN_SELF_UPDATE_MANIFEST").ok();
    let default_manifest_url = default_manifest_url(channel);
    let manifest_source = manifest_source_env
        .clone()
        .unwrap_or_else(|| default_manifest_url.clone());
    let should_fetch_manifest =
        manifest_source_env.is_some() || std::env::var("PYBUN_SELF_UPDATE_FETCH").is_ok();
    let manifest_result = if should_fetch_manifest {
        Some(ReleaseManifest::load(&manifest_source))
    } else {
        None
    };

    let mut latest_version = current_version.to_string();
    let mut update_available = false;
    let mut release_url = release_url_for_version(current_version);
    let mut manifest_detail = None;
    let mut manifest_error = None;

    match manifest_result {
        Some(Ok(manifest)) => {
            latest_version = manifest.version.clone();
            update_available = manifest
                .compare_version(current_version)
                .map(|ordering| ordering == Ordering::Greater)
                .unwrap_or(false);
            release_url = manifest
                .release_url
                .clone()
                .unwrap_or_else(|| release_url_for_version(&manifest.version));

            let target = current_release_target();
            let asset = target
                .as_deref()
                .and_then(|target| manifest.select_asset(target));
            let asset_json = asset
                .map(|asset| serde_json::to_value(asset).unwrap_or_else(|_| json!({})))
                .unwrap_or(Value::Null);

            manifest_detail = Some(json!({
                "version": manifest.version,
                "channel": manifest.channel,
                "published_at": manifest.published_at,
                "release_url": manifest.release_url,
                "release_notes": manifest.release_notes,
                "source": manifest_source,
                "target": target,
                "asset": asset_json,
                "assets": manifest.assets.len(),
                "sbom": manifest.sbom,
                "provenance": manifest.provenance,
            }));
        }
        Some(Err(error)) => {
            manifest_error = Some(error.to_string());
        }
        None => {}
    }

    let summary = if args.dry_run {
        if update_available {
            format!(
                "Update available: {} -> {} (dry-run, no changes made)",
                current_version, latest_version
            )
        } else if let Some(error) = manifest_error.as_deref() {
            format!("Update check failed: {} (dry-run)", error)
        } else {
            format!(
                "Already up to date: {} (channel: {})",
                current_version, channel
            )
        }
    } else if update_available {
        // Would perform actual update here
        format!(
            "Would update: {} -> {} (update not yet implemented)",
            current_version, latest_version
        )
    } else {
        format!(
            "Already up to date: {} (channel: {})",
            current_version, channel
        )
    };

    let json_detail = json!({
        "current_version": current_version,
        "latest_version": latest_version,
        "channel": channel,
        "update_available": update_available,
        "release_url": release_url,
        "dry_run": args.dry_run,
        "manifest": manifest_detail,
        "manifest_error": manifest_error,
        "manifest_source": manifest_source_env.or(Some(default_manifest_url)),
    });

    RenderDetail::with_json(summary, json_detail)
}

fn default_manifest_url(channel: &str) -> String {
    if channel == "nightly" {
        "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/nightly/pybun-release.json"
            .to_string()
    } else {
        "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/latest/download/pybun-release.json"
            .to_string()
    }
}

fn release_url_for_version(version: &str) -> String {
    let trimmed = version.trim_start_matches('v');
    format!(
        "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/tag/v{}",
        trimmed
    )
}

// ---------------------------------------------------------------------------
// pybun gc (garbage collection)
// ---------------------------------------------------------------------------

fn run_gc(args: &crate::cli::GcArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
    let cache = Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;

    // Parse max size if provided
    let max_bytes = if let Some(size_str) = &args.max_size {
        Some(parse_size(size_str).map_err(|e| eyre!("invalid size format: {}", e))?)
    } else {
        None
    };

    collector.info(format!("Running GC on cache at {}", cache.root().display()));

    // Ensure cache directories exist
    cache
        .ensure_dirs()
        .map_err(|e| eyre!("failed to ensure cache dirs: {}", e))?;

    // Run garbage collection on packages/build cache
    let gc_result = cache
        .gc(max_bytes, args.dry_run)
        .map_err(|e| eyre!("GC failed: {}", e))?;

    // Also run GC on PEP 723 venv cache
    let pep723_cache =
        Pep723Cache::new().map_err(|e| eyre!("failed to initialize pep723 cache: {}", e))?;
    let pep723_gc_result = pep723_cache
        .gc(max_bytes, args.dry_run)
        .map_err(|e| eyre!("PEP 723 GC failed: {}", e))?;

    // Combine results
    let total_freed = gc_result.freed_bytes + pep723_gc_result.freed_bytes;
    let total_removed = gc_result.files_removed + pep723_gc_result.envs_removed;
    let total_size_before = gc_result.size_before + pep723_gc_result.size_before;
    let total_size_after = gc_result.size_after + pep723_gc_result.size_after;

    let summary = if args.dry_run {
        let would_remove_count = gc_result.would_remove.len() + pep723_gc_result.would_remove.len();
        if would_remove_count == 0 {
            format!(
                "Cache is within limits ({} used)",
                format_size(total_size_before)
            )
        } else {
            format!(
                "Would free {} ({} files/envs)",
                format_size(total_freed),
                would_remove_count
            )
        }
    } else if total_removed == 0 {
        format!(
            "Cache is within limits ({} used)",
            format_size(total_size_after)
        )
    } else {
        format!(
            "Freed {} ({} files/envs removed)",
            format_size(total_freed),
            total_removed
        )
    };

    let json_detail = json!({
        "freed_bytes": total_freed,
        "freed_human": format_size(total_freed),
        "files_removed": gc_result.files_removed,
        "envs_removed": pep723_gc_result.envs_removed,
        "size_before": total_size_before,
        "size_before_human": format_size(total_size_before),
        "size_after": total_size_after,
        "size_after_human": format_size(total_size_after),
        "dry_run": args.dry_run,
        "max_size": args.max_size,
        "would_remove": gc_result.would_remove.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "would_remove_pep723_envs": pep723_gc_result.would_remove,
        "cache_root": cache.root().display().to_string(),
        "pep723_cache": {
            "freed_bytes": pep723_gc_result.freed_bytes,
            "envs_removed": pep723_gc_result.envs_removed,
            "size_before": pep723_gc_result.size_before,
            "size_after": pep723_gc_result.size_after,
        },
    });

    Ok(RenderDetail::with_json(summary, json_detail))
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

        // Check if we can find it via env discovery
        let working_dir = std::env::current_dir()?;
        if let Ok(env) = find_python_env(&working_dir) {
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

        return Err(eyre!(
            "Python {} is not installed. Use 'pybun python install {}' to install it.",
            version,
            version
        ));
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

// ---------------------------------------------------------------------------
// pybun module-find (Rust-based module finder)
// ---------------------------------------------------------------------------

use crate::module_finder::{ModuleFinder, ModuleFinderConfig};

fn run_module_find(args: &ModuleFindArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
    // Build configuration
    let config = ModuleFinderConfig {
        enabled: true,
        search_paths: if args.paths.is_empty() {
            // Default to current directory if no paths specified
            vec![std::env::current_dir()?]
        } else {
            args.paths.clone()
        },
        threads: args.threads,
        cache_enabled: true,
        ..Default::default()
    };

    let finder = ModuleFinder::new(config);

    if args.scan {
        // Scan mode: list all modules in the search paths
        collector.info("Scanning for modules...");

        let modules = finder.parallel_scan(&finder.config().search_paths.clone());

        let summary = format!("Found {} modules", modules.len());

        let modules_json: Vec<Value> = modules
            .iter()
            .map(|m| {
                json!({
                    "name": m.name,
                    "path": m.path.display().to_string(),
                    "module_type": format!("{:?}", m.module_type),
                    "search_path": m.search_path.display().to_string(),
                })
            })
            .collect();

        let text_output = if modules.is_empty() {
            "No modules found".to_string()
        } else {
            modules
                .iter()
                .map(|m| format!("  {} ({:?}): {}", m.name, m.module_type, m.path.display()))
                .collect::<Vec<_>>()
                .join("\n")
        };

        return Ok(RenderDetail::with_json(
            if args.benchmark {
                format!("{}\n{}", summary, text_output)
            } else {
                text_output
            },
            json!({
                "modules": modules_json,
                "count": modules.len(),
                "search_paths": finder.config().search_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            }),
        ));
    }

    // Find mode: find a specific module
    let module_name = args
        .module
        .as_ref()
        .ok_or_else(|| eyre!("module name is required (or use --scan to list all modules)"))?;

    collector.info(format!("Finding module: {}", module_name));

    let result = finder.find_module(module_name);

    match result.module {
        Some(module_info) => {
            let summary = format!(
                "Found {} at {}",
                module_info.name,
                module_info.path.display()
            );

            let text_output = if args.benchmark {
                format!(
                    "{}\n  Type: {:?}\n  Search path: {}\n  Duration: {}µs",
                    summary,
                    module_info.module_type,
                    module_info.search_path.display(),
                    result.duration_us
                )
            } else {
                format!(
                    "{}\n  Type: {:?}\n  Search path: {}",
                    summary,
                    module_info.module_type,
                    module_info.search_path.display()
                )
            };

            Ok(RenderDetail::with_json(
                text_output,
                json!({
                    "found": true,
                    "name": module_info.name,
                    "path": module_info.path.display().to_string(),
                    "module_type": format!("{:?}", module_info.module_type),
                    "search_path": module_info.search_path.display().to_string(),
                    "searched_paths": result.searched_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                    "duration_us": result.duration_us,
                }),
            ))
        }
        None => {
            let text_output = format!(
                "Module '{}' not found\nSearched paths:\n{}",
                module_name,
                result
                    .searched_paths
                    .iter()
                    .map(|p| format!("  {}", p.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            );

            Ok(RenderDetail::with_json(
                text_output,
                json!({
                    "found": false,
                    "name": module_name,
                    "searched_paths": result.searched_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                    "duration_us": result.duration_us,
                }),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// pybun lazy-import
// ---------------------------------------------------------------------------

#[cfg(feature = "native-watch")]
use crate::hot_reload::run_native_watch_loop;
use crate::hot_reload::{HotReloadConfig, HotReloadWatcher, generate_shell_watcher_command};
use crate::lazy_import::{LazyImportConfig, LazyImportDecision, generate_lazy_import_python_code};

fn run_lazy_import(args: &LazyImportArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
    // Build configuration
    let mut config = LazyImportConfig::with_defaults();
    config.log_imports = args.log_imports;
    config.fallback_to_cpython = !args.no_fallback;

    // Apply allowlist
    for module in &args.allow {
        config.allow(module);
    }

    // Apply denylist
    for module in &args.deny {
        config.deny(module);
    }

    // Handle --check mode
    if let Some(module_name) = &args.check {
        let decision = config.should_lazy_import(module_name);
        let decision_str = match decision {
            LazyImportDecision::Lazy => "lazy",
            LazyImportDecision::Eager => "eager",
            LazyImportDecision::Denied => "denied",
        };

        let text = format!(
            "Module '{}' would be imported: {}",
            module_name, decision_str
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "module": module_name,
                "decision": decision_str,
                "is_denied": config.is_denied(module_name),
                "is_allowed": config.is_allowed(module_name),
            }),
        ));
    }

    // Handle --show-config mode
    if args.show_config {
        collector.info("Showing lazy import configuration");

        let denylist: Vec<_> = config.denylist.iter().cloned().collect();
        let allowlist: Vec<_> = config.allowlist.iter().cloned().collect();

        let text = format!(
            "Lazy Import Configuration:\n  Enabled: {}\n  Fallback: {}\n  Log imports: {}\n  Denylist: {} modules\n  Allowlist: {} modules",
            config.enabled,
            config.fallback_to_cpython,
            config.log_imports,
            denylist.len(),
            allowlist.len()
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "enabled": config.enabled,
                "fallback_to_cpython": config.fallback_to_cpython,
                "log_imports": config.log_imports,
                "denylist": denylist,
                "allowlist": allowlist,
            }),
        ));
    }

    // Handle --generate mode
    if args.generate {
        let code = generate_lazy_import_python_code(&config);

        if let Some(output_path) = &args.output {
            std::fs::write(output_path, &code)
                .map_err(|e| eyre!("failed to write output file: {}", e))?;

            let text = format!("Generated lazy import code to {}", output_path.display());
            collector.info(&text);

            return Ok(RenderDetail::with_json(
                text,
                json!({
                    "output_file": output_path.display().to_string(),
                    "code_length": code.len(),
                    "denylist_count": config.denylist.len(),
                    "allowlist_count": config.allowlist.len(),
                }),
            ));
        }

        // Print to stdout
        return Ok(RenderDetail::with_json(
            code.clone(),
            json!({
                "code": code,
                "code_length": code.len(),
                "denylist_count": config.denylist.len(),
                "allowlist_count": config.allowlist.len(),
            }),
        ));
    }

    // Default: show help
    let text = "Usage: pybun lazy-import [OPTIONS]\n\nOptions:\n  --generate      Generate Python code for lazy import injection\n  --check MODULE  Check if a module would be lazily imported\n  --show-config   Show current configuration\n  --allow MODULE  Add module to allowlist\n  --deny MODULE   Add module to denylist\n  --log-imports   Enable logging in generated code\n  --no-fallback   Disable fallback to CPython import\n  -o, --output    Output file for generated Python code";

    Ok(RenderDetail::with_json(
        text,
        json!({
            "help": true,
            "available_options": ["--generate", "--check", "--show-config", "--allow", "--deny", "--log-imports", "--no-fallback", "-o"],
        }),
    ))
}

// ---------------------------------------------------------------------------
// pybun watch (hot reload)
// ---------------------------------------------------------------------------

fn run_watch(args: &WatchArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
    // Build configuration
    let mut config = HotReloadConfig::dev();

    // Set watch paths
    if !args.paths.is_empty() {
        config.watch_paths = args.paths.clone();
    } else {
        config.watch_paths = vec![std::env::current_dir()?];
    }

    // Set include patterns
    if !args.include.is_empty() {
        config.include_patterns = args.include.clone();
    }

    // Set exclude patterns (merge with defaults)
    for pattern in &args.exclude {
        if !config.exclude_patterns.contains(pattern) {
            config.exclude_patterns.push(pattern.clone());
        }
    }

    config.debounce_ms = args.debounce;
    config.clear_on_reload = args.clear;

    // Handle --show-config mode
    if args.show_config {
        collector.info("Showing watch configuration");

        let stats = HotReloadWatcher::new(config.clone()).stats();

        let text = format!(
            "Watch Configuration:\n  Paths: {:?}\n  Include patterns: {:?}\n  Exclude patterns: {} patterns\n  Debounce: {}ms\n  Clear on reload: {}",
            config.watch_paths,
            config.include_patterns,
            config.exclude_patterns.len(),
            config.debounce_ms,
            config.clear_on_reload
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "watch_paths": config.watch_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "include_patterns": config.include_patterns,
                "exclude_patterns": config.exclude_patterns,
                "debounce_ms": config.debounce_ms,
                "clear_on_reload": config.clear_on_reload,
                "stats": {
                    "is_running": stats.is_running,
                    "watched_paths": stats.watched_paths,
                    "include_patterns": stats.include_patterns,
                    "exclude_patterns": stats.exclude_patterns,
                },
            }),
        ));
    }

    // Handle --shell-command mode
    if args.shell_command {
        let target = args
            .target
            .as_ref()
            .map(|t| format!("pybun run {}", t))
            .unwrap_or_else(|| "echo 'File changed'".to_string());

        let cmd = generate_shell_watcher_command(&config, &target);

        collector.info("Generated shell watcher command");

        return Ok(RenderDetail::with_json(
            cmd.clone(),
            json!({
                "shell_command": cmd,
                "target": target,
                "watch_paths": config.watch_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            }),
        ));
    }

    // Default mode: start watching
    let target = args.target.as_ref();

    if target.is_none() {
        let native_available = HotReloadWatcher::native_watch_available();
        let text = format!(
            "Usage: pybun watch [TARGET] [OPTIONS]\n\n\
            Watch for file changes and re-run a script.\n\n\
            Examples:\n  \
            pybun watch main.py              # Watch current dir, run main.py on changes\n  \
            pybun watch main.py -p src       # Watch src directory\n  \
            pybun watch --show-config        # Show configuration\n  \
            pybun watch --shell-command      # Generate external watcher command\n\n\
            Options:\n  \
            -p, --path PATH          Paths to watch\n  \
            --include PATTERN        Include patterns (e.g., *.py)\n  \
            --exclude PATTERN        Exclude patterns\n  \
            --debounce MS            Debounce delay in ms (default: 300)\n  \
            --clear                  Clear terminal on reload\n\n\
            Native file watching: {}",
            if native_available {
                "enabled"
            } else {
                "disabled (build with --features native-watch)"
            }
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "help": true,
                "status": "awaiting_target",
                "native_watch_available": native_available,
            }),
        ));
    }

    let target_script = target.unwrap();
    let mut watcher = HotReloadWatcher::new(config.clone());

    // Add watch paths
    for path in &config.watch_paths {
        watcher.add_watch_path(path.clone());
    }

    let stats = watcher.stats();

    // Check for dry-run mode (from CLI flag or environment variable for testing)
    let dry_run = args.dry_run || std::env::var("PYBUN_WATCH_DRY_RUN").is_ok();

    // If dry-run, just show preview without starting watcher
    if dry_run {
        let native_available = HotReloadWatcher::native_watch_available();
        let text = format!(
            "Would watch {} paths for changes to run: {}\n\
            Patterns: {} include, {} exclude\n\
            Debounce: {}ms\n\
            Native watching: {}",
            stats.watched_paths,
            target_script,
            stats.include_patterns,
            stats.exclude_patterns,
            stats.debounce_ms,
            if native_available {
                "available"
            } else {
                "not available"
            }
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "status": "dry_run",
                "target": target_script,
                "watch_paths": config.watch_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "include_patterns": config.include_patterns,
                "exclude_patterns": config.exclude_patterns,
                "debounce_ms": config.debounce_ms,
                "native_watch_available": native_available,
                "dry_run": true,
            }),
        ));
    }

    // Check if native watching is available
    #[cfg(feature = "native-watch")]
    {
        collector.info("Starting native file watcher");

        // Build the command to run
        let run_cmd = format!("pybun run {}", target_script);

        // Run the watch loop (this blocks until Ctrl+C)
        let text = format!(
            "Watching {} paths for changes to run: {}\n\
            Patterns: {} include, {} exclude\n\
            Debounce: {}ms\n\
            Native watching: enabled\n\
            Press Ctrl+C to stop.",
            stats.watched_paths,
            target_script,
            stats.include_patterns,
            stats.exclude_patterns,
            stats.debounce_ms
        );

        eprintln!("{}", text);

        // Actually start the watch loop
        match run_native_watch_loop(&config, &run_cmd, None) {
            Ok(()) => Ok(RenderDetail::with_json(
                "File watching stopped".to_string(),
                json!({
                    "status": "stopped",
                    "target": target_script,
                    "native_watch": true,
                }),
            )),
            Err(e) => {
                collector.error(&e);
                Ok(RenderDetail::error(
                    format!("Watch failed: {}", e),
                    json!({
                        "error": e,
                        "status": "error",
                    }),
                ))
            }
        }
    }

    #[cfg(not(feature = "native-watch"))]
    {
        // Native watching not available - show preview
        let text = format!(
            "Would watch {} paths for changes to run: {}\n\
            Patterns: {} include, {} exclude\n\
            Debounce: {}ms\n\n\
            Note: Native file watching requires building with --features native-watch.\n\
            Use --shell-command for external watcher instead.",
            stats.watched_paths,
            target_script,
            stats.include_patterns,
            stats.exclude_patterns,
            stats.debounce_ms
        );

        collector.info(&text);

        Ok(RenderDetail::with_json(
            text,
            json!({
                "status": "preview",
                "target": target_script,
                "watch_paths": config.watch_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "include_patterns": config.include_patterns,
                "exclude_patterns": config.exclude_patterns,
                "debounce_ms": config.debounce_ms,
                "native_watch_available": false,
                "stats": {
                    "watched_paths": stats.watched_paths,
                    "include_patterns": stats.include_patterns,
                    "exclude_patterns": stats.exclude_patterns,
                },
            }),
        ))
    }
}

// ---------------------------------------------------------------------------
// pybun profile (launch profiles)
// ---------------------------------------------------------------------------

use crate::profiles::{Profile, ProfileConfig, ProfileManager};

fn run_profile(args: &ProfileArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
    let manager = ProfileManager::new();

    // Handle --list mode
    if args.list {
        collector.info("Listing available profiles");

        let profiles = manager.available_profiles();
        let text = format!(
            "Available profiles:\n{}",
            profiles
                .iter()
                .map(|p| format!("  - {}", p))
                .collect::<Vec<_>>()
                .join("\n")
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "profiles": profiles.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            }),
        ));
    }

    // Handle --compare mode
    if let Some(compare_profile) = &args.compare {
        let base_profile: Profile = args
            .profile
            .as_ref()
            .ok_or_else(|| eyre!("base profile required for comparison"))?
            .parse()
            .map_err(|e: String| eyre!(e))?;

        let other_profile: Profile = compare_profile.parse().map_err(|e: String| eyre!(e))?;

        let base_config = ProfileConfig::for_profile(base_profile);
        let other_config = ProfileConfig::for_profile(other_profile);

        let text = format!(
            "Profile comparison: {} vs {}\n\n{}\n\n{}\n\n{}",
            base_profile,
            other_profile,
            base_config.summary(),
            "--- vs ---",
            other_config.summary()
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "base_profile": base_profile.to_string(),
                "compare_profile": other_profile.to_string(),
                "base": {
                    "hot_reload": base_config.hot_reload,
                    "lazy_imports": base_config.lazy_imports,
                    "log_level": base_config.log_level,
                    "tracing": base_config.tracing,
                    "optimization_level": base_config.optimization_level,
                },
                "compare": {
                    "hot_reload": other_config.hot_reload,
                    "lazy_imports": other_config.lazy_imports,
                    "log_level": other_config.log_level,
                    "tracing": other_config.tracing,
                    "optimization_level": other_config.optimization_level,
                },
            }),
        ));
    }

    // Handle specific profile
    if let Some(profile_name) = &args.profile {
        let profile: Profile = profile_name.parse().map_err(|e: String| eyre!(e))?;
        let config = ProfileConfig::for_profile(profile);

        // Handle --output mode
        if let Some(output_path) = &args.output {
            config
                .to_file(output_path)
                .map_err(|e| eyre!("failed to export profile: {}", e))?;

            let text = format!("Exported {} profile to {}", profile, output_path.display());
            collector.info(&text);

            return Ok(RenderDetail::with_json(
                text,
                json!({
                    "profile": profile.to_string(),
                    "output_file": output_path.display().to_string(),
                }),
            ));
        }

        // Handle --show mode or default
        let text = if args.show {
            config.summary()
        } else {
            format!(
                "Profile: {}\n\nUse --show for detailed configuration.",
                profile
            )
        };

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "profile": profile.to_string(),
                "config": {
                    "hot_reload": config.hot_reload,
                    "lazy_imports": config.lazy_imports,
                    "module_cache": config.module_cache,
                    "log_level": config.log_level,
                    "log_level_str": config.log_level_str(),
                    "tracing": config.tracing,
                    "timing": config.timing,
                    "debug_checks": config.debug_checks,
                    "optimization_level": config.optimization_level,
                    "python_opt_flags": config.python_opt_flags(),
                },
            }),
        ));
    }

    // Default: show current/detected profile
    let detected = ProfileManager::detect_profile();
    let config = ProfileConfig::for_profile(detected);

    let text = format!(
        "Current profile: {}\n\nUse 'pybun profile <PROFILE>' to view a specific profile.\nUse 'pybun profile --list' to see all available profiles.",
        detected
    );

    Ok(RenderDetail::with_json(
        text,
        json!({
            "current_profile": detected.to_string(),
            "available_profiles": ["dev", "prod", "benchmark"],
            "config": {
                "hot_reload": config.hot_reload,
                "lazy_imports": config.lazy_imports,
                "log_level": config.log_level,
            },
        }),
    ))
}

// ---------------------------------------------------------------------------
// pybun test (test runner)
// ---------------------------------------------------------------------------

use crate::cli::TestBackend;
use crate::test_discovery::{DiscoveryResult, TestDiscovery, TestItem, TestItemType};

/// Get a hint message for a pytest compatibility warning code
fn get_pytest_compat_hint(code: &str) -> Option<&'static str> {
    match code {
        "W001" => Some("Consider using --backend pytest for session/package scoped fixtures"),
        "W002" => Some("This decorator requires the pytest backend to function correctly"),
        "I001" => Some("Parametrized tests will be expanded during discovery"),
        "W003" => Some("This fixture pattern may require pytest plugins"),
        "W004" => Some("Async fixtures require pytest-asyncio or similar"),
        _ => None,
    }
}

/// Parse shard specification (N/M format)
fn parse_shard(shard: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = shard.split('/').collect();
    if parts.len() != 2 {
        return Err(eyre!(
            "invalid shard format '{}': expected N/M (e.g., 1/4)",
            shard
        ));
    }

    let n: u32 = parts[0].parse().map_err(|_| {
        eyre!(
            "invalid shard number '{}': must be a positive integer",
            parts[0]
        )
    })?;
    let m: u32 = parts[1].parse().map_err(|_| {
        eyre!(
            "invalid shard total '{}': must be a positive integer",
            parts[1]
        )
    })?;

    if n == 0 || m == 0 {
        return Err(eyre!("shard values must be greater than 0"));
    }
    if n > m {
        return Err(eyre!("shard {} cannot be greater than total {}", n, m));
    }

    Ok((n, m))
}

/// Detect test backend based on test files
fn detect_test_backend(_paths: &[PathBuf]) -> TestBackend {
    // Default to pytest as it's more common
    // Could be enhanced to detect based on imports in test files

    let python = std::env::current_dir()
        .ok()
        .and_then(|cwd| find_python_env(&cwd).ok().map(|env| env.python_path))
        .unwrap_or_else(|| PathBuf::from("python3"));

    // Check if pytest is available in the selected interpreter
    if let Ok(output) = ProcessCommand::new(&python)
        .args(["-c", "import pytest"])
        .output()
        && output.status.success()
    {
        return TestBackend::Pytest;
    }

    // Fall back to unittest
    TestBackend::Unittest
}

/// Discover test files in given paths (legacy method, kept for backward compatibility)
fn discover_test_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let search_paths = if paths.is_empty() {
        vec![std::env::current_dir().unwrap_or_default()]
    } else {
        paths.to_vec()
    };

    let mut test_files = Vec::new();

    for path in search_paths {
        if path.is_file() {
            // Single file specified
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("test_") || n.ends_with("_test.py"))
                .unwrap_or(false)
            {
                test_files.push(path);
            } else if path.extension().map(|e| e == "py").unwrap_or(false) {
                // Allow any .py file if explicitly specified
                test_files.push(path);
            }
        } else if path.is_dir() {
            // Recursively find test files
            if let Ok(entries) = walkdir(path) {
                for entry in entries {
                    if let Some(name) = entry.file_name().and_then(|n| n.to_str())
                        && (name.starts_with("test_") || name.ends_with("_test.py"))
                        && name.ends_with(".py")
                    {
                        test_files.push(entry);
                    }
                }
            }
        }
    }

    test_files
}

/// Simple directory walker (no external dependency)
fn walkdir(path: impl AsRef<std::path::Path>) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    walkdir_recursive(path.as_ref(), &mut result)?;
    Ok(result)
}

fn walkdir_recursive(path: &std::path::Path, result: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                // Skip hidden directories and common non-test directories
                if let Some(name) = path.file_name().and_then(|n| n.to_str())
                    && !name.starts_with('.')
                    && name != "__pycache__"
                    && name != "node_modules"
                    && name != ".git"
                    && name != "venv"
                    && name != ".venv"
                {
                    walkdir_recursive(&path, result)?;
                }
            } else {
                result.push(path);
            }
        }
    }
    Ok(())
}

/// Use AST-based discovery to find all tests
fn discover_tests_ast(paths: &[PathBuf]) -> DiscoveryResult {
    let discovery = TestDiscovery::new();
    let search_paths = if paths.is_empty() {
        vec![std::env::current_dir().unwrap_or_default()]
    } else {
        paths.to_vec()
    };
    discovery.discover(&search_paths)
}

/// Filter tests by name pattern
fn filter_tests(tests: Vec<TestItem>, pattern: &str) -> Vec<TestItem> {
    tests
        .into_iter()
        .filter(|t| {
            t.name.contains(pattern)
                || t.short_name.contains(pattern)
                || t.class_name
                    .as_ref()
                    .map(|c| c.contains(pattern))
                    .unwrap_or(false)
        })
        .collect()
}

/// Apply sharding to tests
fn shard_tests(tests: Vec<TestItem>, shard_n: u32, shard_m: u32) -> Vec<TestItem> {
    tests
        .into_iter()
        .enumerate()
        .filter(|(i, _)| (*i as u32 % shard_m) + 1 == shard_n)
        .map(|(_, t)| t)
        .collect()
}

fn run_tests(args: &crate::cli::TestArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
    // Check for dry-run mode (for testing)
    let dry_run = std::env::var("PYBUN_TEST_DRY_RUN").is_ok();

    // Parse shard if provided
    let shard_info = if let Some(ref shard_str) = args.shard {
        Some(parse_shard(shard_str)?)
    } else {
        None
    };

    // Determine backend
    let backend = args
        .backend
        .unwrap_or_else(|| detect_test_backend(&args.paths));

    // Use AST-based discovery
    let discovery_result = discover_tests_ast(&args.paths);

    collector.info(format!(
        "AST discovery: found {} tests in {} files ({}µs)",
        discovery_result.tests.len(),
        discovery_result.scanned_files.len(),
        discovery_result.duration_us
    ));

    // Process pytest-compat warnings and add as diagnostics
    if args.pytest_compat && !discovery_result.compat_warnings.is_empty() {
        use crate::schema::DiagnosticLevel;

        for warning in &discovery_result.compat_warnings {
            let level = match warning.severity {
                crate::test_discovery::WarningSeverity::Error => DiagnosticLevel::Error,
                crate::test_discovery::WarningSeverity::Warning => DiagnosticLevel::Warning,
                crate::test_discovery::WarningSeverity::Info => DiagnosticLevel::Info,
            };
            let diag = Diagnostic {
                level,
                code: Some(warning.code.clone()),
                message: warning.message.clone(),
                file: Some(warning.path.display().to_string()),
                line: Some(warning.line as u32),
                suggestion: get_pytest_compat_hint(&warning.code).map(|s| s.to_string()),
                context: None,
            };
            collector.diagnostic(diag);
        }

        // Print warnings in text mode
        if args.verbose {
            eprintln!(
                "\npytest compatibility warnings ({}):",
                discovery_result.compat_warnings.len()
            );
            for w in &discovery_result.compat_warnings {
                let severity_prefix = match w.severity {
                    crate::test_discovery::WarningSeverity::Error => "error",
                    crate::test_discovery::WarningSeverity::Warning => "warning",
                    crate::test_discovery::WarningSeverity::Info => "info",
                };
                eprintln!(
                    "  [{}] {} {}:{}: {}",
                    severity_prefix,
                    w.code,
                    w.path.display(),
                    w.line,
                    w.message
                );
                if let Some(hint) = get_pytest_compat_hint(&w.code) {
                    eprintln!("         hint: {}", hint);
                }
            }
            eprintln!();
        }
    }

    // Get only function/method tests (not class items for running)
    let mut tests: Vec<TestItem> = discovery_result
        .tests
        .iter()
        .filter(|t| t.item_type != TestItemType::Class)
        .cloned()
        .collect();

    // Apply filter if specified
    if let Some(ref pattern) = args.filter {
        tests = filter_tests(tests, pattern);
        collector.info(format!("After filter '{}': {} tests", pattern, tests.len()));
    }

    // Apply sharding if specified
    if let Some((shard_n, shard_m)) = shard_info {
        tests = shard_tests(tests, shard_n, shard_m);
        collector.info(format!(
            "After shard {}/{}: {} tests",
            shard_n,
            shard_m,
            tests.len()
        ));
    }

    // Filter out skipped tests for counting
    let runnable_tests: Vec<&TestItem> = tests.iter().filter(|t| !t.skipped).collect();

    // Legacy file discovery for backward compatibility
    let discovered_files = discover_test_files(&args.paths);

    // Handle --discover mode (just show discovered tests without running)
    if args.discover {
        let summary = format!(
            "Discovered {} tests ({} skipped) in {} files",
            tests.len(),
            tests.iter().filter(|t| t.skipped).count(),
            discovery_result.scanned_files.len()
        );

        let tests_json: Vec<Value> = tests
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "short_name": t.short_name,
                    "path": t.path.display().to_string(),
                    "line": t.line,
                    "type": format!("{:?}", t.item_type).to_lowercase(),
                    "class": t.class_name,
                    "skipped": t.skipped,
                    "skip_reason": t.skip_reason,
                    "xfail": t.xfail,
                    "markers": t.markers.iter().map(|m| &m.name).collect::<Vec<_>>(),
                    "fixtures": t.fixtures,
                    "parametrize": t.parametrize.as_ref().map(|p| json!({
                        "params": p.params,
                        "case_count": p.case_count,
                    })),
                })
            })
            .collect();

        let fixtures_json: Vec<Value> = discovery_result
            .fixtures
            .iter()
            .map(|f| {
                json!({
                    "name": f.name,
                    "path": f.path.display().to_string(),
                    "line": f.line,
                    "scope": format!("{:?}", f.scope).to_lowercase(),
                    "autouse": f.autouse,
                    "dependencies": f.dependencies,
                })
            })
            .collect();

        let warnings_json: Vec<Value> = discovery_result
            .compat_warnings
            .iter()
            .map(|w| {
                json!({
                    "code": w.code,
                    "message": w.message,
                    "path": w.path.display().to_string(),
                    "line": w.line,
                    "severity": format!("{:?}", w.severity).to_lowercase(),
                })
            })
            .collect();

        // Text output for verbose mode
        let text_output = if args.verbose {
            let mut lines = vec![summary.clone()];
            lines.push("".to_string());
            lines.push("Tests:".to_string());
            for t in &tests {
                let status = if t.skipped {
                    " [SKIP]"
                } else if t.xfail {
                    " [XFAIL]"
                } else {
                    ""
                };
                lines.push(format!(
                    "  {}:{} {}{}",
                    t.path.display(),
                    t.line,
                    t.name,
                    status
                ));
                if !t.fixtures.is_empty() {
                    lines.push(format!("    fixtures: {}", t.fixtures.join(", ")));
                }
            }
            if !discovery_result.fixtures.is_empty() {
                lines.push("".to_string());
                lines.push("Fixtures:".to_string());
                for f in &discovery_result.fixtures {
                    lines.push(format!(
                        "  {}:{} {} (scope: {:?})",
                        f.path.display(),
                        f.line,
                        f.name,
                        f.scope
                    ));
                }
            }
            if !discovery_result.compat_warnings.is_empty() {
                lines.push("".to_string());
                lines.push("Compatibility warnings:".to_string());
                for w in &discovery_result.compat_warnings {
                    lines.push(format!("  [{:?}] {}: {}", w.severity, w.code, w.message));
                }
            }
            lines.join("\n")
        } else {
            summary.clone()
        };

        return Ok(RenderDetail::with_json(
            text_output,
            json!({
                "discover": true,
                "tests": tests_json,
                "fixtures": fixtures_json,
                "compat_warnings": warnings_json,
                "scanned_files": discovery_result.scanned_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "error_files": discovery_result.error_files.iter().map(|(p, e)| json!({
                    "path": p.display().to_string(),
                    "error": e,
                })).collect::<Vec<_>>(),
                "duration_us": discovery_result.duration_us,
                "total_tests": tests.len(),
                "runnable_tests": runnable_tests.len(),
                "skipped_tests": tests.iter().filter(|t| t.skipped).count(),
                "xfail_tests": tests.iter().filter(|t| t.xfail).count(),
            }),
        ));
    }

    // If dry-run, just return what would happen
    if dry_run {
        let summary = format!(
            "Would run {} tests ({} skipped) with {:?}",
            runnable_tests.len(),
            tests.iter().filter(|t| t.skipped).count(),
            backend
        );

        // Build compat_warnings for JSON output
        let compat_warnings_json: Vec<Value> = if args.pytest_compat {
            discovery_result
                .compat_warnings
                .iter()
                .map(|w| {
                    json!({
                        "code": w.code,
                        "message": w.message,
                        "path": w.path.display().to_string(),
                        "line": w.line,
                        "severity": format!("{:?}", w.severity).to_lowercase(),
                        "hint": get_pytest_compat_hint(&w.code),
                    })
                })
                .collect()
        } else {
            Vec::new()
        };

        return Ok(RenderDetail::with_json(
            summary,
            json!({
                "dry_run": true,
                "backend": format!("{:?}", backend).to_lowercase(),
                "test_runner": format!("{:?}", backend).to_lowercase(),
                "discovered_files": discovered_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "tests_found": tests.len(),
                "runnable_tests": runnable_tests.len(),
                "fail_fast": args.fail_fast,
                "pytest_compat": args.pytest_compat,
                "shard": shard_info.map(|(n, m)| format!("{}/{}", n, m)),
                "filter": args.filter,
                "parallel": args.parallel,
                "ast_discovery": {
                    "tests": tests.len(),
                    "fixtures": discovery_result.fixtures.len(),
                    "duration_us": discovery_result.duration_us,
                    "compat_warnings": discovery_result.compat_warnings.len(),
                },
                "compat_warnings": compat_warnings_json,
            }),
        ));
    }

    // Find Python interpreter
    let (python, env_source) = find_python_interpreter()?;
    eprintln!("info: using Python from {}", env_source);

    // Build the command based on backend
    let mut cmd = ProcessCommand::new(&python);

    match backend {
        TestBackend::Pytest => {
            cmd.arg("-m").arg("pytest");

            // Add fail-fast flag
            if args.fail_fast {
                cmd.arg("-x");
            }

            // Add verbose for better output
            if args.verbose {
                cmd.arg("-v");
            }

            // Add filter (-k option)
            if let Some(ref pattern) = args.filter {
                cmd.arg("-k").arg(pattern);
            }

            // Add parallel option
            if let Some(workers) = args.parallel {
                cmd.arg("-n").arg(workers.to_string());
            }

            // Add test paths
            if !args.paths.is_empty() {
                for path in &args.paths {
                    cmd.arg(path);
                }
            }

            // Add passthrough args
            for arg in &args.passthrough {
                cmd.arg(arg);
            }
        }
        TestBackend::Unittest => {
            cmd.arg("-m").arg("unittest");

            if args.fail_fast {
                cmd.arg("-f");
            }

            // Add verbose
            if args.verbose {
                cmd.arg("-v");
            }

            // For unittest, we need to specify discover or specific files
            if args.paths.is_empty() {
                cmd.arg("discover");
            } else {
                for path in &args.paths {
                    cmd.arg(path);
                }
            }

            // Add passthrough args
            for arg in &args.passthrough {
                cmd.arg(arg);
            }
        }
    }

    eprintln!("info: running tests with {:?}...", backend);

    // Execute the tests
    let output = cmd
        .output()
        .map_err(|e| eyre!("failed to execute test runner: {}", e))?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Parse test results (simplified)
    let tests_passed = stdout.contains("passed") || stdout.contains("OK");
    let tests_failed = !output.status.success();

    let summary = if tests_failed {
        format!("Tests failed (exit code {})", exit_code)
    } else {
        "All tests passed".to_string()
    };

    // Print output
    if !stdout.is_empty() {
        eprintln!("{}", stdout);
    }
    if !stderr.is_empty() {
        eprintln!("{}", stderr);
    }

    // Build compat_warnings for JSON output
    let run_compat_warnings_json: Vec<Value> = if args.pytest_compat {
        discovery_result
            .compat_warnings
            .iter()
            .map(|w| {
                json!({
                    "code": w.code,
                    "message": w.message,
                    "path": w.path.display().to_string(),
                    "line": w.line,
                    "severity": format!("{:?}", w.severity).to_lowercase(),
                    "hint": get_pytest_compat_hint(&w.code),
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    let detail = json!({
        "backend": format!("{:?}", backend).to_lowercase(),
        "test_runner": format!("{:?}", backend).to_lowercase(),
        "exit_code": exit_code,
        "passed": tests_passed && !tests_failed,
        "fail_fast": args.fail_fast,
        "pytest_compat": args.pytest_compat,
        "shard": shard_info.map(|(n, m)| format!("{}/{}", n, m)),
        "filter": args.filter,
        "parallel": args.parallel,
        "discovered_files": discovered_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "tests_found": tests.len(),
        "ast_discovery": {
            "tests": tests.len(),
            "fixtures": discovery_result.fixtures.len(),
            "duration_us": discovery_result.duration_us,
            "compat_warnings": discovery_result.compat_warnings.len(),
        },
        "compat_warnings": run_compat_warnings_json,
        "stdout": stdout.to_string(),
        "stderr": stderr.to_string(),
    });

    if tests_failed {
        Ok(RenderDetail::error(summary, detail))
    } else {
        Ok(RenderDetail::with_json(summary, detail))
    }
}

// ---------------------------------------------------------------------------
// pybun init
// ---------------------------------------------------------------------------

fn sanitize_project_name(name: &str) -> String {
    let sanitized: String = name
        .replace([' ', '-'], "_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .to_lowercase();

    if sanitized.chars().next().is_some_and(|c| c.is_numeric()) {
        format!("_{}", sanitized)
    } else {
        sanitized
    }
}

fn init_project(args: &InitArgs) -> Result<RenderDetail> {
    let cwd =
        std::env::current_dir().map_err(|e| eyre!("failed to get current directory: {}", e))?;
    let pyproject_path = cwd.join("pyproject.toml");
    let gitignore_path = cwd.join(".gitignore");
    let readme_path = cwd.join("README.md");

    let default_name = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .map(sanitize_project_name)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "my_project".to_string());

    // Resolve arguments (interactive or defaults)
    let (name, description, python, author, template) = if args.yes {
        (
            args.name.clone().unwrap_or(default_name),
            args.description.clone(),
            args.python.clone().or_else(|| Some("3.12".to_string())), // Default to 3.12 if not specified
            args.author.clone(),
            args.template,
        )
    } else {
        // Interactive mode
        let theme = ColorfulTheme::default();

        // Name
        let name: String = if let Some(n) = &args.name {
            n.clone()
        } else {
            Input::with_theme(&theme)
                .with_prompt("Project name")
                .default(default_name)
                .interact_text()?
        };

        // Description
        let description: Option<String> = if let Some(d) = &args.description {
            Some(d.clone())
        } else {
            let d: String = Input::with_theme(&theme)
                .with_prompt("Description")
                .allow_empty(true)
                .interact_text()?;
            if d.is_empty() { None } else { Some(d) }
        };

        // Python Version
        let python: Option<String> = if let Some(p) = &args.python {
            Some(p.clone())
        } else {
            let p: String = Input::with_theme(&theme)
                .with_prompt("Python version")
                .default("3.12".to_string())
                .interact_text()?;
            Some(p)
        };

        // Author
        let author: Option<String> = if let Some(a) = &args.author {
            Some(a.clone())
        } else {
            let a: String = Input::with_theme(&theme)
                .with_prompt("Author")
                .allow_empty(true)
                .interact_text()?;
            if a.is_empty() { None } else { Some(a) }
        };

        // Template
        let template = args.template; // Can also make this interactive later if needed

        (name, description, python, author, template)
    };

    // Check main file existence
    if pyproject_path.exists() {
        return Err(eyre!(
            "pyproject.toml already exists at {}",
            pyproject_path.display()
        ));
    }

    // Build pyproject.toml content
    let mut pyproject = String::new();
    pyproject.push_str("[project]\n");
    pyproject.push_str(&format!("name = \"{}\"\n", name));
    pyproject.push_str("version = \"0.1.0\"\n");

    if let Some(desc) = &description {
        pyproject.push_str(&format!("description = \"{}\"\n", desc));
    }

    if let Some(py) = &python {
        pyproject.push_str(&format!("requires-python = \">={}\"\n", py));
    }

    if let Some(auth) = &author {
        pyproject.push_str(&format!("authors = [{{ name = \"{}\" }}]\n", auth));
    }

    pyproject.push_str("dependencies = []\n");
    pyproject.push_str("\n[build-system]\n");
    pyproject.push_str("requires = [\"hatchling\"]\n");
    pyproject.push_str("build-backend = \"hatchling.build\"\n");

    // Write pyproject.toml
    fs::write(&pyproject_path, &pyproject)
        .map_err(|e| eyre!("failed to write pyproject.toml: {}", e))?;
    let mut files_created = vec![pyproject_path.display().to_string()];
    let mut files_skipped = vec![];

    // Create .gitignore (with check)
    if !gitignore_path.exists() {
        let gitignore_content = r#"# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# Virtual environments
.venv/
venv/
ENV/

# Distribution / packaging
dist/
build/
*.egg-info/

# PyBun
pybun.lockb
.pybun/

# IDE
.vscode/
.idea/
*.swp
*.swo
"#;
        fs::write(&gitignore_path, gitignore_content)
            .map_err(|e| eyre!("failed to write .gitignore: {}", e))?;
        files_created.push(gitignore_path.display().to_string());
    } else {
        files_skipped.push(gitignore_path.display().to_string());
    }

    // Create README.md (with check)
    if !readme_path.exists() {
        let readme_content = format!("# {}\n\nA Python project.\n", name);
        fs::write(&readme_path, readme_content)
            .map_err(|e| eyre!("failed to write README.md: {}", e))?;
        files_created.push(readme_path.display().to_string());
    } else {
        files_skipped.push(readme_path.display().to_string());
    }

    // Create src layout if package template
    if matches!(template, InitTemplate::Package) {
        let package_name = sanitize_project_name(&name);
        let src_dir = cwd.join("src").join(&package_name);
        fs::create_dir_all(&src_dir).map_err(|e| eyre!("failed to create src directory: {}", e))?;

        let init_path = src_dir.join("__init__.py");
        // Safe to overwrite empty init or check? Usually safe to check.
        if !init_path.exists() {
            fs::write(&init_path, "").map_err(|e| eyre!("failed to write __init__.py: {}", e))?;
            files_created.push(init_path.display().to_string());
        } else {
            files_skipped.push(init_path.display().to_string());
        }
    }

    let summary = format!(
        "Initialized project '{}' with {} files ({} skipped)",
        name,
        files_created.len(),
        files_skipped.len()
    );

    Ok(RenderDetail::with_json(
        summary,
        json!({
            "project_name": name,
            "template": format!("{:?}", template).to_lowercase(),
            "files_created": files_created,
            "files_skipped": files_skipped,
        }),
    ))
}

// ---------------------------------------------------------------------------
// pybun outdated
// ---------------------------------------------------------------------------

async fn run_outdated(args: &OutdatedArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
    let cwd =
        std::env::current_dir().map_err(|e| eyre!("failed to get current directory: {}", e))?;
    let lock_path = cwd.join("pybun.lockb");

    if !lock_path.exists() {
        return Err(eyre!("pybun.lockb not found. Run 'pybun install' first."));
    }

    let lockfile = Lockfile::load_from_path(&lock_path)
        .map_err(|e| eyre!("failed to load lockfile: {}", e))?;

    // Load constraints for "wanted" logic
    let constraints = if let Ok(project) = Project::discover(&cwd) {
        let meta = project.metadata();
        let mut map = HashMap::new();
        for dep_str in meta.dependencies {
            if let Ok(req) = Requirement::from_str(&dep_str) {
                map.insert(req.name.clone(), req);
            }
        }
        map
    } else {
        HashMap::new()
    };

    collector.event(EventType::ResolveStart);

    let mut outdated_packages = Vec::new();
    let mut check_errors = Vec::new();
    let packages_to_check: Vec<(String, Package)> = lockfile.packages.into_iter().collect();

    // Setup client
    let client = PyPiClient::from_env(args.offline)
        .map_err(|e| eyre!("failed to create PyPI client: {}", e))?;

    // Setup local index if needed
    let local_index = if let Some(path) = &args.index {
        Some(Arc::new(
            load_index_from_path(path).map_err(|e| eyre!("{}", e))?,
        ))
    } else {
        None
    };

    // Check versions in parallel
    let constraints_ref = &constraints;

    // Use stream buffering for parallel requests
    let results = stream::iter(packages_to_check)
        .map(|(name, pkg)| {
            let client = client.clone();
            let local_index = local_index.clone();
            async move {
                let all_versions_res = if let Some(index) = local_index {
                    index.all(&name).await
                } else {
                    let pypi = PyPiIndex::new(client);
                    pypi.all(&name).await
                };
                (name, pkg, all_versions_res)
            }
        })
        .buffer_unordered(10) // Concurrency limit
        .collect::<Vec<_>>()
        .await;

    for (name, pkg, res) in results {
        match res {
            Ok(all_versions) => {
                let latest = all_versions
                    .iter()
                    .max_by(|a, b| compare_versions(&a.version, &b.version))
                    .map(|p| p.version.clone());

                if let Some(latest_version) = latest {
                    let wanted_version = if let Some(req) = constraints_ref.get(&name) {
                        all_versions
                            .iter()
                            .filter(|p| req.is_satisfied_by(&p.version))
                            .max_by(|a, b| compare_versions(&a.version, &b.version)) // Prefer newest matching
                            .map(|p| p.version.clone())
                            .unwrap_or_else(|| latest_version.clone()) // If constraints exclude everything (unlikely if installed), fallback to latest
                    } else {
                        latest_version.clone()
                    };

                    let is_outdated = latest_version != pkg.version;
                    let is_wanted_outdated = wanted_version != pkg.version;

                    if is_outdated || is_wanted_outdated {
                        let update_type = classify_update(&pkg.version, &latest_version);

                        outdated_packages.push(json!({
                            "package": name,
                            "current": pkg.version,
                            "wanted": wanted_version,
                            "latest": latest_version,
                            "type": update_type,
                        }));
                    }
                }
            }
            Err(e) => {
                collector.warning(format!("failed to check {}: {}", name, e));
                check_errors.push(json!({"package": name, "error": e.to_string()}));
            }
        }
    }

    collector.event(EventType::ResolveComplete);

    // Format output (Table for Summary)
    let mut summary = String::new();
    if outdated_packages.is_empty() {
        summary.push_str("All packages are up to date.");
    } else {
        use std::fmt::Write;
        // Header
        let _ = writeln!(
            summary,
            "{: <20} {: <10} {: <10} {: <10} {: <10}",
            "Package", "Current", "Wanted", "Latest", "Type"
        );

        for item in &outdated_packages {
            let name = item["package"].as_str().unwrap_or("?");
            let current = item["current"].as_str().unwrap_or("?");
            let wanted = item["wanted"].as_str().unwrap_or("?");
            let latest = item["latest"].as_str().unwrap_or("?");
            let type_str = item["type"].as_str().unwrap_or("?");

            let color_style = match type_str {
                "major" => Style::new().red(),
                "minor" => Style::new().yellow(),
                "patch" => Style::new().green(),
                _ => Style::new().dim(),
            };

            let _ = writeln!(
                summary,
                "{: <20} {: <10} {: <10} {: <10} {: <10}",
                name,
                current,
                wanted,
                latest,
                color_style.apply_to(type_str)
            );
        }
    }

    Ok(RenderDetail::with_json(
        summary,
        json!({
            "outdated": outdated_packages,
            "errors": check_errors
        }),
    ))
}

fn classify_update(current: &str, latest: &str) -> &'static str {
    let cur = parse_version_relaxed(current);
    let lat = parse_version_relaxed(latest);

    match (cur, lat) {
        (Some(c), Some(l)) => {
            if l.major > c.major {
                "major"
            } else if l.minor > c.minor {
                "minor"
            } else if l.patch > c.patch {
                "patch"
            } else {
                "other"
            }
        }
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// pybun upgrade
// ---------------------------------------------------------------------------

async fn run_upgrade(args: &UpgradeArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
    let cwd =
        std::env::current_dir().map_err(|e| eyre!("failed to get current directory: {}", e))?;
    let lock_path = if args.lock.is_absolute() {
        args.lock.clone()
    } else {
        cwd.join(&args.lock)
    };

    if !lock_path.exists() {
        return Err(eyre!(
            "lockfile not found at {}. Run 'pybun install' first.",
            lock_path.display()
        ));
    }

    // Load project to get constraints
    let project = Project::discover(&cwd).map_err(|e| eyre!("failed to load project: {}", e))?;

    let dependencies = project.dependencies();
    if dependencies.is_empty() {
        return Ok(RenderDetail::with_json(
            "No dependencies to upgrade",
            json!({
                "upgraded": [],
                "dry_run": args.dry_run,
            }),
        ));
    }

    // Load current lockfile if exists (for partial updates and comparison)
    let current_lock = Lockfile::load_from_path(&lock_path).ok();

    // Prepare requirements
    let mut requirements: Vec<Requirement> = Vec::new();

    // Strategy:
    // 1. If args.packages is empty (upgrade all): Use project dependencies.
    // 2. If args.packages is distinct:
    //    - For packages in args.packages: Use project constraints (or Any).
    //    - For others found in lockfile: Pin to lockfile version (Exact).
    //    - For others NOT in lockfile (new deps?): Use project constraints.

    for dep_str in &dependencies {
        if let Ok(req) = dep_str.parse::<Requirement>() {
            let is_target = if args.packages.is_empty() {
                true // Upgrade everything
            } else {
                // Check if this requirement matches any targeted package
                args.packages
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(&req.name))
            };

            if is_target {
                requirements.push(req);
            } else {
                // Not targeted. Check if we should pin it.
                if let Some(lock) = &current_lock {
                    if let Some(pkg) = lock.packages.get(&req.name) {
                        // Pin to currently locked version
                        requirements.push(Requirement::exact(req.name.clone(), &pkg.version));
                    } else {
                        // Not locked yet, strict requirement
                        requirements.push(req);
                    }
                } else {
                    requirements.push(req);
                }
            }
        }
    }

    collector.event(EventType::ResolveStart);

    // Re-resolve dependencies
    let resolution = if let Some(index_path) = &args.index {
        let index = load_index_from_path(index_path)?;
        resolve(requirements.clone(), &index).await?
    } else {
        let pypi_client = PyPiClient::from_env(args.offline)
            .map_err(|e| eyre!("failed to create PyPI client: {}", e))?;
        let pypi_index = PyPiIndex::new(pypi_client);
        resolve(requirements.clone(), &pypi_index).await?
    };

    collector.event(EventType::ResolveComplete);

    let mut upgraded_packages: Vec<Value> = Vec::new();
    let platform_tags = current_platform_tags();

    // Use an empty lockfile if none exists for comparison base
    let base_lock =
        current_lock.unwrap_or_else(|| Lockfile::new(vec!["3.12".into()], vec!["any".into()]));

    // Build new lockfile
    let mut new_lock = Lockfile::new(
        base_lock.python_versions.clone(),
        base_lock.platforms.clone(),
    );

    for (pkg_name, pkg) in &resolution.packages {
        let selection = select_artifact_for_platform(pkg, &platform_tags);
        let wheel_name = selection.filename.clone();

        // Use real hash if available, otherwise placeholder
        let hash = selection
            .hash
            .clone()
            .unwrap_or_else(|| "sha256:placeholder".to_string());

        let new_pkg = Package {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            source: pkg
                .source
                .clone()
                .unwrap_or_else(|| PackageSource::Registry {
                    index: "https://pypi.org/simple".to_string(),
                    url: String::new(),
                }),
            wheel: wheel_name,
            hash,
            dependencies: pkg.dependencies.iter().map(|r| r.to_string()).collect(),
        };

        // Track upgrades
        let from_version = base_lock.packages.get(pkg_name).map(|p| p.version.clone());
        let is_change = match &from_version {
            Some(v) => *v != pkg.version,
            None => true, // New package
        };

        if is_change {
            upgraded_packages.push(json!({
                "package": pkg_name,
                "from": from_version,
                "to": pkg.version,
                "new": from_version.is_none()
            }));
        }

        new_lock.add_package(new_pkg);
    }

    // Also track removed packages (if any project dependency was removed/untracked)
    // Note: Since we start from project dependencies, packages no longer in project deps won't be resolved.
    for (name, pkg) in &base_lock.packages {
        if !new_lock.packages.contains_key(name) {
            upgraded_packages.push(json!({
                "package": name,
                "from": pkg.version.clone(),
                "to": null,
                "removed": true
            }));
        }
    }

    // Write lockfile unless dry-run
    if !args.dry_run {
        new_lock
            .save_to_path(&lock_path)
            .map_err(|e| eyre!("failed to save lockfile: {}", e))?;
    }

    // Generate Summary
    let mut summary = String::new();
    if upgraded_packages.is_empty() {
        summary.push_str("All packages are already up to date.");
    } else {
        use std::fmt::Write;
        if args.dry_run {
            writeln!(summary, "Changes (dry-run):")?;
        } else {
            writeln!(summary, "Upgraded packages:")?;
        }

        for item in &upgraded_packages {
            let name = item["package"].as_str().unwrap_or("?");
            let from = item["from"].as_str();
            let to = item["to"].as_str();

            if item.get("new").and_then(|v| v.as_bool()).unwrap_or(false) {
                writeln!(summary, "  + {} {}", name, to.unwrap_or("?"))?;
            } else if item
                .get("removed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                writeln!(summary, "  - {} {}", name, from.unwrap_or("?"))?;
            } else {
                writeln!(
                    summary,
                    "  {} {} -> {}",
                    name,
                    from.unwrap_or("?"),
                    to.unwrap_or("?")
                )?;
            }
        }
    }

    Ok(RenderDetail::with_json(
        summary.trim().to_string(),
        json!({
            "upgraded": upgraded_packages,
            "dry_run": args.dry_run,
            "lockfile": lock_path.display().to_string(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_shard_valid() {
        assert_eq!(parse_shard("1/2").unwrap(), (1, 2));
        assert_eq!(parse_shard("3/4").unwrap(), (3, 4));
        assert_eq!(parse_shard("1/1").unwrap(), (1, 1));
    }

    #[test]
    fn test_parse_shard_invalid() {
        assert!(parse_shard("invalid").is_err());
        assert!(parse_shard("1").is_err());
        assert!(parse_shard("a/b").is_err());
        assert!(parse_shard("0/2").is_err());
        assert!(parse_shard("3/2").is_err());
    }

    #[test]
    fn parse_package_spec_simple_name() {
        let (name, version) = parse_package_spec("cowsay");
        assert_eq!(name, "cowsay");
        assert_eq!(version, None);
    }

    #[test]
    fn parse_package_spec_exact_version() {
        let (name, version) = parse_package_spec("cowsay==6.1");
        assert_eq!(name, "cowsay");
        assert_eq!(version, Some("6.1".to_string()));
    }

    #[test]
    fn parse_package_spec_minimum_version() {
        let (name, version) = parse_package_spec("requests>=2.28.0");
        assert_eq!(name, "requests");
        assert_eq!(version, Some("2.28.0".to_string()));
    }

    #[test]
    fn parse_package_spec_maximum_version() {
        let (name, version) = parse_package_spec("numpy<2.0");
        assert_eq!(name, "numpy");
        assert_eq!(version, Some("2.0".to_string()));
    }

    #[test]
    fn parse_package_spec_compatible_version() {
        let (name, version) = parse_package_spec("flask~=2.0.0");
        assert_eq!(name, "flask");
        assert_eq!(version, Some("2.0.0".to_string()));
    }

    #[test]
    fn parse_package_spec_not_equal() {
        let (name, version) = parse_package_spec("django!=3.0");
        assert_eq!(name, "django");
        assert_eq!(version, Some("3.0".to_string()));
    }
}
