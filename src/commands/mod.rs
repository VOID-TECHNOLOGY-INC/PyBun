use crate::build::{BuildBackend, BuildCache};
use crate::cli::{
    Cli, Commands, DriftArgs, InitArgs, InitTemplate, LockArgs, McpCommands, OutdatedArgs,
    OutputFormat, ProgressMode, PythonCommands, SchemaArgs, SchemaCommands, SelfCommands,
    TelemetryCommands, UpgradeArgs,
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
    PackageIndex, Requirement, compare_versions, cp_tag_to_dotted_version, current_platform_tags,
    is_wheel_python_compatible, parse_wheel_tags, python_version_to_cp_tag, resolve,
    select_artifact_for_platform_with_cp,
};
use crate::sandbox;
use crate::sbom;
use crate::schema::{
    Diagnostic, DiagnosticLevel, Event, EventCollector, EventType, JsonEnvelope, Status,
};
use crate::self_update::apply_update_for_asset;
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

mod maintenance;
mod test;
mod tooling;

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
            let pre_error_count = collector.error_diagnostic_count();
            let result = install(args, &mut collector).await;
            match result {
                Ok(InstallOutcome {
                    summary,
                    packages,
                    lockfile,
                    verified,
                    artifacts,
                    workspace,
                    installed_count,
                }) => {
                    collector.event(EventType::InstallComplete);
                    let detail = json!({
                        "lockfile": lockfile.display().to_string(),
                        "packages": packages,
                        "verified": verified,
                        "artifacts": artifacts,
                        "workspace": workspace,
                        "installed_count": installed_count,
                    });
                    (
                        "install".to_string(),
                        RenderDetail::with_json(summary, detail),
                    )
                }
                Err(e) => {
                    // Only push a generic fallback error if install() did not already
                    // record an error-level diagnostic (e.g. resolve errors).
                    if collector.error_diagnostic_count() == pre_error_count {
                        collector.error_with_code(
                            "E_INSTALL_FAILED",
                            e.to_string(),
                            "Check --index/--require and network connectivity, then re-run `pybun install`. Use --format=json for full diagnostics.",
                        );
                    }
                    (
                        "install".to_string(),
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
        Commands::Add(args) => {
            let result = add_package(args);
            match result {
                Ok(AddOutcome {
                    summary,
                    packages,
                    added_deps,
                }) => {
                    // Chain install to ensure the environment is up-to-date
                    let names = packages
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    collector.info(format!("Installing dependencies including {}...", names));

                    let install_args = crate::cli::InstallArgs {
                        offline: args.offline,
                        system: false,
                        requirements: Vec::new(), // install from pyproject.toml
                        index: None,
                        lock: std::path::PathBuf::from("pybun.lockb"),
                        workspace: false,
                        member: None,
                        group: None,
                    };

                    let packages_json: Vec<serde_json::Value> = packages
                        .iter()
                        .map(|p| json!({ "name": p.name, "version": p.version }))
                        .collect();

                    let pre_error_count = collector.error_diagnostic_count();
                    match install(&install_args, &mut collector).await {
                        Ok(_) => (
                            "add".to_string(),
                            RenderDetail::with_json(
                                format!("{} and installed dependencies.", summary),
                                json!({
                                    "package": packages.first().map(|p| p.name.clone()),
                                    "version": packages.first().and_then(|p| p.version.clone()),
                                    "packages": packages_json,
                                    "added_dependencies": added_deps,
                                    "installed": true,
                                }),
                            ),
                        ),
                        Err(e) => {
                            let err_msg = format!(
                                "Added {} to pyproject.toml but failed to install: {}",
                                names, e
                            );
                            // Only push a generic fallback error if install() did not
                            // already record an error-level diagnostic (e.g. resolve errors).
                            if collector.error_diagnostic_count() == pre_error_count {
                                collector.error_with_code(
                                    "E_ADD_INSTALL_FAILED",
                                    err_msg.clone(),
                                    "pyproject.toml was updated; fix the underlying issue (see other diagnostics) and run `pybun install` to finish installing dependencies.",
                                );
                            }
                            (
                                "add".to_string(),
                                RenderDetail::error(
                                    err_msg,
                                    json!({
                                        "packages": packages_json,
                                        "error": e.to_string(),
                                        "installed": false,
                                    }),
                                ),
                            )
                        }
                    }
                }
                Err(e) => {
                    collector.error_with_code(
                        "E_ADD_FAILED",
                        e.to_string(),
                        "Verify the package name/version and pyproject.toml, then retry `pybun add <package>`.",
                    );
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
                Ok(RemoveOutcome { summary, packages }) => {
                    let packages_json: Vec<serde_json::Value> = packages
                        .iter()
                        .map(|p| json!({ "name": p.name, "removed": p.removed }))
                        .collect();
                    (
                        "remove".to_string(),
                        RenderDetail::with_json(
                            summary,
                            json!({
                                "package": packages.first().map(|p| p.name.clone()),
                                "removed": packages.first().map(|p| p.removed),
                                "packages": packages_json,
                            }),
                        ),
                    )
                }
                Err(e) => {
                    collector.error_with_code(
                        "E_REMOVE_FAILED",
                        e.to_string(),
                        "Verify the package is listed in pyproject.toml, then retry `pybun remove <package>`.",
                    );
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
            let pre_error_count = collector.error_diagnostic_count();
            let result = lock_dependencies(args, &mut collector).await;
            match result {
                Ok(LockOutcome {
                    summary,
                    lockfile,
                    packages,
                    verified,
                    artifacts,
                }) => {
                    collector.event(EventType::InstallComplete);
                    (
                        "lock".to_string(),
                        RenderDetail::with_json(
                            summary,
                            json!({
                                "lockfile": lockfile.display().to_string(),
                                "packages": packages,
                                "verified": verified,
                                "artifacts": artifacts,
                            }),
                        ),
                    )
                }
                Err(e) => {
                    // Only push a generic fallback error if lock_dependencies did not
                    // already record an error-level diagnostic (e.g. resolve errors).
                    if collector.error_diagnostic_count() == pre_error_count {
                        collector.error_with_code(
                            "E_LOCK_FAILED",
                            e.to_string(),
                            "Check --index/--require and network connectivity, then re-run `pybun lock`.",
                        );
                    }
                    (
                        "lock".to_string(),
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
                    profile,
                }) => {
                    collector.event(EventType::ScriptEnd);

                    // Enrich diagnostics with structured traceback when the script failed.
                    // If the script exited nonzero without a parseable Python traceback on
                    // stderr (e.g. a plain `sys.exit(N)`), still emit a diagnostic so
                    // `diagnostics[]` is never empty on a failed run (Issue #266) — callers
                    // should not have to fall back to inspecting `detail.exit_code` alone.
                    if exit_code != 0 {
                        match stderr.as_deref().and_then(crate::traceback::parse) {
                            Some(tb) => {
                                let mut diag = Diagnostic::error(tb.message.clone());
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
                                if let Some(action) = &tb.next_action {
                                    diag.suggestion = Some(format!(
                                        "Run: pybun add {}",
                                        action
                                            .args
                                            .get("package")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                    ));
                                }
                                diag.next_action = tb.next_action.map(|a| {
                                    json!({
                                        "tool": a.tool,
                                        "args": a.args,
                                    })
                                });
                                collector.diagnostic(diag);
                            }
                            None => {
                                collector.error_with_code(
                                    "E_SCRIPT_EXIT_NONZERO",
                                    format!(
                                        "Script exited with a nonzero status (exit_code={exit_code})"
                                    ),
                                    "Check detail.exit_code and the script's stdout/stderr for the cause.",
                                );
                            }
                        }
                    }

                    let sandbox_detail = sandbox.as_ref().map(|s| {
                        json!({
                            "enabled": s.enabled,
                            "allow_network": s.allow_network,
                            "allow_read": s.allow_read,
                            "allow_write": s.allow_write,
                            "allow_env": s.allow_env,
                            "default_deny_write": s.default_deny_write,
                            "enforcement": s.enforcement,
                            "audit": s.audit,
                            "resource_limits": s.resource_limits,
                            "timed_out": s.timed_out,
                        })
                    });
                    let profile_detail = json!({
                        "name": profile.name,
                        "optimization_level": profile.optimization_level,
                        "lazy_imports": profile.lazy_imports,
                        "lazy_imports_injected": profile.lazy_imports_injected,
                        "timing": profile.timing,
                    });
                    let detail = RenderDetail::with_json(
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
                            "profile": profile_detail,
                        }),
                    )
                    .with_process_exit_code(exit_code);
                    ("run".to_string(), detail)
                }
                Err(e) => {
                    collector.error_with_code(
                        "E_RUN_FAILED",
                        e.to_string(),
                        "Check the script path and any PEP 723 inline metadata, then re-run `pybun run <script>`.",
                    );
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
                    )
                    .with_process_exit_code(exit_code),
                ),
                Err(e) => {
                    collector.error_with_code(
                        "E_X_FAILED",
                        e.to_string(),
                        "Verify the tool/package name and that it provides a console entry point, then retry `pybun x <tool>`.",
                    );
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
            let result = test::run_tests(args, &mut collector);
            match result {
                Ok(detail) => ("test".to_string(), detail),
                Err(e) => {
                    collector.error_with_code(
                        "E_TEST_RUN_FAILED",
                        e.to_string(),
                        "Check that the test runner and target paths are valid, then re-run `pybun test`.",
                    );
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
        Commands::Build(args) => {
            let pre_error_count = collector.error_diagnostic_count();
            let result = run_build(args, &mut collector, cli.format);
            let detail = match result {
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
                    // Only push a generic fallback error if run_build did not already
                    // record an error-level diagnostic (e.g. E_BUILD_MISSING_BUILD_PKG).
                    if collector.error_diagnostic_count() == pre_error_count {
                        collector.error_with_code(
                            "E_BUILD_FAILED",
                            e.to_string(),
                            "Ensure the `build` package is installed (`pybun add build --dev`) and pyproject.toml is valid, then re-run `pybun build`.",
                        );
                    }
                    RenderDetail::error(
                        e.to_string(),
                        json!({
                            "error": e.to_string(),
                        }),
                    )
                }
            };
            ("build".to_string(), detail)
        }
        Commands::Doctor(args) => {
            collector.info("Running environment diagnostics");
            let detail = maintenance::run_doctor(args, &mut collector);
            ("doctor".to_string(), detail)
        }
        Commands::Mcp(cmd) => match cmd {
            McpCommands::Serve(args) => {
                if args.stdio {
                    // Run MCP server in stdio mode - this blocks until shutdown
                    if let Err(e) = crate::mcp::run_stdio_server().await {
                        collector.error_with_code(
                            "E_MCP_SERVE_FAILED",
                            e.to_string(),
                            "Ensure stdin/stdout are not redirected elsewhere and retry `pybun mcp serve --stdio`.",
                        );
                        (
                            "mcp serve".to_string(),
                            RenderDetail::error(e.to_string(), json!({"error": e.to_string()})),
                        )
                    } else {
                        // stdio mode: stdout is the MCP protocol channel.
                        // Do not print anything after the session ends to
                        // avoid corrupting the stream with non-JSON text.
                        ("mcp serve".to_string(), RenderDetail::silent())
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
            let result = maintenance::run_gc(args, &mut collector);
            match result {
                Ok(detail) => ("gc".to_string(), detail),
                Err(e) => {
                    collector.error_with_code(
                        "E_GC_FAILED",
                        e.to_string(),
                        "Check cache directory permissions (see $PYBUN_HOME or the default cache dir), then re-run `pybun gc`.",
                    );
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
                    // Determine subcommand name for error reporting
                    let subcmd = match cmd {
                        PythonCommands::List(_) => "list",
                        PythonCommands::Install(_) => "install",
                        PythonCommands::Remove(_) => "remove",
                        PythonCommands::Which(_) => "which",
                    };
                    collector.error_with_code(
                        format!("E_PYTHON_{}_FAILED", subcmd.to_uppercase()),
                        e.to_string(),
                        "Run `pybun doctor` to check Python discovery, then retry `pybun python <subcommand>`.",
                    );
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
            let result = tooling::run_module_find(args, &mut collector);
            collector.event(EventType::ModuleFindComplete);
            match result {
                Ok(detail) => ("module-find".to_string(), detail),
                Err(e) => {
                    collector.error_with_code(
                        "E_MODULE_FIND_FAILED",
                        e.to_string(),
                        "Verify the module name and that the target environment is set up, then re-run `pybun module-find`.",
                    );
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
            let result = tooling::run_lazy_import(args, &mut collector);
            collector.event(EventType::LazyImportComplete);
            match result {
                Ok(detail) => ("lazy-import".to_string(), detail),
                Err(e) => {
                    collector.error_with_code(
                        "E_LAZY_IMPORT_FAILED",
                        e.to_string(),
                        "Verify the target script/module path, then re-run `pybun lazy-import`.",
                    );
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
            let result = tooling::run_watch(args, &mut collector);
            match result {
                Ok(detail) => ("watch".to_string(), detail),
                Err(e) => {
                    collector.error_with_code(
                        "E_WATCH_FAILED",
                        e.to_string(),
                        "Verify the watch target and include/exclude patterns, then re-run `pybun watch`.",
                    );
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
            let result = tooling::run_profile(args, &mut collector);
            match result {
                Ok(detail) => ("profile".to_string(), detail),
                Err(e) => {
                    collector.error_with_code(
                        "E_PROFILE_FAILED",
                        e.to_string(),
                        "Check the profile name and the [tool.pybun.profiles] section of pyproject.toml, then re-run `pybun profile`.",
                    );
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
        Commands::Schema(SchemaArgs { command }) => match command {
            None | Some(SchemaCommands::Print(_)) => {
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
            Some(SchemaCommands::Check(args)) => {
                let detail = run_schema_check(args, &mut collector);
                ("schema check".to_string(), detail)
            }
        },
        Commands::Telemetry(cmd) => {
            let result = run_telemetry(cmd);
            match result {
                Ok(detail) => ("telemetry".to_string(), detail),
                Err(e) => {
                    collector.error_with_code(
                        "E_TELEMETRY_FAILED",
                        e.to_string(),
                        "Check $PYBUN_HOME permissions and the telemetry configuration, then re-run `pybun telemetry`.",
                    );
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
            let pre_error_count = collector.error_diagnostic_count();
            let result = init_project(args, &mut collector);
            match result {
                Ok(detail) => ("init".to_string(), detail),
                Err(e) => {
                    // Only push a generic fallback error if init_project did not already
                    // record an error-level diagnostic (e.g. E_INIT_NOT_INTERACTIVE).
                    if collector.error_diagnostic_count() == pre_error_count {
                        collector.error_with_code(
                            "E_INIT_FAILED",
                            e.to_string(),
                            "Check directory permissions and that pyproject.toml does not already exist, then re-run `pybun init`.",
                        );
                    }
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
            let pre_error_count = collector.error_diagnostic_count();
            let result = run_outdated(args, &mut collector).await;
            match result {
                Ok(detail) => ("outdated".to_string(), detail),
                Err(e) => {
                    // Only push a generic fallback error if run_outdated did not already
                    // record an error-level diagnostic (e.g. E_LOCKFILE_NOT_FOUND).
                    if collector.error_diagnostic_count() == pre_error_count {
                        collector.error_with_code(
                            "E_OUTDATED_FAILED",
                            e.to_string(),
                            "Run `pybun install` to generate pybun.lockb, then re-run `pybun outdated`.",
                        );
                    }
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
            let pre_error_count = collector.error_diagnostic_count();
            let result = run_upgrade(args, &mut collector).await;
            match result {
                Ok(detail) => ("upgrade".to_string(), detail),
                Err(e) => {
                    // Only push a generic fallback error if run_upgrade did not already
                    // record an error-level diagnostic (e.g. E_LOCKFILE_NOT_FOUND).
                    if collector.error_diagnostic_count() == pre_error_count {
                        collector.error_with_code(
                            "E_UPGRADE_FAILED",
                            e.to_string(),
                            "Run `pybun install` to generate the lockfile, then re-run `pybun upgrade`.",
                        );
                    }
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
        Commands::Drift(args) => {
            let result = run_drift(args, &mut collector);
            match result {
                Ok(detail) => ("drift".to_string(), detail),
                Err(e) => {
                    if collector.error_diagnostic_count() == 0 {
                        collector.error_with_code(
                            "E_DRIFT_FAILED",
                            e.to_string(),
                            "Ensure a pyproject.toml exists and re-run `pybun drift`.",
                        );
                    }
                    (
                        "drift".to_string(),
                        RenderDetail::error(e.to_string(), json!({ "error": e.to_string() })),
                    )
                }
            }
        }
        Commands::Audit(args) => {
            collector.info("Scanning installed packages for known vulnerabilities");
            let detail = maintenance::run_audit(args, &mut collector).await;
            ("audit".to_string(), detail)
        }
    };

    // Record command end
    collector.event(EventType::CommandEnd);

    let duration = collector.elapsed();
    let (events, diagnostics, trace_id) = collector.into_parts();

    let is_error = detail.is_error;
    let process_exit_code = detail.process_exit_code;
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
    if let Some(output) = rendered {
        println!("{output}");
    }

    // Flush stdout before any std::process::exit call. std::process::exit
    // skips destructors, so a BufWriter around stdout (common on Windows)
    // would otherwise silently discard buffered output.
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // `is_error` and `process_exit_code` are mutually exclusive: the Err
    // arm of every command sets is_error via RenderDetail::error() which
    // leaves process_exit_code = None, while the Ok arm uses with_json()
    // and may call with_process_exit_code(). is_error always takes priority.
    if is_error {
        std::process::exit(1);
    }

    // Propagate the child process exit code (e.g. from `pybun run`).
    if let Some(code) = process_exit_code
        && code != 0
    {
        std::process::exit(code);
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
) -> Option<String> {
    if detail.silent {
        return None;
    }
    Some(match format {
        OutputFormat::Text => {
            if detail.raw_text {
                detail.text
            } else {
                format!("pybun {command}: {}", detail.text)
            }
        }
        OutputFormat::Json => {
            // child_failed is only set on the Ok arm; is_error covers the Err arm (see execute()).
            let child_failed = detail.process_exit_code.is_some_and(|c| c != 0);
            let status = if detail.is_error || child_failed {
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
    })
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

fn run_schema_check(
    args: &crate::cli::SchemaCheckArgs,
    collector: &mut EventCollector,
) -> RenderDetail {
    let embedded = crate::schema::schema_v1_json();
    let embedded_version = schema_version_from(&embedded);
    let expected_version = crate::schema::SCHEMA_VERSION.to_string();

    let mut issues = Vec::new();
    if embedded_version.as_deref() != Some(expected_version.as_str()) {
        let message = format!(
            "embedded schema version mismatch (found {:?}, expected {})",
            embedded_version, expected_version
        );
        collector.error_with_code(
            "E_SCHEMA_VERSION_MISMATCH",
            message.clone(),
            "Update crate::schema::SCHEMA_VERSION or schema_v1_json() so the embedded schema version matches, then rebuild.",
        );
        issues.push(message);
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
                        let message = "schema file differs from embedded definition".to_string();
                        collector.error_with_code(
                            "E_SCHEMA_FILE_MISMATCH",
                            message.clone(),
                            "Regenerate the schema file with `pybun schema print --format=json` to match the embedded schema, or update the embedded schema to match the file.",
                        );
                        issues.push(message);
                    } else {
                        mismatch = Some(false);
                    }
                }
                Err(e) => {
                    let message = format!("failed to parse schema file: {}", e);
                    collector.error_with_code(
                        "E_SCHEMA_FILE_PARSE",
                        message.clone(),
                        "Fix the JSON syntax in the schema file, or regenerate it with `pybun schema print --format=json`.",
                    );
                    file_error = Some(message);
                    issues.push("schema file is not valid JSON".to_string());
                }
            },
            Err(e) => {
                let message = format!("failed to read schema file: {}", e);
                collector.error_with_code(
                    "E_SCHEMA_FILE_READ",
                    message.clone(),
                    "Check that the schema file path exists and is readable, then re-run `pybun schema check`.",
                );
                file_error = Some(message);
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

/// Resolve dependency specifiers scoped by `--member` (optionally narrowed by
/// `--group`) or `--group` alone, against an already-discovered workspace (or
/// the single `project` when no workspace exists). Returns `Ok(None)` when
/// neither selector is set, so callers can fall through to their own default
/// behavior (workspace merge, plain project dependencies, etc).
///
/// This is the shared precedence core behind `pybun install`, `pybun
/// outdated`, and `pybun upgrade`'s `--member`/`--group` selectors.
fn select_member_or_group_dependencies(
    project: &Project,
    workspace: &Option<Workspace>,
    member: Option<&str>,
    group: Option<&str>,
    collector: &mut EventCollector,
) -> Result<Option<(Vec<String>, Option<Value>)>> {
    if let Some(member_name) = member {
        let ws = workspace.as_ref().ok_or_else(|| {
            eyre!("--member requires a workspace; no [tool.pybun.workspace] configuration found")
        })?;
        let member_project = ws.member_by_name(member_name).ok_or_else(|| {
            eyre!(
                "workspace member '{member_name}' not found (available: {})",
                ws.member_names().join(", ")
            )
        })?;
        let deps = match group {
            Some(group_name) => member_project.group_dependencies(group_name),
            None => member_project.dependencies(),
        };
        collector.info(format!(
            "Selected workspace member '{}' at {} ({} dependencies{})",
            member_name,
            member_project.root().display(),
            deps.len(),
            group.map(|g| format!(", group '{g}'")).unwrap_or_default(),
        ));
        return Ok(Some((
            deps,
            Some(json!({
                "scope": "member",
                "root": ws.root.root().display().to_string(),
                "selected_members": [member_name],
                "group": group,
            })),
        )));
    }

    if let Some(group_name) = group {
        if let Some(ws) = workspace {
            let deps = ws.dependencies_for_group(group_name);
            collector.info(format!(
                "Selected dependency group '{}' across workspace at {} ({} dependencies)",
                group_name,
                ws.root.root().display(),
                deps.len(),
            ));
            return Ok(Some((
                deps,
                Some(json!({
                    "scope": "group",
                    "root": ws.root.root().display().to_string(),
                    "selected_members": ws.member_names(),
                    "group": group_name,
                })),
            )));
        }

        let deps = project.group_dependencies(group_name);
        collector.info(format!(
            "Selected dependency group '{}' ({} dependencies)",
            group_name,
            deps.len(),
        ));
        return Ok(Some((
            deps,
            Some(json!({
                "scope": "group",
                "selected_members": Value::Null,
                "group": group_name,
            })),
        )));
    }

    Ok(None)
}

/// Resolve which dependency specifiers to install based on workspace
/// selectors (`--workspace`/`--member`/`--group`). Returns the dependency
/// strings plus an optional JSON blob describing the selection scope for
/// workspace-aware JSON output (`None` for plain single-project installs).
///
/// Selector precedence: `--member` (optionally narrowed by `--group`) takes
/// priority, then `--group` alone (workspace-wide or project-local), then
/// `--workspace`/auto-detected workspace merging, finally falling back to the
/// discovered project's own `[project.dependencies]`.
fn select_install_dependencies(
    project: &Project,
    working_dir: &Path,
    args: &crate::cli::InstallArgs,
    collector: &mut EventCollector,
) -> Result<(Vec<String>, Option<Value>)> {
    let workspace = if args.workspace {
        Workspace::discover_root(working_dir).map_err(|e| eyre!(e))?
    } else {
        Workspace::discover(working_dir).map_err(|e| eyre!(e))?
    };

    if args.workspace && workspace.is_none() {
        return Err(eyre!(
            "--workspace specified but no [tool.pybun.workspace] configuration found"
        ));
    }

    if let Some((deps, detail)) = select_member_or_group_dependencies(
        project,
        &workspace,
        args.member.as_deref(),
        args.group.as_deref(),
        collector,
    )? {
        return Ok((deps, detail));
    }

    if let Some(ws) = &workspace {
        let merged = ws.merged_dependencies();
        collector.info(format!(
            "Workspace detected at {} ({} members); merged {} dependencies",
            ws.root.root().display(),
            ws.members.len(),
            merged.len()
        ));
        return Ok((
            merged,
            Some(json!({
                "scope": "workspace",
                "root": ws.root.root().display().to_string(),
                "selected_members": ws.member_names(),
                "group": Value::Null,
            })),
        ));
    }

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
    Ok((deps, None))
}

/// Resolve dependency specifiers for `pybun outdated`/`pybun upgrade`,
/// honoring `--member`/`--group` selectors against an auto-detected workspace
/// (these commands have no `--workspace` merge mode of their own). Falls back
/// to the discovered project's own `[project.dependencies]` when neither
/// selector is set.
fn select_scoped_dependencies(
    project: &Project,
    working_dir: &Path,
    member: Option<&str>,
    group: Option<&str>,
    collector: &mut EventCollector,
) -> Result<(Vec<String>, Option<Value>)> {
    let workspace = Workspace::discover(working_dir).map_err(|e| eyre!(e))?;

    if let Some((deps, detail)) =
        select_member_or_group_dependencies(project, &workspace, member, group, collector)?
    {
        return Ok((deps, detail));
    }

    Ok((project.dependencies(), None))
}

/// Emit a `W_EXTRAS_IGNORED` warning for every requirement that carries PEP 508
/// extras (e.g. `typer[all]`). PyBun does not yet resolve extras' dependencies
/// (full support is tracked as PR-A5 / Issue #285) — installing such a
/// requirement silently drops the extra's dependencies, so this makes the
/// degradation visible in both `--format=json` diagnostics and human-readable
/// CLI output instead of failing loudly (the old, since-fixed 404 behavior
/// from Issue #93) or succeeding silently with the wrong result (Issue #285).
fn warn_on_ignored_extras(requirements: &[Requirement], collector: &mut EventCollector) {
    for req in requirements {
        if req.extras.is_empty() {
            continue;
        }
        let extras_list = req.extras.join(", ");
        let message = format!(
            "extras ignored for '{}': pybun does not yet resolve PEP 508 extras, so only the base package will be installed (dropped: [{}])",
            req.name, extras_list
        );
        eprintln!("warning: {}", message);
        collector.diagnostic(
            Diagnostic::warning(message)
                .with_code("W_EXTRAS_IGNORED")
                .with_suggestion(format!(
                    "Full extras support is tracked in Issue #285 / PR-A5. Install '{}' extra dependencies manually if you need them.",
                    req.name
                ))
                .with_context(json!({
                    "package": req.name,
                    "extras": req.extras,
                })),
        );
    }
}

pub(crate) async fn install(
    args: &crate::cli::InstallArgs,
    collector: &mut EventCollector,
) -> Result<InstallOutcome> {
    // Gather requirements: either from --require flags or from pyproject.toml
    let (requirements, workspace_detail): (Vec<Requirement>, Option<Value>) =
        if !args.requirements.is_empty() {
            // CLI --require flags take precedence
            (args.requirements.clone(), None)
        } else {
            // Try to load from pyproject.toml
            let working_dir = std::env::current_dir()?;
            let project = Project::discover(&working_dir).map_err(|_| {
                eyre!(
                    "no requirements provided and no pyproject.toml found. \
                     Use --require or create a pyproject.toml with [project.dependencies]"
                )
            })?;

            let (deps, workspace_detail) =
                select_install_dependencies(&project, &working_dir, args, collector)?;

            let requirements = deps
                .into_iter()
                .map(|d| {
                    d.parse::<Requirement>()
                        .unwrap_or_else(|_| Requirement::any(d.trim()))
                })
                .collect();

            (requirements, workspace_detail)
        };

    warn_on_ignored_extras(&requirements, collector);

    // If no requirements (empty pyproject dependencies), create empty lockfile
    if requirements.is_empty() {
        let lock = Lockfile::new(vec!["3.11".into()], vec!["unknown".into()]);
        lock.save_to_path(&args.lock)?;
        return Ok(InstallOutcome {
            summary: format!("no dependencies to install -> {}", args.lock.display()),
            packages: vec![],
            lockfile: args.lock.clone(),
            verified: true,
            artifacts: Vec::new(),
            workspace: workspace_detail.clone(),
            installed_count: 0,
        });
    }

    let source_index_url: String;
    let offline = args.offline;
    let resolution = if let Some(index_path) = args.index.clone() {
        source_index_url = index_path.display().to_string();
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
        source_index_url = client.index_url();
        collector.info(format!(
            "Using PyPI index {} (offline: {})",
            source_index_url, offline
        ));
        let index = PyPiIndex::new(client);
        let resolve_result = resolve(requirements.clone(), &index).await;
        for notice in index.take_stale_cache_notices() {
            collector.warning(notice);
        }
        match resolve_result {
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

    // Detect the CPython tag of the actual install target (PYBUN_ENV / PYBUN_PYTHON /
    // project venv / system Python) *before* selecting wheels, so artifact selection
    // matches the Python interpreter packages will actually be installed into.
    // Selecting wheels against whatever `python3`/`python` happens to resolve on PATH
    // (the previous behavior) can silently pick wheels for the wrong CPython ABI
    // (Issue #291). This is read-only detection only — creating a project-local venv
    // (and the associated system-Python safe-install-target guard) is deferred to the
    // later "Install wheels" step below, so a resolve-only or failed install doesn't
    // have the side effect of mutating the filesystem.
    let working_dir = std::env::current_dir()?;
    let target_env_probe = crate::env::find_python_env(&working_dir)?;

    // PYBUN_FORCE_CP_TAG lets tests (and users) pin the CPython tag deterministically,
    // bypassing interpreter detection entirely.
    let active_cp_tag = std::env::var("PYBUN_FORCE_CP_TAG")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            get_python_version(&target_env_probe.python_path)
                .ok()
                .and_then(|v| python_version_to_cp_tag(&v))
        })
        .unwrap_or_else(|| "cp311".to_string());

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
    let mut verified_artifacts = Vec::new();
    for pkg in resolution.packages.values() {
        let selection = select_artifact_for_platform_with_cp(pkg, &platform_tags, &active_cp_tag);
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
        let (verified_hash, artifact) =
            ensure_selection_is_verifiable(pkg, &selection, collector, &source_index_url)?;
        verified_artifacts.push(artifact);
        lock.add_package(Package {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            source: registry_source_for_index(&source_index_url),
            wheel: selection.filename,
            hash: verified_hash,
            dependencies: pkg.dependencies.iter().map(ToString::to_string).collect(),
        });
    }
    lock.save_to_path(&args.lock)?;

    // Download artifacts in parallel.
    // Respect PYBUN_PYPI_CACHE_DIR when present so tests and callers can
    // isolate both index metadata and downloaded wheel artifacts together.
    let cache_dir = if let Ok(dir) = std::env::var("PYBUN_PYPI_CACHE_DIR") {
        PathBuf::from(dir).join("artifacts")
    } else {
        dirs::cache_dir()
            .ok_or_else(|| eyre!("failed to determine cache directory"))?
            .join("pybun")
            .join("artifacts")
    };

    collector.info(format!("Downloading artifacts to {}", cache_dir.display()));

    let mut download_items = Vec::new();
    let mut sdist_only_packages = Vec::new();
    for pkg in resolution.packages.values() {
        let selection = select_artifact_for_platform_with_cp(pkg, &platform_tags, &active_cp_tag);
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
        collector.error_with_code(
            "E_INSTALL_SDIST_ONLY",
            message.clone(),
            "Source builds are not yet supported; choose packages/versions with prebuilt wheels for your platform, or use a different index.",
        );
        return Err(eyre!(message));
    }

    collector.event_with(EventType::DownloadStart, |event| {
        event.message = Some(format!("Downloading {} artifacts", download_items.len()));
        event.progress = Some(50);
    });

    let mut outcome = InstallOutcome {
        summary: format!(
            "resolved {} packages -> {}",
            lock.packages.len(),
            args.lock.display()
        ),
        packages: lock.packages.keys().cloned().collect(),
        lockfile: args.lock.clone(),
        verified: true,
        artifacts: verified_artifacts,
        workspace: workspace_detail,
        installed_count: 0,
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

        // Install wheels. Re-resolve the target environment now that we know there is
        // something to install; this is where venv creation / the system-Python guard
        // actually mutates the filesystem (deferred from the cp-tag detection above so
        // a resolve-only or failed install has no such side effect).
        let mut env = crate::env::find_python_env(&working_dir)?;

        if matches!(env.source, crate::env::EnvSource::System) {
            if args.system {
                if let Some(marker) = crate::env::externally_managed_marker(&env.python_path) {
                    let message = format!(
                        "refusing to install into externally-managed system Python (marker: {})",
                        marker.display()
                    );
                    collector.error_with_code(
                        "E_INSTALL_EXTERNALLY_MANAGED",
                        message.clone(),
                        "This interpreter is marked externally-managed (PEP 668). Create a virtual environment (e.g. `python3 -m venv .venv`) and re-run, or install with a non-managed interpreter.",
                    );
                    return Err(eyre!(message));
                }

                let warning =
                    "warning: PyBun is installing into system Python (--system was specified).";
                eprintln!("{}", warning);
                collector.warning(warning.to_string());
            } else {
                collector.info(
                    "No virtual environment found; creating project-local environment at .pybun/venv"
                        .to_string(),
                );
                env = crate::env::create_project_venv(&working_dir)?;
            }
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
                outcome.installed_count += 1;
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
pub(crate) struct InstallOutcome {
    pub(crate) summary: String,
    pub(crate) packages: Vec<String>,
    pub(crate) lockfile: PathBuf,
    pub(crate) verified: bool,
    pub(crate) artifacts: Vec<Value>,
    /// Workspace selection details (scope, selected members, group), present
    /// only when dependencies were gathered from a workspace-aware source.
    pub(crate) workspace: Option<Value>,
    /// Number of wheels actually downloaded and installed into a site-packages
    /// directory during this call. This is distinct from `packages.len()`,
    /// which counts *resolved* packages regardless of whether any wheel was
    /// actually fetched and installed (e.g. when no download URL is available
    /// from the index, or when there was nothing new to install). Callers
    /// (including the MCP `pybun_install` tool) must not claim packages were
    /// "installed" unless this count is greater than zero.
    pub(crate) installed_count: usize,
}

#[derive(Debug)]
struct LockOutcome {
    summary: String,
    lockfile: PathBuf,
    packages: Vec<String>,
    verified: bool,
    artifacts: Vec<Value>,
}

fn is_missing_sha256(hash: Option<&str>) -> bool {
    match hash {
        Some(value) => crate::security::is_placeholder_hash(value),
        None => true,
    }
}

fn registry_source_for_index(index_url: &str) -> PackageSource {
    PackageSource::Registry {
        index: "pypi".into(),
        url: index_url.to_string(),
    }
}

fn verification_artifact_value(
    pkg: &crate::resolver::ResolvedPackage,
    selection: &crate::resolver::ArtifactSelection,
    index_url: &str,
    verified_hash: &str,
) -> Value {
    json!({
        "package": pkg.name,
        "version": pkg.version,
        "sha256": verified_hash,
        "index_url": index_url,
        "artifact_url": selection.url,
        "platform_tag": selection.matched_platform,
        "filename": selection.filename,
        "from_source": selection.from_source,
    })
}

fn missing_hash_diagnostic(
    pkg: &crate::resolver::ResolvedPackage,
    selection: &crate::resolver::ArtifactSelection,
    index_url: &str,
) -> Diagnostic {
    Diagnostic {
        level: crate::schema::DiagnosticLevel::Error,
        code: Some("E_VERIFY_MISSING_HASH".to_string()),
        message: format!(
            "selected artifact for {} {} ({}) is missing sha256 verification metadata",
            pkg.name, pkg.version, selection.filename
        ),
        file: None,
        line: None,
        suggestion: Some(
            "use an index that provides sha256 digests, then rerun install/lock/upgrade"
                .to_string(),
        ),
        context: Some(json!({
            "package": pkg.name,
            "version": pkg.version,
            "filename": selection.filename,
            "artifact_url": selection.url,
            "index_url": index_url,
            "platform_tag": selection.matched_platform,
            "from_source": selection.from_source,
        })),
        exception_type: None,
        location: None,
        next_action: None,
        fix_candidates: None,
    }
}

fn ensure_selection_is_verifiable(
    pkg: &crate::resolver::ResolvedPackage,
    selection: &crate::resolver::ArtifactSelection,
    collector: &mut EventCollector,
    index_url: &str,
) -> Result<(String, Value)> {
    if is_missing_sha256(selection.hash.as_deref()) {
        let diagnostic = missing_hash_diagnostic(pkg, selection, index_url);
        let message = diagnostic.message.clone();
        collector.diagnostic(diagnostic);
        return Err(eyre!(message));
    }

    let Some(verified_hash) = selection.hash.clone() else {
        let message = format!(
            "missing SHA-256 hash for {} {} after verification",
            pkg.name, pkg.version
        );
        collector.error_with_code(
            "E_VERIFY_MISSING_HASH",
            message.clone(),
            "Choose a package artifact that includes a SHA-256 digest or use an index that exposes artifact hashes.",
        );
        return Err(eyre!(message));
    };
    Ok((
        verified_hash.clone(),
        verification_artifact_value(pkg, selection, index_url, &verified_hash),
    ))
}

fn emit_lockfile_verification_drift(lockfile: &Lockfile, collector: &mut EventCollector) {
    let drifted_packages: Vec<Value> = lockfile
        .packages
        .values()
        .filter(|pkg| is_missing_sha256(Some(&pkg.hash)))
        .map(|pkg| {
            json!({
                "package": pkg.name,
                "version": pkg.version,
                "filename": pkg.wheel,
                "hash": pkg.hash,
            })
        })
        .collect();

    if drifted_packages.is_empty() {
        return;
    }

    collector.diagnostic(Diagnostic {
        level: crate::schema::DiagnosticLevel::Warning,
        code: Some("W_LOCK_PLACEHOLDER_HASH".to_string()),
        message: format!(
            "existing lockfile contains {} package(s) without verified hashes",
            drifted_packages.len()
        ),
        file: None,
        line: None,
        suggestion: Some(
            "rerun 'pybun install' or 'pybun lock' with an index that provides sha256 digests"
                .to_string(),
        ),
        context: Some(json!({ "packages": drifted_packages })),
        exception_type: None,
        location: None,
        next_action: None,
        fix_candidates: Some(crate::self_heal::fix_candidates_for_lock_drift()),
    });
}

async fn lock_dependencies(args: &LockArgs, collector: &mut EventCollector) -> Result<LockOutcome> {
    let (dep_specs, lock_path): (Vec<String>, PathBuf) =
        if let Some(script_path) = args.script.as_ref() {
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

            (pep723_deps, script_lock_path(script_path))
        } else {
            let cwd = std::env::current_dir()?;
            let Ok(project) = Project::discover(&cwd) else {
                let message =
                    "no pyproject.toml found in the current directory or any parent directory"
                        .to_string();
                collector.diagnostic(Diagnostic {
                    level: crate::schema::DiagnosticLevel::Error,
                    code: Some("E_LOCK_TARGET_REQUIRED".to_string()),
                    message: message.clone(),
                    file: None,
                    line: None,
                    suggestion: Some(
                        "Run 'pybun lock --script <path/to/script.py>' to lock a PEP 723 script, \
                     or create a pyproject.toml with [project.dependencies] to lock a project"
                            .to_string(),
                    ),
                    context: None,
                    exception_type: None,
                    location: None,
                    next_action: None,
                    fix_candidates: None,
                });
                return Err(eyre!(message));
            };

            (project.dependencies(), cwd.join("pybun.lockb"))
        };

    let requirements: Vec<Requirement> = dep_specs
        .iter()
        .map(|d| {
            d.parse::<Requirement>()
                .unwrap_or_else(|_| Requirement::any(d.trim()))
        })
        .collect();

    if dep_specs.is_empty() {
        let lock = Lockfile::new(vec!["3.11".into()], vec!["unknown".into()]);
        lock.save_to_path(&lock_path)?;
        return Ok(LockOutcome {
            summary: format!("no dependencies to lock -> {}", lock_path.display()),
            lockfile: lock_path,
            packages: Vec::new(),
            verified: true,
            artifacts: Vec::new(),
        });
    }

    let source_index_url: String;
    let offline = args.offline;
    let resolution = if let Some(index_path) = args.index.clone() {
        source_index_url = index_path.display().to_string();
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
        source_index_url = client.index_url();
        collector.info(format!(
            "Using PyPI index {} (offline: {})",
            source_index_url, offline
        ));
        let index = PyPiIndex::new(client);
        let resolve_result = resolve(requirements.clone(), &index).await;
        for notice in index.take_stale_cache_notices() {
            collector.warning(notice);
        }
        match resolve_result {
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

    // Detect the CPython tag of the actual lock target's Python (PYBUN_ENV / PYBUN_PYTHON /
    // project venv / system Python) *before* selecting wheels, so the wheel filenames recorded
    // in the lockfile match the interpreter that will actually install them. Selecting wheels
    // against whatever `python3`/`python` happens to resolve on PATH (the previous behavior)
    // could silently record wheels for the wrong CPython ABI, producing the kind of
    // `ImportError` #172's runtime compatibility check was built to detect after the fact
    // (Issue #293; same root cause as #291, fixed for `pybun install` in #292). This is
    // read-only detection only and covers both project-mode and `--script` PEP 723 locking,
    // since both resolve the target interpreter relative to the current working directory
    // (honoring PYBUN_ENV/PYBUN_PYTHON regardless of cwd).
    let working_dir = std::env::current_dir()?;
    let target_env_probe = crate::env::find_python_env(&working_dir)?;

    // PYBUN_FORCE_CP_TAG lets tests (and users) pin the CPython tag deterministically,
    // bypassing interpreter detection entirely.
    let active_cp_tag = std::env::var("PYBUN_FORCE_CP_TAG")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            get_python_version(&target_env_probe.python_path)
                .ok()
                .and_then(|v| python_version_to_cp_tag(&v))
        })
        .unwrap_or_else(|| "cp311".to_string());

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
    let mut verified_artifacts = Vec::new();

    for pkg in resolution.packages.values() {
        let selection = select_artifact_for_platform_with_cp(pkg, &platform_tags, &active_cp_tag);
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
        let (verified_hash, artifact) =
            ensure_selection_is_verifiable(pkg, &selection, collector, &source_index_url)?;
        verified_artifacts.push(artifact);
        lock.add_package(Package {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            source: registry_source_for_index(&source_index_url),
            wheel: selection.filename,
            hash: verified_hash,
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
        verified: true,
        artifacts: verified_artifacts,
    })
}

#[derive(Debug)]
struct RenderDetail {
    text: String,
    json: Value,
    is_error: bool,
    raw_text: bool,
    /// When true, produce no stdout output at all. Used for MCP stdio mode
    /// where stdout is the protocol channel and must not be polluted after
    /// the session ends.
    silent: bool,
    /// Exit code to propagate from a child process (e.g. `pybun run`).
    /// When set and non-zero, `execute` calls `std::process::exit` with this
    /// code after flushing output, so the shell sees the script's own code.
    process_exit_code: Option<i32>,
}

impl RenderDetail {
    fn with_json(text: impl Into<String>, json: Value) -> Self {
        Self {
            text: text.into(),
            json,
            is_error: false,
            raw_text: false,
            silent: false,
            process_exit_code: None,
        }
    }

    fn error(text: impl Into<String>, json: Value) -> Self {
        Self {
            text: text.into(),
            json,
            is_error: true,
            raw_text: false,
            silent: false,
            process_exit_code: None,
        }
    }

    fn with_json_raw_text(text: impl Into<String>, json: Value) -> Self {
        Self {
            text: text.into(),
            json,
            is_error: false,
            raw_text: true,
            silent: false,
            process_exit_code: None,
        }
    }

    /// Produces no stdout output. Used when the command has already written
    /// its own output to stdout (e.g. MCP stdio mode) and the render layer
    /// must stay silent.
    fn silent() -> Self {
        Self {
            text: String::new(),
            json: json!({}),
            is_error: false,
            raw_text: false,
            silent: true,
            process_exit_code: None,
        }
    }

    /// Attach a child-process exit code that `execute` will propagate via
    /// `std::process::exit` after flushing output.
    fn with_process_exit_code(mut self, code: i32) -> Self {
        self.process_exit_code = Some(code);
        self
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
            // CPython 3.x emits "No module named 'build'" (with quotes); older builds may
            // omit the quotes.  Check both forms to be safe.
            let missing_build = stderr.contains("No module named 'build'")
                || stderr.contains("No module named build");
            if missing_build {
                collector.diagnostic(
                    Diagnostic::error("python -m build failed: No module named build")
                        .with_code("E_BUILD_MISSING_BUILD_PKG")
                        .with_suggestion("pybun add build --dev\n  or: pip install build"),
                );
                if matches!(format, OutputFormat::Text) {
                    eprintln!("hint: Install the build package first: pybun add build --dev");
                    eprintln!("      or: pip install build");
                }
                return Err(eyre!("python -m build failed: No module named build"));
            }
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
struct AddedPackage {
    name: String,
    version: Option<String>,
}

#[derive(Debug)]
struct AddOutcome {
    summary: String,
    packages: Vec<AddedPackage>,
    added_deps: Vec<String>,
}

fn add_package(args: &crate::cli::PackageArgs) -> Result<AddOutcome> {
    if args.packages.is_empty() {
        return Err(eyre!("package name is required"));
    }

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

    let mut packages = Vec::with_capacity(args.packages.len());
    for package_spec in &args.packages {
        // Parse the requirement
        let req: Requirement = package_spec
            .parse()
            .map_err(|e: String| eyre!("invalid package spec: {}", e))?;

        // Note: PEP 508 extras (e.g. `typer[all]`) are not yet resolved
        // (Issue #285). `pybun add` always chains into `install()` below,
        // which re-parses the freshly written pyproject.toml dependency and
        // emits the `W_EXTRAS_IGNORED` warning — so we don't duplicate it
        // here.

        // Add to pyproject.toml
        project.add_dependency(package_spec);

        let version = match req.specs.as_slice() {
            [crate::resolver::VersionSpec::Any] => None,
            [crate::resolver::VersionSpec::Exact(v)] => Some(v.clone()),
            specs => Some(
                specs
                    .iter()
                    .map(crate::resolver::VersionSpec::operator_display)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        };

        // A later spec for the same package name replaces the earlier one in
        // pyproject.toml (see `Project::add_dependency`), so keep only the
        // last occurrence here too.
        packages.retain(|p: &AddedPackage| p.name != req.name);
        packages.push(AddedPackage {
            name: req.name.clone(),
            version,
        });
    }

    project.save()?;
    let added_deps = project.dependencies();

    let package_list = args.packages.join(", ");
    let summary = format!("added {} to {}", package_list, project.path().display());

    Ok(AddOutcome {
        summary,
        packages,
        added_deps,
    })
}

// ---------------------------------------------------------------------------
// pybun remove
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RemovedPackage {
    name: String,
    removed: bool,
}

#[derive(Debug)]
struct RemoveOutcome {
    summary: String,
    packages: Vec<RemovedPackage>,
}

fn remove_package(args: &crate::cli::PackageArgs) -> Result<RemoveOutcome> {
    if args.packages.is_empty() {
        return Err(eyre!("package name is required"));
    }

    // Find pyproject.toml
    let current_dir = std::env::current_dir()?;
    let mut project = Project::discover(&current_dir).map_err(|_| {
        eyre!(
            "pyproject.toml not found in {} or any parent directory",
            current_dir.display()
        )
    })?;

    let mut packages = Vec::with_capacity(args.packages.len());
    let mut removed_names = Vec::new();
    let mut not_found_names = Vec::new();
    for package_name in &args.packages {
        let removed = project.remove_dependency(package_name);
        if removed {
            removed_names.push(package_name.clone());
        } else {
            not_found_names.push(package_name.clone());
        }
        packages.push(RemovedPackage {
            name: package_name.clone(),
            removed,
        });
    }

    if !removed_names.is_empty() {
        project.save()?;
    }

    let summary = match (removed_names.is_empty(), not_found_names.is_empty()) {
        (false, true) => format!(
            "removed {} from {}",
            removed_names.join(", "),
            project.path().display()
        ),
        (true, false) => format!(
            "{} was not found in dependencies",
            not_found_names.join(", ")
        ),
        (false, false) => format!(
            "removed {} from {}; {} was not found in dependencies",
            removed_names.join(", "),
            project.path().display(),
            not_found_names.join(", ")
        ),
        (true, true) => unreachable!("at least one package is always processed"),
    };

    Ok(RemoveOutcome { summary, packages })
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
    /// Applied launch profile info
    profile: RunProfileInfo,
}

#[derive(Debug, Clone)]
struct RunProfileInfo {
    name: String,
    optimization_level: u8,
    lazy_imports: bool,
    lazy_imports_injected: bool,
    timing: bool,
}

/// Emit a `warn`-level diagnostic for each resource limit that was requested
/// but cannot be enforced on the current platform (Issue #203).
fn emit_unsupported_resource_limit_diagnostics(
    collector: &mut EventCollector,
    resource_limits: &sandbox::ResourceLimits,
) {
    for limit in &resource_limits.unsupported {
        collector.diagnostic(
            Diagnostic::warning(format!(
                "sandbox {limit} limit is not enforced on this platform and will have no effect"
            ))
            .with_code("W_SANDBOX_LIMIT_UNSUPPORTED"),
        );
    }
}

fn emit_rejected_allow_env_diagnostics(collector: &mut EventCollector, rejected_env: &[String]) {
    for name in rejected_env {
        collector.diagnostic(
            Diagnostic::warning(format!(
                "--allow-env={name} was ignored because its name looks like a credential (e.g. ends in _KEY/_TOKEN, contains _SECRET, or starts with AWS_); sandbox env filtering never passes credential-shaped names through, even when explicitly allow-listed"
            ))
            .with_code("W_SANDBOX_ALLOW_ENV_REJECTED"),
        );
    }
}

#[derive(Debug, Clone)]
struct SandboxInfo {
    enabled: bool,
    allow_network: bool,
    allow_read: Vec<String>,
    allow_write: Vec<String>,
    /// Env var *names* (never values) that were explicitly allowed through the env filter.
    allow_env: Vec<String>,
    default_deny_write: Vec<String>,
    enforcement: String,
    audit: Option<sandbox::SandboxAudit>,
    resource_limits: sandbox::ResourceLimits,
    timed_out: bool,
}

#[derive(Debug)]
enum RunProgram {
    Python(String),
    Uv { uv_path: PathBuf },
}

fn script_lock_path(script_path: &Path) -> PathBuf {
    let mut lock_path = script_path.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

/// Load and parse the binary script lockfile (`<script>.lock`) next to `script_path`.
///
/// Returns `Ok(None)` when the lockfile is missing **or** unreadable/corrupt.
/// A `<script>.lock` that fails to decode (e.g. truncated by a crash mid-write)
/// is treated the same as a missing lockfile rather than propagated as a fatal
/// error - this mirrors the self-heal behavior already applied to the MCP
/// doctor lockfile check (`src/mcp.rs`) and the PEP 723 script cache for issue
/// #299 (itself a recurrence of #262's failure mode). Callers observe a plain
/// "no lock" result and fall through to the existing regenerate-from-scratch
/// path (PEP 723 declared dependencies), which recreates the lockfile.
fn load_script_lock(script_path: &Path) -> Result<Option<ScriptLockInfo>> {
    let lock_path = script_lock_path(script_path);
    if !lock_path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(&lock_path)
        .map_err(|e| eyre!("failed to read script lock {}: {}", lock_path.display(), e))?;
    match Lockfile::from_bytes(&bytes) {
        Ok(lock) => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let digest = hasher.finalize();
            let lock_hash = hex::encode(&digest[..16]);
            Ok(Some(ScriptLockInfo { lock, lock_hash }))
        }
        Err(e) => {
            eprintln!(
                "info: discarded unreadable script lockfile at {} ({}); regenerating",
                lock_path.display(),
                e
            );
            Ok(None)
        }
    }
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
    use crate::profiles::{Profile, ProfileConfig};

    let profile: Profile = args
        .profile
        .parse()
        .map_err(|e: String| eyre!("invalid --profile value: {}", e))?;
    let profile_config = ProfileConfig::for_profile(profile);

    // -c/--code: execute inline Python code, like `python -c "..."`.
    if let Some(code) = &args.code {
        return run_python_code(args, code, collector, format);
    }

    let target = args
        .target
        .as_ref()
        .ok_or_else(|| eyre!("script target is required (e.g., pybun run script.py)"))?;

    // Check if it's a Python file
    let script_path = PathBuf::from(target);

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

        // When a PyBun binary lockfile exists next to the script, bypass uv entirely.
        // uv would detect the .lock file, attempt to parse it as TOML, and crash
        // because the file uses PyBun's binary format (Issue #234).
        if pep723_backend_setting == "uv" && script_lock.is_some() {
            eprintln!(
                "warning: PYBUN_PEP723_BACKEND=uv is set but a PyBun script lockfile exists; \
                 uv cannot parse the binary .lock file — falling back to the pybun backend"
            );
        }
        if !dry_run
            && !no_cache
            && !args.sandbox
            && pep723_backend_setting != "pybun"
            && script_lock.is_none()
        {
            if let Some(uv_path) = crate::env::find_uv_executable() {
                pep723_backend = "uv_run".to_string();

                // `uv run --script` manages its own venv/wheel cache internally, so PyBun
                // has no direct signal for whether this invocation was served from cache.
                // Mirror the same cache-key semantics used by the native "pybun" backend
                // (script path + dependency set + Python version + index settings + lock
                // hash) to detect a repeat ("warm") invocation of this exact script, so
                // `--format=json` can report `cache_hit` accurately instead of always
                // reporting `false` (Issue #267).
                let pep_cache =
                    Pep723Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
                let (base_python, _env_source) = find_python_interpreter()?;
                let python_version = get_python_version(Path::new(&base_python))?;
                let index_settings = pep723_index_settings(pep723_metadata.as_ref());
                let cache_key = Pep723CacheKey::new(
                    &install_deps,
                    &python_version,
                    &index_settings,
                    lock_hash.as_deref(),
                );
                let env_root = pep_cache
                    .script_env_root(&script_path)
                    .map_err(|e| eyre!("failed to resolve script env root: {}", e))?;
                let _env_lock = pep_cache
                    .lock_script_env(&env_root)
                    .map_err(|e| eyre!("failed to lock script env: {}", e))?;

                let uv_cache_hit = pep_cache
                    .read_cache_entry(&env_root)
                    .map_err(|e| eyre!("failed to read cache entry: {}", e))?
                    .map(|info| Pep723Cache::cache_entry_matches_key(&info, &cache_key))
                    .unwrap_or(false);

                pep_cache
                    .record_cache_entry_at(&env_root, &cache_key)
                    .map_err(|e| eyre!("failed to record cache entry: {}", e))?;

                if uv_cache_hit {
                    collector.info(format!(
                        "Cache hit: reusing uv-managed environment (hash: {})",
                        &cache_key.hash[..8]
                    ));
                }

                (RunProgram::Uv { uv_path }, None, uv_cache_hit)
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
                        let resolution = resolve(requirements, &index).await;
                        for notice in index.take_stale_cache_notices() {
                            collector.warning(notice);
                        }
                        let resolution =
                            resolution.map_err(|e: crate::resolver::ResolveError| eyre!(e))?;

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
                        // Issue #294: select wheels for the *target venv's* Python
                        // (already resolved above as `python_version`), not whatever
                        // python3/python happens to resolve on PATH. Same root cause
                        // as Issue #291, fixed for `pybun install` in #292.
                        let active_cp_tag = python_version_to_cp_tag(&python_version)
                            .unwrap_or_else(|| "cp311".to_string());
                        let mut download_futures = Vec::new();

                        for pkg in resolution.packages.values() {
                            let selection = crate::resolver::select_artifact_for_platform_with_cp(
                                pkg,
                                &platform_tags,
                                &active_cp_tag,
                            );
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

        check_lockfile_python_compatibility(&python, collector);

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
        RunProgram::Uv { uv_path } => {
            let mut cmd = ProcessCommand::new(uv_path);
            cmd.args(["run", "--script"]);
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
        let guard = sandbox::apply_python_sandbox(
            &mut cmd,
            sandbox::SandboxConfig {
                allow_network,
                allow_read: args.allow_read.clone(),
                allow_write: args.allow_write.clone(),
                allow_env: args.allow_env.clone(),
                timeout_secs: args.sandbox_timeout,
                memory_limit_mb: args.sandbox_memory,
                cpu_limit_secs: args.sandbox_cpu,
                ..Default::default()
            },
        )?;
        emit_unsupported_resource_limit_diagnostics(collector, &guard.resource_limits);
        emit_rejected_allow_env_diagnostics(collector, &guard.rejected_env);
        sandbox_info = Some(SandboxInfo {
            enabled: true,
            allow_network,
            allow_read: args.allow_read.clone(),
            allow_write: args.allow_write.clone(),
            allow_env: guard.allow_env.clone(),
            default_deny_write: guard.default_deny_write.clone(),
            enforcement: guard.enforcement().to_string(),
            audit: None,
            resource_limits: guard.resource_limits.clone(),
            timed_out: false,
        });
        sandbox_guard = Some(guard);
    }

    // Apply launch profile settings to the command.
    // PYTHONOPTIMIZE maps optimization_level to Python's -O/-OO flag semantics.
    let mut lazy_import_tempdir: Option<tempfile::TempDir> = None;
    let mut lazy_imports_injected = false;
    if profile_config.optimization_level > 0 && std::env::var_os("PYTHONOPTIMIZE").is_none() {
        cmd.env(
            "PYTHONOPTIMIZE",
            profile_config.optimization_level.to_string(),
        );
    }
    if profile_config.timing {
        cmd.env("PYBUN_TIMING", "1");
    }
    for (key, value) in &profile_config.env_vars {
        cmd.env(key, value);
    }
    // Inject lazy imports via sitecustomize.py when not sandboxed (sandbox has its own
    // sitecustomize.py and merging them is deferred to a later PR).
    if profile_config.lazy_imports && !args.sandbox && !is_uv_runner {
        use crate::lazy_import::{LazyImportConfig, generate_lazy_import_python_code};
        let lazy_config = LazyImportConfig::with_defaults();
        let python_code = generate_lazy_import_python_code(&lazy_config);
        match tempfile::tempdir() {
            Ok(dir) => {
                let sitecustomize = dir.path().join("sitecustomize.py");
                if std::fs::write(&sitecustomize, &python_code).is_ok() {
                    let new_path = join_python_path(dir.path());
                    cmd.env("PYTHONPATH", new_path);
                    lazy_imports_injected = true;
                    lazy_import_tempdir = Some(dir);
                }
            }
            Err(e) => {
                collector.warning(format!(
                    "failed to create lazy-import tempdir, skipping injection: {}",
                    e
                ));
            }
        }
    }

    let cleanup = temp_env_dir.is_some();

    // Execute
    // On Unix, use exec to replace the process if cleanup is not needed AND not in JSON mode
    // (JSON mode requires wrapping to emit final summary)
    #[cfg(unix)]
    if !cleanup && format != OutputFormat::Json && sandbox_guard.is_none() {
        // leak lazy_import_tempdir intentionally: exec replaces the process before Rust
        // drop runs, so the directory remains accessible to the spawned Python process.
        std::mem::forget(lazy_import_tempdir);
        let err = cmd.exec();
        return Err(eyre!("failed to exec runner: {}", err));
    }

    let sandbox::SandboxedExecution {
        status,
        stdout,
        stderr,
        timed_out,
    } = sandbox::execute_with_optional_sandbox(
        &mut cmd,
        sandbox_guard.as_ref(),
        format == OutputFormat::Json,
    )
    .map_err(|e| eyre!("failed to execute runner: {}", e))?;
    let stdout = stdout.as_deref().and_then(capture_stdio);
    let stderr = stderr.as_deref().and_then(capture_stdio);
    // Read audit before dropping the guard (guard keeps the audit file alive).
    if let (Some(guard), Some(info)) = (&sandbox_guard, &mut sandbox_info) {
        info.audit = Some(guard.read_audit());
        info.timed_out = timed_out;
    }
    drop(sandbox_guard);

    if timed_out {
        collector.diagnostic(
            Diagnostic::error(format!(
                "sandboxed process killed after exceeding --sandbox-timeout={}s",
                args.sandbox_timeout
            ))
            .with_code("E_SANDBOX_TIMEOUT")
            .with_suggestion("increase --sandbox-timeout, set --sandbox-timeout=0 to disable, or optimize the script to finish sooner"),
        );
    } else if args.sandbox_cpu > 0 && sandbox::cpu_limit_exceeded(&status) {
        collector.diagnostic(
            Diagnostic::error(format!(
                "sandboxed process killed after exceeding --sandbox-cpu={}s of CPU time",
                args.sandbox_cpu
            ))
            .with_code("E_SANDBOX_CPU_LIMIT")
            .with_suggestion("increase --sandbox-cpu, set --sandbox-cpu=0 to disable, or optimize the script to use less CPU time"),
        );
    }

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

    drop(lazy_import_tempdir);

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
        profile: RunProfileInfo {
            name: profile_config.profile.to_string(),
            optimization_level: profile_config.optimization_level,
            lazy_imports: profile_config.lazy_imports,
            lazy_imports_injected,
            timing: profile_config.timing,
        },
    })
}

/// Build a PYTHONPATH string that prepends `dir` before the existing PYTHONPATH.
fn join_python_path(dir: &std::path::Path) -> std::ffi::OsString {
    let sep = if cfg!(windows) { ";" } else { ":" };
    let mut paths = vec![dir.as_os_str().to_os_string()];
    if let Ok(existing) = std::env::var("PYTHONPATH")
        && !existing.is_empty()
    {
        paths.push(std::ffi::OsString::from(existing));
    }
    let joined: Vec<&std::ffi::OsStr> = paths.iter().map(|s| s.as_os_str()).collect();
    joined.join(std::ffi::OsStr::new(sep))
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

/// Validate that the wheels recorded in the project lockfile (`pybun.lockb`)
/// are compatible with the Python interpreter that is about to execute the
/// script. A mismatch (e.g. `cp310` wheels locked but running under `cp312`)
/// otherwise surfaces as an obscure C-extension `ImportError` at runtime
/// rather than an actionable PyBun diagnostic (see Issue #172).
///
/// This check is best-effort: any failure to locate, load, or parse the
/// lockfile or interpreter version silently skips validation rather than
/// blocking the run.
fn check_lockfile_python_compatibility(python_path: &str, collector: &mut EventCollector) {
    let Ok(cwd) = std::env::current_dir() else {
        return;
    };
    let lock_path = cwd.join("pybun.lockb");
    if !lock_path.exists() {
        return;
    }
    let Ok(lockfile) = Lockfile::load_from_path(&lock_path) else {
        return;
    };
    let Ok(active_version) = get_python_version(Path::new(python_path)) else {
        return;
    };
    let Some(active_cp_tag) = python_version_to_cp_tag(&active_version) else {
        return;
    };

    let mismatched_tag = lockfile.packages.values().find_map(|pkg| {
        let (python_tag, abi_tag) = parse_wheel_tags(&pkg.wheel);
        let ptag = python_tag?;
        if is_wheel_python_compatible(Some(&ptag), abi_tag.as_deref(), &active_cp_tag) {
            None
        } else {
            Some(ptag)
        }
    });

    let Some(locked_tag) = mismatched_tag else {
        return;
    };

    let locked_version = cp_tag_to_dotted_version(&locked_tag).unwrap_or(locked_tag);
    let active_minor =
        cp_tag_to_dotted_version(&active_cp_tag).unwrap_or_else(|| active_version.clone());
    let message = format!(
        "Locked package wheels in pybun.lockb (compiled for Python {locked_version}) are \
         incompatible with the active Python interpreter (Python {active_version}). \
         Please run 'pybun install' to re-lock dependencies for Python {active_minor}."
    );
    eprintln!("warning: {message}");
    collector.diagnostic(
        Diagnostic::warning(message)
            .with_code("W_LOCK_PYTHON_VERSION_MISMATCH")
            .with_suggestion("pybun install"),
    );
}

fn run_python_code(
    args: &crate::cli::RunArgs,
    code: &str,
    collector: &mut EventCollector,
    format: OutputFormat,
) -> Result<RunOutcome> {
    use crate::profiles::{Profile, ProfileConfig};

    let profile: Profile = args
        .profile
        .parse()
        .map_err(|e: String| eyre!("invalid --profile value: {}", e))?;
    let profile_config = ProfileConfig::for_profile(profile);

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
        let guard = sandbox::apply_python_sandbox(
            &mut cmd,
            sandbox::SandboxConfig {
                allow_network,
                allow_read: args.allow_read.clone(),
                allow_write: args.allow_write.clone(),
                allow_env: args.allow_env.clone(),
                timeout_secs: args.sandbox_timeout,
                memory_limit_mb: args.sandbox_memory,
                cpu_limit_secs: args.sandbox_cpu,
                ..Default::default()
            },
        )?;
        emit_unsupported_resource_limit_diagnostics(collector, &guard.resource_limits);
        emit_rejected_allow_env_diagnostics(collector, &guard.rejected_env);
        sandbox_info = Some(SandboxInfo {
            enabled: true,
            allow_network,
            allow_read: args.allow_read.clone(),
            allow_write: args.allow_write.clone(),
            allow_env: guard.allow_env.clone(),
            default_deny_write: guard.default_deny_write.clone(),
            enforcement: guard.enforcement().to_string(),
            audit: None,
            resource_limits: guard.resource_limits.clone(),
            timed_out: false,
        });
        sandbox_guard = Some(guard);
    }

    // Apply profile settings (optimization, timing, env vars) — same as run_script.
    let mut lazy_imports_injected = false;
    if profile_config.optimization_level > 0 && std::env::var_os("PYTHONOPTIMIZE").is_none() {
        cmd.env(
            "PYTHONOPTIMIZE",
            profile_config.optimization_level.to_string(),
        );
    }
    if profile_config.timing {
        cmd.env("PYBUN_TIMING", "1");
    }
    for (key, value) in &profile_config.env_vars {
        cmd.env(key, value);
    }
    let mut lazy_import_tempdir: Option<tempfile::TempDir> = None;
    if profile_config.lazy_imports && !args.sandbox {
        use crate::lazy_import::{LazyImportConfig, generate_lazy_import_python_code};
        let lazy_config = LazyImportConfig::with_defaults();
        let python_code = generate_lazy_import_python_code(&lazy_config);
        if let Ok(dir) = tempfile::tempdir() {
            let sitecustomize = dir.path().join("sitecustomize.py");
            if std::fs::write(&sitecustomize, &python_code).is_ok() {
                let new_path = join_python_path(dir.path());
                cmd.env("PYTHONPATH", new_path);
                lazy_imports_injected = true;
                lazy_import_tempdir = Some(dir);
            }
        }
    }

    // Add remaining passthrough arguments
    for arg in args.passthrough.iter().skip(1) {
        cmd.arg(arg);
    }

    #[cfg(unix)]
    if format != OutputFormat::Json && sandbox_guard.is_none() {
        std::mem::forget(lazy_import_tempdir);
        let err = cmd.exec();
        return Err(eyre!("failed to exec Python: {}", err));
    }

    let sandbox::SandboxedExecution {
        status,
        stdout,
        stderr,
        timed_out,
    } = sandbox::execute_with_optional_sandbox(
        &mut cmd,
        sandbox_guard.as_ref(),
        format == OutputFormat::Json,
    )
    .map_err(|e| eyre!("failed to execute Python: {}", e))?;
    let stdout = stdout.as_deref().and_then(capture_stdio);
    let stderr = stderr.as_deref().and_then(capture_stdio);
    if let (Some(guard), Some(info)) = (&sandbox_guard, &mut sandbox_info) {
        info.audit = Some(guard.read_audit());
        info.timed_out = timed_out;
    }
    drop(sandbox_guard);

    if timed_out {
        collector.diagnostic(
            Diagnostic::error(format!(
                "sandboxed process killed after exceeding --sandbox-timeout={}s",
                args.sandbox_timeout
            ))
            .with_code("E_SANDBOX_TIMEOUT")
            .with_suggestion("increase --sandbox-timeout, set --sandbox-timeout=0 to disable, or optimize the script to finish sooner"),
        );
    } else if args.sandbox_cpu > 0 && sandbox::cpu_limit_exceeded(&status) {
        collector.diagnostic(
            Diagnostic::error(format!(
                "sandboxed process killed after exceeding --sandbox-cpu={}s of CPU time",
                args.sandbox_cpu
            ))
            .with_code("E_SANDBOX_CPU_LIMIT")
            .with_suggestion("increase --sandbox-cpu, set --sandbox-cpu=0 to disable, or optimize the script to use less CPU time"),
        );
    }

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

    drop(lazy_import_tempdir);

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
        profile: RunProfileInfo {
            name: profile_config.profile.to_string(),
            optimization_level: profile_config.optimization_level,
            lazy_imports: profile_config.lazy_imports,
            lazy_imports_injected,
            timing: profile_config.timing,
        },
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

use crate::cache::Cache;
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
        // In dry-run mode, just return the planned actions. Tests can set
        // PYBUN_X_DRY_RUN_EXIT_CODE to simulate a tool that exits non-zero
        // without needing network access / a real pip install.
        let exit_code = std::env::var("PYBUN_X_DRY_RUN_EXIT_CODE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        return Ok(XOutcome {
            summary: format!("would execute {} (dry-run)", package_name),
            package: package_name,
            version,
            passthrough: args.passthrough.clone(),
            temp_env: temp_env_path,
            python_version,
            exit_code,
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
    let should_fetch_manifest = !args.dry_run
        || manifest_source_env.is_some()
        || std::env::var("PYBUN_SELF_UPDATE_FETCH").is_ok();
    let manifest_result = if should_fetch_manifest {
        Some(ReleaseManifest::load(&manifest_source))
    } else {
        None
    };

    let mut latest_version = current_version.to_string();
    let mut update_available = false;
    let mut release_url = release_url_for_version(current_version);
    let target = current_release_target();
    let mut selected_asset = None;
    let mut manifest_detail = None;
    let mut manifest_error = None;
    let mut update_applied = false;
    let mut rollback_performed = false;
    let mut install_path = None;
    let mut update_error = None;

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

            selected_asset = target
                .as_deref()
                .and_then(|target| manifest.select_asset(target))
                .cloned();
            let asset_json = selected_asset
                .as_ref()
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

    if !args.dry_run {
        if let Some(error) = manifest_error.as_deref() {
            let message = format!("failed to load release manifest: {error}");
            collector.error_with_code(
                "E_SELF_UPDATE_MANIFEST",
                message.clone(),
                "Check network connectivity and the release manifest URL (--channel or PYBUN_SELF_UPDATE_MANIFEST_URL), then retry `pybun self update`.",
            );
            update_error = Some(message);
        } else if update_available {
            let Some(asset) = selected_asset else {
                let target_text = target
                    .as_deref()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let message = format!("no release asset found for target {target_text}");
                collector.error_with_code(
                    "E_SELF_UPDATE_NO_ASSET",
                    message.clone(),
                    "Pass --target explicitly to select a supported platform/arch, or check that a release asset exists for your platform.",
                );
                update_error = Some(message);
                let summary = "Update failed: no release asset found".to_string();
                let json_detail = json!({
                    "current_version": current_version,
                    "latest_version": latest_version,
                    "channel": channel,
                    "update_available": update_available,
                    "release_url": release_url,
                    "dry_run": args.dry_run,
                    "target": target,
                    "manifest": manifest_detail,
                    "manifest_error": manifest_error,
                    "manifest_source": manifest_source_env.or(Some(default_manifest_url)),
                    "update_applied": false,
                    "rollback_performed": false,
                    "install_path": Value::Null,
                    "error": update_error,
                });
                return RenderDetail::error(summary, json_detail);
            };
            let install_override = std::env::var("PYBUN_SELF_UPDATE_BIN")
                .ok()
                .map(PathBuf::from);
            let fail_swap_for_test = std::env::var("PYBUN_SELF_UPDATE_TEST_FAIL_SWAP").is_ok();
            let target_name = target
                .as_deref()
                .unwrap_or(asset.target.as_str())
                .to_string();

            match apply_update_for_asset(&asset, &target_name, install_override, fail_swap_for_test)
            {
                Ok(outcome) => {
                    update_applied = true;
                    rollback_performed = outcome.rollback_performed;
                    install_path = Some(outcome.install_path.display().to_string());
                    collector.info(format!(
                        "Updated binary at {}",
                        outcome.install_path.display()
                    ));
                }
                Err(error) => {
                    rollback_performed = error.rollback_performed;
                    update_error = Some(error.to_string());
                    collector.error_with_code(
                        "E_SELF_UPDATE_APPLY_FAILED",
                        error.to_string(),
                        "Check write permissions to the install path and retry `pybun self update`. If a backup exists, rollback may have already been performed.",
                    );
                }
            }
        }
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
    } else if let Some(error) = update_error.as_deref() {
        format!("Update failed: {error}")
    } else if update_available && update_applied {
        format!("Updated: {} -> {}", current_version, latest_version)
    } else if update_available {
        format!("Update failed: {} -> {}", current_version, latest_version)
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
        "target": target,
        "manifest": manifest_detail,
        "manifest_error": manifest_error,
        "manifest_source": manifest_source_env.or(Some(default_manifest_url)),
        "update_applied": update_applied,
        "rollback_performed": rollback_performed,
        "install_path": install_path,
        "error": update_error,
    });

    if !args.dry_run && update_error.is_some() {
        RenderDetail::error(summary, json_detail)
    } else {
        RenderDetail::with_json(summary, json_detail)
    }
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

fn init_project(args: &InitArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
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
        // Interactive mode — requires a terminal
        if !std::io::stdin().is_terminal() {
            collector.diagnostic(Diagnostic {
                level: DiagnosticLevel::Error,
                code: Some("E_INIT_NOT_INTERACTIVE".to_string()),
                message: "Interactive prompt requires a terminal".to_string(),
                file: None,
                line: None,
                suggestion: Some(
                    "Run with --yes to accept defaults non-interactively: pybun init --yes"
                        .to_string(),
                ),
                context: None,
                exception_type: None,
                location: None,
                next_action: None,
                fix_candidates: None,
            });
            return Err(eyre!(
                "Interactive prompt requires a terminal. Run with --yes to accept defaults non-interactively: pybun init --yes"
            ));
        }

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
        let message = "pybun.lockb not found. Run 'pybun install' first.".to_string();
        collector.error_with_code(
            "E_LOCKFILE_NOT_FOUND",
            message.clone(),
            "Run `pybun install` to generate pybun.lockb, then re-run `pybun outdated`.",
        );
        return Err(eyre!(message));
    }

    // A pybun.lockb that exists but fails to decode (e.g. truncated by a
    // crash mid-write, or corrupted on disk) is treated the same as a
    // missing lockfile rather than propagated as a fatal error. This
    // mirrors the self-heal behavior already applied to `load_script_lock`
    // (issue #301, itself tracking the same failure mode as #299/#262) and
    // to `run_upgrade`'s `Lockfile::load_from_path(&lock_path).ok()`. We
    // fall back to "no packages currently locked", which naturally reduces
    // `pybun outdated` to reporting nothing outdated rather than crashing.
    let lockfile = match Lockfile::load_from_path(&lock_path) {
        Ok(lockfile) => lockfile,
        Err(e) => {
            collector.warning(format!(
                "discarded unreadable pybun.lockb at {} ({}); treating as no current lock",
                lock_path.display(),
                e
            ));
            Lockfile::new(Vec::new(), Vec::new())
        }
    };

    // Load constraints for "wanted" logic, optionally scoped by --member/--group
    let (constraints, scope_detail) = if let Ok(project) = Project::discover(&cwd) {
        let (dep_strs, scope_detail) = select_scoped_dependencies(
            &project,
            &cwd,
            args.member.as_deref(),
            args.group.as_deref(),
            collector,
        )?;
        let mut map = HashMap::new();
        for dep_str in dep_strs {
            if let Ok(req) = Requirement::from_str(&dep_str) {
                map.insert(req.name.clone(), req);
            }
        }
        (map, scope_detail)
    } else {
        (HashMap::new(), None)
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

    for notice in client.take_stale_cache_notices() {
        collector.warning(notice);
    }

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
            "errors": check_errors,
            "workspace": scope_detail,
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
        let message = format!(
            "lockfile not found at {}. Run 'pybun install' first.",
            lock_path.display()
        );
        collector.error_with_code(
            "E_LOCKFILE_NOT_FOUND",
            message.clone(),
            "Run `pybun install` to generate the lockfile, then re-run `pybun upgrade`.",
        );
        return Err(eyre!(message));
    }

    // Load project to get constraints, optionally scoped by --member/--group
    let project = Project::discover(&cwd).map_err(|e| eyre!("failed to load project: {}", e))?;
    let (dependencies, scope_detail) = select_scoped_dependencies(
        &project,
        &cwd,
        args.member.as_deref(),
        args.group.as_deref(),
        collector,
    )?;
    if dependencies.is_empty() {
        return Ok(RenderDetail::with_json(
            "No dependencies to upgrade",
            json!({
                "upgraded": [],
                "dry_run": args.dry_run,
                "verified": true,
                "artifacts": [],
                "workspace": scope_detail,
            }),
        ));
    }

    // Load current lockfile if exists (for partial updates and comparison)
    let current_lock = Lockfile::load_from_path(&lock_path).ok();
    if let Some(lockfile) = &current_lock {
        emit_lockfile_verification_drift(lockfile, collector);
    }

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
    let source_index_url: String;
    let resolution = if let Some(index_path) = &args.index {
        source_index_url = index_path.display().to_string();
        let index = load_index_from_path(index_path)?;
        resolve(requirements.clone(), &index).await?
    } else {
        let pypi_client = PyPiClient::from_env(args.offline)
            .map_err(|e| eyre!("failed to create PyPI client: {}", e))?;
        source_index_url = pypi_client.index_url();
        let pypi_index = PyPiIndex::new(pypi_client);
        let resolve_result = resolve(requirements.clone(), &pypi_index).await;
        for notice in pypi_index.take_stale_cache_notices() {
            collector.warning(notice);
        }
        resolve_result?
    };

    collector.event(EventType::ResolveComplete);

    let mut upgraded_packages: Vec<Value> = Vec::new();
    let mut verification_artifacts: Vec<Value> = Vec::new();
    let platform_tags = current_platform_tags();

    // Detect the CPython tag of the actual project's Python (PYBUN_ENV / PYBUN_PYTHON /
    // project venv / system Python) *before* re-selecting wheels, so the wheel filenames
    // rewritten into the lockfile match the interpreter that will actually consume it.
    // Selecting wheels against whatever `python3`/`python` happens to resolve on PATH (the
    // previous behavior) could silently record wheels for the wrong CPython ABI, producing
    // the kind of hash/ABI mismatch (or the #172 runtime compatibility warning) that only
    // surfaces later when the rewritten lockfile is consumed (Issue #295; same root cause as
    // #291, fixed for `pybun install` in #292, `pybun lock` in #293, and `pybun run` in #294).
    // This is read-only detection only — `pybun upgrade` doesn't create venvs, so there's no
    // side-effect-ordering concern here (unlike #292's install fix).
    let target_env_probe = crate::env::find_python_env(&cwd)?;

    // PYBUN_FORCE_CP_TAG lets tests (and users) pin the CPython tag deterministically,
    // bypassing interpreter detection entirely.
    let active_cp_tag = std::env::var("PYBUN_FORCE_CP_TAG")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            get_python_version(&target_env_probe.python_path)
                .ok()
                .and_then(|v| python_version_to_cp_tag(&v))
        })
        .unwrap_or_else(|| "cp311".to_string());

    // Use an empty lockfile if none exists for comparison base
    let base_lock =
        current_lock.unwrap_or_else(|| Lockfile::new(vec!["3.12".into()], vec!["any".into()]));

    // Build new lockfile
    let mut new_lock = Lockfile::new(
        base_lock.python_versions.clone(),
        base_lock.platforms.clone(),
    );

    for (pkg_name, pkg) in &resolution.packages {
        let selection = select_artifact_for_platform_with_cp(pkg, &platform_tags, &active_cp_tag);
        let wheel_name = selection.filename.clone();
        let (hash, artifact) =
            ensure_selection_is_verifiable(pkg, &selection, collector, &source_index_url)?;

        let new_pkg = Package {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            source: pkg
                .source
                .clone()
                .unwrap_or_else(|| registry_source_for_index(&source_index_url)),
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

        // Only surface artifacts for packages that actually changed. Otherwise
        // `detail.artifacts` includes every resolved package (changed or not),
        // which contradicts `pybun outdated`'s "has an update" definition and
        // misleads agents gating upgrade decisions on `outdated` (Issue #261).
        if is_change {
            verification_artifacts.push(artifact);
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
            "verified": true,
            "artifacts": verification_artifacts,
            "workspace": scope_detail,
        }),
    ))
}

fn run_drift(args: &DriftArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
    use crate::drift;

    let cwd =
        std::env::current_dir().map_err(|e| eyre!("failed to get current directory: {}", e))?;
    let root = if let Some(path) = &args.path {
        if path.is_absolute() {
            path.clone()
        } else {
            cwd.join(path)
        }
    } else {
        cwd
    };

    // Require pyproject.toml
    if !root.join("pyproject.toml").exists() {
        collector.error_with_code(
            "E_DRIFT_NO_PYPROJECT",
            format!("pyproject.toml not found in {}", root.display()),
            "Run `pybun init` to create a pyproject.toml, or specify a directory with `pybun drift --path <PATH>`.",
        );
        return Ok(RenderDetail::error(
            "pyproject.toml not found".to_string(),
            json!({
                "undeclared_imports": [],
                "unused_declarations": [],
                "analysis_notes": ["pyproject.toml not found"],
                "files_scanned": 0
            }),
        ));
    }

    collector.event(EventType::Custom);

    let result = drift::analyze(&root);

    let undeclared_count = result.undeclared_imports.len();
    let unused_count = result.unused_declarations.len();

    // Surface undeclared imports as warnings
    for u in &result.undeclared_imports {
        collector.diagnostic(Diagnostic {
            level: DiagnosticLevel::Warning,
            code: Some("W_DRIFT_UNDECLARED_IMPORT".to_string()),
            message: format!(
                "Package '{}' is imported but not declared in pyproject.toml",
                u.package
            ),
            file: None,
            line: None,
            suggestion: Some(format!("Run `pybun add {}`", u.package)),
            context: None,
            exception_type: None,
            location: None,
            next_action: None,
            fix_candidates: None,
        });
    }

    // Surface unused declarations as warnings
    for u in &result.unused_declarations {
        collector.diagnostic(Diagnostic {
            level: DiagnosticLevel::Warning,
            code: Some("W_DRIFT_UNUSED_DECLARATION".to_string()),
            message: format!(
                "Package '{}' is declared in pyproject.toml but never imported",
                u.package
            ),
            file: None,
            line: None,
            suggestion: Some(format!("Run `pybun remove {}`", u.package)),
            context: None,
            exception_type: None,
            location: None,
            next_action: None,
            fix_candidates: None,
        });
    }

    let summary = if undeclared_count == 0 && unused_count == 0 {
        format!("No drift detected ({} files scanned)", result.files_scanned)
    } else {
        format!(
            "Drift detected: {} undeclared import(s), {} unused declaration(s) ({} files scanned)",
            undeclared_count, unused_count, result.files_scanned
        )
    };

    Ok(RenderDetail::with_json(
        summary,
        json!({
            "undeclared_imports": result.undeclared_imports,
            "unused_declarations": result.unused_declarations,
            "analysis_notes": result.analysis_notes,
            "files_scanned": result.files_scanned,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
