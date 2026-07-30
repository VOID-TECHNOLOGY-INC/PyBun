use crate::build::{BuildBackend, BuildCache};
use crate::cli::{
    Cli, Commands, DriftArgs, InitArgs, InitTemplate, McpCommands, OutputFormat, ProgressMode,
    PythonCommands, SchemaArgs, SchemaCommands, SelfCommands, TelemetryCommands,
};
use crate::env::find_python_env;
use crate::progress::{ProgressConfig, ProgressDriver};
use crate::project::Project;
use crate::release_manifest::{ReleaseManifest, current_release_target};
use crate::sandbox;
use crate::sbom;
use crate::schema::{
    Diagnostic, DiagnosticLevel, Event, EventCollector, EventType, JsonEnvelope, Status,
};
use crate::self_update::apply_update_for_asset;
use color_eyre::eyre::{Result, eyre};
use dialoguer::{Input, theme::ColorfulTheme};
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::Duration;

mod install;
use install::{AddOutcome, LockOutcome, RemoveOutcome};
pub(crate) use install::{InstallOutcome, RunOutcome, install};
mod maintenance;
mod run;
use run::{SandboxInfo, get_python_version, script_lock_path};
pub(crate) use run::{find_python_interpreter, run_script};
mod test;
mod tooling;

#[derive(Debug)]
pub(crate) struct RenderDetail {
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
            let result = install::install(args, &mut collector).await;
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
            let result = install::add_package(args);
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
                        pre: args.pre,
                    };

                    let packages_json: Vec<serde_json::Value> = packages
                        .iter()
                        .map(|p| json!({ "name": p.name, "version": p.version }))
                        .collect();

                    let pre_error_count = collector.error_diagnostic_count();
                    match install::install(&install_args, &mut collector).await {
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
            let result = install::remove_package(args);
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
            let result = install::lock_dependencies(args, &mut collector).await;
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
            let result = install::run_outdated(args, &mut collector).await;
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
            let result = install::run_upgrade(args, &mut collector).await;
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
fn python_version_env_override() -> Option<String> {
    std::env::var("PYBUN_PYPI_PYTHON_VERSION")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Python version used for `requires-python` candidate filtering during
/// resolution (Issue #342): the `PYBUN_PYPI_PYTHON_VERSION` override wins,
/// otherwise the interpreter detected for the current working directory
/// (`PYBUN_ENV` / project venv / system Python). `None` — for example when
/// no interpreter can be found — disables the filter.
pub(crate) fn resolve_target_python_version() -> Option<String> {
    if let Some(version) = python_version_env_override() {
        return Some(version);
    }
    let cwd = std::env::current_dir().ok()?;
    let probe = crate::env::find_python_env(&cwd).ok()?;
    get_python_version(&probe.python_path).ok()
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
