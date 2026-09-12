//! CLI command dispatch and transport-specific detail construction.

use super::*;

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
        Commands::Install(_)
        | Commands::Add(_)
        | Commands::Remove(_)
        | Commands::Lock(_)
        | Commands::Outdated(_)
        | Commands::Upgrade(_) => dispatch_package(&cli.command, &mut collector).await,
        Commands::Run(_) => dispatch_execution(&cli.command, &mut collector, cli.format).await,
        Commands::Test(_) => dispatch_testing(&cli.command, &mut collector).await,
        Commands::X(_)
        | Commands::Build(_)
        | Commands::SelfCmd(_)
        | Commands::ModuleFind(_)
        | Commands::LazyImport(_)
        | Commands::Watch(_)
        | Commands::Profile(_)
        | Commands::Schema(_)
        | Commands::Telemetry(_) => {
            dispatch_tooling(&cli.command, &mut collector, cli.format).await
        }
        Commands::Doctor(_) | Commands::Mcp(_) | Commands::Gc(_) | Commands::Audit(_) => {
            dispatch_maintenance(&cli.command, &mut collector).await
        }
        Commands::Python(_) => dispatch_python(&cli.command, &mut collector).await,
        Commands::Init(_) | Commands::Drift(_) => {
            dispatch_project(&cli.command, &mut collector).await
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

async fn dispatch_package(
    command: &Commands,
    collector: &mut EventCollector,
) -> (String, RenderDetail) {
    match command {
        Commands::Install(args) => {
            collector.event(EventType::ResolveStart);
            let pre_error_count = collector.error_diagnostic_count();
            let result = install::install(args, collector).await;
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
                    match install::install(&install_args, collector).await {
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
            let result = install::lock_dependencies(args, collector).await;
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
        Commands::Outdated(args) => {
            let pre_error_count = collector.error_diagnostic_count();
            let result = install::run_outdated(args, collector).await;
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
            let result = install::run_upgrade(args, collector).await;
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
        _ => unreachable!("command routed to wrong package dispatcher"),
    }
}

async fn dispatch_execution(
    command: &Commands,
    collector: &mut EventCollector,
    format: OutputFormat,
) -> (String, RenderDetail) {
    match command {
        Commands::Run(args) => {
            collector.event(EventType::ScriptStart);
            // PYBUN_SANDBOX_ALLOW_NETWORK is a documented CLI convenience
            // (equivalent to --allow-network) resolved *only* here, at the
            // real CLI entry point. `run_script`/`run_python_code` are shared
            // with the MCP `pybun_run` tool, which builds `RunArgs` directly
            // from a client-supplied sandbox policy rather than through this
            // dispatcher; resolving the env var inside those shared functions
            // would let an ambient env var on the parent pybun process
            // silently override an MCP client's explicit `allow_network:
            // false` (Issue #376).
            let mut args = args.clone();
            if !args.allow_network {
                args.allow_network = std::env::var("PYBUN_SANDBOX_ALLOW_NETWORK")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
            }
            let result = run_script(&args, collector, format).await;
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
        _ => unreachable!("command routed to wrong execution dispatcher"),
    }
}

async fn dispatch_testing(
    command: &Commands,
    collector: &mut EventCollector,
) -> (String, RenderDetail) {
    match command {
        Commands::Test(args) => {
            collector.event(EventType::CommandStart);
            let result = test::run_tests(args, collector);
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
        _ => unreachable!("command routed to wrong testing dispatcher"),
    }
}

async fn dispatch_tooling(
    command: &Commands,
    collector: &mut EventCollector,
    format: OutputFormat,
) -> (String, RenderDetail) {
    match command {
        Commands::X(args) => {
            collector.event(EventType::EnvCreate);
            let result = tooling::execute_tool(args, collector);
            match result {
                Ok(tooling::XOutcome {
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
        Commands::Build(args) => {
            let pre_error_count = collector.error_diagnostic_count();
            let result = run_build(args, collector, format);
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
        Commands::SelfCmd(cmd) => match cmd {
            SelfCommands::Update(args) => {
                let detail = tooling::run_self_update(args, collector);
                ("self update".to_string(), detail)
            }
        },
        Commands::ModuleFind(args) => {
            collector.event(EventType::ModuleFindStart);
            let result = tooling::run_module_find(args, collector);
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
            let result = tooling::run_lazy_import(args, collector);
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
            let result = tooling::run_watch(args, collector);
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
            let result = tooling::run_profile(args, collector);
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
                let detail = if matches!(format, OutputFormat::Text) {
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
                let detail = run_schema_check(args, collector);
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
        _ => unreachable!("command routed to wrong tooling dispatcher"),
    }
}

async fn dispatch_maintenance(
    command: &Commands,
    collector: &mut EventCollector,
) -> (String, RenderDetail) {
    match command {
        Commands::Doctor(args) => {
            collector.info("Running environment diagnostics");
            let detail = maintenance::run_doctor(args, collector);
            ("doctor".to_string(), detail)
        }
        Commands::Mcp(cmd) => match cmd {
            McpCommands::Serve(args) => {
                if args.allow_unsafe_no_sandbox {
                    // SAFETY: single-threaded at startup, before any concurrent
                    // access to the environment begins.
                    unsafe {
                        std::env::set_var("PYBUN_MCP_ALLOW_UNSAFE_NO_SANDBOX", "1");
                    }
                }
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
        Commands::Gc(args) => {
            collector.event(EventType::CacheHit); // Reuse cache event
            let result = maintenance::run_gc(args, collector);
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
        Commands::Audit(args) => {
            collector.info("Scanning installed packages for known vulnerabilities");
            let detail = maintenance::run_audit(args, collector).await;
            ("audit".to_string(), detail)
        }
        _ => unreachable!("command routed to wrong maintenance dispatcher"),
    }
}

async fn dispatch_python(
    command: &Commands,
    collector: &mut EventCollector,
) -> (String, RenderDetail) {
    match command {
        Commands::Python(cmd) => {
            match python::handle_python_command(cmd, collector) {
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
        _ => unreachable!("command routed to wrong python dispatcher"),
    }
}

async fn dispatch_project(
    command: &Commands,
    collector: &mut EventCollector,
) -> (String, RenderDetail) {
    match command {
        Commands::Init(args) => {
            let pre_error_count = collector.error_diagnostic_count();
            let result = project::init_project(args, collector);
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
        Commands::Drift(args) => {
            let result = project::run_drift(args, collector);
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
        _ => unreachable!("command routed to wrong project dispatcher"),
    }
}
