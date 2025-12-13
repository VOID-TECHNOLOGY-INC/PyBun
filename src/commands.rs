use crate::cli::{
    Cli, Commands, McpCommands, ModuleFindArgs, OutputFormat, PythonCommands, SelfCommands,
};
use crate::env::{EnvSource, find_python_env};
use crate::index::load_index_from_path;
use crate::lockfile::{Lockfile, Package, PackageSource};
use crate::pep723;
use crate::project::Project;
use crate::resolver::{Requirement, resolve};
use crate::schema::{Diagnostic, Event, EventCollector, EventType, JsonEnvelope, Status};
use color_eyre::eyre::{Result, eyre};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::time::Duration;

pub fn execute(cli: Cli) -> Result<()> {
    let mut collector = EventCollector::new();

    // Record command start
    collector.event(EventType::CommandStart);

    let (command, detail) = match &cli.command {
        Commands::Install(args) => {
            collector.event(EventType::ResolveStart);
            let result = install(args, &mut collector);
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
                }) => (
                    "add".to_string(),
                    RenderDetail::with_json(
                        summary,
                        json!({
                            "package": package,
                            "version": version,
                            "added_dependencies": added_deps,
                        }),
                    ),
                ),
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
        Commands::Run(args) => {
            collector.event(EventType::ScriptStart);
            let result = run_script(args, &mut collector);
            match result {
                Ok(RunOutcome {
                    summary,
                    target,
                    exit_code,
                    pep723_deps,
                }) => {
                    collector.event(EventType::ScriptEnd);
                    (
                        "run".to_string(),
                        RenderDetail::with_json(
                            summary,
                            json!({
                                "target": target,
                                "exit_code": exit_code,
                                "pep723_dependencies": pep723_deps,
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
        Commands::Test(args) => (
            "test".to_string(),
            stub_detail(
                format!(
                    "shard={:?} fail_fast={} pytest_compat={}",
                    args.shard, args.fail_fast, args.pytest_compat
                ),
                json!({
                    "shard": args.shard,
                    "fail_fast": args.fail_fast,
                    "pytest_compat": args.pytest_compat,
                }),
            ),
        ),
        Commands::Build(args) => (
            "build".to_string(),
            stub_detail(format!("sbom={}", args.sbom), json!({"sbom": args.sbom})),
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
                    if let Err(e) = crate::mcp::run_stdio_server() {
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
        OutputFormat::Text => format!("pybun {command}: {}", detail.text),
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

// ---------------------------------------------------------------------------
// pybun doctor
// ---------------------------------------------------------------------------

fn run_doctor(args: &crate::cli::DoctorArgs, collector: &mut EventCollector) -> RenderDetail {
    let mut checks: Vec<Value> = Vec::new();
    let mut all_ok = true;

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
    match Cache::new() {
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

    RenderDetail::with_json(
        summary,
        json!({
            "status": status,
            "checks": checks,
            "verbose": args.verbose,
        }),
    )
}

fn install(
    args: &crate::cli::InstallArgs,
    collector: &mut EventCollector,
) -> Result<InstallOutcome> {
    if args.requirements.is_empty() {
        return Err(eyre!(
            "no requirements provided (temporary flag --require needed)"
        ));
    }
    let index_path = args
        .index
        .clone()
        .ok_or_else(|| eyre!("index path is required for now (--index)"))?;

    let index = load_index_from_path(&index_path).map_err(|e| eyre!(e))?;
    let resolution = match resolve(args.requirements.clone(), &index) {
        Ok(r) => r,
        Err(e) => {
            for d in crate::self_heal::diagnostics_for_resolve_error(&args.requirements, &e) {
                collector.diagnostic(d);
            }
            return Err(eyre!(e.to_string()));
        }
    };

    let mut lock = Lockfile::new(vec!["3.11".into()], vec!["unknown".into()]);
    for pkg in resolution.packages.values() {
        lock.add_package(Package {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            source: PackageSource::Registry {
                index: "pypi".into(),
                url: "https://pypi.org/simple".into(),
            },
            wheel: format!("{}-{}-py3-none-any.whl", pkg.name, pkg.version),
            hash: "sha256:placeholder".into(),
            dependencies: pkg.dependencies.iter().map(ToString::to_string).collect(),
        });
    }
    lock.save_to_path(&args.lock)?;

    Ok(InstallOutcome {
        summary: format!(
            "resolved {} packages -> {}",
            lock.packages.len(),
            args.lock.display()
        ),
        packages: lock.packages.keys().cloned().collect(),
        lockfile: args.lock.clone(),
    })
}

#[derive(Debug)]
struct InstallOutcome {
    summary: String,
    packages: Vec<String>,
    lockfile: PathBuf,
}

#[derive(Debug)]
struct RenderDetail {
    text: String,
    json: Value,
    is_error: bool,
}

impl RenderDetail {
    fn with_json(text: impl Into<String>, json: Value) -> Self {
        Self {
            text: text.into(),
            json,
            is_error: false,
        }
    }

    fn error(text: impl Into<String>, json: Value) -> Self {
        Self {
            text: text.into(),
            json,
            is_error: true,
        }
    }
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

#[derive(Debug)]
struct RunOutcome {
    summary: String,
    target: Option<String>,
    exit_code: i32,
    pep723_deps: Vec<String>,
}

fn run_script(args: &crate::cli::RunArgs, collector: &mut EventCollector) -> Result<RunOutcome> {
    let target = args
        .target
        .as_ref()
        .ok_or_else(|| eyre!("script target is required (e.g., pybun run script.py)"))?;

    // Check if it's a Python file
    let script_path = PathBuf::from(target);

    // Check for -c flag style execution
    if target == "-c" {
        return run_python_code(args, collector);
    }

    // Ensure the script exists
    if !script_path.exists() {
        return Err(eyre!("script not found: {}", script_path.display()));
    }

    // Check for PEP 723 metadata
    let pep723_deps = match pep723::parse_script_metadata(&script_path) {
        Ok(Some(metadata)) => {
            if !metadata.dependencies.is_empty() {
                // TODO: In future, install dependencies to a temporary env
                // For now, just report them
                metadata.dependencies
            } else {
                Vec::new()
            }
        }
        Ok(None) => Vec::new(),
        Err(e) => {
            // Log warning but continue
            eprintln!("warning: failed to parse PEP 723 metadata: {}", e);
            Vec::new()
        }
    };

    // Find Python interpreter
    let (python, env_source) = find_python_interpreter()?;
    eprintln!("info: using Python from {}", env_source);

    // Build command
    let mut cmd = ProcessCommand::new(&python);
    cmd.arg(&script_path);

    // Add passthrough arguments
    for arg in &args.passthrough {
        cmd.arg(arg);
    }

    // Execute
    let status = cmd
        .status()
        .map_err(|e| eyre!("failed to execute Python: {}", e))?;

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
    })
}

fn run_python_code(
    args: &crate::cli::RunArgs,
    _collector: &mut EventCollector,
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

    // Add remaining passthrough arguments
    for arg in args.passthrough.iter().skip(1) {
        cmd.arg(arg);
    }

    let status = cmd
        .status()
        .map_err(|e| eyre!("failed to execute Python: {}", e))?;

    let exit_code = status.code().unwrap_or(-1);

    let summary = if status.success() {
        "executed inline code successfully".to_string()
    } else {
        format!("inline code exited with code {}", exit_code)
    };

    Ok(RunOutcome {
        summary,
        target: Some("-c".to_string()),
        exit_code,
        pep723_deps: Vec::new(),
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

    let venv_status = ProcessCommand::new(&python_path)
        .args(["-m", "venv"])
        .arg(&venv_path)
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

    // Install the package
    eprintln!("info: installing {}...", package_spec);
    let install_status = ProcessCommand::new(&pip_path)
        .args(["install", "--quiet", package_spec])
        .status()
        .map_err(|e| eyre!("failed to install package: {}", e))?;

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

    // In a real implementation, this would:
    // 1. Query a release API for the latest version
    // 2. Download the new binary
    // 3. Verify the signature
    // 4. Atomic swap with the current binary

    // For now, we implement a dry-run / check mode
    let update_check = UpdateCheck {
        current_version: current_version.to_string(),
        channel: channel.clone(),
        // Simulated: no update available (in real impl, would check remote)
        latest_version: current_version.to_string(),
        update_available: false,
        release_url: format!(
            "https://github.com/pybun/pybun/releases/tag/v{}",
            current_version
        ),
    };

    let summary = if args.dry_run {
        if update_check.update_available {
            format!(
                "Update available: {} -> {} (dry-run, no changes made)",
                update_check.current_version, update_check.latest_version
            )
        } else {
            format!(
                "Already up to date: {} (channel: {})",
                update_check.current_version, channel
            )
        }
    } else if update_check.update_available {
        // Would perform actual update here
        format!(
            "Would update: {} -> {} (update not yet implemented)",
            update_check.current_version, update_check.latest_version
        )
    } else {
        format!(
            "Already up to date: {} (channel: {})",
            update_check.current_version, channel
        )
    };

    let json_detail = json!({
        "current_version": update_check.current_version,
        "latest_version": update_check.latest_version,
        "channel": channel,
        "update_available": update_check.update_available,
        "release_url": update_check.release_url,
        "dry_run": args.dry_run,
    });

    RenderDetail::with_json(summary, json_detail)
}

#[derive(Debug)]
#[allow(dead_code)]
struct UpdateCheck {
    current_version: String,
    channel: String,
    latest_version: String,
    update_available: bool,
    release_url: String,
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

    // Run garbage collection
    let gc_result = cache
        .gc(max_bytes, args.dry_run)
        .map_err(|e| eyre!("GC failed: {}", e))?;

    let summary = if args.dry_run {
        if gc_result.would_remove.is_empty() {
            format!(
                "Cache is within limits ({} used)",
                format_size(gc_result.size_before)
            )
        } else {
            format!(
                "Would free {} ({} files)",
                format_size(gc_result.freed_bytes),
                gc_result.would_remove.len()
            )
        }
    } else if gc_result.files_removed == 0 {
        format!(
            "Cache is within limits ({} used)",
            format_size(gc_result.size_after)
        )
    } else {
        format!(
            "Freed {} ({} files removed)",
            format_size(gc_result.freed_bytes),
            gc_result.files_removed
        )
    };

    let json_detail = json!({
        "freed_bytes": gc_result.freed_bytes,
        "freed_human": format_size(gc_result.freed_bytes),
        "files_removed": gc_result.files_removed,
        "size_before": gc_result.size_before,
        "size_before_human": format_size(gc_result.size_before),
        "size_after": gc_result.size_after,
        "size_after_human": format_size(gc_result.size_after),
        "dry_run": args.dry_run,
        "max_size": args.max_size,
        "would_remove": gc_result.would_remove.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "cache_root": cache.root().display().to_string(),
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
