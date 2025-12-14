use crate::cli::{
    Cli, Commands, LazyImportArgs, McpCommands, ModuleFindArgs, OutputFormat, ProfileArgs,
    PythonCommands, SelfCommands, WatchArgs,
};
use crate::env::{EnvSource, find_python_env};
use crate::index::load_index_from_path;
use crate::lockfile::{Lockfile, Package, PackageSource};
use crate::pep723;
use crate::pep723_cache::Pep723Cache;
use crate::project::Project;
use crate::resolver::{Requirement, resolve};
use crate::schema::{Diagnostic, Event, EventCollector, EventType, JsonEnvelope, Status};
use color_eyre::eyre::{Result, eyre};
use serde_json::{Value, json};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
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
            let result = run_script(args, &mut collector, cli.format);
            match result {
                Ok(RunOutcome {
                    summary,
                    target,
                    exit_code,
                    pep723_deps,
                    temp_env,
                    cleanup,
                    cache_hit,
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
                                "temp_env": temp_env,
                                "cleanup": cleanup,
                                "cache_hit": cache_hit,
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
    // Gather requirements: either from --require flags or from pyproject.toml
    let requirements = if !args.requirements.is_empty() {
        // CLI --require flags take precedence
        args.requirements.clone()
    } else {
        // Try to load from pyproject.toml
        let working_dir = std::env::current_dir()?;
        match Project::discover(&working_dir) {
            Ok(project) => {
                let deps = project.dependencies();
                if deps.is_empty() {
                    // Project found but no dependencies - this is valid
                    collector.info("No dependencies found in pyproject.toml");
                    vec![]
                } else {
                    collector.info(format!(
                        "Found {} dependencies in {}",
                        deps.len(),
                        project.path().display()
                    ));
                    // Parse each dependency string into a Requirement
                    deps.iter()
                        .map(|d| {
                            d.parse::<Requirement>()
                                .unwrap_or_else(|_| Requirement::any(d.trim()))
                        })
                        .collect()
                }
            }
            Err(_) => {
                return Err(eyre!(
                    "no requirements provided and no pyproject.toml found. \
                     Use --require or create a pyproject.toml with [project.dependencies]"
                ));
            }
        }
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

    let index_path = args
        .index
        .clone()
        .ok_or_else(|| eyre!("index path is required for now (--index)"))?;

    let index = load_index_from_path(&index_path).map_err(|e| eyre!(e))?;
    let resolution = match resolve(requirements.clone(), &index) {
        Ok(r) => r,
        Err(e) => {
            for d in crate::self_heal::diagnostics_for_resolve_error(&requirements, &e) {
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
    /// Environment path used for PEP 723 dependencies (cached or temporary)
    temp_env: Option<String>,
    /// Whether the environment was cleaned up (only in no-cache mode)
    cleanup: bool,
    /// Whether the environment was a cache hit
    cache_hit: bool,
}

fn run_script(
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

    // Check for dry-run mode (for testing)
    let dry_run = std::env::var("PYBUN_PEP723_DRY_RUN").is_ok();
    // Check for no-cache mode (force fresh venv)
    let no_cache = std::env::var("PYBUN_PEP723_NO_CACHE").is_ok();

    // If there are PEP 723 dependencies, use cached or create environment
    let (python_to_use, cached_env_path, cache_hit) = if !pep723_deps.is_empty() {
        collector.info(format!(
            "PEP 723 script with {} dependencies",
            pep723_deps.len()
        ));

        // Initialize PEP 723 cache
        let cache = Pep723Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;

        if dry_run {
            // In dry-run mode, just report what would happen
            let hash = Pep723Cache::compute_deps_hash(&pep723_deps);
            collector.info(format!(
                "Would use cached env at {} or create new one: {:?}",
                cache.venv_path_for_hash(&hash).display(),
                pep723_deps
            ));
            let (python, env_source) = find_python_interpreter()?;
            eprintln!("info: using Python from {} (dry-run)", env_source);
            (
                python,
                Some(
                    cache
                        .venv_path_for_hash(&hash)
                        .to_string_lossy()
                        .to_string(),
                ),
                false,
            )
        } else if !no_cache {
            // Check cache first
            if let Some(cached) = cache.get_cached_env(&pep723_deps) {
                // Cache hit! Reuse existing venv
                collector.info(format!(
                    "Cache hit: reusing venv at {} (hash: {})",
                    cached.venv_path.display(),
                    &cached.hash[..8]
                ));
                eprintln!(
                    "info: using cached environment {} (hash: {})",
                    cached.venv_path.display(),
                    &cached.hash[..8]
                );
                (
                    cached.python_path.to_string_lossy().to_string(),
                    Some(cached.venv_path.to_string_lossy().to_string()),
                    true,
                )
            } else {
                // Cache miss - create new venv and cache it
                let prepared = cache
                    .prepare_cache_dir(&pep723_deps)
                    .map_err(|e| eyre!("failed to prepare cache dir: {}", e))?;

                let (base_python, env_source) = find_python_interpreter()?;
                eprintln!(
                    "info: using Python from {} for new cached env (hash: {})",
                    env_source,
                    &prepared.hash[..8]
                );

                // Create virtual environment
                eprintln!(
                    "info: creating cached environment at {}",
                    prepared.venv_path.display()
                );

                let venv_status = ProcessCommand::new(&base_python)
                    .args(["-m", "venv"])
                    .arg(&prepared.venv_path)
                    .status()
                    .map_err(|e| eyre!("failed to create virtual environment: {}", e))?;

                if !venv_status.success() {
                    return Err(eyre!("failed to create virtual environment"));
                }

                // Get pip path in venv
                let pip_path = if cfg!(windows) {
                    prepared.venv_path.join("Scripts").join("pip.exe")
                } else {
                    prepared.venv_path.join("bin").join("pip")
                };

                // Install dependencies
                if !pep723_deps.is_empty() {
                    eprintln!("info: installing {} dependencies...", pep723_deps.len());

                    // Check for uv
                    if let Some(uv_path) = crate::env::find_uv_executable() {
                        eprintln!("info: using uv for fast installation");
                        let mut install_cmd = ProcessCommand::new(uv_path);
                        install_cmd.args(["pip", "install", "--quiet"]);
                        // uv requires specifying python environment
                        install_cmd.arg("--python");
                        install_cmd.arg(&prepared.venv_path);
                        install_cmd.args(&pep723_deps);

                        let install_status = install_cmd
                            .status()
                            .map_err(|e| eyre!("failed to install dependencies with uv: {}", e))?;

                        if !install_status.success() {
                            collector.warning("failed to install dependencies with uv".to_string());
                            // Fallback to pip? Or just fail? Let's fail for now to be explicit, logic could be refined.
                            let _ = cache.remove_env(&prepared.hash);
                            return Err(eyre!(
                                "failed to install PEP 723 dependencies (uv backend)"
                            ));
                        }
                    } else {
                        // Fallback to standard pip
                        let mut install_cmd = ProcessCommand::new(&pip_path);
                        install_cmd.args(["install", "--quiet"]);
                        install_cmd.args(&pep723_deps);

                        let install_status = install_cmd
                            .status()
                            .map_err(|e| eyre!("failed to install dependencies: {}", e))?;

                        if !install_status.success() {
                            collector.warning("failed to install dependencies".to_string());
                            let _ = cache.remove_env(&prepared.hash);
                            return Err(eyre!("failed to install PEP 723 dependencies"));
                        }
                    }
                }

                // Get Python version for metadata
                let python_version = get_python_version(&prepared.python_path)?;

                // Record cache entry
                cache
                    .record_cache_entry(&prepared.hash, &pep723_deps, &python_version)
                    .map_err(|e| eyre!("failed to record cache entry: {}", e))?;

                eprintln!("info: cached environment ready");

                (
                    prepared.python_path.to_string_lossy().to_string(),
                    Some(prepared.venv_path.to_string_lossy().to_string()),
                    false,
                )
            }
        } else {
            // No-cache mode: create temporary environment (old behavior)
            let temp_dir =
                tempfile::tempdir().map_err(|e| eyre!("failed to create temp directory: {}", e))?;
            let temp_env_str = temp_dir.path().to_string_lossy().to_string();

            let (base_python, env_source) = find_python_interpreter()?;
            eprintln!(
                "info: using Python from {} for temp env (no-cache mode)",
                env_source
            );

            let venv_path = temp_dir.path().join("venv");
            eprintln!(
                "info: creating isolated environment at {}",
                venv_path.display()
            );

            let venv_status = ProcessCommand::new(&base_python)
                .args(["-m", "venv"])
                .arg(&venv_path)
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

            if !pep723_deps.is_empty() {
                eprintln!("info: installing {} dependencies...", pep723_deps.len());

                if let Some(uv_path) = crate::env::find_uv_executable() {
                    eprintln!("info: using uv for fast installation (no-cache mode)");
                    let mut install_cmd = ProcessCommand::new(uv_path);
                    install_cmd.args(["pip", "install", "--quiet"]);
                    install_cmd.arg("--python");
                    install_cmd.arg(&venv_path);
                    install_cmd.args(&pep723_deps);

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
                    install_cmd.args(&pep723_deps);

                    let install_status = install_cmd
                        .status()
                        .map_err(|e| eyre!("failed to install dependencies: {}", e))?;

                    if !install_status.success() {
                        collector.warning("failed to install dependencies".to_string());
                        return Err(eyre!("failed to install PEP 723 dependencies"));
                    }
                }
            }

            // temp_dir will be dropped after execution, cleaning up
            std::mem::forget(temp_dir);
            (
                venv_python.to_string_lossy().to_string(),
                Some(temp_env_str),
                false,
            )
        }
    } else {
        // No PEP 723 dependencies, use system/project Python
        let (python, env_source) = find_python_interpreter()?;
        eprintln!("info: using Python from {}", env_source);
        (python, None, false)
    };

    // Build command
    let mut cmd = ProcessCommand::new(&python_to_use);
    cmd.arg(&script_path);

    // Add passthrough arguments
    for arg in &args.passthrough {
        cmd.arg(arg);
    }

    // Note: with caching, we don't cleanup (venv is reused)
    // cleanup is only true for no-cache mode
    let cleanup =
        cached_env_path.is_some() && !cache_hit && std::env::var("PYBUN_PEP723_NO_CACHE").is_ok();

    // Execute
    // On Unix, use exec to replace the process if cleanup is not needed AND not in JSON mode
    // (JSON mode requires wrapping to emit final summary)
    #[cfg(unix)]
    if !cleanup && format != OutputFormat::Json {
        let err = cmd.exec();
        return Err(eyre!("failed to exec Python: {}", err));
    }

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
        temp_env: cached_env_path,
        cleanup,
        cache_hit,
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
    _collector: &mut EventCollector,
    _format: OutputFormat,
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
        temp_env: None,
        cleanup: false,
        cache_hit: false,
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

    // Check if pytest is available
    if let Ok(output) = ProcessCommand::new("python3")
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
