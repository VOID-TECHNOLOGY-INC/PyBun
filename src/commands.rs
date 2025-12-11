use crate::cli::{Cli, Commands, McpCommands, OutputFormat, PythonCommands, SelfCommands};
use crate::env::{EnvSource, find_python_env};
use crate::index::load_index_from_path;
use crate::lockfile::{Lockfile, Package, PackageSource};
use crate::pep723;
use crate::project::Project;
use crate::resolver::{Requirement, ResolveError, resolve};
use color_eyre::eyre::{Result, eyre};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::time::{Duration, Instant};

pub fn execute(cli: Cli) -> Result<()> {
    let start = Instant::now();
    let (command, detail) = match &cli.command {
        Commands::Install(args) => {
            let InstallOutcome {
                summary,
                packages,
                lockfile,
            } = install(args)?;
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
        Commands::Add(args) => {
            let AddOutcome {
                summary,
                package,
                version,
                added_deps,
            } = add_package(args)?;
            (
                "add".to_string(),
                RenderDetail::with_json(
                    summary,
                    json!({
                        "package": package,
                        "version": version,
                        "added_dependencies": added_deps,
                    }),
                ),
            )
        }
        Commands::Remove(args) => {
            let RemoveOutcome {
                summary,
                package,
                removed,
            } = remove_package(args)?;
            (
                "remove".to_string(),
                RenderDetail::with_json(
                    summary,
                    json!({
                        "package": package,
                        "removed": removed,
                    }),
                ),
            )
        }
        Commands::Run(args) => {
            let RunOutcome {
                summary,
                target,
                exit_code,
                pep723_deps,
            } = run_script(args)?;
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
        Commands::X(args) => (
            "x".to_string(),
            stub_detail(
                format!(
                    "package={:?} passthrough={:?}",
                    args.package, args.passthrough
                ),
                json!({"package": args.package, "passthrough": args.passthrough}),
            ),
        ),
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
        Commands::Doctor(args) => (
            "doctor".to_string(),
            stub_detail(
                format!("verbose={}", args.verbose),
                json!({"verbose": args.verbose}),
            ),
        ),
        Commands::Mcp(cmd) => match cmd {
            McpCommands::Serve(args) => (
                "mcp serve".to_string(),
                stub_detail(format!("port={}", args.port), json!({"port": args.port})),
            ),
        },
        Commands::SelfCmd(cmd) => match cmd {
            SelfCommands::Update(args) => (
                "self update".to_string(),
                stub_detail(
                    format!("channel={}", args.channel),
                    json!({"channel": args.channel}),
                ),
            ),
        },
        Commands::Gc(args) => (
            "gc".to_string(),
            stub_detail(
                format!("max_size={:?}", args.max_size),
                json!({"max_size": args.max_size}),
            ),
        ),
        Commands::Python(cmd) => {
            let (subcmd, detail) = handle_python_command(cmd)?;
            (format!("python {}", subcmd), detail)
        }
    };

    let rendered = render(&command, detail, cli.format, start.elapsed());
    println!("{rendered}");
    Ok(())
}

fn render(command: &str, detail: RenderDetail, format: OutputFormat, duration: Duration) -> String {
    match format {
        OutputFormat::Text => format!("pybun {command}: {}", detail.text),
        OutputFormat::Json => {
            let envelope = JsonEnvelope {
                version: "1",
                command: format!("pybun {command}"),
                status: "ok",
                duration_ms: duration.as_millis() as u64,
                detail: detail.json,
                events: Vec::new(),
                diagnostics: Vec::new(),
                trace_id: None,
            };
            serde_json::to_string(&envelope).expect("json render")
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

fn install(args: &crate::cli::InstallArgs) -> Result<InstallOutcome> {
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
    let resolution = resolve(args.requirements.clone(), &index).map_err(|e| match e {
        ResolveError::Missing { name, constraint } => {
            eyre!("missing package {name} matching {constraint}")
        }
        ResolveError::Conflict {
            name,
            existing,
            requested,
        } => eyre!("version conflict for {name}: {existing} vs {requested}"),
    })?;

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
}

impl RenderDetail {
    fn with_json(text: impl Into<String>, json: Value) -> Self {
        Self {
            text: text.into(),
            json,
        }
    }
}

#[derive(serde::Serialize)]
struct JsonEnvelope {
    version: &'static str,
    command: String,
    status: &'static str,
    duration_ms: u64,
    detail: Value,
    events: Vec<Value>,
    diagnostics: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
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

fn run_script(args: &crate::cli::RunArgs) -> Result<RunOutcome> {
    let target = args
        .target
        .as_ref()
        .ok_or_else(|| eyre!("script target is required (e.g., pybun run script.py)"))?;

    // Check if it's a Python file
    let script_path = PathBuf::from(target);

    // Check for -c flag style execution
    if target == "-c" {
        return run_python_code(args);
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

fn run_python_code(args: &crate::cli::RunArgs) -> Result<RunOutcome> {
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

use crate::cache::Cache;
use crate::runtime::{RuntimeManager, supported_versions};

fn handle_python_command(cmd: &PythonCommands) -> Result<(String, RenderDetail)> {
    match cmd {
        PythonCommands::List(args) => python_list(args),
        PythonCommands::Install(args) => python_install(args),
        PythonCommands::Remove(args) => python_remove(args),
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
