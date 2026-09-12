use crate::build::{BuildBackend, BuildCache};
use crate::cli::{
    Cli, Commands, McpCommands, OutputFormat, ProgressMode, PythonCommands, SchemaArgs,
    SchemaCommands, SelfCommands, TelemetryCommands,
};
use crate::env::find_python_env;
use crate::progress::{ProgressConfig, ProgressDriver};
use crate::project::Project;
use crate::sandbox;
use crate::sbom;
use crate::schema::{Diagnostic, Event, EventCollector, EventType, JsonEnvelope, Status};
use color_eyre::eyre::{Result, eyre};
use serde_json::{Value, json};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::Duration;

mod install;
use install::{AddOutcome, LockOutcome, RemoveOutcome};
pub(crate) use install::{InstallOutcome, RunOutcome, install};
mod dispatch;
pub use dispatch::execute;
mod maintenance;
mod project;
mod python;
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
