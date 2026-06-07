use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};

#[derive(Parser, Debug)]
#[command(
    name = "pybun",
    about = "PyBun CLI: fast installer/runtime/tester for Python projects (use --sandbox for untrusted code)",
    version,
    long_about = None
)]
pub struct Cli {
    /// Output format for machine readability.
    #[arg(long, global = true, default_value_t = OutputFormat::Text, value_enum)]
    pub format: OutputFormat,

    /// Progress UI mode (auto hides on non-TTY).
    #[arg(
        long,
        global = true,
        default_value_t = ProgressMode::Auto,
        value_enum,
        env = "PYBUN_PROGRESS"
    )]
    pub progress: ProgressMode,

    /// Disable progress UI.
    #[arg(long = "no-progress", global = true)]
    pub no_progress: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ProgressMode {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new Python project.
    Init(InitArgs),
    /// Install dependencies from lock or project metadata.
    Install(InstallArgs),
    /// Add a package and update lockfile.
    Add(PackageArgs),
    /// Remove a package and update lockfile.
    Remove(PackageArgs),
    /// Lock dependencies for scripts.
    Lock(LockArgs),
    /// Run a script with import/runtime optimizations.
    Run(RunArgs),
    /// Run an ad-hoc package without prior install.
    X(ToolArgs),
    /// Execute test suite with PyBun's fast runner.
    Test(TestArgs),
    /// Build distributable artifacts.
    Build(BuildArgs),
    /// Diagnose environment and produce support bundle.
    Doctor(DoctorArgs),
    /// Run PyBun as an MCP server.
    #[command(subcommand)]
    Mcp(McpCommands),
    /// Self-related commands.
    #[command(name = "self", subcommand)]
    SelfCmd(SelfCommands),
    /// Manage caches.
    Gc(GcArgs),
    /// Manage Python versions (install, list, remove).
    #[command(subcommand)]
    Python(PythonCommands),
    /// Find Python modules using Rust-based module finder.
    #[command(name = "module-find")]
    ModuleFind(ModuleFindArgs),
    /// Configure and generate lazy import settings.
    #[command(name = "lazy-import")]
    LazyImport(LazyImportArgs),
    /// Watch files and reload on changes (dev mode).
    Watch(WatchArgs),
    /// Show or configure launch profiles.
    Profile(ProfileArgs),
    /// Print or validate the CLI JSON schema.
    Schema(SchemaArgs),
    /// Manage telemetry settings (opt-in/opt-out).
    #[command(subcommand)]
    Telemetry(TelemetryCommands),
    /// Check for outdated dependencies.
    Outdated(OutdatedArgs),
    /// Upgrade dependencies within constraints.
    Upgrade(UpgradeArgs),
}

#[derive(Subcommand, Debug)]
pub enum PythonCommands {
    /// List installed and available Python versions.
    List(PythonListArgs),
    /// Install a Python version.
    Install(PythonInstallArgs),
    /// Remove an installed Python version.
    Remove(PythonRemoveArgs),
    /// Show path to Python for a version.
    Which(PythonWhichArgs),
}

#[derive(Args, Debug)]
pub struct PythonListArgs {
    /// Show all available versions (not just installed).
    #[arg(long)]
    pub all: bool,
}

#[derive(Args, Debug)]
pub struct PythonInstallArgs {
    /// Version to install (e.g., 3.11, 3.12.7).
    #[arg(value_name = "VERSION")]
    pub version: String,
}

#[derive(Args, Debug)]
pub struct PythonRemoveArgs {
    /// Version to remove.
    #[arg(value_name = "VERSION")]
    pub version: String,
}

#[derive(Args, Debug)]
pub struct PythonWhichArgs {
    /// Version to look up.
    #[arg(value_name = "VERSION")]
    pub version: Option<String>,
}

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Use offline mode when cache is sufficient.
    #[arg(long)]
    pub offline: bool,
    /// Requirements to install (temporary M1 flag).
    #[arg(long = "require", value_name = "NAME==VERSION")]
    pub requirements: Vec<crate::resolver::Requirement>,
    /// Path to index JSON (temporary M1 flag).
    #[arg(long)]
    pub index: Option<std::path::PathBuf>,
    /// Path to write lockfile.
    #[arg(long, default_value = "pybun.lockb")]
    pub lock: std::path::PathBuf,
}

#[derive(Args, Debug)]
pub struct LockArgs {
    /// Lock dependencies for a PEP 723 script.
    #[arg(long, value_name = "SCRIPT")]
    pub script: Option<std::path::PathBuf>,
    /// Use offline mode when cache is sufficient.
    #[arg(long)]
    pub offline: bool,
    /// Path to index JSON (temporary M1 flag).
    #[arg(long)]
    pub index: Option<std::path::PathBuf>,
}

#[derive(Args, Debug)]
pub struct PackageArgs {
    /// Package name (optionally with version).
    #[arg(value_name = "PACKAGE")]
    pub package: Option<String>,
    /// Use offline mode when cache is sufficient.
    #[arg(long)]
    pub offline: bool,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Script or module to execute. Use -c for inline code.
    #[arg(value_name = "TARGET", allow_hyphen_values = true)]
    pub target: Option<String>,
    /// Run in sandboxed mode for untrusted code.
    #[arg(long)]
    pub sandbox: bool,
    /// Allow network access inside the sandbox (escape hatch).
    #[arg(long)]
    pub allow_network: bool,
    /// Allow reading from a path inside the sandbox (can be specified multiple times).
    /// When set, reads outside these paths are blocked. Python stdlib is always allowed.
    #[arg(long, value_name = "PATH")]
    pub allow_read: Vec<String>,
    /// Allow writing to a path inside the sandbox (can be specified multiple times).
    /// When set, writes outside these paths are blocked.
    #[arg(long, value_name = "PATH")]
    pub allow_write: Vec<String>,
    /// Optional profile (dev/prod/benchmark).
    #[arg(long, default_value = "dev")]
    pub profile: String,
    /// Pass additional args to the target.
    #[arg(last = true)]
    pub passthrough: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ToolArgs {
    /// Package to execute temporarily.
    #[arg(value_name = "PACKAGE")]
    pub package: Option<String>,
    /// Arguments to forward to the tool.
    #[arg(last = true)]
    pub passthrough: Vec<String>,
}

#[derive(Args, Debug)]
pub struct TestArgs {
    /// Test file(s) or directory to run. Defaults to current directory.
    #[arg(value_name = "PATH")]
    pub paths: Vec<std::path::PathBuf>,
    /// Shard identifier (N/M) for distributed testing.
    #[arg(long)]
    pub shard: Option<String>,
    /// Stop on first failure.
    #[arg(long, short = 'x')]
    pub fail_fast: bool,
    /// Enable pytest compatibility layer.
    #[arg(long)]
    pub pytest_compat: bool,
    /// Test runner backend (pytest or unittest). Auto-detected if not specified.
    #[arg(long, value_enum)]
    pub backend: Option<TestBackend>,
    /// Only discover tests without running them.
    #[arg(long)]
    pub discover: bool,
    /// Run tests in parallel (number of workers).
    #[arg(long, short = 'j')]
    pub parallel: Option<usize>,
    /// Filter tests by name pattern.
    #[arg(long, short = 'k')]
    pub filter: Option<String>,
    /// Show verbose output including fixture information.
    #[arg(long, short = 'v')]
    pub verbose: bool,
    /// Enable snapshot testing.
    #[arg(long)]
    pub snapshot: bool,
    /// Update snapshots instead of comparing them.
    #[arg(long)]
    pub update_snapshots: bool,
    /// Directory for snapshot files (default: __snapshots__).
    #[arg(long, value_name = "DIR")]
    pub snapshot_dir: Option<std::path::PathBuf>,
    /// Additional arguments to pass to the test runner.
    #[arg(last = true)]
    pub passthrough: Vec<String>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum TestBackend {
    Pytest,
    Unittest,
    /// Native Rust-based parallel executor (pybun-native).
    Pybun,
}

#[derive(Args, Debug)]
pub struct BuildArgs {
    /// Emit SBOM along with artifacts.
    #[arg(long)]
    pub sbom: bool,
}

#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Include verbose logs in bundle.
    #[arg(long)]
    pub verbose: bool,
    /// Write support bundle to a directory.
    #[arg(long, value_name = "PATH")]
    pub bundle: Option<std::path::PathBuf>,
    /// Upload support bundle to the configured endpoint.
    #[arg(long)]
    pub upload: bool,
    /// Override the support bundle upload endpoint.
    #[arg(long, value_name = "URL")]
    pub upload_url: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum McpCommands {
    /// Start MCP server for programmatic control.
    Serve(McpServeArgs),
}

#[derive(Args, Debug)]
pub struct SchemaArgs {
    #[command(subcommand)]
    pub command: Option<SchemaCommands>,
}

#[derive(Subcommand, Debug)]
pub enum SchemaCommands {
    /// Print the JSON schema for CLI output.
    Print(SchemaPrintArgs),
    /// Check the JSON schema against the frozen v1 definition.
    Check(SchemaCheckArgs),
}

#[derive(Args, Debug)]
pub struct SchemaPrintArgs {}

#[derive(Args, Debug)]
pub struct SchemaCheckArgs {
    /// Optional path to compare against the embedded schema.
    #[arg(long, value_name = "PATH")]
    pub path: Option<std::path::PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum TelemetryCommands {
    /// Show current telemetry status.
    Status(TelemetryStatusArgs),
    /// Enable telemetry collection.
    Enable(TelemetryEnableArgs),
    /// Disable telemetry collection.
    Disable(TelemetryDisableArgs),
}

#[derive(Args, Debug)]
pub struct TelemetryStatusArgs {}

#[derive(Args, Debug)]
pub struct TelemetryEnableArgs {}

#[derive(Args, Debug)]
pub struct TelemetryDisableArgs {}

#[derive(Args, Debug)]
pub struct McpServeArgs {
    /// Port to bind (for HTTP mode).
    #[arg(long, default_value_t = 9999)]
    pub port: u16,
    /// Use stdio mode for MCP communication.
    #[arg(long)]
    pub stdio: bool,
}

#[derive(Subcommand, Debug)]
pub enum SelfCommands {
    /// Update PyBun binary with signature verification.
    Update(SelfUpdateArgs),
}

#[derive(Args, Debug)]
pub struct SelfUpdateArgs {
    /// Channel to update from (stable/nightly).
    #[arg(long, default_value = "stable")]
    pub channel: String,
    /// Check for updates without installing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct GcArgs {
    /// Maximum cache size (e.g., 10G); LRU eviction if exceeded.
    #[arg(long)]
    pub max_size: Option<String>,
    /// Preview what would be deleted without actually deleting.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct ModuleFindArgs {
    /// Module name to find (e.g., "os.path", "numpy.core").
    #[arg(value_name = "MODULE")]
    pub module: Option<String>,
    /// Search path(s) for modules. Can be specified multiple times.
    #[arg(long = "path", short = 'p', value_name = "PATH")]
    pub paths: Vec<std::path::PathBuf>,
    /// Scan directory and list all modules instead of finding a specific one.
    #[arg(long)]
    pub scan: bool,
    /// Show timing information for benchmarking.
    #[arg(long)]
    pub benchmark: bool,
    /// Number of threads for parallel scanning.
    #[arg(long, default_value = "4")]
    pub threads: usize,
}

#[derive(Args, Debug)]
pub struct LazyImportArgs {
    /// Generate Python code for lazy import injection.
    #[arg(long)]
    pub generate: bool,
    /// Check if a module would be lazily imported.
    #[arg(long, value_name = "MODULE")]
    pub check: Option<String>,
    /// Show current configuration.
    #[arg(long)]
    pub show_config: bool,
    /// Add module to allowlist.
    #[arg(long = "allow", value_name = "MODULE")]
    pub allow: Vec<String>,
    /// Add module to denylist.
    #[arg(long = "deny", value_name = "MODULE")]
    pub deny: Vec<String>,
    /// Enable logging of lazy imports in generated code.
    #[arg(long)]
    pub log_imports: bool,
    /// Disable fallback to CPython import.
    #[arg(long)]
    pub no_fallback: bool,
    /// Output file for generated Python code.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<std::path::PathBuf>,
}

#[derive(Args, Debug)]
pub struct WatchArgs {
    /// Script or command to run on file changes.
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,
    /// Paths to watch (can be specified multiple times).
    #[arg(long = "path", short = 'p', value_name = "PATH")]
    pub paths: Vec<std::path::PathBuf>,
    /// File patterns to include (e.g., "*.py").
    #[arg(long = "include", value_name = "PATTERN")]
    pub include: Vec<String>,
    /// File patterns to exclude (e.g., "__pycache__").
    #[arg(long = "exclude", value_name = "PATTERN")]
    pub exclude: Vec<String>,
    /// Debounce delay in milliseconds.
    #[arg(long, default_value = "300")]
    pub debounce: u64,
    /// Clear terminal before each reload.
    #[arg(long)]
    pub clear: bool,
    /// Show configuration without starting watcher.
    #[arg(long)]
    pub show_config: bool,
    /// Generate shell command for external watcher.
    #[arg(long)]
    pub shell_command: bool,
    /// Preview what would be watched without actually starting (for testing).
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct ProfileArgs {
    /// Profile to show or set (dev, prod, benchmark).
    #[arg(value_name = "PROFILE")]
    pub profile: Option<String>,
    /// List all available profiles.
    #[arg(long)]
    pub list: bool,
    /// Show detailed profile configuration.
    #[arg(long)]
    pub show: bool,
    /// Compare two profiles.
    #[arg(long, value_name = "PROFILE")]
    pub compare: Option<String>,
    /// Export profile to a file.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<std::path::PathBuf>,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Project name (defaults to directory name).
    #[arg(long)]
    pub name: Option<String>,
    /// Project description.
    #[arg(long)]
    pub description: Option<String>,
    /// Python version requirement.
    #[arg(long)]
    pub python: Option<String>,
    /// Author name and email.
    #[arg(long)]
    pub author: Option<String>,
    /// Project template (minimal or package).
    #[arg(long, value_enum, default_value_t = InitTemplate::Minimal)]
    pub template: InitTemplate,
    /// Accept defaults without prompting.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum InitTemplate {
    /// Flat layout with just pyproject.toml.
    Minimal,
    /// Source layout with src/<package>/__init__.py.
    Package,
}

#[derive(Args, Debug)]
pub struct OutdatedArgs {
    /// Path to index JSON (uses PyPI if not specified).
    #[arg(long)]
    pub index: Option<std::path::PathBuf>,
    /// Use offline mode when cache is sufficient.
    #[arg(long)]
    pub offline: bool,
}

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    /// Package(s) to upgrade (upgrades all if not specified).
    #[arg(value_name = "PACKAGE")]
    pub packages: Vec<String>,
    /// Path to index JSON (uses PyPI if not specified).
    #[arg(long)]
    pub index: Option<std::path::PathBuf>,
    /// Use offline mode when cache is sufficient.
    #[arg(long)]
    pub offline: bool,
    /// Preview changes without updating lockfile.
    #[arg(long)]
    pub dry_run: bool,
    /// Path to lockfile.
    #[arg(long, default_value = "pybun.lockb")]
    pub lock: std::path::PathBuf,
}

/// Render a JSON help envelope when the raw CLI arguments request both
/// `--help`/`-h` and `--format=json`. Clap intercepts `--help` and prints
/// plain text before our normal command dispatch ever runs, so this must be
/// checked before `Cli::parse()` is called.
///
/// Returns `None` when the arguments are not a JSON help request, in which
/// case normal `Cli::parse()` handling (including clap's text help) applies.
pub fn json_help_envelope(args: &[String]) -> Option<String> {
    let (wants_help, wants_json, command, path) = scan_help_request(args);
    if !(wants_help && wants_json) {
        return None;
    }

    let mut command_name = vec!["pybun".to_string()];
    command_name.extend(path);
    command_name.push("--help".to_string());

    Some(render_help_envelope(&command, &command_name.join(" ")))
}

/// Scan raw CLI arguments for `--help`/`-h`, `--format=json`, and the
/// subcommand chain (e.g. `pybun mcp serve --help` resolves to the `serve`
/// `clap::Command` and path `["mcp", "serve"]`).
///
/// The subcommand chain is resolved by walking the `clap::Command` tree
/// alongside the argument scan — a token only extends the path when it names
/// an actual subcommand of the command reached so far. This avoids treating
/// option *values* (e.g. the `foo.py` in `lock --script foo.py`) as path
/// segments, which a naive "every non-flag token is a subcommand" scan would
/// misidentify as the target command.
///
/// Global value-taking flags (`--format`, `--progress`) are recognized and
/// their values skipped explicitly; any other unrecognized token simply fails
/// to match a subcommand and is ignored, so the scan keeps looking for the
/// help/format flags without derailing the path.
fn scan_help_request(args: &[String]) -> (bool, bool, clap::Command, Vec<String>) {
    let mut wants_help = false;
    let mut wants_json = false;
    let mut path = Vec::new();
    let mut command = Cli::command();

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => wants_help = true,
            "--format" => {
                if iter.peek().is_some_and(|v| v.as_str() == "json") {
                    wants_json = true;
                }
                iter.next();
            }
            "--format=json" => wants_json = true,
            "--progress" => {
                iter.next();
            }
            s if s.starts_with('-') => {}
            s => {
                let next = command
                    .get_subcommands()
                    .find(|sub| sub.get_name() == s)
                    .cloned();
                if let Some(sub) = next {
                    path.push(s.to_string());
                    command = sub;
                }
                // Otherwise this is a positional value (or an option value we
                // don't special-case) — ignore it and keep scanning for flags.
            }
        }
    }

    (wants_help, wants_json, command, path)
}

fn render_help_envelope(command: &clap::Command, command_name: &str) -> String {
    let detail = command_help_json(command);
    let envelope = crate::schema::JsonEnvelope::new(
        command_name,
        crate::schema::Status::Ok,
        std::time::Duration::default(),
        detail,
    );
    envelope.to_json()
}

fn command_help_json(command: &clap::Command) -> Value {
    let mut cmd = command.clone();
    let usage = cmd.render_usage().to_string();

    let args: Vec<Value> = cmd
        .get_arguments()
        .filter(|a| !matches!(a.get_id().as_str(), "help" | "version"))
        .map(arg_help_json)
        .collect();

    let subcommands: Vec<Value> = cmd
        .get_subcommands()
        .map(|sub| {
            json!({
                "name": sub.get_name(),
                "about": sub.get_about().map(|s| s.to_string()),
            })
        })
        .collect();

    json!({
        "name": cmd.get_name(),
        "about": cmd.get_about().map(|s| s.to_string()),
        "long_about": cmd.get_long_about().map(|s| s.to_string()),
        "usage": usage,
        "args": args,
        "subcommands": subcommands,
    })
}

fn arg_help_json(arg: &clap::Arg) -> Value {
    json!({
        "name": arg.get_id().as_str(),
        "help": arg.get_help().map(|s| s.to_string()),
        "long": arg.get_long(),
        "short": arg.get_short().map(|c| c.to_string()),
        "required": arg.is_required_set(),
        "takes_value": arg.get_num_args().is_some_and(|n| n.takes_values()),
        "default_values": arg
            .get_default_values()
            .iter()
            .map(|v| v.to_string_lossy().to_string())
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod help_tests {
    use super::*;

    #[test]
    fn detects_top_level_json_help_request() {
        let args: Vec<String> = ["--format=json", "--help"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (wants_help, wants_json, _, path) = scan_help_request(&args);
        assert!(wants_help);
        assert!(wants_json);
        assert!(path.is_empty());
    }

    #[test]
    fn detects_subcommand_json_help_request_with_split_format_flag() {
        let args: Vec<String> = ["mcp", "serve", "--format", "json", "-h"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (wants_help, wants_json, _, path) = scan_help_request(&args);
        assert!(wants_help);
        assert!(wants_json);
        assert_eq!(path, vec!["mcp".to_string(), "serve".to_string()]);
    }

    #[test]
    fn ignores_text_format_help_requests() {
        let args: Vec<String> = ["install", "--help"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (wants_help, wants_json, _, _) = scan_help_request(&args);
        assert!(wants_help);
        assert!(!wants_json);
    }

    #[test]
    fn renders_top_level_json_help_envelope() {
        let args: Vec<String> = ["--help", "--format=json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let output = json_help_envelope(&args).expect("expected JSON help envelope");
        let value: Value = serde_json::from_str(&output).expect("valid JSON");
        assert_eq!(value["command"], "pybun --help");
        assert_eq!(value["status"], "ok");
        assert_eq!(value["detail"]["name"], "pybun");
        assert!(
            value["detail"]["subcommands"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["name"] == "install")
        );
    }

    #[test]
    fn renders_subcommand_json_help_envelope() {
        let args: Vec<String> = ["install", "--format=json", "--help"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let output = json_help_envelope(&args).expect("expected JSON help envelope");
        let value: Value = serde_json::from_str(&output).expect("valid JSON");
        assert_eq!(value["command"], "pybun install --help");
        assert_eq!(value["detail"]["name"], "install");
        assert!(
            value["detail"]["args"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["name"] == "offline")
        );
    }

    #[test]
    fn returns_none_when_not_a_help_request() {
        let args: Vec<String> = ["install", "--format=json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(json_help_envelope(&args).is_none());
    }

    #[test]
    fn ignores_option_values_that_resemble_subcommand_names() {
        // `--script foo.py` must not be mistaken for a subcommand path segment —
        // the resolved command should remain `lock`, not descend into `foo.py`.
        let args: Vec<String> = ["lock", "--script", "foo.py", "--format=json", "--help"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (wants_help, wants_json, command, path) = scan_help_request(&args);
        assert!(wants_help);
        assert!(wants_json);
        assert_eq!(path, vec!["lock".to_string()]);
        assert_eq!(command.get_name(), "lock");
    }

    #[test]
    fn renders_help_envelope_with_correct_command_name_when_option_value_looks_like_a_subcommand() {
        let args: Vec<String> = ["lock", "--script", "foo.py", "--format=json", "--help"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let output = json_help_envelope(&args).expect("expected JSON help envelope");
        let value: Value = serde_json::from_str(&output).expect("valid JSON");
        assert_eq!(value["command"], "pybun lock --help");
        assert_eq!(value["detail"]["name"], "lock");
    }
}
