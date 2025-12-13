use clap::{Args, Parser, Subcommand, ValueEnum};

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

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Install dependencies from lock or project metadata.
    Install(InstallArgs),
    /// Add a package and update lockfile.
    Add(PackageArgs),
    /// Remove a package and update lockfile.
    Remove(PackageArgs),
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
    /// Shard identifier (N/M).
    #[arg(long)]
    pub shard: Option<String>,
    /// Fail fast on first failure.
    #[arg(long)]
    pub fail_fast: bool,
    /// Enable pytest compatibility layer.
    #[arg(long)]
    pub pytest_compat: bool,
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
}

#[derive(Subcommand, Debug)]
pub enum McpCommands {
    /// Start MCP server for programmatic control.
    Serve(McpServeArgs),
}

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
