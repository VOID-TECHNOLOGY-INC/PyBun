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
}

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Use offline mode when cache is sufficient.
    #[arg(long)]
    pub offline: bool,
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
    /// Script or module to execute.
    #[arg(value_name = "TARGET")]
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
    /// Port to bind.
    #[arg(long, default_value_t = 9999)]
    pub port: u16,
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
}

#[derive(Args, Debug)]
pub struct GcArgs {
    /// Maximum cache size (e.g., 10G); LRU eviction if exceeded.
    #[arg(long)]
    pub max_size: Option<String>,
}
