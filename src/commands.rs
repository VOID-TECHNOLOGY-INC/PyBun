use crate::cli::{Cli, Commands, McpCommands, OutputFormat, SelfCommands};
use crate::index::load_index_from_path;
use crate::lockfile::{Lockfile, Package, PackageSource};
use crate::resolver::{ResolveError, resolve};
use color_eyre::eyre::{Result, eyre};
use serde_json::{Value, json};
use std::path::PathBuf;
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
        Commands::Add(args) => (
            "add".to_string(),
            stub_detail(
                format!("package={:?} offline={}", args.package, args.offline),
                json!({"package": args.package, "offline": args.offline}),
            ),
        ),
        Commands::Remove(args) => (
            "remove".to_string(),
            stub_detail(
                format!("package={:?} offline={}", args.package, args.offline),
                json!({"package": args.package, "offline": args.offline}),
            ),
        ),
        Commands::Run(args) => (
            "run".to_string(),
            stub_detail(
                format!(
                    "target={:?} sandbox={} profile={} passthrough={:?}",
                    args.target, args.sandbox, args.profile, args.passthrough
                ),
                json!({
                    "target": args.target,
                    "sandbox": args.sandbox,
                    "profile": args.profile,
                    "passthrough": args.passthrough,
                }),
            ),
        ),
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
        ResolveError::Missing { name, .. } => eyre!("missing package {name}"),
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
            dependencies: pkg
                .dependencies
                .iter()
                .map(|d| format!("{}=={}", d.name, d.version))
                .collect(),
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
