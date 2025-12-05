use crate::cli::{Cli, Commands, McpCommands, OutputFormat, SelfCommands};
use crate::lockfile::{Lockfile, Package, PackageSource};
use crate::resolver::{InMemoryIndex, ResolveError, resolve};
use color_eyre::eyre::{Result, eyre};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

pub fn execute(cli: Cli) -> Result<()> {
    let rendered = match &cli.command {
        Commands::Install(args) => {
            let detail = install(args)?;
            render("install", &detail, cli.format)
        }
        Commands::Add(args) => render(
            "add",
            &format!("package={:?} offline={}", args.package, args.offline),
            cli.format,
        ),
        Commands::Remove(args) => render(
            "remove",
            &format!("package={:?} offline={}", args.package, args.offline),
            cli.format,
        ),
        Commands::Run(args) => render(
            "run",
            &format!(
                "target={:?} sandbox={} profile={} passthrough={:?}",
                args.target, args.sandbox, args.profile, args.passthrough
            ),
            cli.format,
        ),
        Commands::X(args) => render(
            "x",
            &format!(
                "package={:?} passthrough={:?}",
                args.package, args.passthrough
            ),
            cli.format,
        ),
        Commands::Test(args) => render(
            "test",
            &format!(
                "shard={:?} fail_fast={} pytest_compat={}",
                args.shard, args.fail_fast, args.pytest_compat
            ),
            cli.format,
        ),
        Commands::Build(args) => render("build", &format!("sbom={}", args.sbom), cli.format),
        Commands::Doctor(args) => {
            render("doctor", &format!("verbose={}", args.verbose), cli.format)
        }
        Commands::Mcp(cmd) => match cmd {
            McpCommands::Serve(args) => {
                render("mcp serve", &format!("port={}", args.port), cli.format)
            }
        },
        Commands::SelfCmd(cmd) => match cmd {
            SelfCommands::Update(args) => render(
                "self update",
                &format!("channel={}", args.channel),
                cli.format,
            ),
        },
        Commands::Gc(args) => render("gc", &format!("max_size={:?}", args.max_size), cli.format),
    };

    println!("{rendered}");
    Ok(())
}

fn render(command: &str, detail: &str, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => format!("pybun {command} (stub): {detail}"),
        OutputFormat::Json => {
            format!(r#"{{"command":"pybun {command}","status":"stub","detail":"{detail}"}}"#)
        }
    }
}

fn install(args: &crate::cli::InstallArgs) -> Result<String> {
    if args.requirements.is_empty() {
        return Err(eyre!(
            "no requirements provided (temporary flag --require needed)"
        ));
    }
    let index_path = args
        .index
        .clone()
        .ok_or_else(|| eyre!("index path is required for now (--index)"))?;

    let pkgs = load_index(&index_path)?;
    let index = InMemoryIndex::from_packages(pkgs);
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

    Ok(format!(
        "resolved {} packages -> {}",
        lock.packages.len(),
        args.lock.display()
    ))
}

#[derive(Debug, Deserialize)]
pub struct IndexPackage {
    name: String,
    version: String,
    dependencies: Vec<String>,
}

fn load_index(path: &PathBuf) -> Result<Vec<IndexPackage>> {
    let data = fs::read_to_string(path)?;
    let parsed: Vec<IndexPackage> = serde_json::from_str(&data)?;
    Ok(parsed)
}

impl InMemoryIndex {
    pub fn from_packages(pkgs: Vec<IndexPackage>) -> Self {
        let mut index = InMemoryIndex::default();
        for pkg in pkgs {
            index.add(pkg.name, pkg.version, pkg.dependencies);
        }
        index
    }
}
