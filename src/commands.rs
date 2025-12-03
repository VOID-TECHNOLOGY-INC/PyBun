use crate::cli::{Cli, Commands, McpCommands, OutputFormat, SelfCommands};
use color_eyre::eyre::Result;

pub fn execute(cli: Cli) -> Result<()> {
    let rendered = match &cli.command {
        Commands::Install(args) => {
            render("install", &format!("offline={}", args.offline), cli.format)
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
