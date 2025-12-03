use clap::Parser;
use pybun::{cli::Cli, commands::execute};

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();
    execute(cli)
}
