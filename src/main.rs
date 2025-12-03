mod cli;
mod commands;

use clap::Parser;
use cli::Cli;
use commands::execute;

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();
    execute(cli)
}
