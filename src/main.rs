use clap::Parser;
use color_eyre::eyre::{Result, WrapErr, eyre};
use pybun::{cli::Cli, commands::execute, entry, support_bundle};

fn main() -> Result<()> {
    let cli = Cli::parse();
    if entry::should_install_color_eyre(&cli) {
        color_eyre::install()?;
    }
    support_bundle::install_crash_hook();

    if !entry::requires_tokio_runtime(&cli) {
        return futures::executor::block_on(execute(cli));
    }

    let stack_size = entry::runtime_stack_size();
    let main2 = move || -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .thread_stack_size(stack_size)
            .build()
            .wrap_err("failed to build tokio runtime")?;
        let result = runtime.block_on(execute(cli));
        runtime.shutdown_background();
        result
    };

    let handle = std::thread::Builder::new()
        .name("pybun-main".to_string())
        .stack_size(stack_size)
        .spawn(main2)
        .wrap_err("tokio executor thread spawn failed")?;

    handle
        .join()
        .map_err(|_| eyre!("tokio executor thread panicked"))?
}
