use crate::cli::{Cli, Commands};

const DEFAULT_STACK_SIZE: usize = 4 * 1024 * 1024;
const MIN_STACK_SIZE: usize = 1024 * 1024;

pub fn runtime_stack_size() -> usize {
    let stack_size = std::env::var("PYBUN_STACK_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .or_else(|| {
            std::env::var("RUST_MIN_STACK")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
        })
        .unwrap_or(DEFAULT_STACK_SIZE);

    if stack_size < MIN_STACK_SIZE {
        DEFAULT_STACK_SIZE
    } else {
        stack_size
    }
}

pub fn should_install_color_eyre(cli: &Cli) -> bool {
    pybun_trace_enabled() || rust_backtrace_enabled() || command_verbose(cli)
}

pub fn requires_tokio_runtime(cli: &Cli) -> bool {
    matches!(
        cli.command,
        Commands::Install(_)
            | Commands::Lock(_)
            | Commands::Mcp(_)
            | Commands::Add(_)
            | Commands::Outdated(_)
            | Commands::Upgrade(_)
            | Commands::Build(_)
    )
}

fn pybun_trace_enabled() -> bool {
    std::env::var_os("PYBUN_TRACE").is_some()
}

fn rust_backtrace_enabled() -> bool {
    std::env::var("RUST_BACKTRACE")
        .map(|value| {
            let trimmed = value.trim();
            !trimmed.is_empty() && trimmed != "0"
        })
        .unwrap_or(false)
}

fn command_verbose(cli: &Cli) -> bool {
    match &cli.command {
        Commands::Test(args) => args.verbose,
        Commands::Doctor(args) => args.verbose,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{requires_tokio_runtime, runtime_stack_size, should_install_color_eyre};
    use crate::cli::{
        Cli, Commands, DoctorArgs, InstallArgs, LockArgs, McpCommands, McpServeArgs, OutputFormat,
        ProgressMode, RunArgs, TestArgs,
    };
    use std::sync::{LazyLock, Mutex};

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn with_env_vars(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _lock = ENV_LOCK.lock().expect("env lock poisoned");
        let saved: Vec<(String, Option<std::ffi::OsString>)> = vars
            .iter()
            .map(|(key, _)| ((*key).to_string(), std::env::var_os(key)))
            .collect();

        for (key, value) in vars {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }

        f();

        for (key, value) in saved {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn test_cli(verbose: bool) -> Cli {
        Cli {
            format: OutputFormat::Text,
            progress: ProgressMode::Auto,
            no_progress: false,
            command: Commands::Test(TestArgs {
                paths: Vec::new(),
                shard: None,
                fail_fast: false,
                pytest_compat: false,
                backend: None,
                discover: false,
                parallel: None,
                filter: None,
                verbose,
                snapshot: false,
                update_snapshots: false,
                snapshot_dir: None,
                passthrough: Vec::new(),
            }),
        }
    }

    fn doctor_cli(verbose: bool) -> Cli {
        Cli {
            format: OutputFormat::Text,
            progress: ProgressMode::Auto,
            no_progress: false,
            command: Commands::Doctor(DoctorArgs {
                verbose,
                bundle: None,
                upload: false,
                upload_url: None,
            }),
        }
    }

    #[test]
    fn installs_color_eyre_for_trace_env() {
        let cli = test_cli(false);
        with_env_vars(
            &[("PYBUN_TRACE", Some("1")), ("RUST_BACKTRACE", None)],
            || {
                assert!(should_install_color_eyre(&cli));
            },
        );
    }

    #[test]
    fn installs_color_eyre_for_backtrace_env() {
        let cli = doctor_cli(false);
        with_env_vars(
            &[("PYBUN_TRACE", None), ("RUST_BACKTRACE", Some("1"))],
            || {
                assert!(should_install_color_eyre(&cli));
            },
        );
    }

    #[test]
    fn installs_color_eyre_for_verbose_flag() {
        let cli = test_cli(true);
        with_env_vars(&[("PYBUN_TRACE", None), ("RUST_BACKTRACE", None)], || {
            assert!(should_install_color_eyre(&cli));
        });
    }

    #[test]
    fn skips_color_eyre_by_default() {
        let cli = test_cli(false);
        with_env_vars(&[("PYBUN_TRACE", None), ("RUST_BACKTRACE", None)], || {
            assert!(!should_install_color_eyre(&cli));
        });
    }

    #[test]
    fn runtime_stack_size_respects_env_override() {
        with_env_vars(&[("PYBUN_STACK_SIZE", Some("2097152"))], || {
            assert_eq!(runtime_stack_size(), 2 * 1024 * 1024);
        });
    }

    #[test]
    fn runtime_stack_size_ignores_too_small_values() {
        with_env_vars(&[("PYBUN_STACK_SIZE", Some("512"))], || {
            assert_eq!(runtime_stack_size(), 4 * 1024 * 1024);
        });
    }

    #[test]
    fn tokio_runtime_required_for_install() {
        let cli = Cli {
            format: OutputFormat::Text,
            progress: ProgressMode::Auto,
            no_progress: false,
            command: Commands::Install(InstallArgs {
                offline: false,
                requirements: Vec::new(),
                index: None,
                lock: "pybun.lockb".into(),
            }),
        };
        assert!(requires_tokio_runtime(&cli));
    }

    #[test]
    fn tokio_runtime_required_for_lock() {
        let cli = Cli {
            format: OutputFormat::Text,
            progress: ProgressMode::Auto,
            no_progress: false,
            command: Commands::Lock(LockArgs {
                script: None,
                offline: false,
                index: None,
            }),
        };
        assert!(requires_tokio_runtime(&cli));
    }

    #[test]
    fn tokio_runtime_required_for_mcp() {
        let cli = Cli {
            format: OutputFormat::Text,
            progress: ProgressMode::Auto,
            no_progress: false,
            command: Commands::Mcp(McpCommands::Serve(McpServeArgs {
                port: 9999,
                stdio: true,
            })),
        };
        assert!(requires_tokio_runtime(&cli));
    }

    #[test]
    fn tokio_runtime_not_required_for_run() {
        let cli = Cli {
            format: OutputFormat::Text,
            progress: ProgressMode::Auto,
            no_progress: false,
            command: Commands::Run(RunArgs {
                target: Some("script.py".to_string()),
                sandbox: false,
                allow_network: false,
                profile: "dev".to_string(),
                passthrough: Vec::new(),
            }),
        };
        assert!(!requires_tokio_runtime(&cli));
    }
}
