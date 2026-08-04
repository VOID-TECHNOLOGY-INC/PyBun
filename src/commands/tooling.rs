use super::RenderDetail;
use crate::cli::{LazyImportArgs, ModuleFindArgs, ProfileArgs, WatchArgs};
use crate::env::find_python_env;
#[cfg(feature = "native-watch")]
use crate::hot_reload::run_native_watch_loop;
#[cfg(not(feature = "native-watch"))]
use crate::hot_reload::run_polling_watch_loop;
use crate::hot_reload::{HotReloadConfig, HotReloadWatcher, generate_shell_watcher_command};
use crate::lazy_import::{
    LazyImportConfig, LazyImportDecision, generate_lazy_import_python_code_with_module_name,
};
use crate::module_finder::{ModuleFinder, ModuleFinderConfig};
use crate::profiles::{Profile, ProfileConfig, ProfileManager};
use crate::release_manifest::{ReleaseManifest, current_release_target};
use crate::schema::EventCollector;
use crate::self_update::apply_update_for_asset;
use color_eyre::eyre::{Result, eyre};
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

// ---------------------------------------------------------------------------
// pybun module-find (Rust-based module finder)
// ---------------------------------------------------------------------------

pub(super) fn run_module_find(
    args: &ModuleFindArgs,
    collector: &mut EventCollector,
) -> Result<RenderDetail> {
    // Build configuration
    let config = ModuleFinderConfig {
        enabled: true,
        search_paths: if args.paths.is_empty() {
            // Default to current directory if no paths specified
            vec![std::env::current_dir()?]
        } else {
            args.paths.clone()
        },
        threads: args.threads,
        cache_enabled: true,
        ..Default::default()
    };

    let finder = ModuleFinder::new(config);

    if args.scan {
        // Scan mode: list all modules in the search paths
        collector.info("Scanning for modules...");

        let crate::module_finder::ScanResult {
            modules,
            duration_us,
        } = finder.parallel_scan_timed(&finder.config().search_paths.clone());

        let summary = format!("Found {} modules", modules.len());

        let modules_json: Vec<Value> = modules
            .iter()
            .map(|m| {
                json!({
                    "name": m.name,
                    "path": m.path.display().to_string(),
                    "module_type": format!("{:?}", m.module_type),
                    "search_path": m.search_path.display().to_string(),
                })
            })
            .collect();

        let text_output = if modules.is_empty() {
            "No modules found".to_string()
        } else {
            modules
                .iter()
                .map(|m| format!("  {} ({:?}): {}", m.name, m.module_type, m.path.display()))
                .collect::<Vec<_>>()
                .join("\n")
        };

        return Ok(RenderDetail::with_json(
            if args.benchmark {
                format!("{}\n{}\nduration_us: {}", summary, text_output, duration_us)
            } else {
                text_output
            },
            json!({
                "modules": modules_json,
                "count": modules.len(),
                "duration_us": duration_us,
                "search_paths": finder.config().search_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            }),
        ));
    }

    // Find mode: find a specific module
    let module_name = args
        .module
        .as_ref()
        .ok_or_else(|| eyre!("module name is required (or use --scan to list all modules)"))?;

    collector.info(format!("Finding module: {}", module_name));

    let result = finder.find_module(module_name);

    match result.module {
        Some(module_info) => {
            let summary = format!(
                "Found {} at {}",
                module_info.name,
                module_info.path.display()
            );

            let text_output = if args.benchmark {
                format!(
                    "{}\n  Type: {:?}\n  Search path: {}\n  Duration: {}µs",
                    summary,
                    module_info.module_type,
                    module_info.search_path.display(),
                    result.duration_us
                )
            } else {
                format!(
                    "{}\n  Type: {:?}\n  Search path: {}",
                    summary,
                    module_info.module_type,
                    module_info.search_path.display()
                )
            };

            Ok(RenderDetail::with_json(
                text_output,
                json!({
                    "found": true,
                    "name": module_info.name,
                    "path": module_info.path.display().to_string(),
                    "module_type": format!("{:?}", module_info.module_type),
                    "search_path": module_info.search_path.display().to_string(),
                    "searched_paths": result.searched_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                    "duration_us": result.duration_us,
                }),
            ))
        }
        None => {
            let text_output = format!(
                "Module '{}' not found\nSearched paths:\n{}",
                module_name,
                result
                    .searched_paths
                    .iter()
                    .map(|p| format!("  {}", p.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            );

            Ok(RenderDetail::with_json(
                text_output,
                json!({
                    "found": false,
                    "name": module_name,
                    "searched_paths": result.searched_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                    "duration_us": result.duration_us,
                }),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// pybun lazy-import
// ---------------------------------------------------------------------------

pub(super) fn run_lazy_import(
    args: &LazyImportArgs,
    collector: &mut EventCollector,
) -> Result<RenderDetail> {
    // Build configuration
    let mut config = LazyImportConfig::with_defaults();
    config.log_imports = args.log_imports;
    config.fallback_to_cpython = !args.no_fallback;

    // Apply allowlist
    for module in &args.allow {
        config.allow(module);
    }

    // Apply denylist
    for module in &args.deny {
        config.deny(module);
    }

    // Handle --check mode
    if let Some(module_name) = &args.check {
        let decision = config.should_lazy_import(module_name);
        let decision_str = match decision {
            LazyImportDecision::Lazy => "lazy",
            LazyImportDecision::Eager => "eager",
            LazyImportDecision::Denied => "denied",
        };

        let text = format!(
            "Module '{}' would be imported: {}",
            module_name, decision_str
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "module": module_name,
                "decision": decision_str,
                "is_denied": config.is_denied(module_name),
                "is_allowed": config.is_allowed(module_name),
            }),
        ));
    }

    // Handle --show-config mode
    if args.show_config {
        collector.info("Showing lazy import configuration");

        let denylist: Vec<_> = config.denylist.iter().cloned().collect();
        let allowlist: Vec<_> = config.allowlist.iter().cloned().collect();

        let text = format!(
            "Lazy Import Configuration:\n  Enabled: {}\n  Fallback: {}\n  Log imports: {}\n  Denylist: {} modules\n  Allowlist: {} modules",
            config.enabled,
            config.fallback_to_cpython,
            config.log_imports,
            denylist.len(),
            allowlist.len()
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "enabled": config.enabled,
                "fallback_to_cpython": config.fallback_to_cpython,
                "log_imports": config.log_imports,
                "denylist": denylist,
                "allowlist": allowlist,
            }),
        ));
    }

    // Handle --generate mode
    if args.generate {
        // Extract module name from output path to add to denylist
        // This prevents recursion when the generated module imports itself (Issue #101)
        let output_module_name = args.output.as_ref().and_then(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(|s| s.to_string())
        });

        let code = generate_lazy_import_python_code_with_module_name(
            &config,
            output_module_name.as_deref(),
        );

        if let Some(output_path) = &args.output {
            std::fs::write(output_path, &code)
                .map_err(|e| eyre!("failed to write output file: {}", e))?;

            let text = format!("Generated lazy import code to {}", output_path.display());
            collector.info(&text);

            return Ok(RenderDetail::with_json(
                text,
                json!({
                    "output_file": output_path.display().to_string(),
                    "output_module": output_module_name,
                    "code_length": code.len(),
                    "denylist_count": config.denylist.len(),
                    "allowlist_count": config.allowlist.len(),
                }),
            ));
        }

        // Print to stdout
        return Ok(RenderDetail::with_json(
            code.clone(),
            json!({
                "code": code,
                "code_length": code.len(),
                "denylist_count": config.denylist.len(),
                "allowlist_count": config.allowlist.len(),
            }),
        ));
    }

    // Default: show help
    let text = "Usage: pybun lazy-import [OPTIONS]\n\nOptions:\n  --generate      Generate Python code for lazy import injection\n  --check MODULE  Check if a module would be lazily imported\n  --show-config   Show current configuration\n  --allow MODULE  Add module to allowlist\n  --deny MODULE   Add module to denylist\n  --log-imports   Enable logging in generated code\n  --no-fallback   Disable fallback to CPython import\n  -o, --output    Output file for generated Python code";

    Ok(RenderDetail::with_json(
        text,
        json!({
            "help": true,
            "available_options": ["--generate", "--check", "--show-config", "--allow", "--deny", "--log-imports", "--no-fallback", "-o"],
        }),
    ))
}

// ---------------------------------------------------------------------------
// pybun watch (hot reload)
// ---------------------------------------------------------------------------

pub(super) fn run_watch(args: &WatchArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
    // Build configuration
    let mut config = HotReloadConfig::dev();

    // Set watch paths
    if !args.paths.is_empty() {
        config.watch_paths = args.paths.clone();
    } else {
        config.watch_paths = vec![std::env::current_dir()?];
    }

    // Set include patterns
    if !args.include.is_empty() {
        config.include_patterns = args.include.clone();
    }

    // Set exclude patterns (merge with defaults)
    for pattern in &args.exclude {
        if !config.exclude_patterns.contains(pattern) {
            config.exclude_patterns.push(pattern.clone());
        }
    }

    config.debounce_ms = args.debounce;
    config.clear_on_reload = args.clear;

    // Handle --show-config mode
    if args.show_config {
        collector.info("Showing watch configuration");

        let stats = HotReloadWatcher::new(config.clone()).stats();

        let text = format!(
            "Watch Configuration:\n  Paths: {:?}\n  Include patterns: {:?}\n  Exclude patterns: {} patterns\n  Debounce: {}ms\n  Clear on reload: {}",
            config.watch_paths,
            config.include_patterns,
            config.exclude_patterns.len(),
            config.debounce_ms,
            config.clear_on_reload
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "watch_paths": config.watch_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "include_patterns": config.include_patterns,
                "exclude_patterns": config.exclude_patterns,
                "debounce_ms": config.debounce_ms,
                "clear_on_reload": config.clear_on_reload,
                "stats": {
                    "is_running": stats.is_running,
                    "watched_paths": stats.watched_paths,
                    "include_patterns": stats.include_patterns,
                    "exclude_patterns": stats.exclude_patterns,
                },
            }),
        ));
    }

    // Handle --shell-command mode
    if args.shell_command {
        let target = args
            .target
            .as_ref()
            .map(|t| format!("pybun run {}", t))
            .unwrap_or_else(|| "echo 'File changed'".to_string());

        let cmd = generate_shell_watcher_command(&config, &target);

        collector.info("Generated shell watcher command");

        return Ok(RenderDetail::with_json(
            cmd.clone(),
            json!({
                "shell_command": cmd,
                "target": target,
                "watch_paths": config.watch_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            }),
        ));
    }

    // Default mode: start watching
    let target = args.target.as_ref();

    if target.is_none() {
        let native_available = HotReloadWatcher::native_watch_available();
        let text = format!(
            "Usage: pybun watch [TARGET] [OPTIONS]\n\n\
            Watch for file changes and re-run a script.\n\n\
            Examples:\n  \
            pybun watch main.py              # Watch current dir, run main.py on changes\n  \
            pybun watch main.py -p src       # Watch src directory\n  \
            pybun watch --show-config        # Show configuration\n  \
            pybun watch --shell-command      # Generate external watcher command\n\n\
            Options:\n  \
            -p, --path PATH          Paths to watch\n  \
            --include PATTERN        Include patterns (e.g., *.py)\n  \
            --exclude PATTERN        Exclude patterns\n  \
            --debounce MS            Debounce delay in ms (default: 300)\n  \
            --clear                  Clear terminal on reload\n\n\
            Native file watching: {}",
            if native_available {
                "enabled"
            } else {
                "disabled (build with --features native-watch)"
            }
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "help": true,
                "status": "awaiting_target",
                "native_watch_available": native_available,
            }),
        ));
    }

    let Some(target_script) = target else {
        return Err(eyre!("watch target is required"));
    };
    let mut watcher = HotReloadWatcher::new(config.clone());

    // Add watch paths
    for path in &config.watch_paths {
        watcher.add_watch_path(path.clone());
    }

    let stats = watcher.stats();

    // Check for dry-run mode (from CLI flag or environment variable for testing)
    let dry_run = args.dry_run || std::env::var("PYBUN_WATCH_DRY_RUN").is_ok();

    // If dry-run, just show preview without starting watcher
    if dry_run {
        let native_available = HotReloadWatcher::native_watch_available();
        let text = format!(
            "Would watch {} paths for changes to run: {}\n\
            Patterns: {} include, {} exclude\n\
            Debounce: {}ms\n\
            Native watching: {}",
            stats.watched_paths,
            target_script,
            stats.include_patterns,
            stats.exclude_patterns,
            stats.debounce_ms,
            if native_available {
                "available"
            } else {
                "not available"
            }
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "status": "dry_run",
                "target": target_script,
                "watch_paths": config.watch_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "include_patterns": config.include_patterns,
                "exclude_patterns": config.exclude_patterns,
                "debounce_ms": config.debounce_ms,
                "native_watch_available": native_available,
                "dry_run": true,
            }),
        ));
    }

    // Check if native watching is available
    #[cfg(feature = "native-watch")]
    {
        collector.info("Starting native file watcher");

        // Build the command to run
        let run_cmd = format!("pybun run {}", target_script);

        // Run the watch loop (this blocks until Ctrl+C)
        let text = format!(
            "Watching {} paths for changes to run: {}\n\
            Patterns: {} include, {} exclude\n\
            Debounce: {}ms\n\
            Native watching: enabled\n\
            Press Ctrl+C to stop.",
            stats.watched_paths,
            target_script,
            stats.include_patterns,
            stats.exclude_patterns,
            stats.debounce_ms
        );

        eprintln!("{}", text);

        // Actually start the watch loop
        match run_native_watch_loop(&config, &run_cmd, None) {
            Ok(()) => Ok(RenderDetail::with_json(
                "File watching stopped".to_string(),
                json!({
                    "status": "stopped",
                    "target": target_script,
                    "native_watch": true,
                }),
            )),
            Err(e) => {
                collector.error_with_code(
                    "E_WATCH_LOOP_FAILED",
                    e.clone(),
                    "Check the watch target and filesystem permissions, then re-run `pybun watch`.",
                );
                Ok(RenderDetail::error(
                    format!("Watch failed: {}", e),
                    json!({
                        "error": e,
                        "status": "error",
                    }),
                ))
            }
        }
    }

    #[cfg(not(feature = "native-watch"))]
    {
        collector.info("Starting polling file watcher");

        // Build the command to run
        let run_cmd = format!("pybun run {}", target_script);

        let text = format!(
            "Watching {} paths for changes to run: {}\n\
            Patterns: {} include, {} exclude\n\
            Debounce: {}ms\n\
            Native watching: disabled (using polling fallback)\n\
            Press Ctrl+C to stop.",
            stats.watched_paths,
            target_script,
            stats.include_patterns,
            stats.exclude_patterns,
            stats.debounce_ms
        );

        eprintln!("{}", text);

        // Test-only escape hatch: bound the loop so E2E tests can observe
        // change detection without running forever.
        let max_iterations = std::env::var("PYBUN_WATCH_MAX_ITERATIONS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok());

        match run_polling_watch_loop(&config, &run_cmd, max_iterations) {
            Ok(outcome) => Ok(RenderDetail::with_json(
                "File watching stopped".to_string(),
                json!({
                    "status": "stopped",
                    "target": target_script,
                    "native_watch": false,
                    "polling": true,
                    "iterations": outcome.iterations,
                    "runs": outcome.runs,
                }),
            )),
            Err(e) => {
                collector.error_with_code(
                    "E_WATCH_LOOP_FAILED",
                    e.clone(),
                    "Check the watch target and filesystem permissions, then re-run `pybun watch`.",
                );
                Ok(RenderDetail::error(
                    format!("Watch failed: {}", e),
                    json!({
                        "error": e,
                        "status": "error",
                    }),
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// pybun profile (launch profiles)
// ---------------------------------------------------------------------------

pub(super) fn run_profile(
    args: &ProfileArgs,
    collector: &mut EventCollector,
) -> Result<RenderDetail> {
    let manager = ProfileManager::new();

    // Handle --list mode
    if args.list {
        collector.info("Listing available profiles");

        let profiles = manager.available_profiles();
        let text = format!(
            "Available profiles:\n{}",
            profiles
                .iter()
                .map(|p| format!("  - {}", p))
                .collect::<Vec<_>>()
                .join("\n")
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "profiles": profiles.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            }),
        ));
    }

    // Handle --compare mode
    if let Some(compare_profile) = &args.compare {
        let base_profile: Profile = args
            .profile
            .as_ref()
            .ok_or_else(|| eyre!("base profile required for comparison"))?
            .parse()
            .map_err(|e: String| eyre!(e))?;

        let other_profile: Profile = compare_profile.parse().map_err(|e: String| eyre!(e))?;

        let base_config = ProfileConfig::for_profile(base_profile);
        let other_config = ProfileConfig::for_profile(other_profile);

        let text = format!(
            "Profile comparison: {} vs {}\n\n{}\n\n{}\n\n{}",
            base_profile,
            other_profile,
            base_config.summary(),
            "--- vs ---",
            other_config.summary()
        );

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "base_profile": base_profile.to_string(),
                "compare_profile": other_profile.to_string(),
                "base": {
                    "hot_reload": base_config.hot_reload,
                    "lazy_imports": base_config.lazy_imports,
                    "tracing": base_config.tracing,
                    "optimization_level": base_config.optimization_level,
                },
                "compare": {
                    "hot_reload": other_config.hot_reload,
                    "lazy_imports": other_config.lazy_imports,
                    "tracing": other_config.tracing,
                    "optimization_level": other_config.optimization_level,
                },
            }),
        ));
    }

    // Handle specific profile
    if let Some(profile_name) = &args.profile {
        let profile: Profile = profile_name.parse().map_err(|e: String| eyre!(e))?;
        let config = ProfileConfig::for_profile(profile);

        // Handle --output mode
        if let Some(output_path) = &args.output {
            config
                .to_file(output_path)
                .map_err(|e| eyre!("failed to export profile: {}", e))?;

            let text = format!("Exported {} profile to {}", profile, output_path.display());
            collector.info(&text);

            return Ok(RenderDetail::with_json(
                text,
                json!({
                    "profile": profile.to_string(),
                    "output_file": output_path.display().to_string(),
                }),
            ));
        }

        // Handle --show mode or default
        let text = if args.show {
            config.summary()
        } else {
            format!(
                "Profile: {}\n\nUse --show for detailed configuration.",
                profile
            )
        };

        return Ok(RenderDetail::with_json(
            text,
            json!({
                "profile": profile.to_string(),
                "config": {
                    "hot_reload": config.hot_reload,
                    "lazy_imports": config.lazy_imports,
                    "module_cache": config.module_cache,
                    "tracing": config.tracing,
                    "timing": config.timing,
                    "debug_checks": config.debug_checks,
                    "optimization_level": config.optimization_level,
                    "python_opt_flags": config.python_opt_flags(),
                },
            }),
        ));
    }

    // Default: show current/detected profile
    let detected = ProfileManager::detect_profile();
    let config = ProfileConfig::for_profile(detected);

    let text = format!(
        "Current profile: {}\n\nUse 'pybun profile <PROFILE>' to view a specific profile.\nUse 'pybun profile --list' to see all available profiles.",
        detected
    );

    Ok(RenderDetail::with_json(
        text,
        json!({
            "current_profile": detected.to_string(),
            "available_profiles": ["dev", "prod", "benchmark"],
            "config": {
                "hot_reload": config.hot_reload,
                "lazy_imports": config.lazy_imports,
            },
        }),
    ))
}

// ---------------------------------------------------------------------------
// pybun x (execute tool ad-hoc)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(super) struct XOutcome {
    pub(super) summary: String,
    pub(super) package: String,
    pub(super) version: Option<String>,
    pub(super) passthrough: Vec<String>,
    pub(super) temp_env: String,
    pub(super) python_version: String,
    pub(super) exit_code: i32,
    pub(super) cleanup: bool,
}

pub(super) fn execute_tool(
    args: &crate::cli::ToolArgs,
    _collector: &mut EventCollector,
) -> Result<XOutcome> {
    let package_spec = args
        .package
        .as_ref()
        .ok_or_else(|| eyre!("package name is required"))?;
    validate_package_spec(package_spec)?;

    // Parse package name and version
    let (package_name, version) = parse_package_spec(package_spec);

    // Check for dry-run mode (for testing)
    let dry_run = std::env::var("PYBUN_X_DRY_RUN").is_ok();

    // Find Python interpreter
    let working_dir = std::env::current_dir()?;
    let env = find_python_env(&working_dir)?;
    let python_path = env.python_path.to_string_lossy().to_string();
    let python_version = env.version.clone().unwrap_or_else(|| "unknown".to_string());

    // Create temporary environment
    let temp_dir =
        tempfile::tempdir().map_err(|e| eyre!("failed to create temp directory: {}", e))?;
    let temp_env_path = temp_dir.path().to_string_lossy().to_string();

    if dry_run {
        // In dry-run mode, just return the planned actions. Tests can set
        // PYBUN_X_DRY_RUN_EXIT_CODE to simulate a tool that exits non-zero
        // without needing network access / a real pip install.
        let exit_code = std::env::var("PYBUN_X_DRY_RUN_EXIT_CODE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        return Ok(XOutcome {
            summary: format!("would execute {} (dry-run)", package_name),
            package: package_name,
            version,
            passthrough: args.passthrough.clone(),
            temp_env: temp_env_path,
            python_version,
            exit_code,
            cleanup: true,
        });
    }

    // Create virtual environment in temp directory
    let venv_path = temp_dir.path().join("venv");
    eprintln!(
        "info: creating temporary environment at {}",
        venv_path.display()
    );

    let uv_available = crate::env::find_uv_executable().is_some();

    let mut venv_cmd = ProcessCommand::new(&python_path);
    venv_cmd.args(["-m", "venv"]);
    if uv_available {
        venv_cmd.arg("--without-pip");
    }
    venv_cmd.arg(&venv_path);
    let venv_status = venv_cmd
        .status()
        .map_err(|e| eyre!("failed to create virtual environment: {}", e))?;

    if !venv_status.success() {
        return Err(eyre!("failed to create virtual environment"));
    }

    // Get pip path in venv
    let pip_path = if cfg!(windows) {
        venv_path.join("Scripts").join("pip.exe")
    } else {
        venv_path.join("bin").join("pip")
    };

    // Get python path in venv
    let venv_python = if cfg!(windows) {
        venv_path.join("Scripts").join("python.exe")
    } else {
        venv_path.join("bin").join("python")
    };

    // Install the package using uv if available, otherwise pip
    eprintln!("info: installing {}...", package_spec);
    let install_status = if let Some(uv_path) = crate::env::find_uv_executable() {
        ProcessCommand::new(uv_path)
            .args(["pip", "install", "--quiet", "--python"])
            .arg(&venv_path)
            .arg(package_spec)
            .status()
            .map_err(|e| eyre!("failed to install package with uv: {}", e))?
    } else {
        ProcessCommand::new(&pip_path)
            .args(["install", "--quiet", package_spec])
            .status()
            .map_err(|e| eyre!("failed to install package: {}", e))?
    };

    if !install_status.success() {
        return Err(eyre!("failed to install package {}", package_spec));
    }

    // Find and execute the entry point
    // Most packages have a console script with the same name as the package
    let entry_point = if cfg!(windows) {
        venv_path
            .join("Scripts")
            .join(format!("{}.exe", package_name))
    } else {
        venv_path.join("bin").join(&package_name)
    };

    let exit_code = if entry_point.exists() {
        // Execute the console script directly
        eprintln!("info: executing {}...", entry_point.display());
        let mut cmd = ProcessCommand::new(&entry_point);
        for arg in &args.passthrough {
            cmd.arg(arg);
        }
        let status = cmd
            .status()
            .map_err(|e| eyre!("failed to execute {}: {}", package_name, e))?;
        status.code().unwrap_or(-1)
    } else {
        // Fallback: try to run as a module
        eprintln!("info: executing python -m {}...", package_name);
        let mut cmd = ProcessCommand::new(&venv_python);
        cmd.args(["-m", &package_name]);
        for arg in &args.passthrough {
            cmd.arg(arg);
        }
        let status = cmd
            .status()
            .map_err(|e| eyre!("failed to execute module {}: {}", package_name, e))?;
        status.code().unwrap_or(-1)
    };

    // Cleanup is automatic when temp_dir is dropped
    let summary = if exit_code == 0 {
        format!("executed {} successfully", package_name)
    } else {
        format!("{} exited with code {}", package_name, exit_code)
    };

    Ok(XOutcome {
        summary,
        package: package_name,
        version,
        passthrough: args.passthrough.clone(),
        temp_env: temp_env_path,
        python_version,
        exit_code,
        cleanup: true,
    })
}

/// Parse a package specification like "cowsay==6.1" into (name, version)
/// Validate a `pybun x` package spec against expected PEP 508 syntax before
/// it is passed to `pip`/`uv`. Rejects specs starting with `-` (which pip/uv
/// would otherwise interpret as a CLI flag rather than a package name) and
/// any characters outside the PEP 508 name/version-specifier grammar.
fn validate_package_spec(spec: &str) -> Result<()> {
    if spec.trim().is_empty() {
        return Err(eyre!("package spec must not be empty"));
    }
    if spec.starts_with('-') {
        return Err(eyre!("package spec must not start with '-': {}", spec));
    }
    let valid = spec.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '.' | '_' | '-' | '=' | '<' | '>' | '!' | '~' | ',' | '*' | '+' | '[' | ']'
            )
    });
    if !valid {
        return Err(eyre!(
            "package spec contains characters outside PEP 508 syntax: {}",
            spec
        ));
    }
    Ok(())
}

pub(super) fn parse_package_spec(spec: &str) -> (String, Option<String>) {
    // Handle various specifier formats
    for sep in ["==", ">=", "<=", "!=", "~=", ">", "<"] {
        if let Some(idx) = spec.find(sep) {
            let name = spec[..idx].to_string();
            let version = spec[idx + sep.len()..].to_string();
            return (name, Some(version));
        }
    }
    (spec.to_string(), None)
}

// ---------------------------------------------------------------------------
// pybun self update
// ---------------------------------------------------------------------------

pub(super) fn run_self_update(
    args: &crate::cli::SelfUpdateArgs,
    collector: &mut EventCollector,
) -> RenderDetail {
    let current_version = env!("CARGO_PKG_VERSION");
    let channel = &args.channel;

    collector.info(format!("Checking for updates on {} channel", channel));

    let manifest_source_env = std::env::var("PYBUN_SELF_UPDATE_MANIFEST").ok();
    let default_manifest_url = default_manifest_url(channel);
    let manifest_source = manifest_source_env
        .clone()
        .unwrap_or_else(|| default_manifest_url.clone());
    let should_fetch_manifest = !args.dry_run
        || manifest_source_env.is_some()
        || std::env::var("PYBUN_SELF_UPDATE_FETCH").is_ok();
    let manifest_result = if should_fetch_manifest {
        Some(ReleaseManifest::load(&manifest_source))
    } else {
        None
    };

    let mut latest_version = current_version.to_string();
    let mut update_available = false;
    let mut release_url = release_url_for_version(current_version);
    let target = current_release_target();
    let mut selected_asset = None;
    let mut manifest_detail = None;
    let mut manifest_error = None;
    let mut update_applied = false;
    let mut rollback_performed = false;
    let mut install_path = None;
    let mut update_error = None;

    match manifest_result {
        Some(Ok(manifest)) => {
            latest_version = manifest.version.clone();
            update_available = manifest
                .compare_version(current_version)
                .map(|ordering| ordering == Ordering::Greater)
                .unwrap_or(false);
            release_url = manifest
                .release_url
                .clone()
                .unwrap_or_else(|| release_url_for_version(&manifest.version));

            selected_asset = target
                .as_deref()
                .and_then(|target| manifest.select_asset(target))
                .cloned();
            let asset_json = selected_asset
                .as_ref()
                .map(|asset| serde_json::to_value(asset).unwrap_or_else(|_| json!({})))
                .unwrap_or(Value::Null);

            manifest_detail = Some(json!({
                "version": manifest.version,
                "channel": manifest.channel,
                "published_at": manifest.published_at,
                "release_url": manifest.release_url,
                "release_notes": manifest.release_notes,
                "source": manifest_source,
                "target": target,
                "asset": asset_json,
                "assets": manifest.assets.len(),
                "sbom": manifest.sbom,
                "provenance": manifest.provenance,
            }));
        }
        Some(Err(error)) => {
            manifest_error = Some(error.to_string());
        }
        None => {}
    }

    if !args.dry_run {
        if let Some(error) = manifest_error.as_deref() {
            let message = format!("failed to load release manifest: {error}");
            collector.error_with_code(
                "E_SELF_UPDATE_MANIFEST",
                message.clone(),
                "Check network connectivity and the release manifest URL (--channel or PYBUN_SELF_UPDATE_MANIFEST_URL), then retry `pybun self update`.",
            );
            update_error = Some(message);
        } else if update_available {
            let Some(asset) = selected_asset else {
                let target_text = target
                    .as_deref()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let message = format!("no release asset found for target {target_text}");
                collector.error_with_code(
                    "E_SELF_UPDATE_NO_ASSET",
                    message.clone(),
                    "Pass --target explicitly to select a supported platform/arch, or check that a release asset exists for your platform.",
                );
                update_error = Some(message);
                let summary = "Update failed: no release asset found".to_string();
                let json_detail = json!({
                    "current_version": current_version,
                    "latest_version": latest_version,
                    "channel": channel,
                    "update_available": update_available,
                    "release_url": release_url,
                    "dry_run": args.dry_run,
                    "target": target,
                    "manifest": manifest_detail,
                    "manifest_error": manifest_error,
                    "manifest_source": manifest_source_env.or(Some(default_manifest_url)),
                    "update_applied": false,
                    "rollback_performed": false,
                    "install_path": Value::Null,
                    "error": update_error,
                });
                return RenderDetail::error(summary, json_detail);
            };
            let install_override = std::env::var("PYBUN_SELF_UPDATE_BIN")
                .ok()
                .map(PathBuf::from);
            let fail_swap_for_test = std::env::var("PYBUN_SELF_UPDATE_TEST_FAIL_SWAP").is_ok();
            let target_name = target
                .as_deref()
                .unwrap_or(asset.target.as_str())
                .to_string();

            match apply_update_for_asset(&asset, &target_name, install_override, fail_swap_for_test)
            {
                Ok(outcome) => {
                    update_applied = true;
                    rollback_performed = outcome.rollback_performed;
                    install_path = Some(outcome.install_path.display().to_string());
                    collector.info(format!(
                        "Updated binary at {}",
                        outcome.install_path.display()
                    ));
                }
                Err(error) => {
                    rollback_performed = error.rollback_performed;
                    update_error = Some(error.to_string());
                    collector.error_with_code(
                        "E_SELF_UPDATE_APPLY_FAILED",
                        error.to_string(),
                        "Check write permissions to the install path and retry `pybun self update`. If a backup exists, rollback may have already been performed.",
                    );
                }
            }
        }
    }

    let summary = if args.dry_run {
        if update_available {
            format!(
                "Update available: {} -> {} (dry-run, no changes made)",
                current_version, latest_version
            )
        } else if let Some(error) = manifest_error.as_deref() {
            format!("Update check failed: {} (dry-run)", error)
        } else {
            format!(
                "Already up to date: {} (channel: {})",
                current_version, channel
            )
        }
    } else if let Some(error) = update_error.as_deref() {
        format!("Update failed: {error}")
    } else if update_available && update_applied {
        format!("Updated: {} -> {}", current_version, latest_version)
    } else if update_available {
        format!("Update failed: {} -> {}", current_version, latest_version)
    } else {
        format!(
            "Already up to date: {} (channel: {})",
            current_version, channel
        )
    };

    let json_detail = json!({
        "current_version": current_version,
        "latest_version": latest_version,
        "channel": channel,
        "update_available": update_available,
        "release_url": release_url,
        "dry_run": args.dry_run,
        "target": target,
        "manifest": manifest_detail,
        "manifest_error": manifest_error,
        "manifest_source": manifest_source_env.or(Some(default_manifest_url)),
        "update_applied": update_applied,
        "rollback_performed": rollback_performed,
        "install_path": install_path,
        "error": update_error,
    });

    if !args.dry_run && update_error.is_some() {
        RenderDetail::error(summary, json_detail)
    } else {
        RenderDetail::with_json(summary, json_detail)
    }
}

fn default_manifest_url(channel: &str) -> String {
    if channel == "nightly" {
        "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/nightly/pybun-release.json"
            .to_string()
    } else {
        "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/latest/download/pybun-release.json"
            .to_string()
    }
}

fn release_url_for_version(version: &str) -> String {
    let trimmed = version.trim_start_matches('v');
    format!(
        "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/tag/v{}",
        trimmed
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_package_spec_accepts_normal_specs() {
        assert!(validate_package_spec("cowsay").is_ok());
        assert!(validate_package_spec("cowsay==6.1").is_ok());
        assert!(validate_package_spec("requests>=2.28.0").is_ok());
        assert!(validate_package_spec("flask~=2.0.0").is_ok());
        assert!(validate_package_spec("pkg[extra]==1.0").is_ok());
    }

    #[test]
    fn validate_package_spec_rejects_leading_dash_and_bad_chars() {
        assert!(validate_package_spec("-e file:///etc/passwd").is_err());
        assert!(validate_package_spec("--upgrade").is_err());
        assert!(validate_package_spec("").is_err());
        assert!(validate_package_spec("   ").is_err());
        assert!(validate_package_spec("pkg; rm -rf /").is_err());
        assert!(validate_package_spec("pkg && echo pwned").is_err());
        assert!(validate_package_spec("pkg\nrm -rf /").is_err());
    }

    #[test]
    fn parse_package_spec_simple_name() {
        let (name, version) = parse_package_spec("cowsay");
        assert_eq!(name, "cowsay");
        assert_eq!(version, None);
    }

    #[test]
    fn parse_package_spec_exact_version() {
        let (name, version) = parse_package_spec("cowsay==6.1");
        assert_eq!(name, "cowsay");
        assert_eq!(version, Some("6.1".to_string()));
    }

    #[test]
    fn parse_package_spec_minimum_version() {
        let (name, version) = parse_package_spec("requests>=2.28.0");
        assert_eq!(name, "requests");
        assert_eq!(version, Some("2.28.0".to_string()));
    }

    #[test]
    fn parse_package_spec_maximum_version() {
        let (name, version) = parse_package_spec("numpy<2.0");
        assert_eq!(name, "numpy");
        assert_eq!(version, Some("2.0".to_string()));
    }

    #[test]
    fn parse_package_spec_compatible_version() {
        let (name, version) = parse_package_spec("flask~=2.0.0");
        assert_eq!(name, "flask");
        assert_eq!(version, Some("2.0.0".to_string()));
    }

    #[test]
    fn parse_package_spec_not_equal() {
        let (name, version) = parse_package_spec("django!=3.0");
        assert_eq!(name, "django");
        assert_eq!(version, Some("3.0".to_string()));
    }
}
