use super::RenderDetail;
use crate::cli::{LazyImportArgs, ModuleFindArgs, ProfileArgs, WatchArgs};
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
use crate::schema::EventCollector;
use color_eyre::eyre::{Result, eyre};
use serde_json::{Value, json};

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
