use super::RenderDetail;
use crate::cache::{Cache, format_size, parse_size};
use crate::env::find_python_env;
use crate::pep723_cache::Pep723Cache;
use crate::project::Project;
use crate::schema::EventCollector;
use crate::support_bundle::{BundleContext, BundleReport, build_support_bundle, upload_bundle};
use color_eyre::eyre::{Result, eyre};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// pybun doctor
// ---------------------------------------------------------------------------

pub(super) fn run_doctor(
    args: &crate::cli::DoctorArgs,
    collector: &mut EventCollector,
) -> RenderDetail {
    let mut checks: Vec<Value> = Vec::new();
    let mut all_ok = true;
    let mut bundle_report: Option<BundleReport> = None;

    // Check pybun binary
    if let Ok(exe) = std::env::current_exe() {
        checks.push(json!({
            "name": "pybun_binary",
            "status": "ok",
            "path": exe.display().to_string(),
        }));
    }

    // Check Python availability
    let working_dir = std::env::current_dir().unwrap_or_default();
    match find_python_env(&working_dir) {
        Ok(env) => {
            checks.push(json!({
                "name": "python",
                "status": "ok",
                "message": format!("Python found at {}", env.python_path.display()),
                "source": format!("{}", env.source),
                "version": env.version,
            }));
            collector.info(format!("Python found: {}", env.python_path.display()));
        }
        Err(e) => {
            checks.push(json!({
                "name": "python",
                "status": "error",
                "message": format!("Python not found: {}", e),
            }));
            collector.warning(format!("Python not found: {}", e));
            all_ok = false;
        }
    }

    // Check cache directory
    match crate::cache::Cache::new() {
        Ok(cache) => {
            let cache_dir = cache.root();
            checks.push(json!({
                "name": "cache",
                "status": "ok",
                "message": format!("Cache directory: {}", cache_dir.display()),
                "path": cache_dir.display().to_string(),
            }));
        }
        Err(e) => {
            checks.push(json!({
                "name": "cache",
                "status": "error",
                "message": format!("Cache initialization failed: {}", e),
            }));
            collector.warning(format!("Cache initialization failed: {}", e));
            all_ok = false;
        }
    }

    // Check PyPI metadata cache directory (separate from the main cache
    // root above - see issue #202). Flag stale entries written by
    // incompatible older pybun versions.
    if let Some(pypi_cache_dir) = crate::pypi::pypi_cache_dir() {
        let stats = crate::pypi::pypi_cache_stats(&pypi_cache_dir);
        let status = if stats.stale_count > 0 { "info" } else { "ok" };
        checks.push(json!({
            "name": "pypi_cache",
            "status": status,
            "message": format!(
                "PyPI metadata cache: {} ({} entries, {} stale)",
                pypi_cache_dir.display(),
                stats.entry_count,
                stats.stale_count,
            ),
            "path": pypi_cache_dir.display().to_string(),
            "entry_count": stats.entry_count,
            "total_bytes": stats.total_bytes,
            "stale_count": stats.stale_count,
        }));
        if stats.stale_count > 0 {
            collector.info(format!(
                "{} stale PyPI cache entries found in {} - run `pybun gc` to remove them",
                stats.stale_count,
                pypi_cache_dir.display(),
            ));
        }
    }

    // Check for pyproject.toml
    match Project::discover(&working_dir) {
        Ok(project) => {
            checks.push(json!({
                "name": "project",
                "status": "ok",
                "message": format!("Project found at {}", project.path().display()),
                "path": project.path().display().to_string(),
                "dependencies": project.dependencies(),
            }));
        }
        Err(_) => {
            checks.push(json!({
                "name": "project",
                "status": "info",
                "message": "No pyproject.toml found in current directory",
            }));
            collector.info("No pyproject.toml found");
        }
    }

    let status = if all_ok { "healthy" } else { "issues_found" };
    let summary = if all_ok {
        "All checks passed".to_string()
    } else {
        "Some issues found".to_string()
    };

    if args.verbose {
        collector.info("Verbose diagnostics enabled");
    }

    if args.bundle.is_some() || args.upload {
        let trace_id = collector.trace_id().map(|value| value.to_string());
        let context = BundleContext {
            checks: checks.clone(),
            verbose_logs: args.verbose,
            trace_id,
            command: "pybun doctor".to_string(),
        };

        let mut temp_bundle: Option<tempfile::TempDir> = None;
        let bundle_path = if let Some(path) = args.bundle.clone() {
            path
        } else if let Ok(temp) = tempfile::TempDir::new() {
            let path = temp.path().join("bundle");
            temp_bundle = Some(temp);
            path
        } else {
            std::env::temp_dir().join("pybun-support-bundle")
        };

        match build_support_bundle(&bundle_path, &context) {
            Ok(collection) => {
                let mut upload_outcome = None;
                let mut bundle_path_out = args.bundle.clone();

                if args.upload {
                    let upload_url = args
                        .upload_url
                        .clone()
                        .or_else(|| std::env::var("PYBUN_SUPPORT_UPLOAD_URL").ok());
                    match upload_url {
                        Some(url) => {
                            let outcome = upload_bundle(&collection, &url);
                            if outcome.status != "uploaded"
                                && bundle_path_out.is_none()
                                && let Some(temp) = temp_bundle.take()
                            {
                                let _ = temp.keep();
                                bundle_path_out = Some(collection.path.clone());
                            }
                            upload_outcome = Some(outcome);
                        }
                        None => {
                            upload_outcome = Some(crate::support_bundle::UploadOutcome {
                                url: "".to_string(),
                                status: "failed".to_string(),
                                http_status: None,
                                error: Some("upload endpoint not configured".to_string()),
                            });
                            if bundle_path_out.is_none()
                                && let Some(temp) = temp_bundle.take()
                            {
                                let _ = temp.keep();
                                bundle_path_out = Some(collection.path.clone());
                            }
                        }
                    }
                }

                bundle_report = Some(BundleReport {
                    bundle_path: bundle_path_out,
                    files: collection.files,
                    redactions: collection.redactions,
                    logs_included: collection.logs_included,
                    upload: upload_outcome,
                });
            }
            Err(err) => {
                collector.error_with_code(
                    "E_DOCTOR_BUNDLE_FAILED",
                    format!("Support bundle failed: {:?}", err),
                    "Check that the bundle output path (or system temp directory) is writable, then re-run `pybun doctor --bundle <path>`.",
                );
                return RenderDetail::error(
                    "Support bundle failed".to_string(),
                    json!({
                        "status": status,
                        "checks": checks,
                        "verbose": args.verbose,
                        "bundle_error": format!("{:?}", err),
                    }),
                );
            }
        }
    }

    let mut detail = json!({
        "status": status,
        "checks": checks,
        "verbose": args.verbose,
    });

    if let Some(bundle) = &bundle_report {
        detail["bundle"] = bundle.to_json();
    }

    let summary = if bundle_report.is_some() {
        format!("{}. Support bundle captured", summary)
    } else {
        summary
    };

    RenderDetail::with_json(summary, detail)
}

// ---------------------------------------------------------------------------
// pybun gc (garbage collection)
// ---------------------------------------------------------------------------

pub(super) fn run_gc(
    args: &crate::cli::GcArgs,
    collector: &mut EventCollector,
) -> Result<RenderDetail> {
    let cache = Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;

    // Parse max size if provided
    let max_bytes = if let Some(size_str) = &args.max_size {
        Some(parse_size(size_str).map_err(|e| eyre!("invalid size format: {}", e))?)
    } else {
        None
    };

    collector.info(format!("Running GC on cache at {}", cache.root().display()));

    // Ensure cache directories exist
    cache
        .ensure_dirs()
        .map_err(|e| eyre!("failed to ensure cache dirs: {}", e))?;

    // Run garbage collection on packages/build cache
    let gc_result = cache
        .gc(max_bytes, args.dry_run)
        .map_err(|e| eyre!("GC failed: {}", e))?;

    // Also run GC on PEP 723 venv cache
    let pep723_cache =
        Pep723Cache::new().map_err(|e| eyre!("failed to initialize pep723 cache: {}", e))?;
    let pep723_gc_result = pep723_cache
        .gc(max_bytes, args.dry_run)
        .map_err(|e| eyre!("PEP 723 GC failed: {}", e))?;

    // Remove stale/corrupt PyPI metadata cache entries (see issue #202).
    // This directory is separate from `cache.root()` and is not covered by
    // `cache.gc()` above.
    let pypi_cache_gc = crate::pypi::pypi_cache_dir()
        .map(|dir| crate::pypi::gc_stale_pypi_cache(&dir, args.dry_run))
        .unwrap_or_default();

    // Combine results
    let total_freed =
        gc_result.freed_bytes + pep723_gc_result.freed_bytes + pypi_cache_gc.freed_bytes;
    let total_removed =
        gc_result.files_removed + pep723_gc_result.envs_removed + pypi_cache_gc.files_removed;
    let total_size_before = gc_result.size_before + pep723_gc_result.size_before;
    let total_size_after = gc_result.size_after + pep723_gc_result.size_after;

    let summary = if args.dry_run {
        let would_remove_count = gc_result.would_remove.len()
            + pep723_gc_result.would_remove.len()
            + pypi_cache_gc.would_remove.len();
        if would_remove_count == 0 {
            format!(
                "Cache is within limits ({} used)",
                format_size(total_size_before)
            )
        } else {
            format!(
                "Would free {} ({} files/envs)",
                format_size(total_freed),
                would_remove_count
            )
        }
    } else if total_removed == 0 {
        format!(
            "Cache is within limits ({} used)",
            format_size(total_size_after)
        )
    } else {
        format!(
            "Freed {} ({} files/envs removed)",
            format_size(total_freed),
            total_removed
        )
    };

    let json_detail = json!({
        "freed_bytes": total_freed,
        "freed_human": format_size(total_freed),
        "files_removed": gc_result.files_removed,
        "envs_removed": pep723_gc_result.envs_removed,
        "size_before": total_size_before,
        "size_before_human": format_size(total_size_before),
        "size_after": total_size_after,
        "size_after_human": format_size(total_size_after),
        "dry_run": args.dry_run,
        "max_size": args.max_size,
        "would_remove": gc_result.would_remove.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "would_remove_pep723_envs": pep723_gc_result.would_remove,
        "cache_root": cache.root().display().to_string(),
        "pep723_cache": {
            "freed_bytes": pep723_gc_result.freed_bytes,
            "envs_removed": pep723_gc_result.envs_removed,
            "size_before": pep723_gc_result.size_before,
            "size_after": pep723_gc_result.size_after,
        },
        "pypi_cache": {
            "path": crate::pypi::pypi_cache_dir().map(|p| p.display().to_string()),
            "freed_bytes": pypi_cache_gc.freed_bytes,
            "files_removed": pypi_cache_gc.files_removed,
            "would_remove": pypi_cache_gc.would_remove,
        },
    });

    Ok(RenderDetail::with_json(summary, json_detail))
}
