use super::{RenderDetail, find_python_interpreter};
use crate::cli::TestBackend;
use crate::env::find_python_env;
use crate::schema::{Diagnostic, EventCollector};
use crate::test_discovery::{DiscoveryResult, TestDiscovery, TestItem, TestItemType};
use crate::workspace::Workspace;
use color_eyre::eyre::{Result, eyre};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

// ---------------------------------------------------------------------------
// pybun test (test runner)
// ---------------------------------------------------------------------------

/// Get a hint message for a pytest compatibility warning code
fn get_pytest_compat_hint(code: &str) -> Option<&'static str> {
    match code {
        "W001" => Some("Consider using --backend pytest for session/package scoped fixtures"),
        "W002" => Some("This decorator requires the pytest backend to function correctly"),
        "I001" => Some("Parametrized tests will be expanded during discovery"),
        "W003" => Some("This fixture pattern may require pytest plugins"),
        "W004" => Some("Async fixtures require pytest-asyncio or similar"),
        _ => None,
    }
}

/// Convert a discovery-time compat warning into a structured diagnostic that
/// is specific to having chosen `--backend=pybun`.
///
/// Unlike `--pytest-compat` (which surfaces these warnings only when the user
/// explicitly opts in), the native backend's compat risk is implied by the
/// backend choice itself: an agent picking `--backend=pybun` for speed has no
/// other signal that a project leans on pytest plugins/fixtures the native
/// executor doesn't fully emulate (see Issue #168), so a real test failure can
/// look identical to a backend-compatibility gap. These diagnostics close that
/// gap by always surfacing the warning — with a `--backend=pytest` hint —
/// whenever the native backend is in use, regardless of `--pytest-compat`.
fn native_backend_compat_diagnostic(warning: &crate::test_discovery::CompatWarning) -> Diagnostic {
    use crate::schema::DiagnosticLevel;
    use crate::test_discovery::WarningSeverity;

    let level = match warning.severity {
        WarningSeverity::Error => DiagnosticLevel::Error,
        WarningSeverity::Warning => DiagnosticLevel::Warning,
        WarningSeverity::Info => DiagnosticLevel::Info,
    };

    Diagnostic {
        level,
        code: Some(format!("W_TEST_BACKEND_COMPAT_{}", warning.code)),
        message: format!(
            "{} (the native --backend=pybun executor may not fully emulate this pytest feature)",
            warning.message
        ),
        file: Some(warning.path.display().to_string()),
        line: Some(warning.line as u32),
        suggestion: Some(
            "Run with --backend=pytest if this project relies on pytest plugins, advanced fixtures, \
             or other features the native executor doesn't fully emulate"
                .to_string(),
        ),
        context: None,
        fix_candidates: None,
    }
}

/// Parse shard specification (N/M format)
fn parse_shard(shard: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = shard.split('/').collect();
    if parts.len() != 2 {
        return Err(eyre!(
            "invalid shard format '{}': expected N/M (e.g., 1/4)",
            shard
        ));
    }

    let n: u32 = parts[0].parse().map_err(|_| {
        eyre!(
            "invalid shard number '{}': must be a positive integer",
            parts[0]
        )
    })?;
    let m: u32 = parts[1].parse().map_err(|_| {
        eyre!(
            "invalid shard total '{}': must be a positive integer",
            parts[1]
        )
    })?;

    if n == 0 || m == 0 {
        return Err(eyre!("shard values must be greater than 0"));
    }
    if n > m {
        return Err(eyre!("shard {} cannot be greater than total {}", n, m));
    }

    Ok((n, m))
}

/// Detect test backend based on test files
fn detect_test_backend(_paths: &[PathBuf]) -> TestBackend {
    // Default to pytest as it's more common
    // Could be enhanced to detect based on imports in test files

    let python = std::env::current_dir()
        .ok()
        .and_then(|cwd| find_python_env(&cwd).ok().map(|env| env.python_path))
        .unwrap_or_else(|| PathBuf::from("python3"));

    // Check if pytest is available in the selected interpreter
    if let Ok(output) = ProcessCommand::new(&python)
        .args(["-c", "import pytest"])
        .output()
        && output.status.success()
    {
        return TestBackend::Pytest;
    }

    // Fall back to unittest
    TestBackend::Unittest
}

/// Discover test files in given paths (legacy method, kept for backward compatibility)
fn discover_test_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let search_paths = if paths.is_empty() {
        vec![std::env::current_dir().unwrap_or_default()]
    } else {
        paths.to_vec()
    };

    let mut test_files = Vec::new();

    for path in search_paths {
        if path.is_file() {
            // Single file specified
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("test_") || n.ends_with("_test.py"))
                .unwrap_or(false)
            {
                test_files.push(path);
            } else if path.extension().map(|e| e == "py").unwrap_or(false) {
                // Allow any .py file if explicitly specified
                test_files.push(path);
            }
        } else if path.is_dir() {
            // Recursively find test files
            if let Ok(entries) = walkdir(path) {
                for entry in entries {
                    if let Some(name) = entry.file_name().and_then(|n| n.to_str())
                        && (name.starts_with("test_") || name.ends_with("_test.py"))
                        && name.ends_with(".py")
                    {
                        test_files.push(entry);
                    }
                }
            }
        }
    }

    test_files
}

/// Simple directory walker (no external dependency)
fn walkdir(path: impl AsRef<std::path::Path>) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    walkdir_recursive(path.as_ref(), &mut result)?;
    Ok(result)
}

fn walkdir_recursive(path: &std::path::Path, result: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                // Skip hidden directories and common non-test directories
                if let Some(name) = path.file_name().and_then(|n| n.to_str())
                    && !name.starts_with('.')
                    && name != "__pycache__"
                    && name != "node_modules"
                    && name != ".git"
                    && name != "venv"
                    && name != ".venv"
                {
                    walkdir_recursive(&path, result)?;
                }
            } else {
                result.push(path);
            }
        }
    }
    Ok(())
}

/// Use AST-based discovery to find all tests
fn discover_tests_ast(paths: &[PathBuf]) -> DiscoveryResult {
    let discovery = TestDiscovery::new();
    let search_paths = if paths.is_empty() {
        vec![std::env::current_dir().unwrap_or_default()]
    } else {
        paths.to_vec()
    };
    discovery.discover(&search_paths)
}

/// Filter tests by name pattern
fn filter_tests(tests: Vec<TestItem>, pattern: &str) -> Vec<TestItem> {
    tests
        .into_iter()
        .filter(|t| {
            t.name.contains(pattern)
                || t.short_name.contains(pattern)
                || t.class_name
                    .as_ref()
                    .map(|c| c.contains(pattern))
                    .unwrap_or(false)
        })
        .collect()
}

/// Apply sharding to tests
fn shard_tests(tests: Vec<TestItem>, shard_n: u32, shard_m: u32) -> Vec<TestItem> {
    tests
        .into_iter()
        .enumerate()
        .filter(|(i, _)| (*i as u32 % shard_m) + 1 == shard_n)
        .map(|(_, t)| t)
        .collect()
}

/// Resolve effective test search paths, honoring `--member` to scope
/// discovery to a single workspace member directory when no explicit PATH is
/// given (relative PATHs are resolved against the member root). Returns the
/// paths plus an optional JSON blob describing the selected member for
/// workspace-aware output (`None` when `--member` was not used).
fn resolve_test_paths(
    args: &crate::cli::TestArgs,
    collector: &mut EventCollector,
) -> Result<(Vec<PathBuf>, Option<Value>)> {
    let Some(member_name) = &args.member else {
        return Ok((args.paths.clone(), None));
    };

    let cwd = std::env::current_dir()?;
    let workspace = Workspace::discover_root(&cwd)
        .map_err(|e| eyre!(e))?
        .ok_or_else(|| {
            eyre!("--member requires a workspace; no [tool.pybun.workspace] configuration found")
        })?;
    let member = workspace.member_by_name(member_name).ok_or_else(|| {
        eyre!(
            "workspace member '{member_name}' not found (available: {})",
            workspace.member_names().join(", ")
        )
    })?;

    let member_root = member.root().to_path_buf();
    let paths = if args.paths.is_empty() {
        vec![member_root.clone()]
    } else {
        args.paths
            .iter()
            .map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    member_root.join(p)
                }
            })
            .collect()
    };

    collector.info(format!(
        "Selected workspace member '{}' at {}",
        member_name,
        member_root.display(),
    ));

    Ok((
        paths,
        Some(json!({
            "scope": "member",
            "root": workspace.root.root().display().to_string(),
            "selected_members": [member_name],
        })),
    ))
}

pub(crate) fn run_tests(
    args: &crate::cli::TestArgs,
    collector: &mut EventCollector,
) -> Result<RenderDetail> {
    // Check for dry-run mode (for testing)
    let dry_run = std::env::var("PYBUN_TEST_DRY_RUN").is_ok();

    // Resolve effective search paths, honoring `--member` to scope discovery
    // to a single workspace member directory.
    let (paths, member_detail) = resolve_test_paths(args, collector)?;

    // Parse shard if provided
    let shard_info = if let Some(ref shard_str) = args.shard {
        Some(parse_shard(shard_str)?)
    } else {
        None
    };

    // Determine backend
    let backend = args.backend.unwrap_or_else(|| detect_test_backend(&paths));

    // Use AST-based discovery
    let discovery_result = discover_tests_ast(&paths);

    collector.info(format!(
        "AST discovery: found {} tests in {} files ({}µs)",
        discovery_result.tests.len(),
        discovery_result.scanned_files.len(),
        discovery_result.duration_us
    ));

    // Surface native-backend compat-warning diagnostics unconditionally
    // (independent of --pytest-compat): choosing --backend=pybun is itself
    // the signal that compatibility matters, since the native executor may
    // not fully emulate every pytest plugin/fixture pattern (Issue #168).
    if backend == TestBackend::Pybun {
        for warning in &discovery_result.compat_warnings {
            collector.diagnostic(native_backend_compat_diagnostic(warning));
        }
    }

    // Process pytest-compat warnings and add as diagnostics
    if args.pytest_compat && !discovery_result.compat_warnings.is_empty() {
        use crate::schema::DiagnosticLevel;

        for warning in &discovery_result.compat_warnings {
            let level = match warning.severity {
                crate::test_discovery::WarningSeverity::Error => DiagnosticLevel::Error,
                crate::test_discovery::WarningSeverity::Warning => DiagnosticLevel::Warning,
                crate::test_discovery::WarningSeverity::Info => DiagnosticLevel::Info,
            };
            let diag = Diagnostic {
                level,
                code: Some(warning.code.clone()),
                message: warning.message.clone(),
                file: Some(warning.path.display().to_string()),
                line: Some(warning.line as u32),
                suggestion: get_pytest_compat_hint(&warning.code).map(|s| s.to_string()),
                context: None,
                fix_candidates: None,
            };
            collector.diagnostic(diag);
        }

        // Print warnings in text mode
        if args.verbose {
            eprintln!(
                "\npytest compatibility warnings ({}):",
                discovery_result.compat_warnings.len()
            );
            for w in &discovery_result.compat_warnings {
                let severity_prefix = match w.severity {
                    crate::test_discovery::WarningSeverity::Error => "error",
                    crate::test_discovery::WarningSeverity::Warning => "warning",
                    crate::test_discovery::WarningSeverity::Info => "info",
                };
                eprintln!(
                    "  [{}] {} {}:{}: {}",
                    severity_prefix,
                    w.code,
                    w.path.display(),
                    w.line,
                    w.message
                );
                if let Some(hint) = get_pytest_compat_hint(&w.code) {
                    eprintln!("         hint: {}", hint);
                }
            }
            eprintln!();
        }
    }

    // Get only function/method tests (not class items for running)
    let mut tests: Vec<TestItem> = discovery_result
        .tests
        .iter()
        .filter(|t| t.item_type != TestItemType::Class)
        .cloned()
        .collect();

    // Apply filter if specified
    if let Some(ref pattern) = args.filter {
        tests = filter_tests(tests, pattern);
        collector.info(format!("After filter '{}': {} tests", pattern, tests.len()));
    }

    // Apply sharding if specified
    if let Some((shard_n, shard_m)) = shard_info {
        tests = shard_tests(tests, shard_n, shard_m);
        collector.info(format!(
            "After shard {}/{}: {} tests",
            shard_n,
            shard_m,
            tests.len()
        ));
    }

    // Filter out skipped tests for counting
    let runnable_tests: Vec<&TestItem> = tests.iter().filter(|t| !t.skipped).collect();

    // Legacy file discovery for backward compatibility
    let discovered_files = discover_test_files(&paths);

    // Handle --discover mode (just show discovered tests without running)
    if args.discover {
        let summary = format!(
            "Discovered {} tests ({} skipped) in {} files",
            tests.len(),
            tests.iter().filter(|t| t.skipped).count(),
            discovery_result.scanned_files.len()
        );

        let tests_json: Vec<Value> = tests
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "short_name": t.short_name,
                    "path": t.path.display().to_string(),
                    "line": t.line,
                    "type": format!("{:?}", t.item_type).to_lowercase(),
                    "class": t.class_name,
                    "skipped": t.skipped,
                    "skip_reason": t.skip_reason,
                    "xfail": t.xfail,
                    "markers": t.markers.iter().map(|m| &m.name).collect::<Vec<_>>(),
                    "fixtures": t.fixtures,
                    "parametrize": t.parametrize.as_ref().map(|p| json!({
                        "params": p.params,
                        "case_count": p.case_count,
                    })),
                })
            })
            .collect();

        let fixtures_json: Vec<Value> = discovery_result
            .fixtures
            .iter()
            .map(|f| {
                json!({
                    "name": f.name,
                    "path": f.path.display().to_string(),
                    "line": f.line,
                    "scope": format!("{:?}", f.scope).to_lowercase(),
                    "autouse": f.autouse,
                    "dependencies": f.dependencies,
                })
            })
            .collect();

        let warnings_json: Vec<Value> = discovery_result
            .compat_warnings
            .iter()
            .map(|w| {
                json!({
                    "code": w.code,
                    "message": w.message,
                    "path": w.path.display().to_string(),
                    "line": w.line,
                    "severity": format!("{:?}", w.severity).to_lowercase(),
                })
            })
            .collect();

        // Text output for verbose mode
        let text_output = if args.verbose {
            let mut lines = vec![summary.clone()];
            lines.push("".to_string());
            lines.push("Tests:".to_string());
            for t in &tests {
                let status = if t.skipped {
                    " [SKIP]"
                } else if t.xfail {
                    " [XFAIL]"
                } else {
                    ""
                };
                lines.push(format!(
                    "  {}:{} {}{}",
                    t.path.display(),
                    t.line,
                    t.name,
                    status
                ));
                if !t.fixtures.is_empty() {
                    lines.push(format!("    fixtures: {}", t.fixtures.join(", ")));
                }
            }
            if !discovery_result.fixtures.is_empty() {
                lines.push("".to_string());
                lines.push("Fixtures:".to_string());
                for f in &discovery_result.fixtures {
                    lines.push(format!(
                        "  {}:{} {} (scope: {:?})",
                        f.path.display(),
                        f.line,
                        f.name,
                        f.scope
                    ));
                }
            }
            if !discovery_result.compat_warnings.is_empty() {
                lines.push("".to_string());
                lines.push("Compatibility warnings:".to_string());
                for w in &discovery_result.compat_warnings {
                    lines.push(format!("  [{:?}] {}: {}", w.severity, w.code, w.message));
                }
            }
            lines.join("\n")
        } else {
            summary.clone()
        };

        return Ok(RenderDetail::with_json(
            text_output,
            json!({
                "discover": true,
                "workspace": member_detail,
                "tests": tests_json,
                "fixtures": fixtures_json,
                "compat_warnings": warnings_json,
                "scanned_files": discovery_result.scanned_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "error_files": discovery_result.error_files.iter().map(|(p, e)| json!({
                    "path": p.display().to_string(),
                    "error": e,
                })).collect::<Vec<_>>(),
                "duration_us": discovery_result.duration_us,
                "total_tests": tests.len(),
                "runnable_tests": runnable_tests.len(),
                "skipped_tests": tests.iter().filter(|t| t.skipped).count(),
                "xfail_tests": tests.iter().filter(|t| t.xfail).count(),
            }),
        ));
    }

    // If dry-run, just return what would happen
    if dry_run {
        let summary = format!(
            "Would run {} tests ({} skipped) with {:?}",
            runnable_tests.len(),
            tests.iter().filter(|t| t.skipped).count(),
            backend
        );

        // Build compat_warnings for JSON output
        let compat_warnings_json: Vec<Value> = if args.pytest_compat {
            discovery_result
                .compat_warnings
                .iter()
                .map(|w| {
                    json!({
                        "code": w.code,
                        "message": w.message,
                        "path": w.path.display().to_string(),
                        "line": w.line,
                        "severity": format!("{:?}", w.severity).to_lowercase(),
                        "hint": get_pytest_compat_hint(&w.code),
                    })
                })
                .collect()
        } else {
            Vec::new()
        };

        let workers = if backend == TestBackend::Pybun {
            Some(args.parallel.unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|p| p.get())
                    .unwrap_or(4)
            }))
        } else {
            args.parallel
        };

        return Ok(RenderDetail::with_json(
            summary,
            json!({
                "dry_run": true,
                "workspace": member_detail,
                "backend": format!("{:?}", backend).to_lowercase(),
                "test_runner": format!("{:?}", backend).to_lowercase(),
                "discovered_files": discovered_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "tests_found": tests.len(),
                "runnable_tests": runnable_tests.len(),
                "fail_fast": args.fail_fast,
                "pytest_compat": args.pytest_compat,
                "shard": shard_info.map(|(n, m)| format!("{}/{}", n, m)),
                "filter": args.filter,
                "parallel": args.parallel,
                "workers": workers,
                "timeout": args.timeout,
                "retries": args.retries.unwrap_or(0),
                "snapshot": args.snapshot,
                "update_snapshots": args.update_snapshots,
                "ast_discovery": {
                    "tests": tests.len(),
                    "fixtures": discovery_result.fixtures.len(),
                    "duration_us": discovery_result.duration_us,
                    "compat_warnings": discovery_result.compat_warnings.len(),
                },
                "compat_warnings": compat_warnings_json,
            }),
        ));
    }

    // Find Python interpreter
    let (python, env_source) = find_python_interpreter()?;
    eprintln!("info: using Python from {}", env_source);

    // Native pybun backend: use Rust TestExecutor
    if backend == TestBackend::Pybun {
        return run_tests_native(args, tests, shard_info, &python, member_detail, collector);
    }

    // Build the command based on backend
    let mut cmd = ProcessCommand::new(&python);

    match backend {
        TestBackend::Pytest => {
            cmd.arg("-m").arg("pytest");

            // Add fail-fast flag
            if args.fail_fast {
                cmd.arg("-x");
            }

            // Add verbose for better output
            if args.verbose {
                cmd.arg("-v");
            }

            // Add filter (-k option)
            if let Some(ref pattern) = args.filter {
                cmd.arg("-k").arg(pattern);
            }

            // Add parallel option
            if let Some(workers) = args.parallel {
                cmd.arg("-n").arg(workers.to_string());
            }

            // Add test paths
            if !paths.is_empty() {
                for path in &paths {
                    cmd.arg(path);
                }
            }

            // Add passthrough args
            for arg in &args.passthrough {
                cmd.arg(arg);
            }
        }
        TestBackend::Unittest => {
            cmd.arg("-m").arg("unittest");

            if args.fail_fast {
                cmd.arg("-f");
            }

            // Add verbose
            if args.verbose {
                cmd.arg("-v");
            }

            // For unittest, we need to specify discover or specific files
            if paths.is_empty() {
                cmd.arg("discover");
            } else {
                // If the first path is a directory, assume the user wants discovery in that dir
                // This fixes "pybun test optimizer/tests" failing to find tests
                if paths.len() == 1 && paths[0].is_dir() {
                    cmd.arg("discover").arg("-s").arg(&paths[0]);
                } else {
                    for path in &paths {
                        cmd.arg(path);
                    }
                }
            }

            // Add passthrough args
            for arg in &args.passthrough {
                cmd.arg(arg);
            }
        }
        // The pybun path returns early via run_tests_native() before reaching
        // this match.  The debug_assert guards against future refactors that
        // accidentally remove that early return.
        TestBackend::Pybun => {
            debug_assert!(
                false,
                "TestBackend::Pybun must be handled before this match"
            );
            unreachable!("pybun backend handled before this point")
        }
    }

    eprintln!("info: running tests with {:?}...", backend);

    // Execute the tests
    let output = cmd
        .output()
        .map_err(|e| eyre!("failed to execute test runner: {}", e))?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Parse test results (simplified)
    let tests_passed = stdout.contains("passed") || stdout.contains("OK");
    let tests_failed = !output.status.success();

    let summary = if tests_failed {
        format!("Tests failed (exit code {})", exit_code)
    } else {
        "All tests passed".to_string()
    };

    // Print output
    if !stdout.is_empty() {
        eprintln!("{}", stdout);
    }
    if !stderr.is_empty() {
        eprintln!("{}", stderr);
    }

    // Build compat_warnings for JSON output
    let run_compat_warnings_json: Vec<Value> = if args.pytest_compat {
        discovery_result
            .compat_warnings
            .iter()
            .map(|w| {
                json!({
                    "code": w.code,
                    "message": w.message,
                    "path": w.path.display().to_string(),
                    "line": w.line,
                    "severity": format!("{:?}", w.severity).to_lowercase(),
                    "hint": get_pytest_compat_hint(&w.code),
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    let detail = json!({
        "backend": format!("{:?}", backend).to_lowercase(),
        "workspace": member_detail,
        "test_runner": format!("{:?}", backend).to_lowercase(),
        "exit_code": exit_code,
        "passed": tests_passed && !tests_failed,
        "fail_fast": args.fail_fast,
        "pytest_compat": args.pytest_compat,
        "shard": shard_info.map(|(n, m)| format!("{}/{}", n, m)),
        "filter": args.filter,
        "parallel": args.parallel,
        "discovered_files": discovered_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "tests_found": tests.len(),
        "ast_discovery": {
            "tests": tests.len(),
            "fixtures": discovery_result.fixtures.len(),
            "duration_us": discovery_result.duration_us,
            "compat_warnings": discovery_result.compat_warnings.len(),
        },
        "compat_warnings": run_compat_warnings_json,
        "stdout": stdout.to_string(),
        "stderr": stderr.to_string(),
    });

    if tests_failed {
        collector.error_with_code(
            "E_TEST_FAILED",
            summary.clone(),
            "Inspect stdout/stderr in the response for failing test output, fix the failing tests, and re-run `pybun test`.",
        );
        Ok(RenderDetail::error(summary, detail))
    } else {
        Ok(RenderDetail::with_json(summary, detail))
    }
}

// ---------------------------------------------------------------------------
// Native pybun test executor
// ---------------------------------------------------------------------------

/// Strip pytest's non-deterministic timing text (e.g. "1 passed in 0.01s")
/// from captured stdout before it is recorded as/compared against a snapshot.
/// Without this, snapshots would flap on every run since pytest reports wall-clock
/// duration in its summary line.
fn normalize_snapshot_stdout(stdout: &str) -> String {
    stdout
        .lines()
        .map(normalize_timing_in_line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Replaces a `in <digits>[.<digits>]s` duration marker that trails a pytest
/// session summary line (e.g. "==== 1 passed in 0.01s ====" or
/// "1 passed, 2 failed in 0.01s") with a stable placeholder.
///
/// Only the *last* `" in "` on a line is considered, and only when the digits+`s`
/// run is followed solely by border/whitespace characters (`=`, ` `) through the
/// end of the line. This anchors the rewrite to pytest's summary format and avoids
/// mangling incidental `" in "` substrings inside test names or assertion text
/// (e.g. "assert 1 in [2, 3]"), which would otherwise corrupt snapshot content.
fn normalize_timing_in_line(line: &str) -> String {
    let Some(marker) = line.rfind(" in ") else {
        return line.to_string();
    };
    let prefix_end = marker + 4;
    let rest = &line[prefix_end..];
    let digits_end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(rest.len());
    let duration = &rest[..digits_end];
    let has_digit = duration.chars().any(|c| c.is_ascii_digit());
    if !has_digit || !rest[digits_end..].starts_with('s') {
        return line.to_string();
    }
    let trailer = &rest[digits_end + 1..];
    if !trailer.chars().all(|c| c == '=' || c.is_whitespace()) {
        return line.to_string();
    }
    format!("{}X.XXs{}", &line[..prefix_end], trailer)
}

fn run_tests_native(
    args: &crate::cli::TestArgs,
    tests: Vec<TestItem>,
    shard_info: Option<(u32, u32)>,
    python: &str,
    member_detail: Option<Value>,
    collector: &mut EventCollector,
) -> Result<RenderDetail> {
    use crate::test_executor::{ExecutorConfig, TestExecutor, TestOutcome};

    let workers = args.parallel.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4)
    });

    let config = ExecutorConfig {
        workers,
        fail_fast: args.fail_fast,
        shard: shard_info,
        verbose: args.verbose,
        timeout: args.timeout,
        retries: args.retries.unwrap_or(0),
        python: python.to_string(),
    };

    let executor = TestExecutor::new(config);

    collector.info(format!(
        "Running {} tests with native pybun executor ({} workers)",
        tests.len(),
        workers
    ));

    let result = executor.execute(tests);
    let summary = &result.summary;

    // Native snapshot integration: each passing test's captured stdout is
    // compared against (or written to, in update mode) its stored snapshot
    // via the same SnapshotManager primitives `pybun test --snapshot` exposes.
    let snapshot_config = if args.snapshot || args.update_snapshots {
        use crate::snapshot::{SnapshotManager, SnapshotResult};

        let snapshot_dir = args
            .snapshot_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("__snapshots__"));
        let mut manager = SnapshotManager::new(snapshot_dir.clone(), args.update_snapshots);

        for r in result
            .results
            .iter()
            .filter(|r| matches!(r.outcome, TestOutcome::Passed | TestOutcome::XPass))
        {
            // A test that needed retries produced different output on at least one
            // earlier attempt, so the snapshot is being recorded against/compared with
            // only its final (non-deterministic) attempt's stdout. Surface this so
            // consumers know the baseline may not be reproducible run-to-run.
            if r.retries > 0 {
                collector.diagnostic(Diagnostic {
                    level: crate::schema::DiagnosticLevel::Warning,
                    code: Some("W_SNAPSHOT_FLAKY_RETRY".to_string()),
                    message: format!(
                        "{}::{} passed only after {} retr{} — its snapshot reflects the final attempt's output, which may not be reproducible",
                        r.path.display(),
                        r.name,
                        r.retries,
                        if r.retries == 1 { "y" } else { "ies" }
                    ),
                    file: Some(r.path.display().to_string()),
                    line: u32::try_from(r.line).ok(),
                    suggestion: Some("Investigate test flakiness before relying on this snapshot as a stable baseline".to_string()),
                    context: None,
                    fix_candidates: None,
                });
            }
            let normalized = normalize_snapshot_stdout(&r.stdout);
            manager.assert_snapshot(&r.path, &r.name, &normalized);
        }

        if let Err(e) = manager.save_all() {
            collector.diagnostic(Diagnostic {
                level: crate::schema::DiagnosticLevel::Warning,
                code: Some("E_SNAPSHOT_SAVE".to_string()),
                message: format!("failed to save snapshot updates: {}", e),
                file: None,
                line: None,
                suggestion: None,
                context: None,
                fix_candidates: None,
            });
        }

        let snap_summary = manager.summary();
        let snapshot_results_json: Vec<Value> = manager
            .results()
            .iter()
            .map(|r| {
                let (status, expected, actual, diff, message) = match &r.result {
                    SnapshotResult::Match => ("match", None, None, None, None),
                    SnapshotResult::Mismatch {
                        expected,
                        actual,
                        diff,
                    } => (
                        "mismatch",
                        Some(expected.clone()),
                        Some(actual.clone()),
                        Some(diff.clone()),
                        None,
                    ),
                    SnapshotResult::New { actual } => {
                        ("new", None, Some(actual.clone()), None, None)
                    }
                    SnapshotResult::Error { message } => {
                        ("error", None, None, None, Some(message.clone()))
                    }
                };
                json!({
                    "test_name": r.test_name,
                    "source_file": r.source_file.display().to_string(),
                    "status": status,
                    "updated": r.updated,
                    "expected": expected,
                    "actual": actual,
                    "diff": diff,
                    "message": message,
                })
            })
            .collect();

        Some(json!({
            "snapshot_dir": snapshot_dir.display().to_string(),
            "update_mode": args.update_snapshots,
            "summary": {
                "total": snap_summary.total(),
                "passed": snap_summary.passed,
                "failed": snap_summary.failed,
                "created": snap_summary.created,
                "updated": snap_summary.updated,
                "new": snap_summary.new,
                "errors": snap_summary.errors,
            },
            "results": snapshot_results_json,
        }))
    } else {
        None
    };

    let text_summary = if summary.all_passed() {
        format!(
            "{} passed, {} skipped in {:.2}s",
            summary.passed,
            summary.skipped,
            summary.duration_ms as f64 / 1000.0
        )
    } else {
        format!(
            "{} passed, {} failed, {} errors, {} skipped in {:.2}s",
            summary.passed,
            summary.failed,
            summary.errors,
            summary.skipped,
            summary.duration_ms as f64 / 1000.0
        )
    };

    // Emit diagnostics for failed and timed-out tests
    for failed in result.failed_or_timed_out_tests() {
        let (code, prefix, suggestion) = if failed.outcome == TestOutcome::Timeout {
            (
                "E_TEST_TIMEOUT",
                "TIMEOUT",
                "This test exceeded its timeout; increase --timeout if the test is legitimately slow, or fix the hang and re-run `pybun test`.",
            )
        } else {
            (
                "E_TEST_FAILED",
                "FAILED",
                "Inspect the file/line and stderr context, fix the failing test or implementation, and re-run `pybun test`.",
            )
        };
        let diag = Diagnostic {
            level: crate::schema::DiagnosticLevel::Error,
            code: Some(code.to_string()),
            message: format!("{prefix} {}", failed.name),
            file: Some(failed.path.display().to_string()),
            line: Some(failed.line as u32),
            suggestion: Some(suggestion.to_string()),
            context: if failed.stderr.is_empty() {
                None
            } else {
                Some(Value::String(failed.stderr.clone()))
            },
            fix_candidates: None,
        };
        collector.diagnostic(diag);
    }

    let results_json: Vec<Value> = result
        .results
        .iter()
        .map(|r| {
            json!({
                "name": r.name,
                "path": r.path.display().to_string(),
                "line": r.line,
                // Use serde serialization, not Debug, so this stays in sync
                // with TestOutcome's #[serde(rename_all = "lowercase")] derive.
                "outcome": serde_json::to_value(&r.outcome).unwrap_or(Value::Null),
                "duration_ms": r.duration_ms,
                "worker_id": r.worker_id,
                "skip_reason": r.skip_reason,
                "retries": r.retries,
            })
        })
        .collect();

    let detail = json!({
        "backend": "pybun",
        "workspace": member_detail,
        "test_runner": "pybun",
        "workers": workers,
        "fail_fast": args.fail_fast,
        "timeout": args.timeout,
        "retries": args.retries.unwrap_or(0),
        "shard": shard_info.map(|(n, m)| format!("{}/{}", n, m)),
        "filter": args.filter,
        "parallel": args.parallel,
        "snapshot": args.snapshot,
        "update_snapshots": args.update_snapshots,
        "snapshot_config": snapshot_config,
        "summary": {
            "total": summary.total,
            "passed": summary.passed,
            "failed": summary.failed,
            "skipped": summary.skipped,
            "errors": summary.errors,
            "timeouts": summary.timeouts,
            "xfail": summary.xfail,
            "xpass": summary.xpass,
            "duration_ms": summary.duration_ms,
            "stopped_early": summary.stopped_early,
        },
        "results": results_json,
    });

    if summary.all_passed() {
        Ok(RenderDetail::with_json(text_summary, detail))
    } else {
        Ok(RenderDetail::error(text_summary, detail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_shard_valid() {
        assert_eq!(parse_shard("1/2").unwrap(), (1, 2));
        assert_eq!(parse_shard("3/4").unwrap(), (3, 4));
        assert_eq!(parse_shard("1/1").unwrap(), (1, 1));
    }

    #[test]
    fn test_parse_shard_invalid() {
        assert!(parse_shard("invalid").is_err());
        assert!(parse_shard("1").is_err());
        assert!(parse_shard("a/b").is_err());
        assert!(parse_shard("0/2").is_err());
        assert!(parse_shard("3/2").is_err());
    }

    #[test]
    fn test_normalize_snapshot_stdout_masks_pytest_duration() {
        let first = "collecting ... collected 1 item\n\
test_snap.py::test_prints PASSED\n\
============================== 1 passed in 0.01s ===============================";
        let second = "collecting ... collected 1 item\n\
test_snap.py::test_prints PASSED\n\
============================== 1 passed in 0.00s ===============================";

        assert_eq!(
            normalize_snapshot_stdout(first),
            normalize_snapshot_stdout(second)
        );
        assert!(normalize_snapshot_stdout(first).contains("in X.XXs"));
    }

    #[test]
    fn test_normalize_snapshot_stdout_handles_multi_status_summary() {
        let first = "================ 2 passed, 1 failed in 0.05s ================";
        let second = "================ 2 passed, 1 failed in 1.23s ================";
        assert_eq!(
            normalize_snapshot_stdout(first),
            normalize_snapshot_stdout(second)
        );
        assert!(normalize_snapshot_stdout(first).contains("in X.XXs"));
    }

    #[test]
    fn test_normalize_snapshot_stdout_does_not_mangle_incidental_in_text() {
        // " in " inside an assertion message or test name must survive untouched —
        // only the trailing pytest summary duration should ever be rewritten.
        let stdout = "FAILED test_foo.py::test_bar - assert 1 in [2, 3]\n\
test_collection.py::test_year checks 1 in 2024\n\
collected 3 items in fixtures.py";
        assert_eq!(normalize_snapshot_stdout(stdout), stdout);
    }

    #[test]
    fn test_normalize_snapshot_stdout_preserves_unrelated_lines() {
        let stdout = "hello snapshot\nPASSED\n";
        assert_eq!(normalize_snapshot_stdout(stdout), "hello snapshot\nPASSED");
    }

    #[test]
    fn native_backend_compat_diagnostic_prefixes_code_and_suggests_pytest_backend() {
        use crate::test_discovery::{CompatWarning, WarningSeverity};
        use std::path::PathBuf;

        let warning = CompatWarning {
            code: "W001".to_string(),
            message: "Session/package scoped fixture may need pytest backend: fixture".to_string(),
            path: PathBuf::from("test_example.py"),
            line: 5,
            severity: WarningSeverity::Warning,
        };

        let diag = native_backend_compat_diagnostic(&warning);

        assert_eq!(diag.code.as_deref(), Some("W_TEST_BACKEND_COMPAT_W001"));
        assert_eq!(diag.level, crate::schema::DiagnosticLevel::Warning);
        assert_eq!(diag.file.as_deref(), Some("test_example.py"));
        assert_eq!(diag.line, Some(5));
        assert!(diag.message.contains(&warning.message));
        let suggestion = diag.suggestion.as_deref().unwrap_or("");
        assert!(
            suggestion.contains("--backend=pytest"),
            "expected suggestion to mention --backend=pytest, got: {suggestion:?}"
        );
    }

    #[test]
    fn native_backend_compat_diagnostic_maps_severity_levels() {
        use crate::test_discovery::{CompatWarning, WarningSeverity};
        use std::path::PathBuf;

        let make = |severity| CompatWarning {
            code: "I001".to_string(),
            message: "info".to_string(),
            path: PathBuf::from("t.py"),
            line: 1,
            severity,
        };

        assert_eq!(
            native_backend_compat_diagnostic(&make(WarningSeverity::Info)).level,
            crate::schema::DiagnosticLevel::Info
        );
        assert_eq!(
            native_backend_compat_diagnostic(&make(WarningSeverity::Warning)).level,
            crate::schema::DiagnosticLevel::Warning
        );
        assert_eq!(
            native_backend_compat_diagnostic(&make(WarningSeverity::Error)).level,
            crate::schema::DiagnosticLevel::Error
        );
    }
}
