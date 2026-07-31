//! Maintenance-oriented MCP tools: gc, doctor, lint, type-check, profile,
//! fix, context, drift, test, audit, upgrade.
//!
//! Extracted from `mcp.rs` (Issue #344).

use super::super::audit::{
    GitAvailability, current_working_dir, get_changed_test_files, parse_ruff_violations,
    resolve_ruff_runner, ruff_failure_message, valid_ruff_status,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

pub(crate) fn call_gc(args: Value) -> Result<String, String> {
    let max_size = args.get("max_size").and_then(|s| s.as_str());
    let dry_run = args
        .get("dry_run")
        .and_then(|d| d.as_bool())
        .unwrap_or(false);

    use crate::cache::{Cache, format_size, parse_size};

    let cache = Cache::new().map_err(|e| e.to_string())?;
    let max_bytes = max_size.map(parse_size).transpose()?;

    let result = cache.gc(max_bytes, dry_run).map_err(|e| e.to_string())?;

    Ok(json!({
        "status": "gc_complete",
        "freed_bytes": result.freed_bytes,
        "freed_human": format_size(result.freed_bytes),
        "files_removed": result.files_removed,
        "dry_run": dry_run
    })
    .to_string())
}

pub(crate) fn call_doctor(args: Value) -> Result<String, String> {
    use crate::cache::Cache;
    use crate::env::find_python_env;
    use crate::project::Project;

    let verbose = args
        .get("verbose")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut checks: Vec<Value> = Vec::new();
    let mut all_ok = true;

    // Check Python availability
    let working_dir = std::env::current_dir().map_err(|e| e.to_string())?;
    match find_python_env(&working_dir) {
        Ok(env) => {
            checks.push(json!({
                "name": "python",
                "status": "ok",
                "message": format!("Python found at {}", env.python_path.display()),
                "source": format!("{}", env.source),
                "version": env.version,
            }));
        }
        Err(e) => {
            checks.push(json!({
                "name": "python",
                "status": "error",
                "message": format!("Python not found: {}", e),
            }));
            all_ok = false;
        }
    }

    // Check cache directory
    match Cache::new() {
        Ok(cache) => {
            let cache_dir = cache.root();
            let mut cache_check = json!({
                "name": "cache",
                "status": "ok",
                "message": format!("Cache directory: {}", cache_dir.display()),
                "path": cache_dir.display().to_string(),
            });

            if verbose && let Ok(size) = cache.total_size() {
                cache_check["total_size"] = json!(size);
                cache_check["total_size_human"] = json!(crate::cache::format_size(size));
            }
            checks.push(cache_check);
        }
        Err(e) => {
            checks.push(json!({
                "name": "cache",
                "status": "error",
                "message": format!("Cache initialization failed: {}", e),
            }));
            all_ok = false;
        }
    }

    // Check the PyPI metadata cache directory (separate from the main
    // cache root above - see issue #202). Flag stale/corrupt entries
    // (e.g. unreadable `.bin`/`.json` files left over from an older or
    // interrupted `pybun` run, see issue #268) as a non-fatal `info`
    // status pointing at `pybun gc` as the fix, mirroring the CLI
    // `pybun doctor` check and the `corrupt` lockfile status below.
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
            "hint": if stats.stale_count > 0 {
                json!("Run `pybun gc` to remove corrupt/stale PyPI cache entries")
            } else {
                Value::Null
            },
        }));
        // Stale/corrupt cache entries are non-fatal (self-healed on
        // next fetch) - they do not flip `all_ok` to false.
    }

    // Check for pyproject.toml
    match Project::discover(&working_dir) {
        Ok(project) => {
            let deps = project.dependencies();
            checks.push(json!({
                "name": "project",
                "status": "ok",
                "message": format!("Project found at {}", project.path().display()),
                "path": project.path().display().to_string(),
                "dependencies_count": deps.len(),
                "dependencies": if verbose { json!(deps) } else { json!(null) },
            }));
        }
        Err(_) => {
            checks.push(json!({
                "name": "project",
                "status": "info",
                "message": "No pyproject.toml found in current directory",
            }));
        }
    }

    // Check for lockfile
    let lockfile_path = working_dir.join("pybun.lock");
    if lockfile_path.exists() {
        checks.push(json!({
            "name": "lockfile",
            "status": "ok",
            "message": format!("Lockfile found at {}", lockfile_path.display()),
            "path": lockfile_path.display().to_string(),
        }));
    } else {
        checks.push(json!({
            "name": "lockfile",
            "status": "info",
            "message": "No pybun.lock found",
        }));
    }

    let status = if all_ok { "healthy" } else { "issues_found" };
    let summary = if all_ok {
        "All checks passed"
    } else {
        "Some issues found"
    };

    Ok(json!({
        "status": status,
        "checks": checks,
        "verbose": verbose,
        "message": summary,
    })
    .to_string())
}

pub(crate) fn call_lint(args: Value) -> Result<String, String> {
    use crate::env::find_python_env;

    let script = args.get("script").and_then(|s| s.as_str());
    let code = args.get("code").and_then(|c| c.as_str());
    let select: Vec<String> = args
        .get("select")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Determine target path (script or temp file for inline code)
    let (target_path, _temp_file) = match (script, code) {
        (Some(p), _) => (p.to_string(), None::<tempfile::NamedTempFile>),
        (None, Some(inline)) => {
            let mut tmp = tempfile::Builder::new()
                .suffix(".py")
                .tempfile()
                .map_err(|e| format!("Failed to create temp file: {}", e))?;
            use std::io::Write;
            write!(tmp, "{}", inline).map_err(|e| e.to_string())?;
            let path = tmp.path().to_string_lossy().to_string();
            (path, Some(tmp))
        }
        _ => return Err("Either 'script' or 'code' must be provided".to_string()),
    };

    let target_display = if script.is_none() {
        "inline_code"
    } else {
        &target_path
    };

    let working_dir = current_working_dir()?;

    if let Some(ruff_runner) = resolve_ruff_runner(&working_dir)? {
        let mut cmd = ruff_runner.command();
        cmd.args(["check", "--output-format=json"]);
        if !select.is_empty() {
            cmd.arg("--select");
            cmd.arg(select.join(","));
        }
        cmd.arg(&target_path);

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run ruff: {}", e))?;
        let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

        if !valid_ruff_status(&output.status) {
            return Err(ruff_failure_message("check", &stdout_str, &stderr_str));
        }

        let violations: Vec<Value> = parse_ruff_violations(&stdout_str)?
            .into_iter()
            .map(|v| {
                json!({
                    "file": v.get("filename").and_then(|f| f.as_str()).unwrap_or(&target_path),
                    "line": v.get("location").and_then(|l| l.get("row")).and_then(|r| r.as_u64()).unwrap_or(0),
                    "column": v.get("location").and_then(|l| l.get("column")).and_then(|c| c.as_u64()).unwrap_or(0),
                    "code": v.get("code").and_then(|c| c.as_str()).unwrap_or(""),
                    "message": v.get("message").and_then(|m| m.as_str()).unwrap_or(""),
                    "fix_available": v.get("fix").is_some(),
                })
            })
            .collect();

        Ok(json!({
            "status": "lint_complete",
            "tool": "ruff",
            "target": target_display,
            "violations": violations,
            "violation_count": violations.len(),
            "clean": violations.is_empty(),
            "diagnostics": violations.iter().filter_map(|v| {
                let msg = v.get("message")?.as_str()?;
                let code = v.get("code")?.as_str()?;
                Some(json!({
                    "kind": code,
                    "message": msg,
                    "hint": if v.get("fix_available").and_then(|f| f.as_bool()).unwrap_or(false) {
                        format!("Auto-fixable with pybun_fix. Code: {}", code)
                    } else {
                        format!("Manual fix required. Code: {}", code)
                    }
                }))
            }).collect::<Vec<_>>(),
        })
        .to_string())
    } else {
        // Fall back to python -m py_compile for basic syntax check
        let env = find_python_env(&working_dir).map_err(|e| e.to_string())?;
        let python_path = env.python_path.to_string_lossy().to_string();

        let output = ProcessCommand::new(&python_path)
            .args(["-m", "py_compile", &target_path])
            .output()
            .map_err(|e| format!("Failed to run py_compile: {}", e))?;

        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok(json!({
            "status": "lint_complete",
            "tool": "py_compile",
            "tool_not_available": "ruff",
            "hint": "Install ruff for full linting: pybun add ruff",
            "violations": [],
            "syntax_ok": output.status.success(),
            "stderr": stderr,
            "target": target_display,
        })
        .to_string())
    }
}

pub(crate) fn call_type_check(args: Value) -> Result<String, String> {
    use crate::env::find_python_env;

    let script = args.get("script").and_then(|s| s.as_str());
    let code = args.get("code").and_then(|c| c.as_str());
    let strict = args
        .get("strict")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);

    let working_dir = std::env::current_dir().map_err(|e| e.to_string())?;
    let env = find_python_env(&working_dir).map_err(|e| e.to_string())?;
    let python_path = env.python_path.to_string_lossy().to_string();

    // Determine target (script or temp file for inline code)
    let (target_path, _temp_file) = match (script, code) {
        (Some(p), _) => (p.to_string(), None::<tempfile::NamedTempFile>),
        (None, Some(inline)) => {
            let mut tmp = tempfile::Builder::new()
                .suffix(".py")
                .tempfile()
                .map_err(|e| format!("Failed to create temp file: {}", e))?;
            use std::io::Write;
            write!(tmp, "{}", inline).map_err(|e| e.to_string())?;
            let path = tmp.path().to_string_lossy().to_string();
            (path, Some(tmp))
        }
        _ => return Err("Either 'script' or 'code' must be provided".to_string()),
    };

    // Check if mypy is available
    let mypy_check = ProcessCommand::new(&python_path)
        .args(["-m", "mypy", "--version"])
        .output();

    if mypy_check.is_err() || !mypy_check.unwrap().status.success() {
        return Ok(json!({
            "status": "type_check_complete",
            "tool_not_available": "mypy",
            "hint": "Install mypy for type checking: pybun add mypy",
            "errors": [],
            "target": target_path,
        })
        .to_string());
    }

    // Run mypy
    let mut cmd = ProcessCommand::new(&python_path);
    cmd.args(["-m", "mypy", "--show-error-codes", "--no-color-output"]);
    if strict {
        cmd.arg("--strict");
    }
    cmd.arg(&target_path);

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run mypy: {}", e))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();

    // Parse mypy output (line format: "file:line: severity: message  [code]")
    let errors: Vec<Value> = stdout_str
        .lines()
        .filter(|line| line.contains(": error:") || line.contains(": warning:") || line.contains(": note:"))
        .filter_map(|line| {
            // Parse: path:line:col: severity: message  [error-code]
            let parts: Vec<&str> = line.splitn(4, ':').collect();
            if parts.len() < 4 {
                return None;
            }
            let file = parts[0];
            let line_num: u64 = parts[1].trim().parse().unwrap_or(0);
            let rest = parts[3];
            let (severity, message) = if let Some(idx) = rest.find(": ") {
                let sev = rest[..idx].trim();
                let msg = rest[idx + 2..].trim();
                (sev, msg)
            } else {
                ("error", rest.trim())
            };
            // Extract error code if present: "message  [error-code]"
            let (msg_clean, error_code) = if let (Some(start), Some(end)) = (message.rfind('['), message.rfind(']')) {
                let code = &message[start + 1..end];
                let msg = message[..start].trim();
                (msg, code.to_string())
            } else {
                (message, String::new())
            };

            Some(json!({
                "file": file,
                "line": line_num,
                "severity": severity.trim(),
                "message": msg_clean,
                "code": error_code,
                "hint": format!("See https://mypy.readthedocs.io/en/stable/error_codes.html#{}", error_code.to_lowercase()),
            }))
        })
        .collect();

    let target_display = if script.is_none() {
        "inline_code"
    } else {
        &target_path
    };

    Ok(json!({
        "status": "type_check_complete",
        "tool": "mypy",
        "target": target_display,
        "strict": strict,
        "success": output.status.success(),
        "errors": errors,
        "error_count": errors.len(),
        "clean": errors.is_empty(),
        "raw_output": stdout_str,
    })
    .to_string())
}

pub(crate) fn call_profile(args: Value) -> Result<String, String> {
    use crate::env::find_python_env;

    let script = args.get("script").and_then(|s| s.as_str());
    let code = args.get("code").and_then(|c| c.as_str());
    let top_n = args.get("top_n").and_then(|n| n.as_u64()).unwrap_or(10) as usize;

    let working_dir = std::env::current_dir().map_err(|e| e.to_string())?;
    let env = find_python_env(&working_dir).map_err(|e| e.to_string())?;
    let python_path = env.python_path.to_string_lossy().to_string();

    // Resolve target: write inline code to temp file if needed
    let (_temp_target, target_path_str): (Option<tempfile::NamedTempFile>, String) =
        match (script, code) {
            (Some(p), _) => {
                let path = PathBuf::from(p);
                if !path.exists() {
                    return Err(format!("Script not found: {}", p));
                }
                (None, p.to_string())
            }
            (None, Some(inline)) => {
                let mut tmp = tempfile::Builder::new()
                    .suffix(".py")
                    .tempfile()
                    .map_err(|e| format!("Failed to create temp file: {}", e))?;
                use std::io::Write as _;
                write!(tmp, "{}", inline).map_err(|e| e.to_string())?;
                let p = tmp.path().to_string_lossy().to_string();
                (Some(tmp), p)
            }
            _ => return Err("Either 'script' or 'code' must be provided".to_string()),
        };

    // Write profiler runner to a temp file to avoid format-string escaping issues
    // with Python dict literals inside Rust format! macros.
    let profiler_src = [
        "import cProfile, pstats, io, json, os, re, sys",
        &format!(
            "_target = {}",
            serde_json::to_string(&target_path_str).unwrap_or_default()
        ),
        &format!("_top_n = {}", top_n),
        "_globals = {'__name__': '__main__', '__file__': _target, '__package__': None, '__cached__': None}",
        "_argv = list(sys.argv)",
        "_path = list(sys.path)",
        "_script_dir = os.path.dirname(_target)",
        "if _script_dir:",
        "    sys.path.insert(0, _script_dir)",
        "sys.argv = [_target]",
        "pr = cProfile.Profile()",
        "try:",
        "    pr.enable()",
        "    with open(_target) as _f:",
        "        exec(compile(_f.read(), _target, 'exec'), _globals)",
        "finally:",
        "    pr.disable()",
        "    sys.argv = _argv",
        "    sys.path[:] = _path",
        "s = io.StringIO()",
        "ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')",
        "ps.print_stats(_top_n)",
        "raw = s.getvalue()",
        "hotspots = []",
        "for line in raw.strip().split('\\n'):",
        "    parts = line.split()",
        "    if len(parts) >= 6 and parts[0].replace('.','',1).isdigit():",
        "        try:",
        "            hotspots.append({'ncalls': parts[0], 'tottime': float(parts[1]),",
        "                'percall_tot': float(parts[2]), 'cumtime': float(parts[3]),",
        "                'percall_cum': float(parts[4]), 'location': ' '.join(parts[5:])})",
        "        except (ValueError, IndexError):",
        "            pass",
        "total_match = re.search(r'(\\d+\\.\\d+) seconds', raw)",
        "total_time = float(total_match.group(1)) if total_match else 0.0",
        "calls_match = re.search(r'(\\d+) function calls', raw)",
        "total_calls = int(calls_match.group(1)) if calls_match else 0",
        "print(json.dumps({'total_time_s': total_time, 'total_calls': total_calls,",
        "    'hotspots': hotspots[:_top_n], 'status': 'profile_complete'}))",
    ]
    .join("\n");

    let mut runner_tmp = tempfile::Builder::new()
        .suffix(".py")
        .tempfile()
        .map_err(|e| format!("Failed to create profiler script: {}", e))?;
    {
        use std::io::Write as _;
        write!(runner_tmp, "{}", profiler_src).map_err(|e| e.to_string())?;
    }

    let profile_script_path = runner_tmp.path().to_string_lossy().to_string();

    let output = ProcessCommand::new(&python_path)
        .arg(&profile_script_path)
        .output()
        .map_err(|e| format!("Failed to run profiler: {}", e))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        return Err(format!(
            "Profiler failed: {}",
            if stderr_str.is_empty() {
                &stdout_str
            } else {
                &stderr_str
            }
        ));
    }

    // Parse the JSON output from the profiler script
    let result: Value = serde_json::from_str(stdout_str.trim()).unwrap_or_else(|_| {
        json!({
            "status": "profile_complete",
            "raw": stdout_str,
        })
    });

    let target_display = script.unwrap_or("inline_code");
    let mut out = result.as_object().cloned().unwrap_or_default();
    out.insert("target".to_string(), json!(target_display));
    out.insert("top_n".to_string(), json!(top_n));

    serde_json::to_string(&out).map_err(|e| e.to_string())
}

pub(crate) fn call_fix(args: Value) -> Result<String, String> {
    let script = args
        .get("script")
        .and_then(|s| s.as_str())
        .ok_or_else(|| "'script' is required for pybun_fix".to_string())?;

    let select: Vec<String> = args
        .get("select")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let unsafe_fixes = args
        .get("unsafe_fixes")
        .and_then(|u| u.as_bool())
        .unwrap_or(false);

    let path = PathBuf::from(script);
    if !path.exists() {
        return Err(format!("Script not found: {}", script));
    }

    let working_dir = current_working_dir()?;
    let Some(ruff_runner) = resolve_ruff_runner(&working_dir)? else {
        return Ok(json!({
            "status": "fix_complete",
            "tool_not_available": "ruff",
            "hint": "Install ruff for auto-fixing: pybun add ruff",
            "fixes_applied": 0,
            "target": script,
        })
        .to_string());
    };

    // Run ruff check --fix to get count of fixable violations before
    let mut check_cmd = ruff_runner.command();
    check_cmd.args(["check", "--output-format=json"]);
    if !select.is_empty() {
        check_cmd.arg("--select");
        check_cmd.arg(select.join(","));
    }
    check_cmd.arg(script);
    let before_output = check_cmd.output().map_err(|e| e.to_string())?;
    let before_str = String::from_utf8_lossy(&before_output.stdout).to_string();
    let before_stderr = String::from_utf8_lossy(&before_output.stderr).to_string();
    if !valid_ruff_status(&before_output.status) {
        return Err(ruff_failure_message("check", &before_str, &before_stderr));
    }
    let before_count = parse_ruff_violations(&before_str)?.len();

    // Apply fixes
    let mut fix_cmd = ruff_runner.command();
    fix_cmd.args(["check", "--fix"]);
    if unsafe_fixes {
        fix_cmd.arg("--unsafe-fixes");
    }
    if !select.is_empty() {
        fix_cmd.arg("--select");
        fix_cmd.arg(select.join(","));
    }
    fix_cmd.arg(script);

    let fix_output = fix_cmd
        .output()
        .map_err(|e| format!("Failed to run ruff fix: {}", e))?;
    let fix_stdout = String::from_utf8_lossy(&fix_output.stdout).to_string();
    let fix_stderr = String::from_utf8_lossy(&fix_output.stderr).to_string();
    if !valid_ruff_status(&fix_output.status) {
        return Err(ruff_failure_message(
            "check --fix",
            &fix_stdout,
            &fix_stderr,
        ));
    }

    // Count remaining violations
    let mut recheck_cmd = ruff_runner.command();
    recheck_cmd.args(["check", "--output-format=json"]);
    if !select.is_empty() {
        recheck_cmd.arg("--select");
        recheck_cmd.arg(select.join(","));
    }
    recheck_cmd.arg(script);
    let after_output = recheck_cmd.output().map_err(|e| e.to_string())?;
    let after_str = String::from_utf8_lossy(&after_output.stdout).to_string();
    let after_stderr = String::from_utf8_lossy(&after_output.stderr).to_string();
    if !valid_ruff_status(&after_output.status) {
        return Err(ruff_failure_message("check", &after_str, &after_stderr));
    }
    let after_count = parse_ruff_violations(&after_str)?.len();

    let fixes_applied = before_count.saturating_sub(after_count);

    Ok(json!({
        "status": "fix_complete",
        "tool": "ruff",
        "target": script,
        "fixes_applied": fixes_applied,
        "violations_before": before_count,
        "violations_after": after_count,
        "unsafe_fixes": unsafe_fixes,
        "stderr": fix_stderr,
    })
    .to_string())
}

pub(crate) fn read_cache_info() -> Result<String, String> {
    use crate::cache::{Cache, format_size};

    let cache = Cache::new().map_err(|e| e.to_string())?;
    let total_size = cache.total_size().map_err(|e| e.to_string())?;

    Ok(json!({
        "root": cache.root().display().to_string(),
        "total_size": total_size,
        "total_size_human": format_size(total_size)
    })
    .to_string())
}

pub(crate) fn read_env_info() -> Result<String, String> {
    use crate::env::find_python_env;

    let working_dir = std::env::current_dir().map_err(|e| e.to_string())?;

    match find_python_env(&working_dir) {
        Ok(env) => Ok(json!({
            "python_path": env.python_path.display().to_string(),
            "source": format!("{}", env.source),
            "version": env.version
        })
        .to_string()),
        Err(e) => Ok(json!({
            "error": e.to_string(),
            "message": "No Python environment found"
        })
        .to_string()),
    }
}

pub(crate) fn call_context(args: Value) -> Result<String, String> {
    use crate::env::{EnvSource, find_python_env};
    use crate::lockfile::Lockfile;
    use crate::project::Project;
    use std::collections::HashSet;
    use std::time::{SystemTime, UNIX_EPOCH};

    let summary_only = args
        .get("summary_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let include_drift = args
        .get("include_drift")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let working_dir = if let Some(cwd) = args.get("cwd").and_then(|v| v.as_str()) {
        std::path::PathBuf::from(cwd)
    } else {
        std::env::current_dir().map_err(|e| e.to_string())?
    };

    let snapshot_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // PEP 503: normalize [-_.] sequences to a single hyphen for package name comparison.
    fn normalize_pkg_name(name: &str) -> String {
        let lower = name.to_lowercase();
        let mut result = String::with_capacity(lower.len());
        let mut prev_was_sep = false;
        for ch in lower.chars() {
            if ch == '-' || ch == '_' || ch == '.' {
                if !prev_was_sep {
                    result.push('-');
                }
                prev_was_sep = true;
            } else {
                result.push(ch);
                prev_was_sep = false;
            }
        }
        result
    }

    // ── Python / venv info ────────────────────────────────────────────────
    let (python_version, venv_path, venv_status) = match find_python_env(&working_dir) {
        Ok(env) => {
            let is_local = matches!(env.source, EnvSource::ProjectLocal | EnvSource::PybunEnv);
            let venv = if is_local {
                env.python_path
                    .parent()
                    .and_then(|p| p.parent())
                    .map(|p| p.display().to_string())
            } else {
                None
            };
            (env.version, venv, "ok".to_string())
        }
        Err(_) => {
            // Mirror find_project_venv's probe list: directory exists but no Python binary = corrupt.
            let venv_candidates = [
                working_dir.join(".pybun").join("venv"),
                working_dir.join(".venv"),
                working_dir.join("venv"),
            ];
            let status = if venv_candidates.iter().any(|p| p.is_dir()) {
                "corrupt"
            } else {
                "missing"
            };
            (None, None, status.to_string())
        }
    };

    // ── Project declared dependencies ─────────────────────────────────────
    let declared_deps: Vec<String> = Project::discover(&working_dir)
        .map(|p| p.dependencies())
        .unwrap_or_default();
    let declared_names: HashSet<String> = declared_deps
        .iter()
        .map(|d| {
            let bare = d
                .split(['>', '<', '=', '!', '~', ';', '['])
                .next()
                .unwrap_or(d)
                .trim();
            normalize_pkg_name(bare)
        })
        .collect();

    // ── Lockfile ──────────────────────────────────────────────────────────
    let lockfile_path = working_dir.join("pybun.lock");
    let (lockfile_status, locked_packages, locked_names) =
        if let Ok(bytes) = std::fs::read(&lockfile_path) {
            match Lockfile::from_bytes(&bytes) {
                Ok(lf) => {
                    let locked_names: HashSet<String> =
                        lf.packages.keys().map(|k| normalize_pkg_name(k)).collect();
                    let locked: Vec<Value> = lf
                        .packages
                        .values()
                        .map(|pkg| {
                            let norm = normalize_pkg_name(&pkg.name);
                            let declared = declared_names.contains(&norm);
                            json!({
                                "name": pkg.name,
                                "version": pkg.version,
                                "declared": declared,
                                "locked": true
                            })
                        })
                        .collect();
                    let has_drift = declared_names
                        .iter()
                        .any(|d| !locked_names.contains(d.as_str()));
                    let status = if has_drift { "drift" } else { "in_sync" };
                    (status.to_string(), locked, Some(locked_names))
                }
                // Parse failure = lockfile exists but is unreadable/corrupt, distinct from drift.
                Err(_) => ("corrupt".to_string(), vec![], None),
            }
        } else {
            ("missing".to_string(), vec![], None)
        };

    // ── Doctor warnings ───────────────────────────────────────────────────
    let mut doctor_warnings: Vec<Value> = Vec::new();
    if venv_status == "missing" {
        doctor_warnings.push(json!({
            "code": "W_VENV_MISSING",
            "message": "No virtual environment found. Run `pybun install` to create one.",
            "severity": "warn"
        }));
    }
    if venv_status == "corrupt" {
        doctor_warnings.push(json!({
            "code": "W_VENV_CORRUPT",
            "message": "Virtual environment directory exists but Python binary is missing or invalid.",
            "severity": "error"
        }));
    }
    if lockfile_status == "missing" {
        doctor_warnings.push(json!({
            "code": "W_LOCKFILE_MISSING",
            "message": "No pybun.lock found. Run `pybun install` to generate one.",
            "severity": "info"
        }));
    }
    if lockfile_status == "corrupt" {
        doctor_warnings.push(json!({
            "code": "W_LOCKFILE_CORRUPT",
            "message": "pybun.lock exists but cannot be parsed. Run `pybun install` to regenerate.",
            "severity": "error"
        }));
    }
    if lockfile_status == "drift" {
        doctor_warnings.push(json!({
            "code": "W_LOCKFILE_DRIFT",
            "message": "Declared dependencies differ from lockfile. Run `pybun install` to sync.",
            "severity": "warn"
        }));
    }

    // ── Import drift analysis (only when include_drift=true) ──────────────
    let import_drift_summary = if include_drift {
        let drift_result = crate::drift::analyze(&working_dir);
        json!({
            "undeclared_imports": drift_result.undeclared_imports,
            "unused_declarations": drift_result.unused_declarations,
            "files_scanned": drift_result.files_scanned,
            "analysis_notes": drift_result.analysis_notes,
        })
    } else {
        json!({
            "undeclared_imports": null,
            "outdated_packages": []
        })
    };

    // ── Assemble response ─────────────────────────────────────────────────
    if summary_only {
        let declared_count = declared_names.len();
        let installed_count = locked_packages.len();
        let drift_count = locked_names.as_ref().map_or(0, |names| {
            declared_names
                .iter()
                .filter(|d| !names.contains(d.as_str()))
                .count()
        });

        Ok(json!({
            "python_version": python_version,
            "venv_path": venv_path,
            "venv_status": venv_status,
            "lockfile_status": lockfile_status,
            "installed_count": installed_count,
            "declared_count": declared_count,
            "drift_count": drift_count,
            "doctor_warnings": doctor_warnings,
            "drift_summary": import_drift_summary,
            "snapshot_at_ms": snapshot_at_ms
        })
        .to_string())
    } else {
        Ok(json!({
            "python_version": python_version,
            "venv_path": venv_path,
            "venv_status": venv_status,
            "lockfile_status": lockfile_status,
            "installed_packages": locked_packages,
            "doctor_warnings": doctor_warnings,
            "drift_summary": import_drift_summary,
            "snapshot_at_ms": snapshot_at_ms
        })
        .to_string())
    }
}

pub(crate) fn call_drift(args: Value) -> Result<String, String> {
    use crate::drift;

    let cwd_path = if let Some(cwd) = args.get("cwd").and_then(|v| v.as_str()) {
        std::path::PathBuf::from(cwd)
    } else {
        std::env::current_dir().map_err(|e| format!("failed to get cwd: {e}"))?
    };

    if !cwd_path.join("pyproject.toml").exists() {
        return Ok(serde_json::to_string(&json!({
            "error": "pyproject.toml not found",
            "undeclared_imports": [],
            "unused_declarations": [],
            "analysis_notes": ["pyproject.toml not found"],
            "files_scanned": 0
        }))
        .unwrap());
    }

    let result = drift::analyze(&cwd_path);
    Ok(serde_json::to_string(&json!({
        "undeclared_imports": result.undeclared_imports,
        "unused_declarations": result.unused_declarations,
        "analysis_notes": result.analysis_notes,
        "files_scanned": result.files_scanned,
    }))
    .unwrap())
}

pub(crate) fn call_test(args: Value) -> Result<String, String> {
    use crate::test_discovery::{TestDiscovery, TestItemType};
    use crate::test_executor::{ExecutorConfig, TestExecutor, TestOutcome};

    let working_dir = current_working_dir()?;

    let path = args.get("path").and_then(|p| p.as_str()).map(String::from);
    let changed = args
        .get("changed")
        .and_then(|c| c.as_bool())
        .unwrap_or(false);
    let fail_fast = args
        .get("fail_fast")
        .and_then(|f| f.as_bool())
        .unwrap_or(false);
    let filter = args
        .get("filter")
        .and_then(|f| f.as_str())
        .map(String::from);

    // `path` and `changed` are mutually exclusive
    if changed && path.is_some() {
        return Err(
            "'path' and 'changed' are mutually exclusive: use 'changed' to run tests in \
             git-modified files, or 'path' to target a specific file or directory"
                .to_string(),
        );
    }

    let (search_paths, analysis_notes): (Vec<std::path::PathBuf>, Vec<&str>) = if changed {
        let (paths, git_status) = get_changed_test_files(&working_dir)?;
        let note = match git_status {
            GitAvailability::NotARepo => {
                return Ok(json!({
                    "summary": {
                        "total": 0, "passed": 0, "failed": 0,
                        "skipped": 0, "errors": 0, "duration_ms": 0
                    },
                    "failures": [],
                    "passed": [],
                    "analysis_notes": [
                        "git is not available or this directory is not a git repository; \
                         cannot determine changed files"
                    ]
                })
                .to_string());
            }
            GitAvailability::Available if paths.is_empty() => {
                return Ok(json!({
                    "summary": {
                        "total": 0, "passed": 0, "failed": 0,
                        "skipped": 0, "errors": 0, "duration_ms": 0
                    },
                    "failures": [],
                    "passed": [],
                    "analysis_notes": ["No changed test files detected since last commit"]
                })
                .to_string());
            }
            GitAvailability::Available => "running tests from git-changed files only",
        };
        (paths, vec![note])
    } else if let Some(p) = path {
        // Guard against path traversal: reject paths that escape working_dir
        let joined = working_dir.join(&p);
        let canonical = joined
            .canonicalize()
            .map_err(|e| format!("path '{}' does not exist or cannot be resolved: {}", p, e))?;
        if !canonical.starts_with(&working_dir) {
            return Err(format!(
                "path '{}' is outside the working directory and is not allowed",
                p
            ));
        }
        (vec![canonical], vec![])
    } else {
        (vec![working_dir.clone()], vec![])
    };

    if search_paths.is_empty() {
        return Ok(json!({
            "summary": {
                "total": 0, "passed": 0, "failed": 0,
                "skipped": 0, "errors": 0, "duration_ms": 0
            },
            "failures": [],
            "passed": [],
            "analysis_notes": analysis_notes
        })
        .to_string());
    }

    let discovery = TestDiscovery::new();
    let discovery_result = discovery.discover(&search_paths);

    let mut tests: Vec<crate::test_discovery::TestItem> = discovery_result
        .tests
        .iter()
        .filter(|t| t.item_type != TestItemType::Class)
        .cloned()
        .collect();

    if let Some(ref pattern) = filter {
        tests.retain(|t| {
            t.name.contains(pattern.as_str()) || t.short_name.contains(pattern.as_str())
        });
    }

    if tests.is_empty() {
        return Ok(json!({
            "summary": {
                "total": 0, "passed": 0, "failed": 0,
                "skipped": 0, "errors": 0, "duration_ms": 0
            },
            "failures": [],
            "passed": [],
        })
        .to_string());
    }

    let python = crate::env::find_python_env(&working_dir)
        .map(|env| env.python_path.to_string_lossy().to_string())
        .unwrap_or_else(|_| "python3".to_string());

    let workers = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);

    let config = ExecutorConfig {
        workers,
        fail_fast,
        shard: None,
        verbose: false,
        timeout: None,
        retries: 0,
        python,
    };

    let executor = TestExecutor::new(config);
    let result = executor.execute(tests);
    let summary = &result.summary;

    let failures: Vec<Value> = result
        .results
        .iter()
        .filter(|r| {
            !matches!(
                r.outcome,
                TestOutcome::Passed | TestOutcome::Skipped | TestOutcome::XFail
            )
        })
        .map(|r| {
            let file = r.path.display().to_string();
            let rerun_command = format!("pybun test {}::{}", file, r.name);
            let message = if !r.stderr.is_empty() {
                r.stderr.clone()
            } else {
                r.stdout.clone()
            };
            json!({
                "name": r.name,
                "file": file,
                "line": r.line,
                "duration_ms": r.duration_ms,
                "status": serde_json::to_value(&r.outcome).unwrap_or(json!("failed")),
                "message": message,
                "rerun_command": rerun_command,
            })
        })
        .collect();

    let passed: Vec<Value> = result
        .results
        .iter()
        .filter(|r| matches!(r.outcome, TestOutcome::Passed))
        .map(|r| {
            json!({
                "name": r.name,
                "file": r.path.display().to_string(),
                "line": r.line,
                "duration_ms": r.duration_ms,
                "status": "passed",
            })
        })
        .collect();

    Ok(json!({
        "summary": {
            "total": summary.total,
            "passed": summary.passed,
            "failed": summary.failed,
            "skipped": summary.skipped,
            "errors": summary.errors,
            "duration_ms": summary.duration_ms,
        },
        "failures": failures,
        "passed": passed,
        "analysis_notes": analysis_notes,
    })
    .to_string())
}

pub(crate) async fn call_audit(args: Value) -> Result<String, String> {
    use crate::audit::{list_installed_packages, scan_for_vulnerabilities};
    use crate::env::find_python_env;

    let fix = args.get("fix").and_then(|v| v.as_bool()).unwrap_or(true);
    let severity_threshold = args
        .get("severity_threshold")
        .and_then(|s| s.as_str())
        .unwrap_or("low");

    let working_dir = std::env::current_dir().map_err(|e| e.to_string())?;

    // Fail open (empty package list) on env/pip errors, consistent with
    // this tool's pre-existing behavior: an agent calling pybun_audit
    // should get a best-effort scan, not a hard error, if the
    // environment can't be inspected.
    let packages = match find_python_env(&working_dir) {
        Ok(env) => list_installed_packages(&env.python_path).unwrap_or_default(),
        Err(_) => vec![],
    };

    if packages.is_empty() {
        return Ok(json!({
            "status": "ok",
            "summary": {
                "scanned": 0,
                "vulnerable": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "vulnerabilities": [],
            "scanner": "osv",
            "scanner_version": "1.0"
        })
        .to_string());
    }

    let osv_url = crate::audit::default_osv_url();
    let report = scan_for_vulnerabilities(&packages, &osv_url, severity_threshold).await?;

    let vulnerabilities: Vec<Value> = report
        .vulnerabilities
        .iter()
        .map(|v| {
            let next_action = if fix {
                v.fix_version.as_ref().map(|fv| {
                    json!({
                        "tool": "pybun_upgrade",
                        "args": {
                            "package": v.package,
                            "version": fv
                        }
                    })
                })
            } else {
                None
            };

            json!({
                "package": v.package,
                "installed_version": v.installed_version,
                "vulnerability_id": v.vulnerability_id,
                "severity": v.severity,
                "description": v.description,
                "fix_version": v.fix_version,
                "next_action": next_action
            })
        })
        .collect();

    Ok(json!({
        "status": "ok",
        "summary": {
            "scanned": report.scanned,
            "vulnerable": vulnerabilities.len(),
            "critical": report.count_at_severity("critical"),
            "high": report.count_at_severity("high"),
            "medium": report.count_at_severity("medium"),
            "low": report.count_at_severity("low"),
            "unscanned": report.unscanned
        },
        "vulnerabilities": vulnerabilities,
        "scanner": "osv",
        "scanner_version": "1.0"
    })
    .to_string())
}

pub(crate) fn call_upgrade(args: Value) -> Result<String, String> {
    use crate::env::find_python_env;

    let package = args
        .get("package")
        .and_then(|p| p.as_str())
        .ok_or_else(|| "Missing required argument: package".to_string())?;
    let version = args
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required argument: version".to_string())?;

    let working_dir = std::env::current_dir().map_err(|e| e.to_string())?;
    let env = find_python_env(&working_dir).map_err(|e| e.to_string())?;
    let python_path = env.python_path.to_string_lossy().to_string();

    let spec = format!("{}=={}", package, version);
    let output = ProcessCommand::new(&python_path)
        .args(["-m", "pip", "install", "--disable-pip-version-check", &spec])
        .output()
        .map_err(|e| format!("Failed to run pip install: {}", e))?;

    if output.status.success() {
        Ok(json!({
            "status": "upgraded",
            "package": package,
            "version": version,
            "spec": spec
        })
        .to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("pip install {} failed: {}", spec, stderr.trim()))
    }
}
