use super::*;
use crate::cli::RunArgs;
use crate::sandbox::{self, SandboxConfig};

/// Build the same structured traceback diagnostic the native path emits,
/// including the `next_action` self-healing hint. `dispatch_execution`
/// promotes this into the response envelope (Issue #520).
pub(crate) fn runtime_diagnostic(stderr: &str) -> crate::schema::Diagnostic {
    let Some(tb) = crate::traceback::parse(stderr) else {
        return crate::schema::Diagnostic::error("Python execution failed.")
            .with_code("E_RUN_FAILED");
    };
    let mut diagnostic = crate::schema::Diagnostic::error(tb.message).with_code(tb.code);
    diagnostic.exception_type = Some(tb.exception_type);
    if let Some(location) = tb.location {
        diagnostic.file = Some(location.file.clone());
        diagnostic.line = Some(location.line);
        diagnostic.location = Some(json!({
            "file": location.file,
            "line": location.line,
            "function": location.function,
        }));
    }
    if let Some(action) = &tb.next_action {
        diagnostic.suggestion = Some(format!(
            "Run: pybun add {}",
            action
                .args
                .get("package")
                .and_then(Value::as_str)
                .unwrap_or("")
        ));
        diagnostic.next_action = Some(json!({
            "tool": action.tool,
            "args": action.args,
        }));
    }
    diagnostic
}

pub fn applicable(args: &RunArgs) -> bool {
    if native_selected() {
        return false;
    }
    let root = std::env::current_dir().ok();
    if root.as_deref().and_then(project_root).is_some() {
        return true;
    }
    args.target
        .as_ref()
        .is_some_and(|target| script_metadata_or_lock(target))
}

fn script_metadata_or_lock(target: &str) -> bool {
    fs::read_to_string(target).is_ok_and(|text| text.contains("# /// script"))
        || PathBuf::from(format!("{target}.lock")).exists()
}

pub async fn run(args: &RunArgs) -> Result<Value, BackendError> {
    run_scoped(args, Vec::new()).await
}
pub(crate) async fn run_scoped(args: &RunArgs, roots: Vec<PathBuf>) -> Result<Value, BackendError> {
    let args = args.clone();
    let root = std::env::current_dir().map_err(|_| {
        error(
            "E_BACKEND_PROJECT",
            "Cannot locate the current project directory.",
        )
    })?;
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::spawn_blocking(move || {
            UvBackend::discover(&root)?.scoped(roots).run_python(&args)
        })
        .await
        .map_err(|_| {
            error(
                "E_BACKEND_FAILED",
                "Backend worker terminated unexpectedly.",
            )
        })?
    } else {
        UvBackend::discover(&root)?.scoped(roots).run_python(&args)
    }
}

impl UvBackend {
    fn run_python(&self, args: &RunArgs) -> Result<Value, BackendError> {
        let start = Instant::now();
        self.run_checked(args).map_err(|mut error| {
            error.detected_version = Some(self.version.clone());
            error.operation = Some("run");
            error.duration_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
            error
        })
    }

    fn run_checked(&self, args: &RunArgs) -> Result<Value, BackendError> {
        let start = Instant::now();
        if args.code.is_none()
            && !args
                .target
                .as_ref()
                .is_some_and(|target| !target.starts_with('-') && Path::new(target).is_file())
        {
            return Err(error(
                "E_BACKEND_ARGUMENT",
                "Provide an existing script file or --code; interpreter flags are not script targets.",
            ));
        }
        let profile: crate::profiles::Profile = args.profile.parse().map_err(|_| {
            error(
                "E_BACKEND_ARGUMENT",
                "Invalid launch profile. Use dev, prod, or benchmark.",
            )
        })?;
        let profile_config = crate::profiles::ProfileConfig::for_profile(profile);
        let script = args
            .target
            .as_ref()
            .filter(|target| script_metadata_or_lock(target))
            .map(PathBuf::from);
        if let Some(script_path) = &script
            && let Ok(Some(metadata)) = crate::pep723::parse_script_metadata(script_path)
            && metadata
                .dependencies
                .iter()
                .any(|requirement| requirement.trim_start().starts_with('-'))
        {
            return Err(error(
                "E_BACKEND_ARGUMENT",
                "PEP 723 dependencies must be package requirements, not installer options.",
            ));
        }
        let root = if script.is_none() {
            self.workspace_root()?
        } else {
            self.root.clone()
        };
        self.check_project_scope(&root)?;
        let offline = args.sandbox && !args.allow_network;
        let lock_path = if let Some(script) = &script {
            let mut path = self.root.join(script).into_os_string();
            path.push(".lock");
            PathBuf::from(path)
        } else {
            root.join("uv.lock")
        };
        if script.is_some() && lock_path.exists() {
            read_lock(&lock_path)?;
        }
        let mut lock = self.command("lock");
        if let Some(script) = &script {
            lock.arg("--script").arg(script);
        }
        if offline {
            lock.arg("--offline").arg("--no-python-downloads");
        }
        if args.sandbox {
            lock.arg("--no-build");
        }
        self.spawn(&mut lock, true)?;
        let (digest, packages) = read_lock(&lock_path)?;
        let mut sync = self.command("sync");
        sync.args(["--locked", "--inexact"]);
        if let Some(script) = &script {
            sync.arg("--script").arg(script);
        }
        if offline {
            sync.arg("--offline").arg("--no-python-downloads");
        }
        if args.sandbox {
            sync.arg("--no-build");
            if script.is_none() {
                sync.args(["--no-install-project", "--no-install-workspace"]);
            }
        }
        self.spawn(&mut sync, true)?;
        let python = if let Some(script) = &script {
            let mut find = self.command("python");
            find.args(["find", "--script"]).arg(script).arg("--offline");
            let output = self.spawn(&mut find, true)?;
            let path = std::str::from_utf8(&output)
                .map_err(|_| {
                    error(
                        "E_BACKEND_ARTIFACT",
                        "uv returned an invalid script interpreter.",
                    )
                })?
                .trim();
            if path.is_empty() || path.contains(['\n', '\r']) || !Path::new(path).is_absolute() {
                return Err(error(
                    "E_BACKEND_ARTIFACT",
                    "uv returned an invalid script interpreter.",
                ));
            }
            PathBuf::from(path)
        } else {
            environment_python(&root)
        };
        verify_python(&python, self.timeout_secs)?;
        // Validate preparation before executing user code or creating a receipt.
        let (current_digest, _) = read_lock(&lock_path)?;
        if current_digest != digest {
            return Err(error(
                "E_BACKEND_ARTIFACT",
                "The execution lock changed during environment preparation.",
            ));
        }
        let mut command = Command::new(&python);
        command.current_dir(&self.root);
        let guard = if args.sandbox {
            Some(
                sandbox::apply_python_sandbox(
                    &mut command,
                    SandboxConfig {
                        allow_network: args.allow_network,
                        allow_net: args.allow_net.clone(),
                        allow_run: args.allow_run.clone(),
                        allow_read: args.allow_read.clone(),
                        allow_write: args.allow_write.clone(),
                        deny_write: args.deny_write.clone(),
                        allow_env: args.allow_env.clone(),
                        timeout_secs: args.sandbox_timeout,
                        memory_limit_mb: args.sandbox_memory,
                        cpu_limit_secs: args.sandbox_cpu,
                        ..Default::default()
                    },
                )
                .map_err(|_| {
                    error(
                        "E_BACKEND_POLICY",
                        "Cannot apply the requested Python sandbox.",
                    )
                })?,
            )
        } else {
            None
        };
        if args.sandbox {
            // Install the guard before site.main() can execute environment startup hooks.
            // Drop the code-mode cwd entry before importing the trusted guard.
            command.args(["-S", "-c"]);
            if let Some(code) = &args.code {
                command.arg("import sys; sys.path.pop(0); import sitecustomize, site; site.main(); code=sys.argv[1]; sys.argv=['-c']+sys.argv[2:]; exec(compile(code, '<string>', 'exec'))").arg(code);
            } else if let Some(target) = &args.target {
                command.arg("import sys; sys.path.pop(0); import sitecustomize, site, runpy, os; site.main(); sys.argv=sys.argv[1:]; sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[0]))); runpy.run_path(sys.argv[0], run_name='__main__')").arg(target);
            }
        } else if let Some(code) = &args.code {
            command.arg("-c").arg(code);
        } else if let Some(target) = &args.target {
            command.arg("--").arg(target);
        }
        command.args(&args.passthrough);
        if profile_config.optimization_level > 0 {
            command.env(
                "PYTHONOPTIMIZE",
                profile_config.optimization_level.to_string(),
            );
        }
        if profile_config.timing {
            command.env("PYBUN_TIMING", "1");
        }
        for (key, value) in &profile_config.env_vars {
            command.env(key, value);
        }
        let result = sandbox::execute_with_optional_sandbox(&mut command, guard.as_ref(), true)
            .map_err(|_| {
                error(
                    "E_BACKEND_FAILED",
                    "Could not execute the prepared Python environment.",
                )
            })?;
        let exit_code = result.status.code().unwrap_or(1);
        let stdout =
            String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).to_string();
        let stderr =
            String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default()).to_string();
        let diagnostics = if exit_code != 0 {
            vec![runtime_diagnostic(&stderr)]
        } else {
            Vec::new()
        };
        let result = json!({
            "contract_version": "2", "status": if exit_code == 0 { "success" } else { "error" },
            "backend": { "name": "uv", "version": self.version, "operation": "run" },
            "environment": { "fingerprint": fingerprint(&root, &python), "python": python.display().to_string(),
                "preparation": if script.is_some() { "uv sync --script --locked --inexact" } else { "uv sync --locked --inexact" } },
            "lock": { "source": lock_path.display().to_string(), "digest": digest },
            "packages": packages, "target": args.target, "exit_code": exit_code,
            "stdout": stdout, "stderr": stderr, "sandboxed": args.sandbox,
            "audit": guard.as_ref().map(|g| g.read_audit()),
            "resource_limits": guard.as_ref().map(|g| &g.resource_limits), "timed_out": result.timed_out,
            "effective_policy": { "native_fallback": false, "sandboxed": args.sandbox,
                "allow_network": args.allow_network, "allow_net": args.allow_net, "allow_run": args.allow_run, "preparation_offline": offline,
                "preparation_builds_allowed": !args.sandbox, "backend_timeout_secs": self.timeout_secs,
                "execution_enforcement": guard.as_ref().map(|g| g.enforcement()) },
            "duration_ms": start.elapsed().as_millis().min(u64::MAX as u128) as u64,
            "receipt_id": uuid::Uuid::new_v4().to_string(), "diagnostics": diagnostics,
            "profile": { "name": args.profile, "optimization_level": profile_config.optimization_level,
                "lazy_imports": profile_config.lazy_imports, "lazy_imports_injected": false, "timing": profile_config.timing },
        });
        publish_receipt(&root, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_not_found_promotes_the_self_healing_hint() {
        let stderr = "Traceback (most recent call last):\n  File \"main.py\", line 1, in <module>\n    import requests\nModuleNotFoundError: No module named 'requests'\n";
        let diagnostic = runtime_diagnostic(stderr);
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("E_RUNTIME_MODULE_NOT_FOUND")
        );
        assert_eq!(
            diagnostic.suggestion.as_deref(),
            Some("Run: pybun add requests")
        );
        assert!(diagnostic.next_action.is_some());
        assert_eq!(
            diagnostic.exception_type.as_deref(),
            Some("ModuleNotFoundError")
        );
    }

    #[test]
    fn non_traceback_failure_falls_back_to_generic_code() {
        let diagnostic = runtime_diagnostic("plain failure\n");
        assert_eq!(diagnostic.code.as_deref(), Some("E_RUN_FAILED"));
        assert!(diagnostic.suggestion.is_none());
    }
}
