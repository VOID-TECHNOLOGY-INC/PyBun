//! Transport-independent uv project operations. Backend output is never a wire format.

use crate::cli::Commands;
use crate::proc_exec::{ProcExecOutcome, spawn_with_timeout};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
mod scope;
pub(crate) use scope::check_scope;
mod graph;
pub(crate) use graph::provenance_graph_scoped;
pub use graph::{GraphEvidence, provenance_graph};
mod run;
pub(crate) use run::run_scoped;
pub use run::{applicable as run_applicable, run};

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct BackendError {
    pub code: &'static str,
    pub message: &'static str,
    suggestion: &'static str,
    detected_version: Option<String>,
    operation: Option<&'static str>,
    duration_ms: u64,
}

impl BackendError {
    pub fn suggestion(&self) -> &'static str {
        self.suggestion
    }

    pub fn detail(&self, command: &str) -> Value {
        let operation = self.operation.unwrap_or(match command {
            "install" => "sync",
            "upgrade" => "lock",
            other => other,
        });
        json!({ "contract_version": "2", "status": "error", "code": self.code, "error": self.message,
            "backend": { "name": "uv", "version": self.detected_version, "operation": operation },
            "duration_ms": self.duration_ms,
            "diagnostics": [{ "level": "error", "code": self.code, "message": self.message,
                "suggestion": self.suggestion }] })
    }
}

fn error(code: &'static str, message: &'static str) -> BackendError {
    BackendError {
        code,
        message,
        suggestion: "Check uv configuration and supported project arguments.",
        detected_version: None,
        operation: None,
        duration_ms: 0,
    }
}

fn classified(code: &'static str, message: &'static str, suggestion: &'static str) -> BackendError {
    BackendError {
        suggestion,
        ..error(code, message)
    }
}

/// Map a uv failure to an actionable code without echoing raw backend output.
///
/// uv's stderr is deliberately withheld from JSON responses because it can
/// contain index credentials. Classification uses only a small allowlist of
/// stable uv error prefixes plus the exit code (Issue #520).
fn classify_backend_failure(exit_code: Option<i32>, stderr: &str) -> BackendError {
    let text = stderr.to_ascii_lowercase();
    let contains = |needles: &[&str]| needles.iter().any(|needle| text.contains(needle));
    if contains(&[
        "no solution found",
        "could not be found in",
        "package not found",
        "failed to resolve",
        "because it does not exist",
    ]) {
        return classified(
            "E_BACKEND_RESOLUTION",
            "uv could not resolve dependencies or find a requested package.",
            "Check package names and version constraints, then run `uv lock --check` to reproduce the resolver error locally.",
        );
    }
    if contains(&[
        "401",
        "403",
        "unauthorized",
        "authentication",
        "forbidden",
        "keyring",
        "credentials",
    ]) {
        return classified(
            "E_BACKEND_AUTH",
            "uv could not authenticate to the package index.",
            "Check index credentials, keyring configuration, and UV_INDEX_URL/PIP_INDEX_URL, then retry.",
        );
    }
    if contains(&[
        "failed to fetch",
        "network",
        "connection refused",
        "connection reset",
        "timed out",
        "timeout",
        "dns",
        "temporary failure in name resolution",
    ]) {
        return classified(
            "E_BACKEND_NETWORK",
            "uv could not reach the package index.",
            "Check network connectivity, proxy settings, and index availability, then retry.",
        );
    }
    if exit_code == Some(2)
        || contains(&[
            "project.name",
            "not a valid",
            "failed to parse",
            "invalid value",
            "unexpected argument",
        ])
    {
        return classified(
            "E_BACKEND_ARGUMENT",
            "uv rejected the project configuration or command arguments.",
            "Inspect pyproject.toml (including parent workspace config) and the command arguments, then retry.",
        );
    }
    classified(
        "E_BACKEND_FAILED",
        "uv failed. Backend output is withheld to protect credentials.",
        "Run the equivalent `uv` command locally with --verbose to inspect the failure.",
    )
}

pub fn native_selected() -> bool {
    std::env::var("PYBUN_BACKEND").is_ok_and(|v| v == "native")
}

/// A request contains only uv arguments; subprocess diagnostics are kept private.
#[derive(Debug)]
pub struct BackendRequest {
    pub operation: &'static str,
    args: Vec<OsString>,
    script: Option<PathBuf>,
    needs_env: bool,
    mutation: Option<(bool, Vec<String>)>,
}

impl BackendRequest {
    fn index(&mut self, index: Option<&Path>) -> Result<(), BackendError> {
        if let Some(index) = index {
            let value = index
                .to_str()
                .ok_or_else(|| error("E_BACKEND_ARGUMENT", "Invalid index URL."))?;
            let parsed = reqwest::Url::parse(value).ok().or_else(|| {
                value
                    .split_once('=')
                    .and_then(|(_, url)| reqwest::Url::parse(url).ok())
            });
            if !parsed.is_some_and(|url| matches!(url.scheme(), "http" | "https")) {
                return Err(error(
                    "E_BACKEND_ARGUMENT",
                    "Use an HTTP(S) uv index URL or NAME=URL; JSON fixture indexes require PYBUN_BACKEND=native.",
                ));
            }
            self.args.extend(["--index".into(), index.into()]);
        }
        Ok(())
    }

    pub fn from_command(command: &Commands) -> Result<Self, BackendError> {
        let mut request = Self {
            operation: "lock",
            args: Vec::new(),
            script: None,
            needs_env: false,
            mutation: None,
        };
        let (offline, pre) = match command {
            Commands::Install(a) => {
                if a.system || !a.requirements.is_empty() || a.lock != Path::new("pybun.lockb") {
                    return Err(error(
                        "E_BACKEND_ARGUMENT",
                        "uv install uses project sync; legacy --system/--require/--lock require PYBUN_BACKEND=native. Use pybun add to change dependencies.",
                    ));
                }
                request.index(a.index.as_deref())?;
                request.operation = "sync";
                request.needs_env = true;
                if a.workspace {
                    request.args.push("--all-packages".into());
                }
                if let Some(member) = &a.member {
                    request.args.extend(["--package".into(), member.into()]);
                }
                if let Some(group) = &a.group {
                    request.args.extend(["--group".into(), group.into()]);
                }
                (a.offline, a.pre)
            }
            Commands::Add(a) | Commands::Remove(a) => {
                let add = matches!(command, Commands::Add(_));
                request.operation = if add { "add" } else { "remove" };
                request.index(a.index.as_deref())?;
                request.needs_env = true;
                request.mutation = Some((add, a.packages.clone()));
                if a.packages.iter().any(|p| p.starts_with('-')) {
                    return Err(error(
                        "E_BACKEND_ARGUMENT",
                        "Package arguments must be requirements, not backend flags.",
                    ));
                }
                if a.dev {
                    request.args.push("--dev".into());
                }
                if let Some(group) = &a.group {
                    request.args.extend(["--group".into(), group.into()]);
                }
                if let Some(extra) = &a.optional {
                    request.args.extend(["--optional".into(), extra.into()]);
                }
                request.args.extend(a.packages.iter().map(OsString::from));
                (a.offline, a.pre)
            }
            Commands::Lock(a) => {
                request.index(a.index.as_deref())?;
                request.script = a.script.clone();
                (a.offline, false)
            }
            Commands::Upgrade(a) => {
                if a.lock != Path::new("pybun.lockb") || a.dry_run || a.member.is_some() {
                    return Err(error(
                        "E_BACKEND_ARGUMENT",
                        "uv upgrade updates uv.lock; legacy --lock/--dry-run/--member require PYBUN_BACKEND=native.",
                    ));
                }
                request.index(a.index.as_deref())?;
                if let Some(group) = &a.group {
                    request
                        .args
                        .extend(["--upgrade-group".into(), group.into()]);
                } else if a.packages.is_empty() {
                    request.args.push("--upgrade".into());
                }
                for package in &a.packages {
                    request
                        .args
                        .extend(["--upgrade-package".into(), package.into()]);
                }
                (a.offline, a.pre)
            }
            _ => {
                return Err(error(
                    "E_BACKEND_ARGUMENT",
                    "Unsupported backend operation.",
                ));
            }
        };
        if offline {
            request.args.push("--offline".into());
        }
        if pre {
            request.args.extend(["--prerelease".into(), "allow".into()]);
        }
        if let Some(script) = &request.script {
            request.args.extend(["--script".into(), script.into()]);
        }
        Ok(request)
    }
}

pub struct UvBackend {
    executable: PathBuf,
    root: PathBuf,
    timeout_secs: u64,
    version: String,
    authorized_roots: Vec<PathBuf>,
}

impl UvBackend {
    pub fn discover(root: &Path) -> Result<Self, BackendError> {
        if std::env::var("PYBUN_BACKEND").is_ok_and(|v| v != "uv" && v != "native") {
            return Err(error(
                "E_BACKEND_ARGUMENT",
                "PYBUN_BACKEND must be uv or native.",
            ));
        }
        let executable = std::env::var_os("PYBUN_UV").map(PathBuf::from)
            .or_else(crate::env::find_uv_executable)
            .ok_or_else(|| error("E_BACKEND_MISSING", "uv is required. Install uv and add it to PATH; no native fallback is performed."))?;
        let mut backend = Self {
            executable,
            root: root.to_path_buf(),
            timeout_secs: 300,
            version: String::new(),
            authorized_roots: Vec::new(),
        };
        let mut command = Command::new(&backend.executable);
        command.arg("--version").current_dir(root);
        let output = backend.spawn(&mut command, true)?;
        let text = std::str::from_utf8(&output).map_err(|_| {
            error(
                "E_BACKEND_VERSION",
                "uv returned an invalid version response.",
            )
        })?;
        let version = text.split_whitespace().collect::<Vec<_>>();
        let parsed = version
            .get(1)
            .filter(|_| version.first() == Some(&"uv"))
            .and_then(|v| semver::Version::parse(v).ok())
            .ok_or_else(|| {
                error(
                    "E_BACKEND_VERSION",
                    "uv returned an invalid version response.",
                )
            })?;
        // Script sync/export and upgrade-group are part of the supported adapter surface.
        if parsed < semver::Version::new(0, 12, 0) || parsed >= semver::Version::new(0, 13, 0) {
            return Err(error(
                "E_BACKEND_VERSION",
                "This adapter supports uv >=0.12.0,<0.13.0. Install a supported uv version.",
            ));
        }
        backend.version = parsed.to_string();
        Ok(backend)
    }

    fn spawn(&self, command: &mut Command, capture: bool) -> Result<Vec<u8>, BackendError> {
        command.stdin(std::process::Stdio::null());
        match spawn_with_timeout(command, Some(self.timeout_secs), capture).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                error(
                    "E_BACKEND_MISSING",
                    "uv could not be started. Install uv and verify PATH or PYBUN_UV.",
                )
            } else {
                error(
                    "E_BACKEND_FAILED",
                    "The backend process could not be started.",
                )
            }
        })? {
            ProcExecOutcome::Completed { status, stdout, .. } if status.success() => {
                Ok(stdout.unwrap_or_default())
            }
            ProcExecOutcome::Completed { status, stderr, .. } => Err(classify_backend_failure(
                status.code(),
                &String::from_utf8_lossy(stderr.as_deref().unwrap_or_default()),
            )),
            ProcExecOutcome::TimedOut => Err(error(
                "E_BACKEND_TIMEOUT",
                "uv exceeded the operation timeout and was terminated.",
            )),
        }
    }

    fn command(&self, operation: &str) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .arg(operation)
            .arg("--no-progress")
            .current_dir(&self.root);
        for (pip, uv, aliases) in [
            (
                "PIP_INDEX_URL",
                "UV_DEFAULT_INDEX",
                ["UV_DEFAULT_INDEX", "UV_INDEX_URL"],
            ),
            (
                "PIP_EXTRA_INDEX_URL",
                "UV_INDEX",
                ["UV_INDEX", "UV_EXTRA_INDEX_URL"],
            ),
        ] {
            if aliases.iter().all(|name| std::env::var_os(name).is_none())
                && let Some(value) = std::env::var_os(pip)
            {
                command.env(uv, value);
            }
        }
        command
    }

    fn workspace_root(&self) -> Result<PathBuf, BackendError> {
        let mut command = self.command("workspace");
        command.args(["dir", "--offline"]);
        let output = self.spawn(&mut command, true)?;
        let path = std::str::from_utf8(&output)
            .map_err(|_| {
                error(
                    "E_BACKEND_ARTIFACT",
                    "uv returned an invalid workspace root.",
                )
            })?
            .trim();
        let root = PathBuf::from(path);
        if path.is_empty()
            || path.contains(['\n', '\r'])
            || !root.is_absolute()
            || !root.join("pyproject.toml").is_file()
        {
            return Err(error(
                "E_BACKEND_ARTIFACT",
                "uv returned an invalid workspace root.",
            ));
        }
        self.check_project_scope(&root)?;
        Ok(root)
    }

    pub fn execute(&self, request: BackendRequest) -> Result<Value, BackendError> {
        let start = Instant::now();
        let operation = request.operation;
        self.execute_checked(request).map_err(|mut error| {
            error.detected_version = Some(self.version.clone());
            error.operation = Some(operation);
            error.duration_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
            error
        })
    }

    fn execute_checked(&self, request: BackendRequest) -> Result<Value, BackendError> {
        let start = Instant::now();
        let root = if request.script.is_none() {
            self.workspace_root()?
        } else {
            self.root.clone()
        };
        self.check_project_scope(&root)?;
        let lock_path = if let Some(script) = &request.script {
            let mut lock = self.root.join(script).into_os_string();
            lock.push(".lock");
            PathBuf::from(lock)
        } else {
            root.join("uv.lock")
        };
        // uv must never overwrite a legacy binary script lock.
        if request.script.is_some() && lock_path.exists() {
            read_lock(&lock_path)?;
        }
        let mut command = self.command(request.operation);
        command.args(&request.args);
        self.spawn(&mut command, true)?;
        let (lock_digest, packages) = read_lock(&lock_path)?;
        let python = environment_python(&root);
        if request.needs_env {
            verify_python(&python, self.timeout_secs)?;
        }
        if let Some((add, specs)) = request.mutation {
            let member = self
                .root
                .ancestors()
                .find(|p| p.join("pyproject.toml").is_file())
                .unwrap_or(&root);
            verify_mutation(member, add, &specs)?;
        }
        let result = json!({
            "contract_version": "2", "status": "success",
            "backend": { "name": "uv", "version": self.version, "operation": request.operation },
            "environment": { "fingerprint": fingerprint(&root, &python), "python": request.needs_env.then(|| python.display().to_string()) },
            "lock": { "source": lock_path.display().to_string(), "digest": lock_digest },
            "packages": packages,
            "effective_policy": { "backend_timeout_secs": self.timeout_secs, "native_fallback": false, "sandboxed": false },
            "duration_ms": start.elapsed().as_millis().min(u64::MAX as u128) as u64,
            "receipt_id": uuid::Uuid::new_v4().to_string(), "diagnostics": [],
            "legacy_lock_preserved": root.join("pybun.lockb").exists(),
        });
        publish_receipt(&root, result)
    }
}

pub async fn execute(request: BackendRequest) -> Result<Value, BackendError> {
    execute_scoped(request, Vec::new()).await
}
pub(crate) async fn execute_scoped(
    request: BackendRequest,
    roots: Vec<PathBuf>,
) -> Result<Value, BackendError> {
    let root = std::env::current_dir().map_err(|_| {
        error(
            "E_BACKEND_PROJECT",
            "Cannot locate the current project directory.",
        )
    })?;
    if let Some(script) = &request.script {
        check_scope(&root.join(script), &roots)?;
        let mut lock = root.join(script).into_os_string();
        lock.push(".lock");
        check_scope(Path::new(&lock), &roots)?;
    }
    // The CLI also uses futures::executor for lightweight commands.
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::spawn_blocking(move || {
            UvBackend::discover(&root)?.scoped(roots).execute(request)
        })
        .await
        .map_err(|_| {
            error(
                "E_BACKEND_FAILED",
                "Backend worker terminated unexpectedly.",
            )
        })?
    } else {
        UvBackend::discover(&root)?.scoped(roots).execute(request)
    }
}

pub fn project_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|p| p.join("pyproject.toml").is_file())
        .map(Path::to_path_buf)
}

fn environment_python(root: &Path) -> PathBuf {
    let env = std::env::var_os("UV_PROJECT_ENVIRONMENT")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".venv"));
    let env = if env.is_absolute() {
        env
    } else {
        root.join(env)
    };
    env.join(if cfg!(windows) {
        "Scripts/python.exe"
    } else {
        "bin/python"
    })
}

fn verify_python(python: &Path, timeout: u64) -> Result<(), BackendError> {
    let mut command = Command::new(python);
    command.args([
        "-I",
        "-S",
        "-c",
        "import sys; print(sys.version_info.major)",
    ]);
    let config = python
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("pyvenv.cfg"));
    if !config.is_some_and(|p| p.is_file()) {
        return Err(error(
            "E_BACKEND_ARTIFACT",
            "uv did not produce an isolated Python environment.",
        ));
    }
    match spawn_with_timeout(&mut command, Some(timeout), true) {
        Ok(ProcExecOutcome::Completed {
            status,
            stdout: Some(stdout),
            ..
        }) if status.success() && stdout == b"3\n" => Ok(()),
        _ => Err(error(
            "E_BACKEND_ARTIFACT",
            "uv did not produce a usable isolated Python environment.",
        )),
    }
}

pub fn read_lock(path: &Path) -> Result<(String, Vec<Value>), BackendError> {
    let invalid = || {
        error(
            "E_BACKEND_ARTIFACT",
            "uv did not produce a valid supported TOML lockfile. A legacy script lock must be explicitly moved aside before migration.",
        )
    };
    let bytes = fs::read(path).map_err(|_| invalid())?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    let lock: toml::Value = toml::from_str(text).map_err(|_| invalid())?;
    if lock.get("version").and_then(toml::Value::as_integer) != Some(1) {
        return Err(invalid());
    }
    let empty = Vec::new();
    let packages = match lock.get("package") {
        Some(value) => value.as_array().ok_or_else(invalid)?,
        None if lock
            .get("requires-python")
            .and_then(toml::Value::as_str)
            .is_some_and(|s| !s.is_empty()) =>
        {
            &empty
        }
        None => return Err(invalid()),
    };
    let mut result = Vec::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|n| !n.is_empty())
            .ok_or_else(invalid)?;
        let source = package
            .get("source")
            .and_then(toml::Value::as_table)
            .ok_or_else(invalid)?;
        let direct_subdirectory = source.len() == 2
            && source.contains_key("url")
            && source
                .get("subdirectory")
                .and_then(toml::Value::as_str)
                .is_some_and(|s| !s.is_empty());
        if (source.len() != 1 && !direct_subdirectory)
            || ![
                "registry",
                "git",
                "url",
                "path",
                "directory",
                "editable",
                "virtual",
            ]
            .iter()
            .any(|key| {
                source
                    .get(*key)
                    .and_then(toml::Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            })
        {
            return Err(invalid());
        }
        let local = ["editable", "virtual", "directory"]
            .iter()
            .any(|key| source.get(*key).is_some_and(toml::Value::is_str));
        let version = match package.get("version") {
            Some(value) => Some(
                value
                    .as_str()
                    .filter(|v| crate::pep440::Pep440Version::parse(v).is_some())
                    .ok_or_else(invalid)?,
            ),
            None if local => None,
            None => return Err(invalid()),
        };
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            return Err(invalid());
        }
        // No registry URLs or arbitrary backend fields cross the public boundary.
        result.push(json!({ "name": name, "version": version }));
    }
    Ok((hex::encode(Sha256::digest(&bytes)), result))
}

fn fingerprint(root: &Path, python: &Path) -> String {
    let mut hash = Sha256::new();
    hash.update(
        format!(
            "{}\n{}\n{}\n{}",
            root.display(),
            python.display(),
            std::env::consts::OS,
            std::env::consts::ARCH
        )
        .as_bytes(),
    );
    for path in [
        root.join("uv.lock"),
        root.join(".python-version"),
        python
            .parent()
            .and_then(Path::parent)
            .unwrap_or(root)
            .join("pyvenv.cfg"),
    ] {
        if let Ok(bytes) = fs::read(path) {
            hash.update(bytes);
        }
    }
    hex::encode(hash.finalize())
}

fn publish_receipt(root: &Path, result: Value) -> Result<Value, BackendError> {
    let result = crate::support_bundle::redact_protocol(&result);
    let mut receipt = result.clone();
    if let Some(object) = receipt.as_object_mut() {
        object.remove("stdout");
        object.remove("stderr");
    }
    let id = result["receipt_id"].as_str().expect("generated receipt ID");
    let path = root.join(".pybun/receipts").join(format!("{id}.json"));
    let bytes = serde_json::to_vec_pretty(&receipt).expect("JSON receipt");
    crate::atomic_fs::atomic_write(&path, &bytes).map_err(|_| {
        error(
            "E_BACKEND_RECEIPT",
            "Operation completed but its execution receipt could not be persisted.",
        )
    })?;
    Ok(result)
}

fn verify_mutation(root: &Path, added: bool, specs: &[String]) -> Result<(), BackendError> {
    let invalid = || {
        error(
            "E_BACKEND_ARTIFACT",
            "uv exited successfully without the requested project dependency mutation.",
        )
    };
    let text = fs::read_to_string(root.join("pyproject.toml")).map_err(|_| invalid())?;
    let project: toml::Value = toml::from_str(&text).map_err(|_| invalid())?;
    let deps = project
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_array)
        .ok_or_else(invalid)?;
    for spec in specs {
        // Validate local project identity from metadata, without resolving dependencies.
        let local = root.join(spec).join("pyproject.toml");
        let local_name = if local.is_file() {
            fs::read_to_string(local)
                .ok()
                .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
                .and_then(|value| {
                    value
                        .get("project")?
                        .get("name")?
                        .as_str()
                        .map(String::from)
                })
        } else {
            None
        };
        let name = requirement_name(local_name.as_deref().unwrap_or(spec));
        let exists = deps
            .iter()
            .filter_map(toml::Value::as_str)
            .any(|dep| requirement_name(dep) == name);
        if exists != added {
            return Err(invalid());
        }
    }
    Ok(())
}

fn requirement_name(spec: &str) -> String {
    let mut name = String::new();
    for c in spec
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
    {
        if "-_.".contains(c) {
            if !name.ends_with('-') {
                name.push('-');
            }
        } else {
            name.push(c.to_ascii_lowercase());
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn backend_failures_are_classified_without_echoing_output() {
        for (exit, stderr, code) in [
            (
                Some(1),
                "x No solution found when resolving dependencies",
                "E_BACKEND_RESOLUTION",
            ),
            (
                Some(2),
                "error: The dependency 'requests' could not be found in 'project.dependencies'",
                "E_BACKEND_RESOLUTION",
            ),
            (
                Some(1),
                "error: Failed to fetch https://example.org: 401 Unauthorized",
                "E_BACKEND_AUTH",
            ),
            (
                Some(1),
                "error: network error: connection refused",
                "E_BACKEND_NETWORK",
            ),
            (
                Some(2),
                "error: project.name field is not set",
                "E_BACKEND_ARGUMENT",
            ),
            (
                Some(1),
                "password=netrc-secret https://user:pass@example.org token=secret",
                "E_BACKEND_FAILED",
            ),
        ] {
            let error = classify_backend_failure(exit, stderr);
            assert_eq!(error.code, code, "{stderr}");
            assert!(!error.suggestion().contains("PYBUN_BACKEND=native"));
            let detail = error.detail("lock").to_string();
            for secret in ["netrc-secret", "user:pass", "token=secret"] {
                assert!(!detail.contains(secret), "{detail}");
            }
        }
    }

    #[test]
    fn index_urls_preserve_queries_and_delegate_named_indexes() {
        for index in [
            "https://user:pass@example.org/simple?token=value",
            "HTTPS://user:prefix=httpsecret@example.org/simple",
            "private=https://example.org/simple",
        ] {
            let cli = crate::cli::Cli::try_parse_from(["pybun", "lock", "--index", index]).unwrap();
            let request = BackendRequest::from_command(&cli.command).unwrap();
            assert_eq!(
                request.args,
                vec![OsString::from("--index"), OsString::from(index)]
            );
        }
    }

    #[test]
    fn malformed_lock_sources_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("uv.lock");
        for source in [
            "{}",
            "{unknown='x'}",
            "{registry=''}",
            "{editable=''}",
            "{registry='x',virtual='.'}",
        ] {
            fs::write(
                &path,
                format!("version=1\n[[package]]\nname='demo'\nversion='0.1.0'\nsource={source}\n"),
            )
            .unwrap();
            assert!(read_lock(&path).is_err(), "accepted {source}");
        }
        fs::write(&path, "version=1\n[[package]]\nname='demo'\nversion='0.1.0'\nsource={url='https://example.org/demo.tar.gz',subdirectory='pkg'}\n").unwrap();
        assert!(read_lock(&path).is_ok());
    }

    #[test]
    fn dynamic_editable_project_lock_has_an_unknown_version() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("uv.lock");
        fs::write(
            &path,
            "version=1\n[[package]]\nname='demo'\nsource={editable='.'}\n",
        )
        .unwrap();
        let (_, packages) = read_lock(&path).unwrap();
        assert_eq!(packages[0]["name"], "demo");
        assert!(packages[0]["version"].is_null());
    }

    #[test]
    fn project_operations_map_to_uv_arguments() {
        for (args, operation, expected) in [
            (
                vec![
                    "pybun",
                    "install",
                    "--workspace",
                    "--member",
                    "demo",
                    "--group",
                    "dev",
                    "--offline",
                    "--pre",
                ],
                "sync",
                vec![
                    "--all-packages",
                    "--package",
                    "demo",
                    "--group",
                    "dev",
                    "--offline",
                    "--prerelease",
                    "allow",
                ],
            ),
            (
                vec!["pybun", "upgrade", "demo"],
                "lock",
                vec!["--upgrade-package", "demo"],
            ),
            (
                vec!["pybun", "lock", "--script", "demo.py"],
                "lock",
                vec!["--script", "demo.py"],
            ),
        ] {
            let cli = crate::cli::Cli::try_parse_from(args).unwrap();
            let request = BackendRequest::from_command(&cli.command).unwrap();
            assert_eq!(request.operation, operation);
            assert_eq!(
                request.args,
                expected.iter().map(OsString::from).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn legacy_flags_are_rejected_before_delegation() {
        for args in [
            vec!["pybun", "install", "--system"],
            vec!["pybun", "lock", "--index", "fixture.json"],
            vec!["pybun", "upgrade", "--dry-run"],
        ] {
            let cli = crate::cli::Cli::try_parse_from(args).unwrap();
            assert_eq!(
                BackendRequest::from_command(&cli.command).unwrap_err().code,
                "E_BACKEND_ARGUMENT"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn backend_timeout_is_an_error_without_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let backend = UvBackend {
            executable: "/bin/sh".into(),
            root: temp.path().into(),
            timeout_secs: 0,
            authorized_roots: Vec::new(),
            version: "0.12.0".into(),
        };
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 5"]);
        assert_eq!(
            backend.spawn(&mut command, true).unwrap_err().code,
            "E_BACKEND_TIMEOUT"
        );
        assert!(!temp.path().join(".pybun/receipts").exists());
    }
}
