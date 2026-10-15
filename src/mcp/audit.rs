//! MCP audit logging and sandbox glue.
//!
//! Extracted from `mcp.rs` (Issue #344): tool-call audit trail recording,
//! file-write snapshotting, and the sandbox-policy helpers used by
//! `tools/run.rs` when reporting risk/policy back to the caller.

use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use super::{PROTOCOL_VERSION, SERVER_VERSION};

#[derive(Debug, Clone)]
pub(super) struct AuditConfig {
    enabled: bool,
    path: Option<PathBuf>,
    pub(super) hash_inputs: bool,
    retention_days: u64,
}

#[derive(Debug, Clone, Serialize)]
struct AuditToolSchema {
    name: String,
    schema_version: u64,
    protocol_version: &'static str,
    server_version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct AuditOutputSummary {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i64>,
    stdout_bytes: u64,
    stderr_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
struct AuditSandboxEvent {
    #[serde(rename = "type")]
    event_type: String,
    count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct AuditFileWrite {
    path: String,
    size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256_after: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct AuditEntry {
    session_id: String,
    call_id: String,
    timestamp: String,
    tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<Value>,
    input_hash: String,
    tool_schema: AuditToolSchema,
    output_summary: AuditOutputSummary,
    sandbox_events: Vec<AuditSandboxEvent>,
    file_writes: Vec<AuditFileWrite>,
    file_snapshot_complete: bool,
    duration_ms: u64,
}

#[derive(Debug, Clone)]
pub(super) struct FileState {
    size_bytes: u64,
    sha256: String,
}

pub(super) struct FileSnapshot {
    files: BTreeMap<PathBuf, FileState>,
    observed_paths: BTreeSet<PathBuf>,
    listed_directories: BTreeSet<PathBuf>,
    missing_paths: BTreeSet<PathBuf>,
    complete: bool,
    entries: usize,
    bytes: u64,
}
impl FileSnapshot {
    fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            observed_paths: BTreeSet::new(),
            listed_directories: BTreeSet::new(),
            missing_paths: BTreeSet::new(),
            complete: true,
            entries: 0,
            bytes: 0,
        }
    }

    fn proves_absent(&self, path: &Path) -> bool {
        let mut candidate = path;
        loop {
            if self.observed_paths.contains(candidate) {
                return false;
            }
            if self.missing_paths.contains(candidate) {
                return true;
            }
            let Some(parent) = candidate.parent() else {
                return false;
            };
            if self.listed_directories.contains(parent) {
                return true;
            }
            candidate = parent;
        }
    }
}
pub(super) struct AuditDiff {
    pub writes: Vec<AuditFileWrite>,
    pub complete: bool,
}
impl Default for AuditDiff {
    fn default() -> Self {
        Self {
            writes: vec![],
            complete: true,
        }
    }
}

#[derive(Debug)]
pub(super) struct McpAuditLog {
    pub(super) config: AuditConfig,
    recent: VecDeque<AuditEntry>,
}

#[derive(Debug, Clone)]
pub(super) struct ToolRunner {
    program: PathBuf,
    base_args: Vec<String>,
}

impl ToolRunner {
    pub(super) fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            base_args: Vec::new(),
        }
    }

    fn python_module(python_path: impl Into<PathBuf>, module: &str) -> Self {
        Self {
            program: python_path.into(),
            base_args: vec!["-m".to_string(), module.to_string()],
        }
    }

    pub(super) fn command(&self) -> ProcessCommand {
        let mut cmd = ProcessCommand::new(&self.program);
        cmd.args(&self.base_args);
        cmd
    }
}

pub(super) fn current_working_dir() -> Result<PathBuf, String> {
    std::env::current_dir().map_err(|e| e.to_string())
}

pub(super) fn valid_ruff_status(status: &std::process::ExitStatus) -> bool {
    matches!(status.code(), Some(0 | 1))
}

pub(super) fn ruff_failure_message(action: &str, stdout: &str, stderr: &str) -> String {
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    if detail.is_empty() {
        format!("ruff {action} failed")
    } else {
        format!("ruff {action} failed: {detail}")
    }
}

pub(super) fn parse_ruff_violations(stdout: &str) -> Result<Vec<Value>, String> {
    if stdout.trim().is_empty() {
        return Ok(vec![]);
    }

    serde_json::from_str::<Vec<Value>>(stdout)
        .map_err(|e| format!("Failed to parse ruff JSON output: {e}"))
}

fn find_env_executable(python_path: &Path, tool_name: &str) -> Option<PathBuf> {
    let bin_dir = python_path.parent()?;
    let candidates: Vec<String> = if cfg!(windows) {
        vec![
            format!("{tool_name}.exe"),
            format!("{tool_name}.cmd"),
            format!("{tool_name}.bat"),
            tool_name.to_string(),
        ]
    } else {
        vec![tool_name.to_string()]
    };

    candidates
        .iter()
        .map(|candidate| bin_dir.join(candidate))
        .find(|candidate| candidate.is_file())
}

pub(super) fn resolve_ruff_runner(working_dir: &Path) -> Result<Option<ToolRunner>, String> {
    use crate::env::find_python_env;

    if let Ok(env) = find_python_env(working_dir) {
        if let Some(ruff_path) = find_env_executable(&env.python_path, "ruff") {
            return Ok(Some(ToolRunner::new(ruff_path)));
        }

        let module_runner = ToolRunner::python_module(env.python_path, "ruff");
        if module_runner
            .command()
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            return Ok(Some(module_runner));
        }
    }

    let global_runner = ToolRunner::new("ruff");
    if global_runner
        .command()
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
    {
        return Ok(Some(global_runner));
    }

    Ok(None)
}

impl AuditConfig {
    fn load() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let (project_root, mut config) = load_pyproject_audit_config(&cwd).unwrap_or_else(|| {
            (
                cwd.clone(),
                Self {
                    enabled: true,
                    path: default_audit_log_path(),
                    hash_inputs: false,
                    retention_days: 30,
                },
            )
        });

        if config.path.is_none() && config.enabled {
            config.path = default_audit_log_path();
        }

        if let Some(path) = config.path.take() {
            config.path = Some(resolve_audit_path(path, &project_root));
        }

        if let Ok(path) = std::env::var("PYBUN_AUDIT_LOG") {
            if path == "/dev/null" {
                config.enabled = false;
                config.path = None;
            } else if !path.trim().is_empty() {
                config.enabled = true;
                config.path = Some(resolve_audit_path(PathBuf::from(path), &cwd));
            }
        }

        config
    }
}

impl McpAuditLog {
    pub(super) fn new() -> Self {
        Self {
            config: AuditConfig::load(),
            recent: VecDeque::new(),
        }
    }

    pub(super) fn prepare_for_call(&self, tool_args: &Value) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        let Some(path) = &self.config.path else {
            return Ok(());
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "failed to create audit log directory {}: {e}",
                    parent.display()
                )
            })?;
        }

        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("failed to create audit log {}: {e}", path.display()))?;

        if audit_path_conflicts_with_allow_write(path, tool_args) {
            return Err(format!(
                "audit log path {} must be outside sandbox allow_write paths",
                path.display()
            ));
        }

        Ok(())
    }

    pub(super) fn record(&mut self, entry: AuditEntry) {
        if !self.config.enabled {
            return;
        }

        self.recent.push_back(entry.clone());
        while self.recent.len() > 20 {
            self.recent.pop_front();
        }

        let Some(path) = &self.config.path else {
            return;
        };
        let write_result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| e.to_string())?;
            let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
            writeln!(file, "{line}").map_err(|e| e.to_string())
        })();

        if let Err(err) = write_result {
            eprintln!("warning: failed to append MCP audit log: {err}");
        }
    }

    pub(super) fn recent_json(&self, session_id: &str) -> String {
        json!({
            "session_id": session_id,
            "count": self.recent.len(),
            "entries": self.recent,
            "retention_days": self.config.retention_days,
        })
        .to_string()
    }
}

fn default_audit_log_path() -> Option<PathBuf> {
    crate::cache::Cache::new().ok().map(|cache| {
        cache
            .logs_dir()
            .join(format!("mcp-audit-{}.jsonl", utc_date_now()))
    })
}

fn load_pyproject_audit_config(start: &Path) -> Option<(PathBuf, AuditConfig)> {
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join("pyproject.toml");
        if candidate.exists() {
            let content = fs::read_to_string(&candidate).ok()?;
            let value: toml::Value = toml::from_str(&content).ok()?;
            let audit = value.get("tool")?.get("pybun")?.get("mcp")?.get("audit")?;

            let enabled = audit
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let path = audit
                .get("path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from);
            let hash_inputs = audit
                .get("hash_inputs")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let retention_days = audit
                .get("retention_days")
                .and_then(|v| v.as_integer())
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(30);

            return Some((
                current,
                AuditConfig {
                    enabled,
                    path,
                    hash_inputs,
                    retention_days,
                },
            ));
        }

        if !current.pop() {
            return None;
        }
    }
}

fn resolve_audit_path(path: PathBuf, base: &Path) -> PathBuf {
    let path_string = path.to_string_lossy();
    if path_string == "~" {
        return dirs::home_dir().unwrap_or_else(|| base.to_path_buf());
    }
    if let Some(stripped) = path_string.strip_prefix("~/") {
        return dirs::home_dir()
            .unwrap_or_else(|| base.to_path_buf())
            .join(stripped);
    }
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn audit_path_conflicts_with_allow_write(audit_path: &Path, tool_args: &Value) -> bool {
    let Some(allow_write) = tool_args
        .get("sandbox_policy")
        .and_then(|p| p.get("allow_write"))
        .and_then(|v| v.as_array())
    else {
        return false;
    };

    let audit_path = normalized_absolute_path(audit_path);
    allow_write.iter().filter_map(|v| v.as_str()).any(|path| {
        let allowed = normalized_absolute_path(Path::new(path));
        path_within(&audit_path, &allowed)
    })
}

fn normalized_absolute_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    absolute.canonicalize().unwrap_or(absolute)
}

fn path_within(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn utc_date_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let days = (now.as_secs() / 86_400) as i64;
    let (year, month, day) = civil_from_unix_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn utc_timestamp_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = now.as_secs();
    let days = (total_secs / 86_400) as i64;
    let secs_of_day = total_secs % 86_400;
    let (year, month, day) = civil_from_unix_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    let micros = now.subsec_micros();
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z")
}

fn civil_from_unix_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year as i32, month as u32, day as u32)
}

fn input_hash(input: &Value) -> String {
    let bytes = serde_json::to_vec(input).unwrap_or_default();
    format!("sha256:{}", crate::security::sha256_bytes(&bytes))
}

pub(super) fn build_audit_entry(
    session_id: &str,
    tool_name: &str,
    tool_args: &Value,
    result: &Result<String, String>,
    hash_inputs: bool,
    file_writes: AuditDiff,
    duration_ms: u64,
) -> AuditEntry {
    AuditEntry {
        session_id: session_id.to_string(),
        call_id: Uuid::new_v4().to_string(),
        timestamp: utc_timestamp_now(),
        tool: crate::support_bundle::redact_text(tool_name),
        input: (!hash_inputs).then(|| crate::support_bundle::redact_json(tool_args)),
        input_hash: input_hash(&crate::support_bundle::redact_json(tool_args)),
        tool_schema: AuditToolSchema {
            name: crate::support_bundle::redact_text(tool_name),
            schema_version: 1,
            protocol_version: PROTOCOL_VERSION,
            server_version: SERVER_VERSION,
        },
        output_summary: summarize_tool_result(result),
        sandbox_events: sandbox_events_from_result(result),
        file_writes: file_writes.writes,
        file_snapshot_complete: file_writes.complete,
        duration_ms,
    }
}

fn summarize_tool_result(result: &Result<String, String>) -> AuditOutputSummary {
    match result {
        Ok(content) => {
            let parsed = serde_json::from_str::<Value>(content).ok();
            let status = parsed
                .as_ref()
                .and_then(|value| value.get("status"))
                .and_then(|value| value.as_str())
                .map(|status| {
                    if status == "error" {
                        "error".to_string()
                    } else {
                        "ok".to_string()
                    }
                })
                .unwrap_or_else(|| "ok".to_string());
            let exit_code = parsed
                .as_ref()
                .and_then(|value| value.get("exit_code"))
                .and_then(|value| value.as_i64());
            let stdout_bytes = parsed
                .as_ref()
                .and_then(|value| value.get("stdout"))
                .and_then(|value| value.as_str())
                .map(|stdout| stdout.len() as u64)
                .unwrap_or(0);
            let stderr_bytes = parsed
                .as_ref()
                .and_then(|value| value.get("stderr"))
                .and_then(|value| value.as_str())
                .map(|stderr| stderr.len() as u64)
                .unwrap_or(0);
            AuditOutputSummary {
                status,
                exit_code,
                stdout_bytes,
                stderr_bytes,
            }
        }
        Err(message) => AuditOutputSummary {
            status: "error".to_string(),
            exit_code: None,
            stdout_bytes: 0,
            stderr_bytes: message.len() as u64,
        },
    }
}

fn sandbox_events_from_result(result: &Result<String, String>) -> Vec<AuditSandboxEvent> {
    let Ok(content) = result else {
        return vec![];
    };
    let Ok(value) = serde_json::from_str::<Value>(content) else {
        return vec![];
    };
    let Some(audit) = value.get("audit").and_then(|v| v.as_object()) else {
        return vec![];
    };

    [
        ("blocked_subprocesses", "blocked_subprocess"),
        ("blocked_network", "blocked_network"),
        ("blocked_file_reads", "blocked_file_read"),
        ("blocked_file_writes", "blocked_file_write"),
    ]
    .iter()
    .filter_map(|(key, event_type)| {
        let count = audit.get(*key).and_then(|v| v.as_u64()).unwrap_or(0);
        (count > 0).then(|| AuditSandboxEvent {
            event_type: (*event_type).to_string(),
            count,
        })
    })
    .collect()
}

pub(super) fn snapshot_for_tool(tool_name: &str, tool_args: &Value) -> FileSnapshot {
    if tool_name != "pybun_run" {
        return FileSnapshot::new();
    }

    let Some(paths) = tool_args
        .get("sandbox_policy")
        .and_then(|p| p.get("allow_write"))
        .and_then(|v| v.as_array())
    else {
        return FileSnapshot::new();
    };

    let mut snapshot = FileSnapshot::new();
    if paths.len() > 2000 {
        snapshot.complete = false;
    }
    for path in paths.iter().take(2000).filter_map(|v| v.as_str()) {
        collect_file_snapshot(&normalized_absolute_path(Path::new(path)), &mut snapshot);
    }
    snapshot
}

fn string_array_arg(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|name| !name.is_empty() && !name.contains('=') && !name.contains('\0'))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn mcp_sandbox_config_from_policy(policy: &Value) -> crate::sandbox::SandboxConfig {
    crate::sandbox::SandboxConfig {
        allow_network: policy
            .get("allow_network")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        allow_net: string_array_arg(policy, "allow_net"),
        allow_run: string_array_arg(policy, "allow_run"),
        allow_read: string_array_arg(policy, "allow_read"),
        allow_write: string_array_arg(policy, "allow_write"),
        allow_env: string_array_arg(policy, "allow_env")
            .into_iter()
            .filter(|name| !crate::sandbox::is_credential_env_name(name))
            .collect(),
        memory_limit_mb: policy
            .get("memory_limit_mb")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cpu_limit_secs: policy
            .get("cpu_limit_secs")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        timeout_secs: policy
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(crate::sandbox::DEFAULT_SANDBOX_TIMEOUT_SECS),
        ..Default::default()
    }
}

pub(super) fn sandbox_policy_json(config: &crate::sandbox::SandboxConfig) -> Value {
    json!({
        "allow_network": config.allow_network,
        "allow_net": config.allow_net,
        "allow_run": config.allow_run,
        "allow_read": config.allow_read,
        "allow_write": config.allow_write,
        "allow_env": config.allow_env,
        "timeout_secs": config.timeout_secs,
        "memory_limit_mb": config.memory_limit_mb,
        "cpu_limit_secs": config.cpu_limit_secs,
        "max_processes": config.max_processes,
        "file_size_limit_mb": config.file_size_limit_mb,
    })
}

/// Server-side gate for `unsafe_no_sandbox`. Client-supplied JSON-RPC arguments
/// alone must never disable the sandbox; the operator must also opt in via
/// `pybun mcp serve --allow-unsafe-no-sandbox` (which sets this env var).
pub(super) fn mcp_allow_unsafe_no_sandbox() -> bool {
    std::env::var("PYBUN_MCP_ALLOW_UNSAFE_NO_SANDBOX")
        .map(|v| v == "1")
        .unwrap_or(false)
}

pub(super) fn unsafe_no_sandbox_warning(enabled: bool) -> Vec<Value> {
    if enabled {
        vec![json!({
            "level": "warning",
            "code": "W_MCP_UNSAFE_NO_SANDBOX",
            "message": "pybun_run executed without the default MCP sandbox because unsafe_no_sandbox=true was set",
            "suggestion": "Only set unsafe_no_sandbox=true in controlled environments."
        })]
    } else {
        vec![]
    }
}

pub(super) fn unsafe_no_sandbox_denied_warning() -> Vec<Value> {
    vec![json!({
        "level": "warning",
        "code": "W_MCP_UNSAFE_NO_SANDBOX_DENIED",
        "message": "unsafe_no_sandbox=true was requested but denied because the MCP server was not started with --allow-unsafe-no-sandbox",
        "suggestion": "Restart `pybun mcp serve` with --allow-unsafe-no-sandbox if you intend to allow sandbox opt-out."
    })]
}

pub(super) fn describe_run_target(script: Option<&str>, code: Option<&str>) -> String {
    if let Some(script) = script {
        format!("Python script: {script}")
    } else if let Some(code) = code {
        format!("Python inline code ({} bytes)", code.len())
    } else {
        "No Python target".to_string()
    }
}

pub(super) fn estimate_run_risk(
    script: Option<&str>,
    code: Option<&str>,
    sandboxed: bool,
) -> (String, Vec<String>) {
    let mut reasons = Vec::new();
    let source = code.or(script).unwrap_or_default();
    for (needle, reason) in [
        (
            "shutil.rmtree",
            "recursive file deletion detected: shutil.rmtree",
        ),
        ("os.remove", "file deletion detected: os.remove"),
        ("os.unlink", "file deletion detected: os.unlink"),
        ("subprocess", "subprocess execution detected"),
        ("socket", "network access detected"),
        ("ctypes", "native library access detected: ctypes"),
        ("cffi", "native library access detected: cffi"),
    ] {
        if source.contains(needle) {
            reasons.push(reason.to_string());
        }
    }
    if !sandboxed {
        reasons.push("sandbox disabled by unsafe_no_sandbox=true".to_string());
    }

    let risk = if reasons
        .iter()
        .any(|reason| reason.contains("deletion") || reason.contains("sandbox disabled"))
    {
        "high"
    } else if reasons.is_empty() {
        "low"
    } else {
        "medium"
    };

    (risk.to_string(), reasons)
}

fn collect_file_snapshot(path: &Path, snapshot: &mut FileSnapshot) {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    const MAX_ENTRIES: usize = 2000;
    const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
    let mut pending = vec![(path.to_path_buf(), 0)];
    while let Some((path, depth)) = pending.pop() {
        if snapshot.entries >= MAX_ENTRIES || depth > 32 {
            snapshot.complete = false;
            break;
        }
        snapshot.entries += 1;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                snapshot.missing_paths.insert(path);
                continue;
            }
            Err(_) => {
                snapshot.complete = false;
                continue;
            }
        };
        snapshot.observed_paths.insert(path.clone());
        if metadata.file_type().is_symlink() {
            snapshot.complete = false;
            continue;
        }
        if metadata.is_dir() {
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    matches!(
                        name,
                        "target" | ".git" | ".venv" | "venv" | "__pycache__" | "node_modules"
                    )
                })
            {
                snapshot.complete = false;
                continue;
            }
            let Ok(entries) = fs::read_dir(&path) else {
                snapshot.complete = false;
                continue;
            };
            let remaining = MAX_ENTRIES.saturating_sub(snapshot.entries + pending.len());
            let mut children = Vec::new();
            let mut fully_listed = true;
            for entry in entries.take(remaining + 1) {
                if children.len() == remaining {
                    snapshot.complete = false;
                    fully_listed = false;
                    break;
                }
                match entry {
                    Ok(entry) => children.push(entry.path()),
                    Err(_) => {
                        snapshot.complete = false;
                        fully_listed = false;
                    }
                }
            }
            if fully_listed {
                snapshot.listed_directories.insert(path);
            }
            snapshot.observed_paths.extend(children.iter().cloned());
            children.sort();
            pending.extend(children.into_iter().rev().map(|path| (path, depth + 1)));
            continue;
        }
        if !metadata.is_file()
            || metadata.len() > MAX_FILE_BYTES
            || snapshot.bytes.saturating_add(metadata.len()) > MAX_TOTAL_BYTES
        {
            snapshot.complete = false;
            continue;
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let Ok(file) = options.open(&path) else {
            snapshot.complete = false;
            continue;
        };
        if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
            snapshot.complete = false;
            continue;
        }
        let mut bytes = Vec::new();
        let budget = MAX_FILE_BYTES.min(MAX_TOTAL_BYTES.saturating_sub(snapshot.bytes));
        let read = file.take(budget + 1).read_to_end(&mut bytes);
        snapshot.bytes = snapshot
            .bytes
            .saturating_add(bytes.len() as u64)
            .min(MAX_TOTAL_BYTES);
        if read.is_err() || bytes.len() as u64 > budget {
            snapshot.complete = false;
            continue;
        }
        snapshot.files.insert(
            normalized_absolute_path(&path),
            FileState {
                size_bytes: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(&bytes)),
            },
        );
    }
}

pub(super) fn diff_file_writes(before: &FileSnapshot, after: &FileSnapshot) -> AuditDiff {
    let writes = after
        .files
        .iter()
        .filter_map(|(path, after_state)| {
            let before_state = before.files.get(path);
            let changed = before_state
                .map(|state| {
                    state.size_bytes != after_state.size_bytes || state.sha256 != after_state.sha256
                })
                .unwrap_or_else(|| before.proves_absent(path));
            changed.then(|| AuditFileWrite {
                path: path.display().to_string(),
                size_bytes: after_state.size_bytes,
                sha256_before: before_state.map(|state| state.sha256.clone()),
                sha256_after: Some(after_state.sha256.clone()),
            })
        })
        .collect();
    AuditDiff {
        writes,
        complete: before.complete && after.complete,
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    #[test]
    fn partial_baselines_do_not_claim_preexisting_unobserved_files_were_written() {
        let temp = tempfile::tempdir().unwrap();
        for name in ["a", "b", "c", "d", "e"] {
            fs::File::create(temp.path().join(name))
                .unwrap()
                .set_len(4 * 1024 * 1024)
                .unwrap();
        }
        let args = json!({"sandbox_policy":{"allow_write":[temp.path()]}});
        let before = snapshot_for_tool("pybun_run", &args);
        assert!(!before.complete);
        fs::remove_file(temp.path().join("a")).unwrap();
        fs::write(temp.path().join("b"), "changed").unwrap();
        fs::write(temp.path().join("new"), "created").unwrap();
        let after = snapshot_for_tool("pybun_run", &args);
        let diff = diff_file_writes(&before, &after);
        let names: Vec<_> = diff
            .writes
            .iter()
            .map(|write| {
                Path::new(&write.path)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            })
            .collect();
        assert_eq!(names, ["b", "new"]);
        assert!(!diff.complete);
    }
    #[test]
    fn snapshots_exclude_generated_build_trees_and_bound_file_reads() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("target")).unwrap();
        fs::write(temp.path().join("target/build-artifact"), "generated").unwrap();
        let large = fs::File::create(temp.path().join("large-output")).unwrap();
        large.set_len(5 * 1024 * 1024).unwrap();
        fs::write(temp.path().join("source.py"), "print('source')").unwrap();
        let snapshot = snapshot_for_tool(
            "pybun_run",
            &json!({"sandbox_policy":{"allow_write":[temp.path()]}}),
        );
        assert!(!snapshot.files.contains_key(&normalized_absolute_path(
            &temp.path().join("target/build-artifact")
        )));
        assert!(
            !snapshot
                .files
                .contains_key(&normalized_absolute_path(&temp.path().join("large-output")))
        );
        assert!(
            snapshot
                .files
                .contains_key(&normalized_absolute_path(&temp.path().join("source.py")))
        );
    }
    #[cfg(unix)]
    #[test]
    fn snapshots_do_not_follow_external_links_or_cycles() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), "private").unwrap();
        std::os::unix::fs::symlink(outside.path(), temp.path().join("escape")).unwrap();
        let snapshot = snapshot_for_tool(
            "pybun_run",
            &json!({"sandbox_policy":{"allow_write":[temp.path()]}}),
        );
        assert!(snapshot.files.is_empty());
        assert!(!snapshot.complete);
    }
    #[test]
    fn snapshot_entry_and_byte_budgets_are_global_across_roots() {
        let temp = tempfile::tempdir().unwrap();
        for index in 0..5 {
            fs::File::create(temp.path().join(format!("data-{index}")))
                .unwrap()
                .set_len(4 * 1024 * 1024)
                .unwrap();
        }
        let snapshot = snapshot_for_tool(
            "pybun_run",
            &json!({"sandbox_policy":{"allow_write":[temp.path(),temp.path()]}}),
        );
        assert!(!snapshot.complete);
        assert!(snapshot.bytes <= 16 * 1024 * 1024);
        assert!(snapshot.files.len() <= 4);
        let entries = tempfile::tempdir().unwrap();
        for index in 0..2001 {
            fs::write(entries.path().join(format!("item-{index}")), "").unwrap();
        }
        let snapshot = snapshot_for_tool(
            "pybun_run",
            &json!({"sandbox_policy":{"allow_write":[entries.path()]}}),
        );
        assert!(!snapshot.complete);
        assert!(snapshot.entries <= 2000);
    }
}
