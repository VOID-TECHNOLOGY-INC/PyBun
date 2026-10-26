mod permissions;
use color_eyre::eyre::{Result, eyre};
use std::fs;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use tempfile::TempDir;

/// Default wall-clock timeout (in seconds) applied to sandboxed runs.
pub const DEFAULT_SANDBOX_TIMEOUT_SECS: u64 = 60;
/// Default maximum subprocess count for sandboxed runs on Unix.
pub const DEFAULT_SANDBOX_MAX_PROCESSES: u64 = 0;
/// Default maximum file size a sandboxed run may create, in MiB, on Unix.
pub const DEFAULT_SANDBOX_FILE_SIZE_LIMIT_MB: u64 = 10;

/// Process-creation APIs intercepted by the Python sandbox guard. The MCP
/// dry-run risk heuristic uses the same list so enforcement and preview cannot
/// silently drift (Issue #523).
pub(crate) const PROCESS_CREATION_APIS: &[&str] = &[
    "subprocess",
    "os.system",
    "os.popen",
    "os.fork",
    "os.exec",
    "os.posix_spawn",
    "os.spawn",
    "pty",
];

/// Network primitives intercepted by the Python sandbox guard / common client
/// libraries that open sockets internally.
pub(crate) const NETWORK_APIS: &[&str] = &[
    "socket",
    "urllib",
    "http.client",
    "requests",
    "httpx",
    "aiohttp",
];

fn serialize_policy_paths(paths: &[String]) -> Result<String> {
    serde_json::to_string(paths).map_err(|e| eyre!("failed to serialize sandbox policy paths: {e}"))
}

/// Configuration for a sandboxed Python process.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Whether network access should be allowed inside the sandbox.
    pub allow_network: bool,
    pub allow_net: Vec<String>,
    pub allow_run: Vec<String>,
    /// Paths allowed for reading. Empty = no read restriction.
    pub allow_read: Vec<String>,
    /// Paths allowed for writing. Empty = no write restriction (default deny applies).
    pub allow_write: Vec<String>,
    /// Paths denied for writing even when `allow_write` would allow them.
    /// Used by MCP to protect the operator policy file from sandboxed scripts.
    pub deny_write: Vec<String>,
    /// Additional env var names to pass through into the sandbox beyond the safe default set.
    /// Sandbox always filters env vars to prevent secret leakage; this allowlist extends the
    /// default safe set (PATH, HOME, LANG, etc.) with caller-specified names.
    pub allow_env: Vec<String>,
    /// Maximum wall-clock execution time in seconds (0 = unlimited).
    pub timeout_secs: u64,
    /// Maximum memory (virtual address space) in megabytes (Unix only; 0 = unlimited).
    pub memory_limit_mb: u64,
    /// Maximum CPU time in seconds (Unix only; 0 = unlimited).
    pub cpu_limit_secs: u64,
    /// Maximum subprocess count (Unix only; 0 = no fork/exec children).
    pub max_processes: u64,
    /// Maximum file size that may be written, in megabytes (Unix only; 0 = unlimited).
    pub file_size_limit_mb: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            allow_network: false,
            allow_net: Vec::new(),
            allow_run: Vec::new(),
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            deny_write: Vec::new(),
            allow_env: Vec::new(),
            timeout_secs: DEFAULT_SANDBOX_TIMEOUT_SECS,
            memory_limit_mb: 0,
            cpu_limit_secs: 0,
            max_processes: DEFAULT_SANDBOX_MAX_PROCESSES,
            file_size_limit_mb: DEFAULT_SANDBOX_FILE_SIZE_LIMIT_MB,
        }
    }
}

/// Resource limits applied to a sandboxed process, reported back for diagnostics.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ResourceLimits {
    /// Configured wall-clock timeout in seconds (0 = unlimited).
    pub timeout_secs: u64,
    /// Configured memory limit in megabytes (0 = unlimited).
    pub memory_limit_mb: u64,
    /// Configured CPU time limit in seconds (0 = unlimited).
    pub cpu_limit_secs: u64,
    /// Configured maximum subprocess count (0 = no fork/exec children).
    pub max_processes: u64,
    /// Configured maximum file size in megabytes (0 = unlimited).
    pub file_size_limit_mb: u64,
    /// Names of requested limits that could not be enforced on this platform.
    pub unsupported: Vec<String>,
}

/// Returns true if `RLIMIT_AS` (memory limit) is enforceable on this platform.
/// macOS rejects `setrlimit(RLIMIT_AS, ...)` with `EINVAL`, so memory limits
/// are only applied on other Unix platforms (e.g. Linux).
fn memory_limit_supported() -> bool {
    cfg!(all(unix, not(target_os = "macos")))
}

/// Returns true if `RLIMIT_CPU` (CPU time limit) is enforceable on this platform.
fn cpu_limit_supported() -> bool {
    cfg!(unix)
}

/// Returns the minimal set of environment variable names that are always safe to
/// pass into a sandboxed process (Python runtime essentials + locale + temp dirs).
///
/// Intentionally excludes:
/// - `SHELL`: subprocess creation is blocked; leaks host shell path unnecessarily.
/// - `VIRTUAL_ENV` / `VIRTUAL_ENV_PROMPT`: expose host venv path; not needed in sandbox.
/// - `PYTHONPATH`: PyBun constructs the child's PYTHONPATH from scratch (tempdir only).
pub fn default_safe_env_vars() -> &'static [&'static str] {
    &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TERM",
        "COLORTERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "LC_TIME",
        "LC_COLLATE",
        "LC_NUMERIC",
        "LC_MONETARY",
        "TMPDIR",
        "TEMP",
        "TMP",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        // PyBun's own non-secret runtime vars (secret values like tokens are never here)
        "PYBUN_ENV",
        "PYBUN_PYTHON",
        "PYBUN_HOME",
        "PYBUN_PROFILE",
    ]
}

/// Returns true when an environment variable name is likely to carry credentials
/// and must not be passed through even if a caller includes it in allow_env.
pub fn is_credential_env_name(name: &str) -> bool {
    name.to_ascii_uppercase().starts_with("AWS_") || is_secret_env_name(name)
}

/// Names whose values may contain secrets, rather than ordinary AWS settings.
/// Sandbox filtering intentionally denies the wider AWS_* family above.
pub(crate) fn is_secret_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper == "AWS_ACCESS_KEY_ID"
        || upper.starts_with("AWS_BEARER_TOKEN_")
        || upper.contains("_SECRET")
        || upper.ends_with("_TOKEN")
        || upper.ends_with("_KEY")
        || upper.ends_with("_PASSWORD")
        || upper.ends_with("_USERNAME")
        || is_index_env_name(name)
}

pub fn is_index_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("UV_INDEX")
        || matches!(
            upper.as_str(),
            "UV_DEFAULT_INDEX" | "UV_EXTRA_INDEX_URL" | "PIP_INDEX_URL" | "PIP_EXTRA_INDEX_URL"
        )
}

/// Returns the default system-critical paths that should be denied for writes
/// when sandbox mode is active and no explicit `--allow-write` policy is set.
pub fn default_system_deny_write_paths() -> Vec<String> {
    let paths: &[&str] = &[
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/proc",
        "/sys",
        "/dev",
        "/boot",
        #[cfg(target_os = "macos")]
        "/System",
        #[cfg(target_os = "macos")]
        "/Library",
        #[cfg(target_os = "macos")]
        "/Applications",
        // Defense in depth: /etc resolves to /private/etc on macOS via realpath, but
        // list both forms so the deny fires regardless of whether the caller normalized.
        #[cfg(target_os = "macos")]
        "/private/etc",
        // /private/var is intentionally excluded: /private/var/folders is the macOS
        // user temp dir (used by tempfile::tempdir()), so denying the whole subtree
        // would block legitimate writes. Specific high-value sub-paths are protected
        // by macOS SIP and file ownership independently of this sandbox layer.
    ];
    paths.iter().map(|&s| s.to_string()).collect()
}

/// Audit data collected by the sandbox after execution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct SandboxAudit {
    pub blocked_subprocesses: u64,
    pub blocked_network: u64,
    pub blocked_file_reads: u64,
    pub blocked_file_writes: u64,
}

/// Guard that keeps sandbox assets (sitecustomize) alive for the child process.
#[derive(Debug)]
pub struct SandboxGuard {
    _tempdir: TempDir,
    _audit_tempdir: TempDir,
    enforcement: &'static str,
    audit_file: PathBuf,
    /// Default system-critical paths denied for writes (empty when explicit allow_write is set).
    pub default_deny_write: Vec<String>,
    /// Extra env var names allowed through the filter beyond the default safe set.
    pub allow_env: Vec<String>,
    /// Names from `SandboxConfig::allow_env` that were rejected because they look like
    /// credentials (see `is_credential_env_name`) and silently dropped instead of passed through.
    pub rejected_env: Vec<String>,
    /// Resource limits requested for this sandbox, including any unsupported on this platform.
    pub resource_limits: ResourceLimits,
}

impl SandboxGuard {
    /// Name of the sandbox enforcement strategy used.
    pub fn enforcement(&self) -> &str {
        self.enforcement
    }

    /// Read the audit report written by the sandboxed process on exit.
    /// Returns default zeroed audit if the file is missing or unparseable.
    pub fn read_audit(&self) -> SandboxAudit {
        fs::read_to_string(&self.audit_file)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
}

/// Apply a lightweight sandbox to a Python command by injecting a `sitecustomize`
/// module that blocks subprocess creation, network access, and enforces
/// filesystem read/write policies.
pub fn apply_python_sandbox(cmd: &mut Command, config: SandboxConfig) -> Result<SandboxGuard> {
    permissions::validate(&config)?;
    let tempdir = tempfile::tempdir()?;
    let audit_tempdir = tempfile::Builder::new()
        .prefix("pybun-sandbox-audit-")
        .tempdir()?;
    let audit_file = audit_tempdir.path().join("audit.json");
    fs::write(&audit_file, "{}")
        .map_err(|e| eyre!("failed to initialize sandbox audit file: {e}"))?;

    let sitecustomize_path: PathBuf = tempdir.path().join("sitecustomize.py");
    fs::write(
        &sitecustomize_path,
        SITECUSTOMIZE_PY.replace("# GRANULAR_PERMISSIONS", permissions::PY),
    )
    .map_err(|e| eyre!("failed to write sandbox shim: {e}"))?;

    // --- Environment variable filtering ---
    // Clear all inherited env vars so the sandbox child doesn't inherit secrets.
    // env_clear() only affects the *child* process env; std::env::var() below still
    // reads from the *parent* process environment — this is intentional.
    cmd.env_clear();

    // Re-add the default safe set plus any caller-specified names.
    // Use a HashSet to avoid duplicate cmd.env() calls when a name appears in both
    // the default set and allow_env (harmless but wasteful).
    let filtered_allow_env: Vec<String> = config
        .allow_env
        .iter()
        .filter(|name| !is_credential_env_name(name))
        .cloned()
        .collect();
    let rejected_env: Vec<String> = config
        .allow_env
        .iter()
        .filter(|name| is_credential_env_name(name))
        .cloned()
        .collect();
    let safe_names: std::collections::HashSet<String> = default_safe_env_vars()
        .iter()
        .map(|&s| s.to_string())
        .chain(filtered_allow_env.iter().cloned())
        .collect();
    for name in &safe_names {
        if let Ok(val) = std::env::var(name) {
            cmd.env(name, val);
        }
    }

    // Build PYTHONPATH from scratch: only the sandbox tempdir (for sitecustomize).
    // The parent's PYTHONPATH is intentionally dropped — forwarding it would
    // reintroduce potentially attacker-controlled paths into the sandbox.
    let joined = std::env::join_paths(std::iter::once(tempdir.path()))
        .map_err(|e| eyre!("failed to join PYTHONPATH entries for sandbox: {e}"))?;
    cmd.env("PYTHONPATH", joined);

    // Network access is decided solely by `config.allow_network`. Do not also
    // consult the parent process's `PYBUN_SANDBOX_ALLOW_NETWORK` here: this
    // function is the single security-relevant chokepoint shared by both the
    // CLI and MCP entry points, and an ambient env var on the *parent* pybun
    // process (inherited from a shell, CI runner, or wrapper script) must
    // never be able to silently flip an explicit `allow_network: false` to
    // true. Callers that want the env var to act as a CLI convenience flag
    // (see `commands/mod.rs`'s CLI dispatcher) resolve it themselves before
    // building the config, where the decision is explicit and auditable.
    let allow_network = config.allow_network;
    for (key, values) in [
        ("PYBUN_SANDBOX_ALLOW_NET", &config.allow_net),
        ("PYBUN_SANDBOX_ALLOW_RUN", &config.allow_run),
    ] {
        cmd.env(key, serialize_policy_paths(values)?);
    }

    cmd.env("PYBUN_SANDBOX", "1");
    if allow_network {
        cmd.env("PYBUN_SANDBOX_ALLOW_NETWORK", "1");
    } else {
        cmd.env_remove("PYBUN_SANDBOX_ALLOW_NETWORK");
    }

    // Pass filesystem policies as JSON arrays so path separators remain portable.
    cmd.env(
        "PYBUN_SANDBOX_ALLOW_READ",
        serialize_policy_paths(&config.allow_read)?,
    );
    cmd.env(
        "PYBUN_SANDBOX_ALLOW_WRITE",
        serialize_policy_paths(&config.allow_write)?,
    );
    cmd.env(
        "PYBUN_SANDBOX_DENY_WRITE",
        serialize_policy_paths(&config.deny_write)?,
    );

    // When no explicit write policy is set, apply default system-path restrictions.
    // When an explicit allow_write policy is set, the default deny is not needed
    // (the allowlist already restricts all other paths).
    let default_deny = if config.allow_write.is_empty() {
        default_system_deny_write_paths()
    } else {
        vec![]
    };
    cmd.env(
        "PYBUN_SANDBOX_DEFAULT_DENY_WRITE",
        serialize_policy_paths(&default_deny)?,
    );

    // Tell the sitecustomize where to write the audit JSON.
    cmd.env("PYBUN_SANDBOX_AUDIT_FILE", audit_file.as_os_str());
    cmd.env("PYBUN_SANDBOX_HELPER_DIR", tempdir.path().as_os_str());

    // --- Resource limits ---
    let mut unsupported = Vec::new();
    if !config.allow_run.is_empty() {
        unsupported.push("process".to_string());
    }
    if config.memory_limit_mb > 0 && !memory_limit_supported() {
        unsupported.push("memory".to_string());
    }
    if config.cpu_limit_secs > 0 && !cpu_limit_supported() {
        unsupported.push("cpu".to_string());
    }
    if !cfg!(unix) {
        if config.max_processes == 0 {
            unsupported.push("process".to_string());
        }
        if config.file_size_limit_mb > 0 {
            unsupported.push("file_size".to_string());
        }
    }

    #[cfg(unix)]
    {
        let apply_memory = config.memory_limit_mb > 0 && memory_limit_supported();
        let apply_cpu = config.cpu_limit_secs > 0 && cpu_limit_supported();
        let apply_process = config.allow_run.is_empty();
        let apply_file_size = config.file_size_limit_mb > 0;
        let memory_limit_mb = config.memory_limit_mb;
        let cpu_limit_secs = config.cpu_limit_secs;
        let max_processes = config.max_processes;
        let file_size_limit_mb = config.file_size_limit_mb;
        if apply_memory || apply_cpu || apply_process || apply_file_size {
            // SAFETY: the closure only calls async-signal-safe libc functions
            // (`setrlimit`) between fork and exec, as required by `pre_exec`.
            unsafe {
                cmd.pre_exec(move || {
                    if apply_process {
                        let limit = libc::rlimit {
                            rlim_cur: max_processes as libc::rlim_t,
                            rlim_max: max_processes as libc::rlim_t,
                        };
                        if libc::setrlimit(libc::RLIMIT_NPROC, &limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    if apply_file_size {
                        let bytes = file_size_limit_mb.saturating_mul(1024 * 1024);
                        let limit = libc::rlimit {
                            rlim_cur: bytes as libc::rlim_t,
                            rlim_max: bytes as libc::rlim_t,
                        };
                        if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    if apply_memory {
                        let bytes = memory_limit_mb.saturating_mul(1024 * 1024);
                        let limit = libc::rlimit {
                            rlim_cur: bytes as libc::rlim_t,
                            rlim_max: bytes as libc::rlim_t,
                        };
                        if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    if apply_cpu {
                        // Give the hard limit one extra second of headroom over the soft
                        // limit. On Linux, `rlim_cur == rlim_max` causes the kernel to
                        // send SIGKILL alongside SIGXCPU as soon as the limit is hit,
                        // and SIGKILL (which can't be caught) wins the race — so
                        // `cpu_limit_exceeded` would never see SIGXCPU. With headroom,
                        // SIGXCPU's default terminate action fires first.
                        let limit = libc::rlimit {
                            rlim_cur: cpu_limit_secs as libc::rlim_t,
                            rlim_max: cpu_limit_secs.saturating_add(1) as libc::rlim_t,
                        };
                        if libc::setrlimit(libc::RLIMIT_CPU, &limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }
    }

    let resource_limits = ResourceLimits {
        timeout_secs: config.timeout_secs,
        memory_limit_mb: config.memory_limit_mb,
        cpu_limit_secs: config.cpu_limit_secs,
        max_processes: config.max_processes,
        file_size_limit_mb: config.file_size_limit_mb,
        unsupported,
    };

    Ok(SandboxGuard {
        _tempdir: tempdir,
        _audit_tempdir: audit_tempdir,
        enforcement: "python-sitecustomize",
        audit_file,
        default_deny_write: default_deny,
        allow_env: filtered_allow_env,
        rejected_env,
        resource_limits,
    })
}

/// Outcome of executing a sandboxed command, possibly subject to a wall-clock timeout.
pub enum SandboxExecOutcome {
    /// The process exited on its own (or no timeout was configured).
    Completed {
        status: ExitStatus,
        stdout: Option<Vec<u8>>,
        stderr: Option<Vec<u8>>,
    },
    /// The process was killed because it exceeded the configured timeout.
    TimedOut,
}

/// Run `cmd` to completion, optionally capturing stdout/stderr, killing it if
/// it exceeds `timeout_secs` (0 = unlimited). Delegates to
/// [`crate::proc_exec::spawn_with_timeout`], the shared spawn/poll/kill helper
/// also used by `test_executor::run_with_timeout` (Issue #273), so a chatty
/// process can't deadlock on a full pipe buffer while we wait for exit.
pub fn execute_sandboxed(
    cmd: &mut Command,
    timeout_secs: u64,
    capture: bool,
) -> std::io::Result<SandboxExecOutcome> {
    let timeout = (timeout_secs > 0).then_some(timeout_secs);
    match crate::proc_exec::spawn_with_timeout(cmd, timeout, capture)? {
        crate::proc_exec::ProcExecOutcome::Completed {
            status,
            stdout,
            stderr,
        } => Ok(SandboxExecOutcome::Completed {
            status,
            stdout,
            stderr,
        }),
        crate::proc_exec::ProcExecOutcome::TimedOut => Ok(SandboxExecOutcome::TimedOut),
    }
}

/// Synthesize an `ExitStatus` representing a timed-out process: exit code 124,
/// matching the POSIX `timeout(1)` convention.
pub fn timeout_exit_status() -> ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(124 << 8)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(124)
    }
}

/// Returns true if `status` indicates the process was terminated by `SIGXCPU`,
/// i.e. it exceeded the CPU time limit configured via `--sandbox-cpu`
/// (enforced through `RLIMIT_CPU`, see [`cpu_limit_supported`]).
#[cfg(unix)]
pub fn cpu_limit_exceeded(status: &ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;
    status.signal() == Some(libc::SIGXCPU)
}

/// `RLIMIT_CPU` is only enforced on Unix, so a non-Unix process can never be
/// killed by `SIGXCPU`.
#[cfg(not(unix))]
pub fn cpu_limit_exceeded(_status: &ExitStatus) -> bool {
    false
}

/// Outcome of [`execute_with_optional_sandbox`]: the finished (or timed-out) process.
pub struct SandboxedExecution {
    pub status: ExitStatus,
    pub stdout: Option<Vec<u8>>,
    pub stderr: Option<Vec<u8>>,
    pub timed_out: bool,
}

/// Run `cmd` to completion, honoring `sandbox_guard`'s timeout when present, and
/// capture output when `capture_output` is set.
///
/// This is the single execution primitive shared by the CLI `pybun run` command
/// (`commands::run_script` / `commands::run_python_code`) and the MCP `pybun_run`
/// tool (`mcp::call_run`). Callers are still responsible for building their own
/// `SandboxConfig` and calling [`apply_python_sandbox`] beforehand (CLI flags vs
/// MCP `sandbox_policy` JSON have different shapes, and sandbox application must
/// happen before other `cmd.env()` calls because it clears the environment) — but
/// centralizing the sandboxed-vs-plain execution branch, timeout handling, and
/// output capture here means the two entry points can no longer silently diverge
/// in this behavior (Issue #272).
pub fn execute_with_optional_sandbox(
    cmd: &mut Command,
    sandbox_guard: Option<&SandboxGuard>,
    capture_output: bool,
) -> std::io::Result<SandboxedExecution> {
    // Index authentication belongs to dependency preparation, not user code.
    let names: Vec<_> = std::env::vars_os()
        .map(|(name, _)| name)
        .chain(cmd.get_envs().map(|(name, _)| name.to_os_string()))
        .filter(|name| is_index_env_name(&name.to_string_lossy()))
        .collect();
    for name in names {
        cmd.env_remove(name);
    }
    let mut timed_out = false;
    let (status, stdout, stderr) = if let Some(guard) = sandbox_guard {
        match execute_sandboxed(cmd, guard.resource_limits.timeout_secs, capture_output)? {
            SandboxExecOutcome::Completed {
                status,
                stdout,
                stderr,
            } => (status, stdout, stderr),
            SandboxExecOutcome::TimedOut => {
                timed_out = true;
                (timeout_exit_status(), None, None)
            }
        }
    } else if capture_output {
        let output = cmd.output()?;
        (output.status, Some(output.stdout), Some(output.stderr))
    } else {
        let status = cmd.status()?;
        (status, None, None)
    };

    Ok(SandboxedExecution {
        status,
        stdout,
        stderr,
        timed_out,
    })
}

/// The sitecustomize.py injected into every sandboxed Python process.
///
/// All configuration is read from environment variables so this can be a
/// static string with no Rust format-macro escaping issues.
const SITECUSTOMIZE_PY: &str = r#"
import os
import io
import _io
import sys
import json
import atexit
import socket
import subprocess
import builtins

# Originals are captured as default arguments inside the patching functions
# below, never as module globals: a sandboxed script can import sitecustomize
# and would otherwise be able to call `sitecustomize._orig_open` to bypass
# every read/write policy.

ALLOW_NETWORK = os.environ.get("PYBUN_SANDBOX_ALLOW_NETWORK") == "1"
_AUDIT_FILE = os.environ.get("PYBUN_SANDBOX_AUDIT_FILE", "")
_HELPER_DIR = os.environ.get("PYBUN_SANDBOX_HELPER_DIR", "")


def _load_policy_paths(name):
    raw = os.environ.get(name, "")
    if not raw:
        return []
    value = json.loads(raw)
    if not isinstance(value, list):
        raise ValueError("{} must decode to a list".format(name))
    return [entry for entry in value if isinstance(entry, str)]


def _normalize_path(path):
    # KNOWN RESIDUAL RISK (TOCTOU): realpath() resolves symlinks at the time
    # of this check, but the actual open()/os.open() call happens afterward.
    # A symlink swapped in between the check and the syscall (e.g. by a
    # concurrent process) could redirect an allowed path to a denied one.
    # Closing this fully would require O_NOFOLLOW plus resolving-then-
    # opening by file descriptor throughout the stdlib, which is impractical
    # to retrofit onto every os.* call the sandbox patches. Accepted as a
    # low-probability gap for now: sandboxed code cannot itself create
    # symlinks outside its write allowlist (symlink() is checked above), so
    # exploiting this requires an external actor racing the filesystem.
    return os.path.realpath(os.path.abspath(path))


_CASE_INSENSITIVE = sys.platform in ("darwin", "win32")


def _path_within(path, allowed_root):
    try:
        if _CASE_INSENSITIVE:
            path = path.casefold()
            allowed_root = allowed_root.casefold()
        return os.path.commonpath([path, allowed_root]) == allowed_root
    except ValueError:
        return False


_ALLOW_READ = [_normalize_path(p) for p in _load_policy_paths("PYBUN_SANDBOX_ALLOW_READ")]
_ALLOW_WRITE = [_normalize_path(p) for p in _load_policy_paths("PYBUN_SANDBOX_ALLOW_WRITE")]
_DENY_WRITE = [_normalize_path(p) for p in _load_policy_paths("PYBUN_SANDBOX_DENY_WRITE")]
_DEFAULT_DENY_WRITE = [_normalize_path(p) for p in _load_policy_paths("PYBUN_SANDBOX_DEFAULT_DENY_WRITE")]
_AUDIT_FILE_PATH = _normalize_path(_AUDIT_FILE) if _AUDIT_FILE else ""
_HAS_READ_POLICY = bool(_ALLOW_READ)
_HAS_WRITE_POLICY = bool(_ALLOW_WRITE)
_HAS_DENY_WRITE = bool(_DENY_WRITE)
_HAS_DEFAULT_DENY_WRITE = bool(_DEFAULT_DENY_WRITE)

# Sys prefixes are always readable so Python imports keep working.
_SYS_PREFIXES = []
for _attr in ("prefix", "exec_prefix", "base_prefix"):
    _v = getattr(sys, _attr, None)
    if _v:
        _SYS_PREFIXES.append(_normalize_path(_v))
if hasattr(sys, "real_prefix"):
    _SYS_PREFIXES.append(_normalize_path(sys.real_prefix))
# Before site.main(), Python <=3.13 with -S still reports the base prefixes.
# The interpreter's own venv must be readable to initialize pyvenv.cfg and imports.
_venv_prefix = os.path.dirname(os.path.dirname(sys.executable))
if os.path.isfile(os.path.join(_venv_prefix, "pyvenv.cfg")):
    _SYS_PREFIXES.append(_normalize_path(_venv_prefix))

_ALWAYS_ALLOW_READ = list(_SYS_PREFIXES)
if _HELPER_DIR:
    _ALWAYS_ALLOW_READ.append(_normalize_path(_HELPER_DIR))

_audit = {
    "blocked_subprocesses": 0,
    "blocked_network": 0,
    "blocked_file_reads": 0,
    "blocked_file_writes": 0,
}


def _deny(reason, audit_key=None):
    if audit_key:
        _audit[audit_key] += 1
    raise PermissionError("pybun sandbox: " + reason + " blocked")


def _is_read_allowed(path):
    """Return True if path is readable: under the read allowlist or a sys prefix.

    Sys prefixes (the interpreter's own install dirs) are always readable so
    that Python's own imports keep working even under a restrictive read
    policy.
    """
    try:
        normalized_path = _normalize_path(os.fsdecode(os.fspath(path)))
        if any(_path_within(normalized_path, p) for p in _ALWAYS_ALLOW_READ):
            return True
        return any(_path_within(normalized_path, p) for p in _ALLOW_READ)
    except Exception:
        return False


def _is_write_allowed(path):
    """Return True if path is under the write allowlist.

    Deliberately does NOT consult _ALWAYS_ALLOW_READ: sys prefixes must stay
    readable for imports but are not implicitly writable just because an
    explicit write allowlist was configured. Treating them as always-writable
    let sandboxed code overwrite interpreter/stdlib files whenever a write
    policy was set (the policy was meant to restrict writes, not widen them).
    """
    try:
        normalized_path = _normalize_path(os.fsdecode(os.fspath(path)))
        return any(_path_within(normalized_path, p) for p in _ALLOW_WRITE)
    except Exception:
        return False


def _is_in_denied(path, denied_paths):
    """Return True if path is within any of the denied directories.

    Fails closed (returns True) on any evaluation error so that an
    unexpected exception does not silently grant write access.
    """
    try:
        normalized_path = _normalize_path(os.fsdecode(os.fspath(path)))
        if not normalized_path:
            return False
        return any(_path_within(normalized_path, p) for p in denied_paths)
    except Exception:
        return True  # fail-closed: deny on error


def _mode_needs_read(mode):
    return "+" in mode or not any(flag in mode for flag in "wxa")


def _mode_needs_write(mode):
    return any(flag in mode for flag in "wxa+")


def _block_subprocesses():
    def _blocked(*_a, **_kw):
        _deny("process creation E_SANDBOX_RUN_DENIED " + str(_a[0] if _a else "process creation") + "; use --allow-run", "blocked_subprocesses")

    def _blocked_popen_init(_self, *_a, **_kw):
        _deny("process creation E_SANDBOX_RUN_DENIED " + str(_a[0] if _a else "process creation") + "; use --allow-run", "blocked_subprocesses")

    # Deny at the point of the actual spawn (Popen.__init__, which is what
    # invokes _execute_child) instead of replacing subprocess.Popen itself.
    # Reassigning subprocess.Popen to a plain function corrupts any code
    # that subclasses it (`class MyPopen(subprocess.Popen): ...`, used by
    # asyncio's subprocess transports and third-party process wrappers) or
    # does isinstance()/issubclass() checks against it: once
    # subprocess.Popen is a function instead of a class, the class
    # statement fails with a confusing low-level TypeError instead of a
    # clean sandbox denial. Patching __init__ on the real class keeps
    # subclassing and isinstance checks working while still blocking every
    # path that actually spawns a child process.
    subprocess.Popen.__init__ = _blocked_popen_init
    subprocess.call = _blocked
    subprocess.run = _blocked
    subprocess.check_call = _blocked
    subprocess.check_output = _blocked
    os.system = _blocked

    if hasattr(os, "fork"):
        os.fork = lambda *_a, **_kw: _deny("fork", "blocked_subprocesses")

    for _name in ("execv", "execve", "execl", "execlp", "execvp", "execvpe", "execle"):
        if hasattr(os, _name):
            setattr(os, _name, lambda *_a, **_kw: _deny("process execution", "blocked_subprocesses"))

    # os.posix_spawn / os.posix_spawnp and the os.spawn* family create
    # processes without going through subprocess.* or os.exec*, and were
    # previously left unblocked (sandbox escape via os.posix_spawn).
    for _name in (
        "posix_spawn",
        "posix_spawnp",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "startfile",
    ):
        if hasattr(os, _name):
            setattr(os, _name, lambda *_a, **_kw: _deny("process creation E_SANDBOX_RUN_DENIED " + str(_a[0] if _a else "process creation") + "; use --allow-run", "blocked_subprocesses"))


def _block_network():
    def _blocked(*_a, **_kw):
        _deny("network access E_SANDBOX_NET_DENIED " + str(_a[0] if _a else "network access") + "; use --allow-net", "blocked_network")

    def _blocked_connect(_self, *_a, **_kw):
        _deny("network access E_SANDBOX_NET_DENIED " + str(_a[0] if _a else "network access") + "; use --allow-net", "blocked_network")

    # Deny at the point of the actual network operation (connect) instead of
    # replacing socket.socket itself. Reassigning socket.socket to a plain
    # function corrupts unrelated stdlib import machinery: modules such as
    # ssl.py do `from socket import socket` at import time and then subclass
    # it (`class SSLSocket(socket):`), so once socket.socket is a function
    # instead of a class, that class statement fails with a confusing
    # low-level TypeError instead of a clean sandbox denial. Patching
    # connect/connect_ex on the real class keeps subclassing working while
    # still blocking every path that establishes an outbound connection.
    socket.socket.connect = _blocked_connect
    socket.socket.connect_ex = _blocked_connect
    socket.create_connection = _blocked
    if hasattr(socket, "socketpair"):
        socket.socketpair = _blocked

    # connect/connect_ex only cover connection-oriented (TCP) sockets. A
    # connectionless UDP socket can send and receive datagrams to arbitrary
    # remote addresses via sendto/sendmsg/recvfrom/recvmsg without ever
    # calling connect, which previously bypassed the network block entirely.
    for _name in ("sendto", "sendmsg"):
        if hasattr(socket.socket, _name):
            setattr(socket.socket, _name, _blocked_connect)
    for _name in ("recvfrom", "recvmsg"):
        if hasattr(socket.socket, _name):
            setattr(socket.socket, _name, _blocked_connect)


def _patch_filesystem(orig_open=builtins.open, orig_os_open=os.open, orig_fileio=_io.FileIO):
    # Capture policy as immutable locals. Module globals can be mutated or
    # re-read by importlib.reload from attacker-controlled environment
    # variables; these closure cells cannot.
    allow_read = tuple(_ALLOW_READ)
    allow_write = tuple(_ALLOW_WRITE)
    deny_write = tuple(_DENY_WRITE)
    default_deny = tuple(_DEFAULT_DENY_WRITE)
    always_allow_read = tuple(_ALWAYS_ALLOW_READ)
    audit_file = _AUDIT_FILE_PATH
    has_read = bool(allow_read)
    has_write = bool(allow_write)
    has_deny = bool(deny_write)
    has_default_deny = bool(default_deny)

    def _is_read_allowed(path):
        try:
            normalized_path = _normalize_path(os.fsdecode(os.fspath(path)))
            if any(_path_within(normalized_path, p) for p in always_allow_read):
                return True
            return any(_path_within(normalized_path, p) for p in allow_read)
        except Exception:
            return False

    def _is_write_allowed(path):
        try:
            normalized_path = _normalize_path(os.fsdecode(os.fspath(path)))
            return any(_path_within(normalized_path, p) for p in allow_write)
        except Exception:
            return False

    def _is_in_denied(path, denied_paths):
        try:
            normalized_path = _normalize_path(os.fsdecode(os.fspath(path)))
            if not normalized_path:
                return False
            return any(_path_within(normalized_path, p) for p in denied_paths)
        except Exception:
            return True

    def _check_read_path(path):
        if has_read and not _is_read_allowed(path):
            _deny("read from " + os.fsdecode(os.fspath(path)), "blocked_file_reads")

    def _check_write_path(path, action):
        if not isinstance(path, (str, bytes, os.PathLike)):
            return
        decoded = os.fsdecode(os.fspath(path))
        if not decoded:
            return
        if audit_file and _normalize_path(decoded) == audit_file:
            _deny(action + " sandbox audit file", "blocked_file_writes")
        if has_deny and _is_in_denied(decoded, deny_write):
            _deny(action + " protected file " + decoded, "blocked_file_writes")
        if has_write:
            if not _is_write_allowed(decoded):
                _deny(action + " " + decoded, "blocked_file_writes")
        elif has_default_deny:
            if _is_in_denied(decoded, default_deny):
                _deny(action + " " + decoded, "blocked_file_writes")

    def _checked_open(file, mode="r", *args, **kwargs):
        if not isinstance(file, (str, bytes, os.PathLike)):
            return orig_open(file, mode, *args, **kwargs)
        path = os.fsdecode(os.fspath(file))
        if not path:
            return orig_open(file, mode, *args, **kwargs)
        if _mode_needs_read(mode):
            _check_read_path(path)
        if _mode_needs_write(mode):
            _check_write_path(path, "write to")
        return orig_open(file, mode, *args, **kwargs)

    builtins.open = _checked_open
    io.open = _checked_open
    _io.open = _checked_open

    class _CheckedFileIO(orig_fileio):
        def __init__(self, file, mode="r", *args, **kwargs):
            if isinstance(file, (str, bytes, os.PathLike)):
                path = os.fsdecode(os.fspath(file))
                if path:
                    if _mode_needs_read(mode):
                        _check_read_path(path)
                    if _mode_needs_write(mode):
                        _check_write_path(path, "write to")
            super().__init__(file, mode, *args, **kwargs)

    io.FileIO = _CheckedFileIO
    _io.FileIO = _CheckedFileIO

    _WRITE_FLAGS = os.O_CREAT | os.O_TRUNC | os.O_APPEND
    if hasattr(os, "O_TMPFILE"):
        _WRITE_FLAGS |= os.O_TMPFILE

    def _checked_os_open(path, flags, *args, **kwargs):
        accmode = flags & os.O_ACCMODE
        wants_read = accmode in (os.O_RDONLY, os.O_RDWR)
        wants_write = accmode in (os.O_WRONLY, os.O_RDWR) or bool(flags & _WRITE_FLAGS)
        if not isinstance(path, (str, bytes, os.PathLike)):
            return orig_os_open(path, flags, *args, **kwargs)
        decoded = os.fsdecode(os.fspath(path))
        if decoded:
            if wants_read:
                _check_read_path(decoded)
            if wants_write:
                _check_write_path(decoded, "write to")
        return orig_os_open(path, flags, *args, **kwargs)

    os.open = _checked_os_open

    def _wrap_single_path_mutation(fn, action):
        def _wrapped(path, *args, **kwargs):
            _check_write_path(path, action)
            return fn(path, *args, **kwargs)
        return _wrapped

    def _wrap_two_path_mutation(fn, action):
        def _wrapped(src, dst, *args, **kwargs):
            _check_write_path(src, action + " from")
            _check_write_path(dst, action + " to")
            return fn(src, dst, *args, **kwargs)
        return _wrapped

    for _name, _action in (
        ("remove", "delete"),
        ("unlink", "delete"),
        ("rmdir", "delete"),
        ("mkdir", "create directory"),
        ("makedirs", "create directory"),
        ("removedirs", "delete directory"),
        ("truncate", "truncate"),
    ):
        if hasattr(os, _name):
            setattr(os, _name, _wrap_single_path_mutation(getattr(os, _name), _action))

    for _name, _action in (
        ("rename", "rename"),
        ("replace", "replace"),
    ):
        if hasattr(os, _name):
            setattr(os, _name, _wrap_two_path_mutation(getattr(os, _name), _action))

    def _wrap_link_mutation(fn, action):
        def _wrapped(src, dst, *args, **kwargs):
            if isinstance(src, (str, bytes, os.PathLike)):
                _check_read_path(src)
                # A hardlink gives a second writable name for `src`; deny
                # linking a protected file even when dst is inside allow_write.
                _check_write_path(src, action + " from")
            _check_write_path(dst, action + " to")
            return fn(src, dst, *args, **kwargs)
        return _wrapped

    if hasattr(os, "link"):
        os.link = _wrap_link_mutation(os.link, "link")

    def _wrap_symlink_mutation(fn, action):
        def _wrapped(src, dst, *args, **kwargs):
            _check_write_path(dst, action + " to")
            return fn(src, dst, *args, **kwargs)
        return _wrapped

    if hasattr(os, "symlink"):
        os.symlink = _wrap_symlink_mutation(os.symlink, "symlink")


def _write_audit(orig_open=builtins.open):
    if _AUDIT_FILE:
        try:
            with orig_open(_AUDIT_FILE, "w") as _f:
                _f.write(json.dumps(_audit))
        except Exception:
            pass


# GRANULAR_PERMISSIONS

try:
    _audit_writer = _write_audit
    atexit.register(_audit_writer)
    del _write_audit
    del _audit_writer
    _install_permissions()
    if not _ALLOW_RUN:
        _block_subprocesses()
    if not ALLOW_NETWORK and not _ALLOW_NET:
        _block_network()
    if _HAS_READ_POLICY or _HAS_WRITE_POLICY or _HAS_DEFAULT_DENY_WRITE or _HAS_DENY_WRITE:
        _patch_filesystem()
    sys.stderr.write(
        "[pybun] sandbox active (allow_network={}, read_policy={}, write_policy={}, default_deny_write={})\n".format(
            ALLOW_NETWORK, _HAS_READ_POLICY, _HAS_WRITE_POLICY, _HAS_DEFAULT_DENY_WRITE or _HAS_DENY_WRITE
        )
    )
    # The module is fully installed now. Remove it and its helper directory so
    # sandboxed code cannot mutate policy globals or importlib.reload a new
    # policy from attacker-controlled environment variables.
    sys.modules.pop("sitecustomize", None)
    try:
        sys.path[:] = [
            p for p in sys.path
            if os.path.abspath(p or ".") != os.path.abspath(_HELPER_DIR)
        ]
    except Exception:
        pass
except Exception as exc:  # pragma: no cover - defensive, should not happen
    sys.stderr.write("[pybun] sandbox init failed: {}\n".format(exc))
    os._exit(126)
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc_exec::tests::successful_command;

    fn output_command(message: &str) -> Command {
        #[cfg(unix)]
        {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg(format!("echo {message}"));
            cmd
        }
        #[cfg(windows)]
        {
            let mut cmd = Command::new("cmd");
            cmd.arg("/C").arg(format!("echo {message}"));
            cmd
        }
    }

    fn long_running_command() -> Command {
        #[cfg(unix)]
        {
            let mut cmd = Command::new("sleep");
            cmd.arg("5");
            cmd
        }
        #[cfg(windows)]
        {
            let mut cmd = Command::new("cmd");
            cmd.arg("/C").arg("ping -n 6 127.0.0.1 >NUL");
            cmd
        }
    }

    #[test]
    fn aws_settings_remain_filtered_without_becoming_secret_values() {
        for name in [
            "AWS_PROFILE",
            "AWS_DEFAULT_OUTPUT",
            "AWS_PAGER",
            "AWS_REGION",
        ] {
            assert!(is_credential_env_name(name));
            assert!(!is_secret_env_name(name));
        }
        for name in [
            "AWS_ACCESS_KEY_ID",
            "AWS_BEARER_TOKEN_BEDROCK",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_SECURITY_TOKEN",
            "SECRET_API_KEY",
            "UV_INDEX_PRIVATE_PASSWORD",
        ] {
            assert!(is_credential_env_name(name));
            assert!(is_secret_env_name(name));
        }
    }

    #[test]
    fn default_safe_env_vars_includes_path_and_home() {
        let safe = default_safe_env_vars();
        assert!(
            safe.contains(&"PATH"),
            "PATH must be in the default safe set"
        );
        assert!(
            safe.contains(&"HOME"),
            "HOME must be in the default safe set"
        );
        assert!(
            safe.contains(&"LANG"),
            "LANG must be in the default safe set"
        );
    }

    #[test]
    fn default_safe_env_vars_excludes_secret_like_names() {
        let safe = default_safe_env_vars();
        // These look like secret names and must not be in the default allowlist.
        // The test ensures we don't accidentally expose them by default.
        assert!(!safe.contains(&"AWS_SECRET_ACCESS_KEY"));
        assert!(!safe.contains(&"OPENAI_API_KEY"));
        assert!(!safe.contains(&"DATABASE_URL"));
    }

    #[test]
    fn sandbox_config_allow_env_defaults_to_empty() {
        let config = SandboxConfig::default();
        assert!(config.allow_env.is_empty());
    }

    #[test]
    fn apply_python_sandbox_passes_through_non_credential_allow_env() {
        let mut cmd = Command::new("true");
        let config = SandboxConfig {
            allow_env: vec!["MY_FLAG".to_string()],
            ..Default::default()
        };
        let guard = apply_python_sandbox(&mut cmd, config).expect("sandbox setup should succeed");
        assert_eq!(guard.allow_env, vec!["MY_FLAG".to_string()]);
        assert!(guard.rejected_env.is_empty());
    }

    #[test]
    fn apply_python_sandbox_rejects_credential_shaped_allow_env() {
        let mut cmd = Command::new("true");
        let config = SandboxConfig {
            allow_env: vec!["SECRET_API_KEY".to_string()],
            ..Default::default()
        };
        let guard = apply_python_sandbox(&mut cmd, config).expect("sandbox setup should succeed");
        assert!(guard.allow_env.is_empty());
        assert_eq!(guard.rejected_env, vec!["SECRET_API_KEY".to_string()]);
    }

    // ─── execute_with_optional_sandbox (Issue #272) ─────────────────────────
    //
    // `execute_with_optional_sandbox` is the single execution primitive now
    // shared by CLI `pybun run` (`commands::run_script` / `run_python_code`)
    // and MCP `pybun_run` (`mcp::call_run`). These tests exercise it directly
    // so that a future change to sandboxed-vs-plain execution, timeout
    // handling, or output capture is guaranteed to affect both entry points
    // identically instead of silently diverging between them.

    #[test]
    fn protected_files_cannot_be_rewritten_through_python_bypasses() {
        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("pyproject.toml");
        fs::write(&protected, "original").unwrap();
        let protected_str = protected.to_string_lossy().to_string();
        let scripts = [
            format!(
                "import sitecustomize as sc\nsc._DENY_WRITE.clear()\nsc._HAS_DENY_WRITE = False\nopen({protected:?}, 'w').write('x')",
                protected = protected_str
            ),
            format!(
                "import importlib\nimportlib.reload(importlib.import_module('sitecustomize'))\nopen({protected:?}, 'w').write('x')",
                protected = protected_str
            ),
            format!(
                "import os\nos.link({protected:?}, 'copy')\nopen('copy', 'w').write('x')",
                protected = protected_str
            ),
            format!(
                "import os\nos.truncate({protected:?}, 0)",
                protected = protected_str
            ),
            format!(
                "import io\nio.FileIO({protected:?}, 'w').write(b'x')",
                protected = protected_str
            ),
        ];
        for script in scripts {
            let mut cmd = Command::new("python3");
            cmd.arg("-c").arg(&script);
            let config = SandboxConfig {
                allow_write: vec![temp.path().to_string_lossy().to_string()],
                deny_write: vec![protected_str.clone()],
                ..Default::default()
            };
            let guard =
                apply_python_sandbox(&mut cmd, config).expect("sandbox setup should succeed");
            let result = execute_with_optional_sandbox(&mut cmd, Some(&guard), true)
                .expect("sandboxed command should execute");
            assert!(!result.status.success(), "bypass succeeded: {script}");
            assert_eq!(fs::read_to_string(&protected).unwrap(), "original");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn deny_write_is_case_insensitive_on_macos() {
        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("pyproject.toml");
        fs::write(&protected, "original").unwrap();
        let mut cmd = Command::new("python3");
        cmd.args(["-c", "open('PYPROJECT.TOML', 'w').write('overwritten')"]);
        cmd.current_dir(temp.path());
        let config = SandboxConfig {
            allow_write: vec![temp.path().to_string_lossy().to_string()],
            deny_write: vec![protected.to_string_lossy().to_string()],
            ..Default::default()
        };
        let guard = apply_python_sandbox(&mut cmd, config).expect("sandbox setup should succeed");
        let result = execute_with_optional_sandbox(&mut cmd, Some(&guard), true)
            .expect("sandboxed command should execute");
        assert!(!result.status.success());
        assert_eq!(fs::read_to_string(&protected).unwrap(), "original");
    }

    #[test]
    fn sandbox_does_not_expose_original_open_functions() {
        let mut cmd = Command::new("python3");
        cmd.args([
            "-c",
            "try:\n import sitecustomize as sc\nexcept ImportError:\n raise SystemExit(0)\nraise SystemExit(3 if hasattr(sc, '_orig_open') or hasattr(sc, '_orig_os_open') else 0)",
        ]);
        let guard = apply_python_sandbox(&mut cmd, SandboxConfig::default())
            .expect("sandbox setup should succeed");
        let result = execute_with_optional_sandbox(&mut cmd, Some(&guard), true)
            .expect("sandboxed command should execute");
        assert!(
            result.status.success(),
            "sandbox leaked an original open function"
        );
    }

    #[cfg(unix)]
    #[test]
    fn external_venv_is_readable_before_site_initialization() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let venv = temp.path().join("venv");
        fs::create_dir(&project).unwrap();
        let created = Command::new("python3")
            .args(["-m", "venv", "--without-pip"])
            .arg(&venv)
            .output()
            .unwrap();
        assert!(created.status.success(), "{created:?}");
        let mut cmd = Command::new(venv.join("bin/python"));
        cmd.current_dir(&project).args(["-S", "-c", "import runpy, os; runpy.run_path(os.path.join(os.environ['PYBUN_SANDBOX_HELPER_DIR'], 'sitecustomize.py')); import site; site.main(); print('runtime-ok')"]);
        let guard = apply_python_sandbox(
            &mut cmd,
            SandboxConfig {
                allow_read: vec![project.to_string_lossy().into_owned()],
                ..Default::default()
            },
        )
        .unwrap();
        let result = execute_with_optional_sandbox(&mut cmd, Some(&guard), true).unwrap();
        assert!(result.status.success(), "{:?}", result.stderr);
        assert_eq!(result.stdout.as_deref(), Some(b"runtime-ok\n".as_slice()));
    }

    #[test]
    fn deny_write_overrides_allow_write() {
        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("policy.toml");
        let allowed = temp.path().join("output.txt");
        fs::write(&protected, "original").unwrap();
        let mut cmd = Command::new("python3");
        cmd.args([
            "-c",
            "import sys; open(sys.argv[1], 'w').write('overwritten')",
            protected.to_str().unwrap(),
        ]);
        let config = SandboxConfig {
            allow_write: vec![temp.path().to_string_lossy().to_string()],
            deny_write: vec![protected.to_string_lossy().to_string()],
            ..Default::default()
        };
        let guard = apply_python_sandbox(&mut cmd, config).expect("sandbox setup should succeed");
        let result = execute_with_optional_sandbox(&mut cmd, Some(&guard), true)
            .expect("sandboxed command should execute");
        assert!(!result.status.success());
        assert_eq!(fs::read_to_string(&protected).unwrap(), "original");

        let mut cmd = Command::new("python3");
        cmd.args([
            "-c",
            "import sys; open(sys.argv[1], 'w').write('allowed')",
            allowed.to_str().unwrap(),
        ]);
        let config = SandboxConfig {
            allow_write: vec![temp.path().to_string_lossy().to_string()],
            deny_write: vec![protected.to_string_lossy().to_string()],
            ..Default::default()
        };
        let guard = apply_python_sandbox(&mut cmd, config).expect("sandbox setup should succeed");
        let result = execute_with_optional_sandbox(&mut cmd, Some(&guard), true)
            .expect("sandboxed command should execute");
        assert!(result.status.success());
        assert_eq!(fs::read_to_string(&allowed).unwrap(), "allowed");
    }

    #[test]
    fn execute_with_optional_sandbox_plain_no_capture_uses_status() {
        let mut cmd = successful_command();
        let result = execute_with_optional_sandbox(&mut cmd, None, false)
            .expect("plain command should execute");
        assert!(result.status.success());
        assert!(result.stdout.is_none());
        assert!(result.stderr.is_none());
        assert!(!result.timed_out);
    }

    #[test]
    fn execute_with_optional_sandbox_plain_capture_returns_output() {
        let mut cmd = output_command("hello");
        let result = execute_with_optional_sandbox(&mut cmd, None, true)
            .expect("plain command should execute");
        assert!(result.status.success());
        assert_eq!(
            String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).trim(),
            "hello"
        );
        assert!(!result.timed_out);
    }

    #[test]
    fn execute_with_optional_sandbox_honors_sandbox_timeout() {
        let mut cmd = long_running_command();
        let config = SandboxConfig {
            timeout_secs: 1,
            ..Default::default()
        };
        let guard = apply_python_sandbox(&mut cmd, config).expect("sandbox setup should succeed");
        let result = execute_with_optional_sandbox(&mut cmd, Some(&guard), true)
            .expect("sandboxed timeout should not error");
        assert!(
            result.timed_out,
            "a 1s-timeout sandbox running `sleep 5` should report timed_out"
        );
        assert_eq!(result.status, timeout_exit_status());
    }

    #[test]
    fn execute_with_optional_sandbox_sandboxed_completion_captures_output() {
        let mut cmd = output_command("from-sandbox");
        let guard = apply_python_sandbox(&mut cmd, SandboxConfig::default())
            .expect("sandbox setup should succeed");
        let result = execute_with_optional_sandbox(&mut cmd, Some(&guard), true)
            .expect("sandboxed command should execute");
        assert!(!result.timed_out);
        assert!(result.status.success());
        assert_eq!(
            String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()).trim(),
            "from-sandbox"
        );
    }

    #[test]
    fn execute_with_optional_sandbox_preserves_io_error_type() {
        let mut cmd = Command::new("pybun-command-that-does-not-exist");
        let result = execute_with_optional_sandbox(&mut cmd, None, false);
        let _: &std::io::Result<SandboxedExecution> = &result;
        match result {
            Ok(_) => panic!("missing executable should fail"),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
        }
    }

    #[test]
    fn apply_python_sandbox_splits_mixed_allow_env_into_allowed_and_rejected() {
        let mut cmd = Command::new("true");
        let config = SandboxConfig {
            allow_env: vec!["MY_FLAG".to_string(), "SECRET_API_KEY".to_string()],
            ..Default::default()
        };
        let guard = apply_python_sandbox(&mut cmd, config).expect("sandbox setup should succeed");
        assert_eq!(guard.allow_env, vec!["MY_FLAG".to_string()]);
        assert_eq!(guard.rejected_env, vec!["SECRET_API_KEY".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn cpu_limit_exceeded_detects_sigxcpu() {
        use std::os::unix::process::ExitStatusExt;
        let killed_by_sigxcpu = ExitStatus::from_raw(libc::SIGXCPU);
        assert!(cpu_limit_exceeded(&killed_by_sigxcpu));
    }

    #[cfg(unix)]
    #[test]
    fn cpu_limit_exceeded_ignores_other_signals_and_normal_exit() {
        use std::os::unix::process::ExitStatusExt;
        let killed_by_sigterm = ExitStatus::from_raw(libc::SIGTERM);
        assert!(!cpu_limit_exceeded(&killed_by_sigterm));

        let exited_zero = ExitStatus::from_raw(0);
        assert!(!cpu_limit_exceeded(&exited_zero));
    }
}
