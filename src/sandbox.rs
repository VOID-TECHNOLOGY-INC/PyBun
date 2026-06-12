use color_eyre::eyre::{Result, eyre};
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Default wall-clock timeout (in seconds) applied to sandboxed runs.
pub const DEFAULT_SANDBOX_TIMEOUT_SECS: u64 = 60;

fn serialize_policy_paths(paths: &[String]) -> Result<String> {
    serde_json::to_string(paths).map_err(|e| eyre!("failed to serialize sandbox policy paths: {e}"))
}

/// Configuration for a sandboxed Python process.
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    /// Whether network access should be allowed inside the sandbox.
    pub allow_network: bool,
    /// Paths allowed for reading. Empty = no read restriction.
    pub allow_read: Vec<String>,
    /// Paths allowed for writing. Empty = no write restriction (default deny applies).
    pub allow_write: Vec<String>,
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
    enforcement: &'static str,
    audit_file: PathBuf,
    /// Default system-critical paths denied for writes (empty when explicit allow_write is set).
    pub default_deny_write: Vec<String>,
    /// Extra env var names allowed through the filter beyond the default safe set.
    pub allow_env: Vec<String>,
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
    let tempdir = tempfile::tempdir()?;
    let audit_file = tempdir.path().join("pybun_audit.json");

    let sitecustomize_path: PathBuf = tempdir.path().join("sitecustomize.py");
    fs::write(&sitecustomize_path, SITECUSTOMIZE_PY)
        .map_err(|e| eyre!("failed to write sandbox shim: {e}"))?;

    // --- Environment variable filtering ---
    // Clear all inherited env vars so the sandbox child doesn't inherit secrets.
    // env_clear() only affects the *child* process env; std::env::var() below still
    // reads from the *parent* process environment — this is intentional.
    cmd.env_clear();

    // Re-add the default safe set plus any caller-specified names.
    // Use a HashSet to avoid duplicate cmd.env() calls when a name appears in both
    // the default set and allow_env (harmless but wasteful).
    let safe_names: std::collections::HashSet<String> = default_safe_env_vars()
        .iter()
        .map(|&s| s.to_string())
        .chain(config.allow_env.iter().cloned())
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

    // Note: std::env::var reads from the *parent process* environment, not from `cmd`.
    // env_clear() above only strips the *child's* inherited env, so reading
    // PYBUN_SANDBOX_ALLOW_NETWORK here correctly reflects the caller's intent.
    let allow_network = config.allow_network
        || std::env::var("PYBUN_SANDBOX_ALLOW_NETWORK")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

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
    if config.memory_limit_mb > 0 && !memory_limit_supported() {
        unsupported.push("memory".to_string());
    }
    if config.cpu_limit_secs > 0 && !cpu_limit_supported() {
        unsupported.push("cpu".to_string());
    }

    #[cfg(unix)]
    {
        let apply_memory = config.memory_limit_mb > 0 && memory_limit_supported();
        let apply_cpu = config.cpu_limit_secs > 0 && cpu_limit_supported();
        let memory_limit_mb = config.memory_limit_mb;
        let cpu_limit_secs = config.cpu_limit_secs;
        if apply_memory || apply_cpu {
            // SAFETY: the closure only calls async-signal-safe libc functions
            // (`setrlimit`) between fork and exec, as required by `pre_exec`.
            unsafe {
                cmd.pre_exec(move || {
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
                        let limit = libc::rlimit {
                            rlim_cur: cpu_limit_secs as libc::rlim_t,
                            rlim_max: cpu_limit_secs as libc::rlim_t,
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
        unsupported,
    };

    Ok(SandboxGuard {
        _tempdir: tempdir,
        enforcement: "python-sitecustomize",
        audit_file,
        default_deny_write: default_deny,
        allow_env: config.allow_env,
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

/// Run `cmd` to completion, optionally capturing stdout/stderr, killing it if it
/// exceeds `timeout_secs` (0 = unlimited). Mirrors
/// `test_executor::run_with_timeout`'s spawn/poll/kill pattern so a chatty
/// process can't deadlock on a full pipe buffer while we wait for exit.
pub fn execute_sandboxed(
    cmd: &mut Command,
    timeout_secs: u64,
    capture: bool,
) -> std::io::Result<SandboxExecOutcome> {
    if capture {
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
    }

    let mut child = cmd.spawn()?;

    let stdout_handle = child.stdout.take().map(spawn_pipe_reader);
    let stderr_handle = child.stderr.take().map(spawn_pipe_reader);

    let timeout = (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs));
    let poll_interval = Duration::from_millis(50);
    let start = Instant::now();

    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }

        if let Some(timeout) = timeout
            && start.elapsed() >= timeout
        {
            let _ = child.kill();
            let _ = child.wait();
            join_pipe_reader(stdout_handle);
            join_pipe_reader(stderr_handle);
            return Ok(SandboxExecOutcome::TimedOut);
        }

        thread::sleep(poll_interval);
    };

    let stdout = join_pipe_reader(stdout_handle);
    let stderr = join_pipe_reader(stderr_handle);

    Ok(SandboxExecOutcome::Completed {
        status,
        stdout,
        stderr,
    })
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

/// Spawn a thread that reads a child process pipe to completion.
fn spawn_pipe_reader<R>(mut reader: R) -> thread::JoinHandle<Vec<u8>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        buf
    })
}

/// Join a pipe reader thread, discarding the handle. Returns `None` if there
/// was no pipe to read or the thread panicked.
fn join_pipe_reader(handle: Option<thread::JoinHandle<Vec<u8>>>) -> Option<Vec<u8>> {
    handle.and_then(|h| h.join().ok())
}

/// The sitecustomize.py injected into every sandboxed Python process.
///
/// All configuration is read from environment variables so this can be a
/// static string with no Rust format-macro escaping issues.
const SITECUSTOMIZE_PY: &str = r#"
import os
import sys
import json
import atexit
import socket
import subprocess
import builtins

_orig_open = builtins.open  # save before any patching

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
    return os.path.realpath(os.path.abspath(path))


def _path_within(path, allowed_root):
    try:
        return os.path.commonpath([path, allowed_root]) == allowed_root
    except ValueError:
        return False


_ALLOW_READ = [_normalize_path(p) for p in _load_policy_paths("PYBUN_SANDBOX_ALLOW_READ")]
_ALLOW_WRITE = [_normalize_path(p) for p in _load_policy_paths("PYBUN_SANDBOX_ALLOW_WRITE")]
_DEFAULT_DENY_WRITE = [_normalize_path(p) for p in _load_policy_paths("PYBUN_SANDBOX_DEFAULT_DENY_WRITE")]
_HAS_READ_POLICY = bool(_ALLOW_READ)
_HAS_WRITE_POLICY = bool(_ALLOW_WRITE)
_HAS_DEFAULT_DENY_WRITE = bool(_DEFAULT_DENY_WRITE)

# Sys prefixes are always readable so Python imports keep working.
_SYS_PREFIXES = []
for _attr in ("prefix", "exec_prefix", "base_prefix"):
    _v = getattr(sys, _attr, None)
    if _v:
        _SYS_PREFIXES.append(_normalize_path(_v))
if hasattr(sys, "real_prefix"):
    _SYS_PREFIXES.append(_normalize_path(sys.real_prefix))

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


def _is_allowed(path, allowed_paths):
    """Return True if path is under any of the allowed directories or sys prefixes."""
    try:
        normalized_path = _normalize_path(os.fsdecode(os.fspath(path)))
        if any(_path_within(normalized_path, p) for p in _ALWAYS_ALLOW_READ):
            return True
        return any(_path_within(normalized_path, p) for p in allowed_paths)
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
        _deny("process creation", "blocked_subprocesses")

    subprocess.Popen = _blocked
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
            setattr(os, _name, lambda *_a, **_kw: _deny("process creation", "blocked_subprocesses"))


def _block_network():
    def _blocked(*_a, **_kw):
        _deny("network access", "blocked_network")

    socket.socket = _blocked
    socket.create_connection = _blocked
    if hasattr(socket, "socketpair"):
        socket.socketpair = _blocked


def _patch_filesystem():
    def _checked_open(file, mode="r", *args, **kwargs):
        # File objects (e.g. from io) pass through unchanged.
        if not isinstance(file, (str, bytes, os.PathLike)):
            return _orig_open(file, mode, *args, **kwargs)
        path = os.fsdecode(os.fspath(file))
        if not path:
            return _orig_open(file, mode, *args, **kwargs)
        if _HAS_READ_POLICY and _mode_needs_read(mode):
            if not _is_allowed(path, _ALLOW_READ):
                _deny("read from " + path, "blocked_file_reads")
        if _HAS_WRITE_POLICY and _mode_needs_write(mode):
            if not _is_allowed(path, _ALLOW_WRITE):
                _deny("write to " + path, "blocked_file_writes")
        elif _HAS_DEFAULT_DENY_WRITE and _mode_needs_write(mode):
            if _is_in_denied(path, _DEFAULT_DENY_WRITE):
                _deny("write to " + path, "blocked_file_writes")
        return _orig_open(file, mode, *args, **kwargs)

    builtins.open = _checked_open


def _write_audit():
    if _AUDIT_FILE:
        try:
            with _orig_open(_AUDIT_FILE, "w") as _f:
                _f.write(json.dumps(_audit))
        except Exception:
            pass


try:
    atexit.register(_write_audit)
    _block_subprocesses()
    if not ALLOW_NETWORK:
        _block_network()
    if _HAS_READ_POLICY or _HAS_WRITE_POLICY or _HAS_DEFAULT_DENY_WRITE:
        _patch_filesystem()
    sys.stderr.write(
        "[pybun] sandbox active (allow_network={}, read_policy={}, write_policy={}, default_deny_write={})\n".format(
            ALLOW_NETWORK, _HAS_READ_POLICY, _HAS_WRITE_POLICY, _HAS_DEFAULT_DENY_WRITE
        )
    )
except Exception as exc:  # pragma: no cover - defensive, should not happen
    sys.stderr.write("[pybun] sandbox init failed: {}\n".format(exc))
    raise
"#;

#[cfg(test)]
mod tests {
    use super::*;

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
}
