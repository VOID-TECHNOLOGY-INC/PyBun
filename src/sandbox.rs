use color_eyre::eyre::{Result, eyre};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Configuration for a sandboxed Python process.
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    /// Whether network access should be allowed inside the sandbox.
    pub allow_network: bool,
    /// Paths allowed for reading. Empty = no read restriction.
    pub allow_read: Vec<String>,
    /// Paths allowed for writing. Empty = no write restriction.
    pub allow_write: Vec<String>,
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

    // Ensure our tempdir is first on PYTHONPATH so sitecustomize is picked up.
    let mut paths = vec![tempdir.path().to_path_buf()];
    if let Ok(existing) = std::env::var("PYTHONPATH") {
        paths.extend(std::env::split_paths(&existing));
    }
    let joined = std::env::join_paths(paths)
        .map_err(|e| eyre!("failed to join PYTHONPATH entries for sandbox: {e}"))?;
    cmd.env("PYTHONPATH", joined);

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

    // Pass filesystem policies as colon-separated path lists.
    cmd.env("PYBUN_SANDBOX_ALLOW_READ", config.allow_read.join(":"));
    cmd.env("PYBUN_SANDBOX_ALLOW_WRITE", config.allow_write.join(":"));

    // Tell the sitecustomize where to write the audit JSON.
    cmd.env("PYBUN_SANDBOX_AUDIT_FILE", audit_file.as_os_str());

    Ok(SandboxGuard {
        _tempdir: tempdir,
        enforcement: "python-sitecustomize",
        audit_file,
    })
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
_ALLOW_READ_RAW = os.environ.get("PYBUN_SANDBOX_ALLOW_READ", "")
_ALLOW_WRITE_RAW = os.environ.get("PYBUN_SANDBOX_ALLOW_WRITE", "")
_AUDIT_FILE = os.environ.get("PYBUN_SANDBOX_AUDIT_FILE", "")

_ALLOW_READ = [p for p in _ALLOW_READ_RAW.split(":") if p]
_ALLOW_WRITE = [p for p in _ALLOW_WRITE_RAW.split(":") if p]
_HAS_READ_POLICY = bool(_ALLOW_READ)
_HAS_WRITE_POLICY = bool(_ALLOW_WRITE)

# Sys prefixes are always readable so Python imports keep working.
_SYS_PREFIXES = []
for _attr in ("prefix", "exec_prefix", "base_prefix"):
    _v = getattr(sys, _attr, None)
    if _v:
        _SYS_PREFIXES.append(os.path.abspath(_v))
if hasattr(sys, "real_prefix"):
    _SYS_PREFIXES.append(os.path.abspath(sys.real_prefix))

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
        abs_path = os.path.abspath(str(path))
        # Python internals are always allowed.
        if any(abs_path.startswith(p) for p in _SYS_PREFIXES):
            return True
        # PYTHONPATH entries are always allowed (needed for sitecustomize dir itself).
        for pp in os.environ.get("PYTHONPATH", "").split(":"):
            if pp and abs_path.startswith(os.path.abspath(pp)):
                return True
        return any(abs_path.startswith(os.path.abspath(p)) for p in allowed_paths)
    except Exception:
        return True  # don't block on path resolution errors


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
        path = str(file)
        is_write = any(c in mode for c in "wxa+")
        if is_write and _HAS_WRITE_POLICY:
            if not _is_allowed(path, _ALLOW_WRITE):
                _deny("write to " + path, "blocked_file_writes")
        elif not is_write and _HAS_READ_POLICY:
            if not _is_allowed(path, _ALLOW_READ):
                _deny("read from " + path, "blocked_file_reads")
        return _orig_open(file, mode, *args, **kwargs)

    builtins.open = _checked_open


def _write_audit():
    if _AUDIT_FILE:
        try:
            _orig_open(_AUDIT_FILE, "w").write(json.dumps(_audit))
        except Exception:
            pass


try:
    atexit.register(_write_audit)
    _block_subprocesses()
    if not ALLOW_NETWORK:
        _block_network()
    if _HAS_READ_POLICY or _HAS_WRITE_POLICY:
        _patch_filesystem()
    sys.stderr.write(
        "[pybun] sandbox active (allow_network={}, read_policy={}, write_policy={})\n".format(
            ALLOW_NETWORK, _HAS_READ_POLICY, _HAS_WRITE_POLICY
        )
    )
except Exception as exc:  # pragma: no cover - defensive, should not happen
    sys.stderr.write("[pybun] sandbox init failed: {}\n".format(exc))
    raise
"#;
