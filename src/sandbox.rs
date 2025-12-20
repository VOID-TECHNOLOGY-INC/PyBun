use color_eyre::eyre::{Result, eyre};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Configuration for a sandboxed Python process.
#[derive(Debug, Clone, Copy)]
pub struct SandboxConfig {
    /// Whether network access should be allowed inside the sandbox.
    pub allow_network: bool,
}

/// Guard that keeps sandbox assets (sitecustomize) alive for the child process.
#[derive(Debug)]
pub struct SandboxGuard {
    _tempdir: TempDir,
    enforcement: &'static str,
}

impl SandboxGuard {
    /// Name of the sandbox enforcement strategy used.
    pub fn enforcement(&self) -> &str {
        self.enforcement
    }
}

/// Apply a lightweight sandbox to a Python command by injecting a `sitecustomize`
/// module that blocks subprocess creation and (optionally) network sockets.
pub fn apply_python_sandbox(cmd: &mut Command, config: SandboxConfig) -> Result<SandboxGuard> {
    let tempdir = tempfile::tempdir()?;
    let sitecustomize_path: PathBuf = tempdir.path().join("sitecustomize.py");
    fs::write(&sitecustomize_path, sitecustomize_contents())
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

    Ok(SandboxGuard {
        _tempdir: tempdir,
        enforcement: "python-sitecustomize",
    })
}

fn sitecustomize_contents() -> &'static str {
    r#"
import os
import socket
import subprocess
import sys

ALLOW_NETWORK = os.environ.get("PYBUN_SANDBOX_ALLOW_NETWORK") == "1"

def _deny(reason: str):
    raise PermissionError(f"pybun sandbox: {reason} blocked")

def _block_subprocesses():
    def _blocked(*_args, **_kwargs):
        _deny("process creation")

    subprocess.Popen = _blocked
    subprocess.call = _blocked
    subprocess.run = _blocked
    subprocess.check_call = _blocked
    subprocess.check_output = _blocked
    os.system = _blocked

    if hasattr(os, "fork"):
        os.fork = lambda *_a, **_kw: _deny("fork")

    for name in ("execv", "execve", "execl", "execlp", "execvp", "execvpe", "execle"):
        if hasattr(os, name):
            setattr(os, name, lambda *_a, **_kw: _deny("process execution"))

def _block_network():
    def _blocked(*_args, **_kwargs):
        _deny("network access")

    socket.socket = _blocked
    socket.create_connection = _blocked
    if hasattr(socket, "socketpair"):
        socket.socketpair = _blocked

try:
    _block_subprocesses()
    if not ALLOW_NETWORK:
        _block_network()
    sys.stderr.write(f"[pybun] sandbox active (allow_network={ALLOW_NETWORK})\n")
except Exception as exc:  # pragma: no cover - defensive, should not happen
    sys.stderr.write(f"[pybun] sandbox init failed: {exc}\n")
    raise
"#
}
