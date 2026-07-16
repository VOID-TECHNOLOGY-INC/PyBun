//! Regression test for Issue #294: `pybun run`'s native (non-uv) PEP 723
//! installer selected wheels using the PATH-detected CPython tag instead of
//! the *target venv's* already-known Python version (same root cause as
//! Issue #291, fixed for `pybun install` in #292).
//!
//! ## Why this test calls `pybun::commands::execute()` in-process instead of
//! spawning the compiled binary
//!
//! `pybun run` is deliberately excluded from `entry::requires_tokio_runtime`
//! (see `src/entry.rs`), so `pybun`'s `main()` dispatches plain `run` via
//! `futures::executor::block_on`, which provides no Tokio reactor. The native
//! PEP 723 installer branch exercised here performs real async I/O
//! (`PyPiClient` / `reqwest` / `tokio::task::spawn_blocking`) and panics with
//! "there is no reactor running" if invoked without an active Tokio runtime —
//! this is a separate, pre-existing limitation of the compiled CLI entry
//! point, not something introduced by or in scope for Issue #294. Calling
//! `execute()` directly under `#[tokio::test]` gives the exact same
//! `run_script` code under test a real reactor, which is representative of
//! how it *is* reachable in-process (e.g. from a Tokio-hosted caller).
//!
//! ## Why the test re-executes its own test binary as a child process
//!
//! The `run_script` path under test reads its configuration from ambient
//! environment variables (`PYBUN_ENV`, `PATH`, `PYBUN_PEP723_BACKEND`,
//! `PYBUN_PYPI_BASE_URL`, `PYBUN_PYPI_CACHE_DIR`, `PYBUN_HOME`). Mutating
//! those with `std::env::set_var` in the test process is a latent race with
//! any other test thread in the same binary (Issue #349) — Rust 2024 made
//! `set_var` unsafe for exactly this reason. Instead, the outer test spawns
//! the current test binary again, selecting the `#[ignore]`d child test
//! below, and passes the environment overrides per-child via
//! `Command::env(...)`, which is race-free. The child runs `execute()`
//! in-process under `#[tokio::test]` and never mutates any environment; the
//! outer test owns the mock PyPI server and asserts on which wheels were
//! downloaded after the child exits.

use httpmock::prelude::*;
use pybun::cli::{Cli, Commands, OutputFormat, ProgressMode, RunArgs};
use pybun::commands::execute;
use pybun::sandbox::DEFAULT_SANDBOX_TIMEOUT_SECS;
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

/// Minimal but valid (openable-as-zip) wheel body — content doesn't matter,
/// only that `installer::install_wheel` can extract it as a zip archive.
fn fake_wheel_bytes() -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    zip.start_file("dummy.txt", options)
        .expect("start wheel entry");
    use std::io::Write;
    zip.write_all(b"ok").expect("write wheel entry");
    zip.finish().expect("finish wheel zip").into_inner()
}

/// Query the real `python3` (or `python`) resolved on PATH so the test can
/// pick a "fake" venv version that is guaranteed to differ from it —
/// otherwise a coincidental match would make the regression test a false
/// pass.
fn real_path_python_version() -> String {
    for candidate in ["python3", "python"] {
        if let Ok(output) = std::process::Command::new(candidate)
            .arg("--version")
            .output()
            && output.status.success()
        {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if let Some(v) = text.strip_prefix("Python ") {
                return v.to_string();
            }
        }
    }
    "3.11.0".to_string()
}

/// Check whether `dir` contains an executable file named `name`.
fn which_executable_in_dir(dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
    let candidate = dir.join(name);
    let metadata = fs::metadata(&candidate).ok()?;
    if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
        Some(candidate)
    } else {
        None
    }
}

/// Create a fake venv whose `bin/python` reports a controlled `--version`
/// output (independent of the real PATH python), but forwards every other
/// invocation (notably `-m venv ...`) to the real `python3` so PyBun's cache
/// venv creation still works.
fn fake_venv_reporting_version(root: &std::path::Path, version_line: &str) -> std::path::PathBuf {
    let venv_dir = root.join(".fake-venv");
    let bin_dir = venv_dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let python = bin_dir.join("python");
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo '{version_line}'\n  exit 0\nfi\nexec python3 \"$@\"\n"
    );
    fs::write(&python, script).unwrap();
    let mut perms = fs::metadata(&python).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&python, perms).unwrap();

    fs::write(venv_dir.join("pyvenv.cfg"), "version = 3.99.0\n").unwrap();

    venv_dir
}

/// Name of the env var the outer test uses to hand the PEP 723 script path
/// to the child test process. Its presence also marks "running as the
/// spawned child" — the child test skips itself when invoked any other way
/// (e.g. a manual `cargo test -- --ignored`).
const CHILD_SCRIPT_ENV: &str = "PYBUN_TEST_CP_TAG_SCRIPT";

/// Child half of the regression test: runs `pybun run` in-process against
/// the environment prepared by the outer test. Never mutates process env —
/// everything it needs was injected per-child by `Command::env(...)`.
#[tokio::test]
#[ignore = "child process half of run_pep723_native_installer_selects_wheel_for_target_venv_python_not_path_python; not meaningful standalone"]
async fn run_pep723_native_cp_tag_child() {
    let Ok(script) = std::env::var(CHILD_SCRIPT_ENV) else {
        eprintln!("skipping: {CHILD_SCRIPT_ENV} not set (only runs as a spawned child test)");
        return;
    };

    let cli = Cli {
        format: OutputFormat::Json,
        progress: ProgressMode::Never,
        no_progress: true,
        command: Commands::Run(RunArgs {
            target: Some(script),
            code: None,
            sandbox: false,
            allow_network: false,
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            allow_env: Vec::new(),
            sandbox_timeout: DEFAULT_SANDBOX_TIMEOUT_SECS,
            sandbox_memory: 0,
            sandbox_cpu: 0,
            profile: "dev".to_string(),
            passthrough: Vec::new(),
        }),
    };

    let result = execute(cli).await;

    assert!(
        result.is_ok(),
        "pybun run (native PEP 723 installer) failed: {:?}",
        result.err()
    );
}

#[test]
fn run_pep723_native_installer_selects_wheel_for_target_venv_python_not_path_python() {
    // Pick a fake target-venv Python version guaranteed to differ from
    // whatever python3/python resolves on PATH in this test environment.
    let real_version = real_path_python_version();
    let real_minor: u32 = real_version
        .split('.')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(11);
    let fake_minor = if real_minor == 12 { 13 } else { 12 };
    let fake_version_line = format!("Python 3.{fake_minor}.0");
    let fake_cp_tag = format!("cp3{fake_minor}");
    let real_cp_tag = format!("cp3{real_minor}");

    let temp = tempdir().unwrap();
    let venv = fake_venv_reporting_version(temp.path(), &fake_version_line);

    // Isolated cache roots so this test doesn't touch (or race with) any real
    // PyBun cache/config on the host, and so it always starts from a clean
    // (cache-miss) state.
    let pybun_home = tempdir().unwrap();
    let pypi_cache = tempdir().unwrap();

    // The native PEP 723 installer path (which contains the Issue #294 bug)
    // is only reached when `uv` is unavailable — otherwise the uv-based
    // installer is preferred instead. Strip any directory containing a `uv`
    // executable from PATH so this test deterministically exercises the
    // native installer regardless of whether uv happens to be installed on
    // the host running the test.
    let filtered_path = std::env::var_os("PATH")
        .map(|path| {
            let dirs: Vec<_> = std::env::split_paths(&path)
                .filter(|dir| which_executable_in_dir(dir, "uv").is_none())
                .collect();
            std::env::join_paths(dirs).expect("join filtered PATH")
        })
        .unwrap_or_default();

    let server = MockServer::start();
    let base = server.base_url();

    let wheel_body = fake_wheel_bytes();
    let real_wheel_filename = format!("cptagpkg-1.0.0-{real_cp_tag}-{real_cp_tag}-any.whl");
    let fake_wheel_filename = format!("cptagpkg-1.0.0-{fake_cp_tag}-{fake_cp_tag}-any.whl");

    let project_body = json!({
        "info": { "name": "cptagpkg", "version": "1.0.0" },
        "releases": {
            "1.0.0": [
                {
                    "filename": real_wheel_filename,
                    "packagetype": "bdist_wheel",
                    "url": format!("{base}/files/{real_wheel_filename}"),
                    "yanked": false,
                    "digests": { "sha256": "0".repeat(64) }
                },
                {
                    "filename": fake_wheel_filename,
                    "packagetype": "bdist_wheel",
                    "url": format!("{base}/files/{fake_wheel_filename}"),
                    "yanked": false,
                    "digests": { "sha256": "1".repeat(64) }
                }
            ]
        }
    })
    .to_string();

    server.mock(|when, then| {
        when.method(GET).path("/pypi/cptagpkg/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(&project_body);
    });

    let meta_body = json!({
        "info": { "name": "cptagpkg", "version": "1.0.0", "requires_dist": [] }
    })
    .to_string();
    server.mock(|when, then| {
        when.method(GET).path("/pypi/cptagpkg/1.0.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(&meta_body);
    });

    let real_wheel_mock = server.mock(|when, then| {
        when.method(GET)
            .path(format!("/files/{real_wheel_filename}"));
        then.status(200)
            .header("Content-Type", "application/octet-stream")
            .body(wheel_body.clone());
    });
    let fake_wheel_mock = server.mock(|when, then| {
        when.method(GET)
            .path(format!("/files/{fake_wheel_filename}"));
        then.status(200)
            .header("Content-Type", "application/octet-stream")
            .body(wheel_body.clone());
    });

    let script = temp.path().join("cp_tag_mismatch.py");
    let content = r#"# /// script
# dependencies = ["cptagpkg==1.0.0"]
# ///
print("hello")
"#;
    fs::write(&script, content).unwrap();

    // Re-execute this test binary, selecting only the `#[ignore]`d child
    // test above, with all environment overrides applied per-child via
    // `Command::env(...)`. Child-process env is isolated, so no other test
    // thread in this process can ever observe these values (Issue #349).
    let exe = std::env::current_exe().expect("locate current test binary");
    let output = std::process::Command::new(exe)
        .args([
            "run_pep723_native_cp_tag_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PATH", &filtered_path)
        .env("PYBUN_ENV", &venv)
        .env_remove("PYBUN_FORCE_CP_TAG")
        .env("PYBUN_PEP723_BACKEND", "pybun")
        .env("PYBUN_PYPI_BASE_URL", &base)
        .env("PYBUN_PYPI_CACHE_DIR", pypi_cache.path())
        .env("PYBUN_HOME", pybun_home.path())
        .env(CHILD_SCRIPT_ENV, &script)
        .output()
        .expect("spawn child test process");

    assert!(
        output.status.success(),
        "child test process failed (status {:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Regression check for Issue #294: the wheel matching the *target venv's*
    // Python (fake_cp_tag) must be downloaded — not the wheel matching
    // whatever python3/python resolves on PATH (real_cp_tag).
    assert_eq!(
        fake_wheel_mock.calls(),
        1,
        "expected the wheel matching the target venv's Python ({fake_cp_tag}) to be \
         downloaded exactly once"
    );
    assert_eq!(
        real_wheel_mock.calls(),
        0,
        "the wheel matching PATH's python ({real_cp_tag}) must NOT be downloaded — this \
         indicates the native PEP 723 installer ignored the already-known target venv \
         Python version and re-detected via PATH instead"
    );
}
