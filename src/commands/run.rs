use super::install::{self, RunProfileInfo, ScriptLockInfo};
use super::{
    RunOutcome, emit_rejected_allow_env_diagnostics, emit_unsupported_resource_limit_diagnostics,
    python_version_env_override,
};
use crate::cache::Cache;
use crate::cli::OutputFormat;
use crate::env::{EnvSource, find_python_env};
use crate::installer;
use crate::lockfile::Lockfile;
use crate::pep723;
use crate::pep723_cache::{Pep723Cache, Pep723CacheKey};
use crate::project::Project;
use crate::pypi::{PyPiClient, PyPiIndex};
use crate::resolver::{
    Requirement, ResolveOptions, cp_tag_to_dotted_version, is_wheel_python_compatible,
    parse_wheel_tags, python_version_to_cp_tag, resolve_with_options,
};
use crate::sandbox;
use crate::schema::{Diagnostic, EventCollector};
use crate::wheel_cache::WheelCache;
use color_eyre::eyre::{Result, eyre};
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

#[derive(Debug, Clone)]
pub(crate) struct SandboxInfo {
    pub(crate) enabled: bool,
    pub(crate) allow_network: bool,
    pub(crate) allow_read: Vec<String>,
    pub(crate) allow_write: Vec<String>,
    /// Env var *names* (never values) that were explicitly allowed through the env filter.
    pub(crate) allow_env: Vec<String>,
    pub(crate) default_deny_write: Vec<String>,
    pub(crate) enforcement: String,
    pub(crate) audit: Option<sandbox::SandboxAudit>,
    pub(crate) resource_limits: sandbox::ResourceLimits,
    pub(crate) timed_out: bool,
}

#[derive(Debug)]
enum RunProgram {
    Python(String),
    Uv { uv_path: PathBuf },
}

pub(crate) fn script_lock_path(script_path: &Path) -> PathBuf {
    let mut lock_path = script_path.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

/// Load and parse the binary script lockfile (`<script>.lock`) next to `script_path`.
///
/// Returns `Ok(None)` when the lockfile is missing **or** unreadable/corrupt.
/// A `<script>.lock` that fails to decode (e.g. truncated by a crash mid-write)
/// is treated the same as a missing lockfile rather than propagated as a fatal
/// error - this mirrors the self-heal behavior already applied to the MCP
/// doctor lockfile check (`src/mcp.rs`) and the PEP 723 script cache for issue
/// #299 (itself a recurrence of #262's failure mode). Callers observe a plain
/// "no lock" result and fall through to the existing regenerate-from-scratch
/// path (PEP 723 declared dependencies), which recreates the lockfile.
fn load_script_lock(script_path: &Path) -> Result<Option<ScriptLockInfo>> {
    let lock_path = script_lock_path(script_path);
    if !lock_path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(&lock_path)
        .map_err(|e| eyre!("failed to read script lock {}: {}", lock_path.display(), e))?;
    match Lockfile::from_bytes(&bytes) {
        Ok(lock) => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let digest = hasher.finalize();
            let lock_hash = hex::encode(&digest[..16]);
            Ok(Some(ScriptLockInfo { lock, lock_hash }))
        }
        Err(e) => {
            eprintln!(
                "info: discarded unreadable script lockfile at {} ({}); regenerating",
                lock_path.display(),
                e
            );
            Ok(None)
        }
    }
}

fn pep723_index_settings(metadata: Option<&pep723::ScriptMetadata>) -> Vec<String> {
    let mut settings = Vec::new();
    if let Some(metadata) = metadata {
        settings.extend(metadata.index_urls());
    }
    if let Ok(url) = std::env::var("PIP_INDEX_URL") {
        settings.extend(split_env_list(&url));
    }
    if let Ok(extra) = std::env::var("PIP_EXTRA_INDEX_URL") {
        settings.extend(split_env_list(&extra));
    }
    if let Ok(url) = std::env::var("UV_INDEX_URL") {
        settings.extend(split_env_list(&url));
    }
    if let Ok(extra) = std::env::var("UV_EXTRA_INDEX_URL") {
        settings.extend(split_env_list(&extra));
    }
    settings
}

fn split_env_list(raw: &str) -> Vec<String> {
    raw.split(|c: char| c.is_whitespace() || c == ',')
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect()
}

const MAX_RUN_STDIO_CAPTURE_BYTES: usize = 64 * 1024;

fn capture_stdio(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let truncated = bytes.len() > MAX_RUN_STDIO_CAPTURE_BYTES;
    let slice = if truncated {
        &bytes[..MAX_RUN_STDIO_CAPTURE_BYTES]
    } else {
        bytes
    };
    let mut out = String::from_utf8_lossy(slice).to_string();
    if truncated {
        out.push_str("\n...[truncated]");
    }
    Some(out)
}

pub(crate) async fn run_script(
    args: &crate::cli::RunArgs,
    collector: &mut EventCollector,
    format: OutputFormat,
) -> Result<RunOutcome> {
    use crate::profiles::{Profile, ProfileConfig};

    let profile: Profile = args
        .profile
        .parse()
        .map_err(|e: String| eyre!("invalid --profile value: {}", e))?;
    let profile_config = ProfileConfig::for_profile(profile);

    // -c/--code: execute inline Python code, like `python -c "..."`.
    if let Some(code) = &args.code {
        return run_python_code(args, code, collector, format);
    }

    let target = args
        .target
        .as_ref()
        .ok_or_else(|| eyre!("script target is required (e.g., pybun run script.py)"))?;

    // Check if it's a Python file
    let script_path = PathBuf::from(target);

    // Ensure the script exists
    if !script_path.exists() {
        return Err(eyre!("script not found: {}", script_path.display()));
    }

    // Check for PEP 723 metadata
    let pep723_metadata = match pep723::parse_script_metadata(&script_path) {
        Ok(metadata) => metadata,
        Err(e) => {
            // Log warning but continue
            eprintln!("warning: failed to parse PEP 723 metadata: {}", e);
            None
        }
    };

    let pep723_deps = pep723_metadata
        .as_ref()
        .map(|m| m.dependencies.clone())
        .unwrap_or_default();

    let script_lock = load_script_lock(&script_path)?;
    let (install_deps, lock_hash) = if let Some(lock_info) = &script_lock {
        let mut locked = lock_info
            .lock
            .packages
            .values()
            .map(|pkg| format!("{}=={}", pkg.name, pkg.version))
            .collect::<Vec<_>>();
        if locked.is_empty() {
            locked = pep723_deps.clone();
        }
        (locked, Some(lock_info.lock_hash.clone()))
    } else {
        (pep723_deps.clone(), None)
    };

    let has_pep723_deps = !install_deps.is_empty();

    // Shared wheel cache directory for PEP 723 installs (align with uv cache use).
    let wheel_cache_dir = if !has_pep723_deps {
        None
    } else {
        let cache = Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
        let dir = cache.packages_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| eyre!("failed to create wheel cache dir {}: {}", dir.display(), e))?;
        Some(dir)
    };

    // Check for dry-run mode (for testing)
    let dry_run = std::env::var("PYBUN_PEP723_DRY_RUN").is_ok();
    // Check for no-cache mode (force fresh venv)
    let no_cache = std::env::var("PYBUN_PEP723_NO_CACHE").is_ok();
    let pep723_backend_setting =
        std::env::var("PYBUN_PEP723_BACKEND").unwrap_or_else(|_| "auto".to_string());
    let pep723_backend_setting = pep723_backend_setting.trim().to_ascii_lowercase();

    let mut pep723_backend = "system".to_string();
    let mut temp_env_dir: Option<tempfile::TempDir> = None;

    // If there are PEP 723 dependencies, use cached or create environment
    let (runner, cached_env_path, cache_hit) = if has_pep723_deps {
        collector.info(format!(
            "PEP 723 script with {} dependencies",
            install_deps.len()
        ));

        match pep723_backend_setting.as_str() {
            "auto" | "pybun" | "uv" => {}
            other => {
                return Err(eyre!(
                    "invalid PYBUN_PEP723_BACKEND value: {other} (expected auto|pybun|uv)"
                ));
            }
        }

        // When a PyBun binary lockfile exists next to the script, bypass uv entirely.
        // uv would detect the .lock file, attempt to parse it as TOML, and crash
        // because the file uses PyBun's binary format (Issue #234).
        if pep723_backend_setting == "uv" && script_lock.is_some() {
            eprintln!(
                "warning: PYBUN_PEP723_BACKEND=uv is set but a PyBun script lockfile exists; \
                 uv cannot parse the binary .lock file — falling back to the pybun backend"
            );
        }
        if !dry_run
            && !no_cache
            && !args.sandbox
            && pep723_backend_setting != "pybun"
            && script_lock.is_none()
        {
            if let Some(uv_path) = crate::env::find_uv_executable() {
                pep723_backend = "uv_run".to_string();

                // `uv run --script` manages its own venv/wheel cache internally, so PyBun
                // has no direct signal for whether this invocation was served from cache.
                // Mirror the same cache-key semantics used by the native "pybun" backend
                // (script path + dependency set + Python version + index settings + lock
                // hash) to detect a repeat ("warm") invocation of this exact script, so
                // `--format=json` can report `cache_hit` accurately instead of always
                // reporting `false` (Issue #267).
                let pep_cache =
                    Pep723Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
                let (base_python, _env_source) = find_python_interpreter()?;
                let python_version = get_python_version(Path::new(&base_python))?;
                let index_settings = pep723_index_settings(pep723_metadata.as_ref());
                let cache_key = Pep723CacheKey::new(
                    &install_deps,
                    &python_version,
                    &index_settings,
                    lock_hash.as_deref(),
                );
                let env_root = pep_cache
                    .script_env_root(&script_path)
                    .map_err(|e| eyre!("failed to resolve script env root: {}", e))?;
                let _env_lock = pep_cache
                    .lock_script_env(&env_root)
                    .map_err(|e| eyre!("failed to lock script env: {}", e))?;

                let uv_cache_hit = pep_cache
                    .read_cache_entry(&env_root)
                    .map_err(|e| eyre!("failed to read cache entry: {}", e))?
                    .map(|info| Pep723Cache::cache_entry_matches_key(&info, &cache_key))
                    .unwrap_or(false);

                pep_cache
                    .record_cache_entry_at(&env_root, &cache_key)
                    .map_err(|e| eyre!("failed to record cache entry: {}", e))?;

                if uv_cache_hit {
                    collector.info(format!(
                        "Cache hit: reusing uv-managed environment (hash: {})",
                        &cache_key.hash[..8]
                    ));
                }

                (RunProgram::Uv { uv_path }, None, uv_cache_hit)
            } else if pep723_backend_setting == "uv" {
                return Err(eyre!(
                    "PYBUN_PEP723_BACKEND=uv requires `uv` to be available in PATH"
                ));
            } else {
                pep723_backend = "pybun".to_string();
                // Continue with the built-in runner below.
                let pep_cache =
                    Pep723Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
                let (base_python, env_source) = find_python_interpreter()?;
                let python_version = get_python_version(Path::new(&base_python))?;
                let index_settings = pep723_index_settings(pep723_metadata.as_ref());
                let cache_key = Pep723CacheKey::new(
                    &install_deps,
                    &python_version,
                    &index_settings,
                    lock_hash.as_deref(),
                );
                let install_no_deps = script_lock.is_some();
                let env_root = pep_cache
                    .script_env_root(&script_path)
                    .map_err(|e| eyre!("failed to resolve script env root: {}", e))?;
                let venv_path = pep_cache.venv_path_for_root(&env_root);
                let venv_python = pep_cache.python_path_for_venv(&venv_path);

                if dry_run {
                    collector.info(format!(
                        "Would use cached env at {} or create new one: {:?}",
                        venv_path.display(),
                        install_deps
                    ));
                    eprintln!("info: using Python from {} (dry-run)", env_source);
                    (
                        RunProgram::Python(base_python),
                        Some(venv_path.to_string_lossy().to_string()),
                        false,
                    )
                } else {
                    let _env_lock = pep_cache
                        .lock_script_env(&env_root)
                        .map_err(|e| eyre!("failed to lock script env: {}", e))?;

                    let mut cache_hit = false;
                    if venv_path.exists()
                        && venv_python.exists()
                        && let Some(info) = pep_cache
                            .read_cache_entry(&env_root)
                            .map_err(|e| eyre!("failed to read cache entry: {}", e))?
                        && Pep723Cache::cache_entry_matches_key(&info, &cache_key)
                    {
                        let _ = pep_cache.update_last_used_at(&env_root);
                        cache_hit = true;
                    }

                    if cache_hit {
                        collector.info(format!(
                            "Cache hit: reusing venv at {} (hash: {})",
                            venv_path.display(),
                            &cache_key.hash[..8]
                        ));
                        eprintln!(
                            "info: using cached environment {} (hash: {})",
                            venv_path.display(),
                            &cache_key.hash[..8]
                        );
                        (
                            RunProgram::Python(venv_python.to_string_lossy().to_string()),
                            Some(venv_path.to_string_lossy().to_string()),
                            true,
                        )
                    } else {
                        if venv_path.exists() {
                            fs::remove_dir_all(&venv_path).map_err(|e| {
                                eyre!("failed to remove stale venv {}: {}", venv_path.display(), e)
                            })?;
                        }
                        let info_path = env_root.join("deps.json");
                        let _ = fs::remove_file(&info_path);

                        eprintln!(
                            "info: using Python from {} for new cached env (hash: {})",
                            env_source,
                            &cache_key.hash[..8]
                        );

                        // Create virtual environment
                        eprintln!(
                            "info: creating cached environment at {}",
                            venv_path.display()
                        );

                        let mut venv_cmd = ProcessCommand::new(&base_python);
                        venv_cmd.args(["-m", "venv"]);
                        if crate::env::find_uv_executable().is_some() {
                            venv_cmd.arg("--without-pip");
                        }
                        venv_cmd.arg(&venv_path);
                        let venv_status = venv_cmd
                            .status()
                            .map_err(|e| eyre!("failed to create virtual environment: {}", e))?;

                        if !venv_status.success() {
                            return Err(eyre!("failed to create virtual environment"));
                        }

                        // Get pip path in venv (for fallback install)
                        let pip_path = if cfg!(windows) {
                            venv_path.join("Scripts").join("pip.exe")
                        } else {
                            venv_path.join("bin").join("pip")
                        };

                        // Install dependencies
                        eprintln!("info: installing {} dependencies...", install_deps.len());
                        if let Some(uv_path) = crate::env::find_uv_executable() {
                            eprintln!("info: using uv for fast installation");
                            let mut install_cmd = ProcessCommand::new(uv_path);
                            install_cmd.args(["pip", "install", "--quiet"]);
                            if install_no_deps {
                                install_cmd.arg("--no-deps");
                            }
                            install_cmd.arg("--python");
                            install_cmd.arg(&venv_path);
                            if let Some(dir) = &wheel_cache_dir {
                                if std::env::var_os("UV_CACHE_DIR").is_none() {
                                    install_cmd.env("UV_CACHE_DIR", dir);
                                }
                                if std::env::var_os("PIP_CACHE_DIR").is_none() {
                                    install_cmd.env("PIP_CACHE_DIR", dir);
                                }
                            }
                            install_cmd.args(&install_deps);

                            let install_status = install_cmd.status().map_err(|e| {
                                eyre!("failed to install dependencies with uv: {}", e)
                            })?;

                            if !install_status.success() {
                                collector
                                    .warning("failed to install dependencies with uv".to_string());
                                return Err(eyre!(
                                    "failed to install PEP 723 dependencies (uv backend)"
                                ));
                            }
                        } else {
                            // Fallback to standard pip
                            let mut install_cmd = ProcessCommand::new(&pip_path);
                            install_cmd.args(["install", "--quiet"]);
                            if install_no_deps {
                                install_cmd.arg("--no-deps");
                            }
                            if let Some(dir) = &wheel_cache_dir {
                                install_cmd.arg("--cache-dir");
                                install_cmd.arg(dir);
                            }
                            install_cmd.args(&install_deps);

                            let install_status = install_cmd
                                .status()
                                .map_err(|e| eyre!("failed to install dependencies: {}", e))?;

                            if !install_status.success() {
                                collector.warning("failed to install dependencies".to_string());
                                return Err(eyre!("failed to install PEP 723 dependencies"));
                            }
                        }

                        pep_cache
                            .record_cache_entry_at(&env_root, &cache_key)
                            .map_err(|e| eyre!("failed to record cache entry: {}", e))?;

                        eprintln!("info: cached environment ready");

                        (
                            RunProgram::Python(venv_python.to_string_lossy().to_string()),
                            Some(venv_path.to_string_lossy().to_string()),
                            false,
                        )
                    }
                }
            }
        } else {
            pep723_backend = "pybun".to_string();
            // Initialize PEP 723 cache
            let pep_cache =
                Pep723Cache::new().map_err(|e| eyre!("failed to initialize cache: {}", e))?;
            let (base_python, env_source) = find_python_interpreter()?;
            let python_version = get_python_version(Path::new(&base_python))?;
            let index_settings = pep723_index_settings(pep723_metadata.as_ref());
            let cache_key = Pep723CacheKey::new(
                &install_deps,
                &python_version,
                &index_settings,
                lock_hash.as_deref(),
            );
            let install_no_deps = script_lock.is_some();
            let env_root = pep_cache
                .script_env_root(&script_path)
                .map_err(|e| eyre!("failed to resolve script env root: {}", e))?;
            let venv_path = pep_cache.venv_path_for_root(&env_root);
            let venv_python = pep_cache.python_path_for_venv(&venv_path);

            if dry_run {
                collector.info(format!(
                    "Would use cached env at {} or create new one: {:?}",
                    venv_path.display(),
                    install_deps
                ));
                eprintln!("info: using Python from {} (dry-run)", env_source);
                (
                    RunProgram::Python(base_python),
                    Some(venv_path.to_string_lossy().to_string()),
                    false,
                )
            } else if !no_cache {
                let _env_lock = pep_cache
                    .lock_script_env(&env_root)
                    .map_err(|e| eyre!("failed to lock script env: {}", e))?;

                let mut cache_hit = false;
                if venv_path.exists()
                    && venv_python.exists()
                    && let Some(info) = pep_cache
                        .read_cache_entry(&env_root)
                        .map_err(|e| eyre!("failed to read cache entry: {}", e))?
                    && Pep723Cache::cache_entry_matches_key(&info, &cache_key)
                {
                    let _ = pep_cache.update_last_used_at(&env_root);
                    cache_hit = true;
                }

                if cache_hit {
                    collector.info(format!(
                        "Cache hit: reusing venv at {} (hash: {})",
                        venv_path.display(),
                        &cache_key.hash[..8]
                    ));
                    eprintln!(
                        "info: using cached environment {} (hash: {})",
                        venv_path.display(),
                        &cache_key.hash[..8]
                    );
                    (
                        RunProgram::Python(venv_python.to_string_lossy().to_string()),
                        Some(venv_path.to_string_lossy().to_string()),
                        true,
                    )
                } else {
                    if venv_path.exists() {
                        fs::remove_dir_all(&venv_path).map_err(|e| {
                            eyre!("failed to remove stale venv {}: {}", venv_path.display(), e)
                        })?;
                    }
                    let info_path = env_root.join("deps.json");
                    let _ = fs::remove_file(&info_path);

                    eprintln!(
                        "info: using Python from {} for new cached env (hash: {})",
                        env_source,
                        &cache_key.hash[..8]
                    );

                    // Create virtual environment
                    eprintln!(
                        "info: creating cached environment at {}",
                        venv_path.display()
                    );

                    let mut venv_cmd = ProcessCommand::new(&base_python);
                    venv_cmd.args(["-m", "venv"]);
                    if crate::env::find_uv_executable().is_some() {
                        venv_cmd.arg("--without-pip");
                    }
                    venv_cmd.arg(&venv_path);
                    let venv_status = venv_cmd
                        .status()
                        .map_err(|e| eyre!("failed to create virtual environment: {}", e))?;

                    if !venv_status.success() {
                        return Err(eyre!("failed to create virtual environment"));
                    }

                    // Get pip path in venv (for fallback install)
                    let _pip_path = if cfg!(windows) {
                        venv_path.join("Scripts").join("pip.exe")
                    } else {
                        venv_path.join("bin").join("pip")
                    };

                    eprintln!("info: installing {} dependencies...", install_deps.len());
                    if let Some(uv_path) = crate::env::find_uv_executable() {
                        eprintln!("info: using uv for fast installation");
                        let mut install_cmd = ProcessCommand::new(uv_path);
                        install_cmd.args(["pip", "install", "--quiet"]);
                        if install_no_deps {
                            install_cmd.arg("--no-deps");
                        }
                        install_cmd.arg("--python");
                        install_cmd.arg(&venv_path);
                        if let Some(dir) = &wheel_cache_dir {
                            if std::env::var_os("UV_CACHE_DIR").is_none() {
                                install_cmd.env("UV_CACHE_DIR", dir);
                            }
                            if std::env::var_os("PIP_CACHE_DIR").is_none() {
                                install_cmd.env("PIP_CACHE_DIR", dir);
                            }
                        }
                        install_cmd.args(&install_deps);

                        let install_status = install_cmd
                            .status()
                            .map_err(|e| eyre!("failed to install dependencies with uv: {}", e))?;

                        if !install_status.success() {
                            collector.warning("failed to install dependencies with uv".to_string());
                            return Err(eyre!(
                                "failed to install PEP 723 dependencies (uv backend)"
                            ));
                        }
                    } else {
                        // Native PyBun Installation
                        eprintln!("info: resolving dependencies (native)...");

                        let requirements: Vec<Requirement> = install_deps
                            .iter()
                            .map(|d| d.parse().unwrap_or_else(|_| Requirement::any(d)))
                            .collect();

                        // Use offline flag from args if available?
                        // run_script args doesn't strictly have offline flag passed down easily unless we parse it?
                        // But PyPiClient::from_env handles env vars.
                        let client = PyPiClient::from_env(false).map_err(|e| eyre!(e))?;
                        let index = PyPiIndex::new(client);
                        let resolution = resolve_with_options(
                            requirements,
                            &index,
                            ResolveOptions {
                                python_version: python_version_env_override()
                                    .or_else(|| Some(python_version.clone())),
                                ..Default::default()
                            },
                        )
                        .await;
                        for notice in index.take_stale_cache_notices() {
                            collector.warning(notice);
                        }
                        let resolution =
                            resolution.map_err(|e: crate::resolver::ResolveError| eyre!(e))?;
                        install::warn_on_prerelease_fallback(&resolution, collector);

                        // Prepare site-packages path
                        let major_minor = python_version
                            .split('.')
                            .take(2)
                            .collect::<Vec<_>>()
                            .join(".");
                        let site_packages = if cfg!(windows) {
                            venv_path.join("Lib").join("site-packages")
                        } else {
                            venv_path
                                .join("lib")
                                .join(format!("python{}", major_minor))
                                .join("site-packages")
                        };

                        let wheel_cache = WheelCache::new()
                            .map_err(|e| eyre!("failed to init wheel cache: {}", e))?;
                        eprintln!(
                            "info: downloading {} packages...",
                            resolution.packages.len()
                        );

                        let platform_tags = crate::resolver::current_platform_tags();
                        // Issue #294: select wheels for the *target venv's* Python
                        // (already resolved above as `python_version`), not whatever
                        // python3/python happens to resolve on PATH. Same root cause
                        // as Issue #291, fixed for `pybun install` in #292.
                        let active_cp_tag = python_version_to_cp_tag(&python_version)
                            .unwrap_or_else(|| "cp311".to_string());
                        let mut download_futures = Vec::new();

                        for pkg in resolution.packages.values() {
                            let selection = crate::resolver::select_artifact_for_platform_with_cp(
                                pkg,
                                &platform_tags,
                                &active_cp_tag,
                            );
                            if selection.from_source {
                                return Err(eyre!(
                                    "native installer does not support sdist for {}",
                                    pkg.name
                                ));
                            }
                            if let Some(url) = &selection.url {
                                let name = pkg.name.clone();
                                let filename = selection.filename.clone();
                                let url = url.clone();
                                let wc = &wheel_cache;
                                download_futures.push(async move {
                                    wc.get_wheel(&name, &filename, &url, None).await
                                });
                            } else {
                                return Err(eyre!("no download URL for {}", pkg.name));
                            }
                        }

                        let results = futures::future::join_all(download_futures).await;
                        let mut wheels_to_install = Vec::new();
                        for res in results {
                            match res {
                                Ok(path) => wheels_to_install.push(path),
                                Err(e) => return Err(eyre!("download failed: {}", e)),
                            }
                        }

                        eprintln!("info: installing {} packages...", wheels_to_install.len());
                        for wheel in wheels_to_install {
                            installer::install_wheel(&wheel, &site_packages)
                                .map_err(|e| eyre!("failed to install wheel: {}", e))?;
                        }
                    }

                    pep_cache
                        .record_cache_entry_at(&env_root, &cache_key)
                        .map_err(|e| eyre!("failed to record cache entry: {}", e))?;

                    eprintln!("info: cached environment ready");

                    (
                        RunProgram::Python(venv_python.to_string_lossy().to_string()),
                        Some(venv_path.to_string_lossy().to_string()),
                        false,
                    )
                }
            } else {
                // No-cache mode: create temporary environment
                let temp_dir = tempfile::tempdir()
                    .map_err(|e| eyre!("failed to create temp directory: {}", e))?;
                let temp_env_str = temp_dir.path().to_string_lossy().to_string();

                eprintln!(
                    "info: using Python from {} for temp env (no-cache mode)",
                    env_source
                );

                let venv_path = temp_dir.path().join("venv");
                eprintln!(
                    "info: creating isolated environment at {}",
                    venv_path.display()
                );

                let mut venv_cmd = ProcessCommand::new(&base_python);
                venv_cmd.args(["-m", "venv"]);
                if crate::env::find_uv_executable().is_some() {
                    venv_cmd.arg("--without-pip");
                }
                venv_cmd.arg(&venv_path);
                let venv_status = venv_cmd
                    .status()
                    .map_err(|e| eyre!("failed to create virtual environment: {}", e))?;

                if !venv_status.success() {
                    return Err(eyre!("failed to create virtual environment"));
                }

                let pip_path = if cfg!(windows) {
                    venv_path.join("Scripts").join("pip.exe")
                } else {
                    venv_path.join("bin").join("pip")
                };
                let venv_python = if cfg!(windows) {
                    venv_path.join("Scripts").join("python.exe")
                } else {
                    venv_path.join("bin").join("python")
                };

                eprintln!("info: installing {} dependencies...", install_deps.len());

                if let Some(uv_path) = crate::env::find_uv_executable() {
                    eprintln!("info: using uv for fast installation (no-cache mode)");
                    let mut install_cmd = ProcessCommand::new(uv_path);
                    install_cmd.args(["pip", "install", "--quiet"]);
                    if install_no_deps {
                        install_cmd.arg("--no-deps");
                    }
                    install_cmd.arg("--python");
                    install_cmd.arg(&venv_path);
                    if let Some(dir) = &wheel_cache_dir {
                        if std::env::var_os("UV_CACHE_DIR").is_none() {
                            install_cmd.env("UV_CACHE_DIR", dir);
                        }
                        if std::env::var_os("PIP_CACHE_DIR").is_none() {
                            install_cmd.env("PIP_CACHE_DIR", dir);
                        }
                    }
                    install_cmd.args(&install_deps);

                    let install_status = install_cmd
                        .status()
                        .map_err(|e| eyre!("failed to install dependencies with uv: {}", e))?;

                    if !install_status.success() {
                        collector.warning("failed to install dependencies with uv".to_string());
                        return Err(eyre!("failed to install PEP 723 dependencies (uv)"));
                    }
                } else {
                    let mut install_cmd = ProcessCommand::new(&pip_path);
                    install_cmd.args(["install", "--quiet"]);
                    if install_no_deps {
                        install_cmd.arg("--no-deps");
                    }
                    if let Some(dir) = &wheel_cache_dir {
                        install_cmd.arg("--cache-dir");
                        install_cmd.arg(dir);
                    }
                    install_cmd.args(&install_deps);

                    let install_status = install_cmd
                        .status()
                        .map_err(|e| eyre!("failed to install dependencies: {}", e))?;

                    if !install_status.success() {
                        collector.warning("failed to install dependencies".to_string());
                        return Err(eyre!("failed to install PEP 723 dependencies"));
                    }
                }

                // Keep the temp dir alive until after execution.
                temp_env_dir = Some(temp_dir);
                (
                    RunProgram::Python(venv_python.to_string_lossy().to_string()),
                    Some(temp_env_str),
                    false,
                )
            }
        }
    } else {
        // No PEP 723 dependencies, use system/project Python
        let (python, env_source) = find_python_interpreter()?;

        check_lockfile_python_compatibility(&python, collector);

        if matches!(env_source, crate::env::EnvSource::System) {
            let current_dir = std::env::current_dir()?;
            if Project::discover(&current_dir).is_ok() {
                eprintln!("warning: PyBun is using system Python but a pyproject.toml exists.");
                eprintln!(
                    "hint: Ensure your virtual environment is at .venv, .pybun/venv, or set PYBUN_ENV."
                );
            }
        }

        eprintln!("info: using Python from {}", env_source);
        (RunProgram::Python(python), None, false)
    };

    // Build command
    let (mut cmd, is_uv_runner) = match runner {
        RunProgram::Python(python) => {
            let mut cmd = ProcessCommand::new(python);
            cmd.arg(&script_path);
            for arg in &args.passthrough {
                cmd.arg(arg);
            }
            (cmd, false)
        }
        RunProgram::Uv { uv_path } => {
            let mut cmd = ProcessCommand::new(uv_path);
            cmd.args(["run", "--script"]);
            cmd.arg(&script_path);
            if let Some(dir) = &wheel_cache_dir {
                if std::env::var_os("UV_CACHE_DIR").is_none() {
                    cmd.env("UV_CACHE_DIR", dir);
                }
                if std::env::var_os("PIP_CACHE_DIR").is_none() {
                    cmd.env("PIP_CACHE_DIR", dir);
                }
            }
            if !args.passthrough.is_empty() {
                cmd.arg("--");
                for arg in &args.passthrough {
                    cmd.arg(arg);
                }
            }
            (cmd, true)
        }
    };

    // Enable sandbox if requested.
    let mut sandbox_guard: Option<sandbox::SandboxGuard> = None;
    let mut sandbox_info: Option<SandboxInfo> = None;
    if args.sandbox {
        if is_uv_runner {
            return Err(eyre!("--sandbox is not supported with uv run backend"));
        }
        let allow_network = args.allow_network
            || std::env::var("PYBUN_SANDBOX_ALLOW_NETWORK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        collector.info(format!("sandbox enabled (allow_network={})", allow_network));
        let guard = sandbox::apply_python_sandbox(
            &mut cmd,
            sandbox::SandboxConfig {
                allow_network,
                allow_read: args.allow_read.clone(),
                allow_write: args.allow_write.clone(),
                allow_env: args.allow_env.clone(),
                timeout_secs: args.sandbox_timeout,
                memory_limit_mb: args.sandbox_memory,
                cpu_limit_secs: args.sandbox_cpu,
                ..Default::default()
            },
        )?;
        emit_unsupported_resource_limit_diagnostics(collector, &guard.resource_limits);
        emit_rejected_allow_env_diagnostics(collector, &guard.rejected_env);
        sandbox_info = Some(SandboxInfo {
            enabled: true,
            allow_network,
            allow_read: args.allow_read.clone(),
            allow_write: args.allow_write.clone(),
            allow_env: guard.allow_env.clone(),
            default_deny_write: guard.default_deny_write.clone(),
            enforcement: guard.enforcement().to_string(),
            audit: None,
            resource_limits: guard.resource_limits.clone(),
            timed_out: false,
        });
        sandbox_guard = Some(guard);
    }

    // Apply launch profile settings to the command.
    // PYTHONOPTIMIZE maps optimization_level to Python's -O/-OO flag semantics.
    let mut lazy_import_tempdir: Option<tempfile::TempDir> = None;
    let mut lazy_imports_injected = false;
    if profile_config.optimization_level > 0 && std::env::var_os("PYTHONOPTIMIZE").is_none() {
        cmd.env(
            "PYTHONOPTIMIZE",
            profile_config.optimization_level.to_string(),
        );
    }
    if profile_config.timing {
        cmd.env("PYBUN_TIMING", "1");
    }
    for (key, value) in &profile_config.env_vars {
        cmd.env(key, value);
    }
    // Inject lazy imports via sitecustomize.py when not sandboxed (sandbox has its own
    // sitecustomize.py and merging them is deferred to a later PR).
    if profile_config.lazy_imports && !args.sandbox && !is_uv_runner {
        use crate::lazy_import::{LazyImportConfig, generate_lazy_import_python_code};
        let lazy_config = LazyImportConfig::with_defaults();
        let python_code = generate_lazy_import_python_code(&lazy_config);
        match tempfile::tempdir() {
            Ok(dir) => {
                let sitecustomize = dir.path().join("sitecustomize.py");
                if std::fs::write(&sitecustomize, &python_code).is_ok() {
                    let new_path = join_python_path(dir.path());
                    cmd.env("PYTHONPATH", new_path);
                    lazy_imports_injected = true;
                    lazy_import_tempdir = Some(dir);
                }
            }
            Err(e) => {
                collector.warning(format!(
                    "failed to create lazy-import tempdir, skipping injection: {}",
                    e
                ));
            }
        }
    }

    let cleanup = temp_env_dir.is_some();

    // Execute
    // On Unix, use exec to replace the process if cleanup is not needed AND not in JSON mode
    // (JSON mode requires wrapping to emit final summary)
    #[cfg(unix)]
    if !cleanup && format != OutputFormat::Json && sandbox_guard.is_none() {
        // leak lazy_import_tempdir intentionally: exec replaces the process before Rust
        // drop runs, so the directory remains accessible to the spawned Python process.
        std::mem::forget(lazy_import_tempdir);
        let err = cmd.exec();
        return Err(eyre!("failed to exec runner: {}", err));
    }

    let sandbox::SandboxedExecution {
        status,
        stdout,
        stderr,
        timed_out,
    } = sandbox::execute_with_optional_sandbox(
        &mut cmd,
        sandbox_guard.as_ref(),
        format == OutputFormat::Json,
    )
    .map_err(|e| eyre!("failed to execute runner: {}", e))?;
    let stdout = stdout.as_deref().and_then(capture_stdio);
    let stderr = stderr.as_deref().and_then(capture_stdio);
    // Read audit before dropping the guard (guard keeps the audit file alive).
    if let (Some(guard), Some(info)) = (&sandbox_guard, &mut sandbox_info) {
        info.audit = Some(guard.read_audit());
        info.timed_out = timed_out;
    }
    drop(sandbox_guard);

    if timed_out {
        collector.diagnostic(
            Diagnostic::error(format!(
                "sandboxed process killed after exceeding --sandbox-timeout={}s",
                args.sandbox_timeout
            ))
            .with_code("E_SANDBOX_TIMEOUT")
            .with_suggestion("increase --sandbox-timeout, set --sandbox-timeout=0 to disable, or optimize the script to finish sooner"),
        );
    } else if args.sandbox_cpu > 0 && sandbox::cpu_limit_exceeded(&status) {
        collector.diagnostic(
            Diagnostic::error(format!(
                "sandboxed process killed after exceeding --sandbox-cpu={}s of CPU time",
                args.sandbox_cpu
            ))
            .with_code("E_SANDBOX_CPU_LIMIT")
            .with_suggestion("increase --sandbox-cpu, set --sandbox-cpu=0 to disable, or optimize the script to use less CPU time"),
        );
    }

    let exit_code = status.code().unwrap_or(-1);

    let summary = if status.success() {
        format!("executed {} successfully", script_path.display())
    } else {
        format!(
            "script {} exited with code {}",
            script_path.display(),
            exit_code
        )
    };

    drop(lazy_import_tempdir);

    Ok(RunOutcome {
        summary,
        target: Some(target.clone()),
        exit_code,
        pep723_deps,
        pep723_backend,
        temp_env: cached_env_path,
        cleanup,
        cache_hit,
        stdout,
        stderr,
        sandbox: sandbox_info,
        profile: RunProfileInfo {
            name: profile_config.profile.to_string(),
            optimization_level: profile_config.optimization_level,
            lazy_imports: profile_config.lazy_imports,
            lazy_imports_injected,
            timing: profile_config.timing,
        },
    })
}

/// Build a PYTHONPATH string that prepends `dir` before the existing PYTHONPATH.
fn join_python_path(dir: &std::path::Path) -> std::ffi::OsString {
    let sep = if cfg!(windows) { ";" } else { ":" };
    let mut paths = vec![dir.as_os_str().to_os_string()];
    if let Ok(existing) = std::env::var("PYTHONPATH")
        && !existing.is_empty()
    {
        paths.push(std::ffi::OsString::from(existing));
    }
    let joined: Vec<&std::ffi::OsStr> = paths.iter().map(|s| s.as_os_str()).collect();
    joined.join(std::ffi::OsStr::new(sep))
}

/// Get Python version from a Python interpreter
pub(crate) fn get_python_version(python_path: &std::path::Path) -> Result<String> {
    let output = ProcessCommand::new(python_path)
        .args(["--version"])
        .output()
        .map_err(|e| eyre!("failed to get Python version: {}", e))?;

    let version_str = String::from_utf8_lossy(&output.stdout);
    // Parse "Python 3.11.0" -> "3.11.0"
    let version = version_str
        .trim()
        .strip_prefix("Python ")
        .unwrap_or(version_str.trim())
        .to_string();
    Ok(version)
}

/// Validate that the wheels recorded in the project lockfile (`pybun.lockb`)
/// are compatible with the Python interpreter that is about to execute the
/// script. A mismatch (e.g. `cp310` wheels locked but running under `cp312`)
/// otherwise surfaces as an obscure C-extension `ImportError` at runtime
/// rather than an actionable PyBun diagnostic (see Issue #172).
///
/// This check is best-effort: any failure to locate, load, or parse the
/// lockfile or interpreter version silently skips validation rather than
/// blocking the run.
fn check_lockfile_python_compatibility(python_path: &str, collector: &mut EventCollector) {
    let Ok(cwd) = std::env::current_dir() else {
        return;
    };
    let lock_path = cwd.join("pybun.lockb");
    if !lock_path.exists() {
        return;
    }
    let Ok(lockfile) = Lockfile::load_from_path(&lock_path) else {
        return;
    };
    let Ok(active_version) = get_python_version(Path::new(python_path)) else {
        return;
    };
    let Some(active_cp_tag) = python_version_to_cp_tag(&active_version) else {
        return;
    };

    let mismatched_tag = lockfile.packages.values().find_map(|pkg| {
        let (python_tag, abi_tag) = parse_wheel_tags(&pkg.wheel);
        let ptag = python_tag?;
        if is_wheel_python_compatible(Some(&ptag), abi_tag.as_deref(), &active_cp_tag) {
            None
        } else {
            Some(ptag)
        }
    });

    let Some(locked_tag) = mismatched_tag else {
        return;
    };

    let locked_version = cp_tag_to_dotted_version(&locked_tag).unwrap_or(locked_tag);
    let active_minor =
        cp_tag_to_dotted_version(&active_cp_tag).unwrap_or_else(|| active_version.clone());
    let message = format!(
        "Locked package wheels in pybun.lockb (compiled for Python {locked_version}) are \
         incompatible with the active Python interpreter (Python {active_version}). \
         Please run 'pybun install' to re-lock dependencies for Python {active_minor}."
    );
    eprintln!("warning: {message}");
    collector.diagnostic(
        Diagnostic::warning(message)
            .with_code("W_LOCK_PYTHON_VERSION_MISMATCH")
            .with_suggestion("pybun install"),
    );
}

fn run_python_code(
    args: &crate::cli::RunArgs,
    code: &str,
    collector: &mut EventCollector,
    format: OutputFormat,
) -> Result<RunOutcome> {
    use crate::profiles::{Profile, ProfileConfig};

    let profile: Profile = args
        .profile
        .parse()
        .map_err(|e: String| eyre!("invalid --profile value: {}", e))?;
    let profile_config = ProfileConfig::for_profile(profile);

    let (python, env_source) = find_python_interpreter()?;
    eprintln!("info: using Python from {}", env_source);

    let mut cmd = ProcessCommand::new(&python);
    cmd.arg("-c").arg(code);

    let mut sandbox_info: Option<SandboxInfo> = None;
    let mut sandbox_guard: Option<sandbox::SandboxGuard> = None;
    if args.sandbox {
        let allow_network = args.allow_network
            || std::env::var("PYBUN_SANDBOX_ALLOW_NETWORK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        collector.info(format!(
            "sandbox enabled for inline code (allow_network={})",
            allow_network
        ));
        let guard = sandbox::apply_python_sandbox(
            &mut cmd,
            sandbox::SandboxConfig {
                allow_network,
                allow_read: args.allow_read.clone(),
                allow_write: args.allow_write.clone(),
                allow_env: args.allow_env.clone(),
                timeout_secs: args.sandbox_timeout,
                memory_limit_mb: args.sandbox_memory,
                cpu_limit_secs: args.sandbox_cpu,
                ..Default::default()
            },
        )?;
        emit_unsupported_resource_limit_diagnostics(collector, &guard.resource_limits);
        emit_rejected_allow_env_diagnostics(collector, &guard.rejected_env);
        sandbox_info = Some(SandboxInfo {
            enabled: true,
            allow_network,
            allow_read: args.allow_read.clone(),
            allow_write: args.allow_write.clone(),
            allow_env: guard.allow_env.clone(),
            default_deny_write: guard.default_deny_write.clone(),
            enforcement: guard.enforcement().to_string(),
            audit: None,
            resource_limits: guard.resource_limits.clone(),
            timed_out: false,
        });
        sandbox_guard = Some(guard);
    }

    // Apply profile settings (optimization, timing, env vars) — same as run_script.
    let mut lazy_imports_injected = false;
    if profile_config.optimization_level > 0 && std::env::var_os("PYTHONOPTIMIZE").is_none() {
        cmd.env(
            "PYTHONOPTIMIZE",
            profile_config.optimization_level.to_string(),
        );
    }
    if profile_config.timing {
        cmd.env("PYBUN_TIMING", "1");
    }
    for (key, value) in &profile_config.env_vars {
        cmd.env(key, value);
    }
    let mut lazy_import_tempdir: Option<tempfile::TempDir> = None;
    if profile_config.lazy_imports && !args.sandbox {
        use crate::lazy_import::{LazyImportConfig, generate_lazy_import_python_code};
        let lazy_config = LazyImportConfig::with_defaults();
        let python_code = generate_lazy_import_python_code(&lazy_config);
        if let Ok(dir) = tempfile::tempdir() {
            let sitecustomize = dir.path().join("sitecustomize.py");
            if std::fs::write(&sitecustomize, &python_code).is_ok() {
                let new_path = join_python_path(dir.path());
                cmd.env("PYTHONPATH", new_path);
                lazy_imports_injected = true;
                lazy_import_tempdir = Some(dir);
            }
        }
    }

    // Add remaining passthrough arguments
    for arg in args.passthrough.iter().skip(1) {
        cmd.arg(arg);
    }

    #[cfg(unix)]
    if format != OutputFormat::Json && sandbox_guard.is_none() {
        std::mem::forget(lazy_import_tempdir);
        let err = cmd.exec();
        return Err(eyre!("failed to exec Python: {}", err));
    }

    let sandbox::SandboxedExecution {
        status,
        stdout,
        stderr,
        timed_out,
    } = sandbox::execute_with_optional_sandbox(
        &mut cmd,
        sandbox_guard.as_ref(),
        format == OutputFormat::Json,
    )
    .map_err(|e| eyre!("failed to execute Python: {}", e))?;
    let stdout = stdout.as_deref().and_then(capture_stdio);
    let stderr = stderr.as_deref().and_then(capture_stdio);
    if let (Some(guard), Some(info)) = (&sandbox_guard, &mut sandbox_info) {
        info.audit = Some(guard.read_audit());
        info.timed_out = timed_out;
    }
    drop(sandbox_guard);

    if timed_out {
        collector.diagnostic(
            Diagnostic::error(format!(
                "sandboxed process killed after exceeding --sandbox-timeout={}s",
                args.sandbox_timeout
            ))
            .with_code("E_SANDBOX_TIMEOUT")
            .with_suggestion("increase --sandbox-timeout, set --sandbox-timeout=0 to disable, or optimize the script to finish sooner"),
        );
    } else if args.sandbox_cpu > 0 && sandbox::cpu_limit_exceeded(&status) {
        collector.diagnostic(
            Diagnostic::error(format!(
                "sandboxed process killed after exceeding --sandbox-cpu={}s of CPU time",
                args.sandbox_cpu
            ))
            .with_code("E_SANDBOX_CPU_LIMIT")
            .with_suggestion("increase --sandbox-cpu, set --sandbox-cpu=0 to disable, or optimize the script to use less CPU time"),
        );
    }

    let exit_code = status.code().unwrap_or(-1);

    let summary = if status.success() {
        if args.sandbox {
            "executed inline code successfully (sandboxed)".to_string()
        } else {
            "executed inline code successfully".to_string()
        }
    } else {
        format!("inline code exited with code {}", exit_code)
    };

    drop(lazy_import_tempdir);

    Ok(RunOutcome {
        summary,
        target: Some("-c".to_string()),
        exit_code,
        pep723_deps: Vec::new(),
        pep723_backend: "system".to_string(),
        temp_env: None,
        cleanup: false,
        cache_hit: false,
        stdout,
        stderr,
        sandbox: sandbox_info,
        profile: RunProfileInfo {
            name: profile_config.profile.to_string(),
            optimization_level: profile_config.optimization_level,
            lazy_imports: profile_config.lazy_imports,
            lazy_imports_injected,
            timing: profile_config.timing,
        },
    })
}

/// Find the Python interpreter to use.
/// Uses the new env module with full priority-based selection.
///
/// Priority:
/// 1. PYBUN_ENV environment variable (venv path)
/// 2. PYBUN_PYTHON environment variable (explicit binary)
/// 3. Project-local .pybun/venv directory
/// 4. .python-version file (pyenv-style)
/// 5. System Python (python3/python in PATH)
pub(crate) fn find_python_interpreter() -> Result<(String, EnvSource)> {
    let working_dir = std::env::current_dir()?;
    let env = find_python_env(&working_dir)?;
    Ok((env.python_path.to_string_lossy().to_string(), env.source))
}
