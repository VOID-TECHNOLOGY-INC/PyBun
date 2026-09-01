use super::{
    RenderDetail, SandboxInfo, get_python_version, python_version_env_override,
    resolve_target_python_version, script_lock_path,
};
use crate::cli::{LockArgs, OutdatedArgs, UpgradeArgs};
use crate::index::load_index_from_path;
use crate::lockfile::{Lockfile, Package, PackageSource};
use crate::pep723;
use crate::project::Project;
use crate::pypi::{PyPiClient, PyPiIndex};
use crate::resolver::parse_version_relaxed;
use crate::resolver::{
    PackageIndex, Requirement, Resolution, ResolveOptions, compare_versions, current_platform_tags,
    python_version_to_cp_tag, resolve_with_options, select_artifact_for_platform_with_cp,
};
use crate::schema::{Diagnostic, EventCollector, EventType};
use crate::workspace::Workspace;
use color_eyre::eyre::{Result, eyre};
use console::Style;
use futures::stream::{self, StreamExt};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

/// Resolve dependency specifiers scoped by `--member` (optionally narrowed by
/// `--group`) or `--group` alone, against an already-discovered workspace (or
/// the single `project` when no workspace exists). Returns `Ok(None)` when
/// neither selector is set, so callers can fall through to their own default
/// behavior (workspace merge, plain project dependencies, etc).
///
/// This is the shared precedence core behind `pybun install`, `pybun
/// outdated`, and `pybun upgrade`'s `--member`/`--group` selectors.
fn select_member_or_group_dependencies(
    project: &Project,
    workspace: &Option<Workspace>,
    member: Option<&str>,
    group: Option<&str>,
    collector: &mut EventCollector,
) -> Result<Option<(Vec<String>, Option<Value>)>> {
    if let Some(member_name) = member {
        let ws = workspace.as_ref().ok_or_else(|| {
            eyre!("--member requires a workspace; no [tool.pybun.workspace] configuration found")
        })?;
        let member_project = ws.member_by_name(member_name).ok_or_else(|| {
            eyre!(
                "workspace member '{member_name}' not found (available: {})",
                ws.member_names().join(", ")
            )
        })?;
        let deps = match group {
            Some(group_name) => member_project.group_dependencies(group_name),
            None => member_project.dependencies(),
        };
        collector.info(format!(
            "Selected workspace member '{}' at {} ({} dependencies{})",
            member_name,
            member_project.root().display(),
            deps.len(),
            group.map(|g| format!(", group '{g}'")).unwrap_or_default(),
        ));
        return Ok(Some((
            deps,
            Some(json!({
                "scope": "member",
                "root": ws.root.root().display().to_string(),
                "selected_members": [member_name],
                "group": group,
            })),
        )));
    }

    if let Some(group_name) = group {
        if let Some(ws) = workspace {
            let deps = ws.dependencies_for_group(group_name);
            collector.info(format!(
                "Selected dependency group '{}' across workspace at {} ({} dependencies)",
                group_name,
                ws.root.root().display(),
                deps.len(),
            ));
            return Ok(Some((
                deps,
                Some(json!({
                    "scope": "group",
                    "root": ws.root.root().display().to_string(),
                    "selected_members": ws.member_names(),
                    "group": group_name,
                })),
            )));
        }

        let deps = project.group_dependencies(group_name);
        collector.info(format!(
            "Selected dependency group '{}' ({} dependencies)",
            group_name,
            deps.len(),
        ));
        return Ok(Some((
            deps,
            Some(json!({
                "scope": "group",
                "selected_members": Value::Null,
                "group": group_name,
            })),
        )));
    }

    Ok(None)
}

/// Resolve which dependency specifiers to install based on workspace
/// selectors (`--workspace`/`--member`/`--group`). Returns the dependency
/// strings plus an optional JSON blob describing the selection scope for
/// workspace-aware JSON output (`None` for plain single-project installs).
///
/// Selector precedence: `--member` (optionally narrowed by `--group`) takes
/// priority, then `--group` alone (workspace-wide or project-local), then
/// `--workspace`/auto-detected workspace merging, finally falling back to the
/// discovered project's own `[project.dependencies]`.
fn select_install_dependencies(
    project: &Project,
    working_dir: &Path,
    args: &crate::cli::InstallArgs,
    collector: &mut EventCollector,
) -> Result<(Vec<String>, Option<Value>)> {
    let workspace = if args.workspace {
        Workspace::discover_root(working_dir).map_err(|e| eyre!(e))?
    } else {
        Workspace::discover(working_dir).map_err(|e| eyre!(e))?
    };

    if args.workspace && workspace.is_none() {
        return Err(eyre!(
            "--workspace specified but no [tool.pybun.workspace] configuration found"
        ));
    }

    if let Some((deps, detail)) = select_member_or_group_dependencies(
        project,
        &workspace,
        args.member.as_deref(),
        args.group.as_deref(),
        collector,
    )? {
        return Ok((deps, detail));
    }

    if let Some(ws) = &workspace {
        let merged = ws.merged_dependencies();
        collector.info(format!(
            "Workspace detected at {} ({} members); merged {} dependencies",
            ws.root.root().display(),
            ws.members.len(),
            merged.len()
        ));
        return Ok((
            merged,
            Some(json!({
                "scope": "workspace",
                "root": ws.root.root().display().to_string(),
                "selected_members": ws.member_names(),
                "group": Value::Null,
            })),
        ));
    }

    let deps = project.dependencies();
    if deps.is_empty() {
        collector.info("No dependencies found in pyproject.toml");
    } else {
        collector.info(format!(
            "Found {} dependencies in {}",
            deps.len(),
            project.path().display()
        ));
    }
    Ok((deps, None))
}

/// Resolve dependency specifiers for `pybun outdated`/`pybun upgrade`,
/// honoring `--member`/`--group` selectors against an auto-detected workspace
/// (these commands have no `--workspace` merge mode of their own). Falls back
/// to the discovered project's own `[project.dependencies]` when neither
/// selector is set.
fn select_scoped_dependencies(
    project: &Project,
    working_dir: &Path,
    member: Option<&str>,
    group: Option<&str>,
    collector: &mut EventCollector,
) -> Result<(Vec<String>, Option<Value>)> {
    let workspace = Workspace::discover(working_dir).map_err(|e| eyre!(e))?;

    if let Some((deps, detail)) =
        select_member_or_group_dependencies(project, &workspace, member, group, collector)?
    {
        return Ok((deps, detail));
    }

    Ok((project.dependencies(), None))
}

/// Emit a `W_EXTRAS_IGNORED` warning for every requirement that carries PEP 508
/// extras (e.g. `typer[all]`). PyBun does not yet resolve extras' dependencies
/// (full support is tracked as PR-A5 / Issue #285) — installing such a
/// requirement silently drops the extra's dependencies, so this makes the
/// degradation visible in both `--format=json` diagnostics and human-readable
/// CLI output instead of failing loudly (the old, since-fixed 404 behavior
/// from Issue #93) or succeeding silently with the wrong result (Issue #285).
fn warn_on_ignored_extras(requirements: &[Requirement], collector: &mut EventCollector) {
    for req in requirements {
        if req.extras.is_empty() {
            continue;
        }
        let extras_list = req.extras.join(", ");
        let message = format!(
            "extras ignored for '{}': pybun does not yet resolve PEP 508 extras, so only the base package will be installed (dropped: [{}])",
            req.name, extras_list
        );
        eprintln!("warning: {}", message);
        collector.diagnostic(
            Diagnostic::warning(message)
                .with_code("W_EXTRAS_IGNORED")
                .with_suggestion(format!(
                    "Full extras support is tracked in Issue #285 / PR-A5. Install '{}' extra dependencies manually if you need them.",
                    req.name
                ))
                .with_context(json!({
                    "package": req.name,
                    "extras": req.extras,
                })),
        );
    }
}

/// Emit a `W_PRERELEASE_SELECTED` warning for every package that resolved to
/// a pre-release version via the fallback path (only pre-releases satisfied
/// the constraints, without a `--pre` opt-in or a specifier mentioning a
/// pre-release). PEP 440 excludes pre-releases from version selection by
/// default, so the fallback is made visible instead of silent (Issue #341).
pub(super) fn warn_on_prerelease_fallback(resolution: &Resolution, collector: &mut EventCollector) {
    for pick in &resolution.prerelease_fallbacks {
        let message = format!(
            "selected pre-release version {} {} because only pre-release versions satisfy the constraints",
            pick.name, pick.version
        );
        eprintln!("warning: {}", message);
        collector.diagnostic(
            Diagnostic::warning(message)
                .with_code("W_PRERELEASE_SELECTED")
                .with_suggestion(
                    "Pass --pre to opt in to pre-release versions explicitly, or pin a stable version."
                        .to_string(),
                )
                .with_context(json!({
                    "package": pick.name,
                    "version": pick.version,
                })),
        );
    }
}

/// Explicit `PYBUN_PYPI_PYTHON_VERSION` override for the resolution target
/// Python version, if set and non-empty.
pub(crate) async fn install(
    args: &crate::cli::InstallArgs,
    collector: &mut EventCollector,
) -> Result<InstallOutcome> {
    // Gather requirements: either from --require flags or from pyproject.toml
    let (requirements, workspace_detail): (Vec<Requirement>, Option<Value>) =
        if !args.requirements.is_empty() {
            // CLI --require flags take precedence
            (args.requirements.clone(), None)
        } else {
            // Try to load from pyproject.toml
            let working_dir = std::env::current_dir()?;
            let project = Project::discover(&working_dir).map_err(|_| {
                eyre!(
                    "no requirements provided and no pyproject.toml found. \
                     Use --require or create a pyproject.toml with [project.dependencies]"
                )
            })?;

            let (deps, workspace_detail) =
                select_install_dependencies(&project, &working_dir, args, collector)?;

            let requirements = deps
                .into_iter()
                .map(|d| {
                    d.parse::<Requirement>()
                        .unwrap_or_else(|_| Requirement::any(d.trim()))
                })
                .collect();

            (requirements, workspace_detail)
        };

    warn_on_ignored_extras(&requirements, collector);

    // Detect the CPython tag of the actual install target (PYBUN_ENV / PYBUN_PYTHON /
    // project venv / system Python) *before* selecting wheels, so artifact selection
    // matches the Python interpreter packages will actually be installed into.
    // Selecting wheels against whatever `python3`/`python` happens to resolve on PATH
    // (the previous behavior) can silently pick wheels for the wrong CPython ABI
    // (Issue #291). This is read-only detection only — creating a project-local venv
    // (and the associated system-Python safe-install-target guard) is deferred to the
    // later "Install wheels" step below, so a resolve-only or failed install doesn't
    // have the side effect of mutating the filesystem.
    //
    // Detection happens before resolution (and before the empty-dependency early return
    // below) because the same interpreter version also drives `requires-python` candidate
    // filtering (Issue #342) and is the single source of truth recorded into the lockfile's
    // `python_versions` (Issue #399) — it must never diverge from what wheel selection
    // actually targeted. The interpreter is only spawned when no environment override makes
    // it unnecessary.
    let working_dir = std::env::current_dir()?;
    let target_env_probe = crate::env::find_python_env(&working_dir)?;
    let python_version_override = python_version_env_override();
    // PYBUN_FORCE_CP_TAG lets tests (and users) pin the CPython tag deterministically.
    // Note it no longer bypasses interpreter detection on its own: the detected version
    // is also needed for `requires-python` filtering, so detection is only skipped when
    // PYBUN_PYPI_PYTHON_VERSION covers that too.
    let forced_cp_tag = std::env::var("PYBUN_FORCE_CP_TAG")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let detected_python_version = if python_version_override.is_none() || forced_cp_tag.is_none() {
        get_python_version(&target_env_probe.python_path).ok()
    } else {
        None
    };
    let active_cp_tag = forced_cp_tag
        .or_else(|| {
            detected_python_version
                .as_deref()
                .and_then(python_version_to_cp_tag)
        })
        .unwrap_or_else(|| "cp311".to_string());
    // Canonical target Python version for this install: the explicit
    // PYBUN_PYPI_PYTHON_VERSION override wins, otherwise the detected interpreter version.
    // Used both for resolver `requires-python` filtering and for the lockfile's
    // `python_versions` metadata, so the two can never disagree (Issue #399).
    let target_python_version = python_version_override
        .clone()
        .or_else(|| detected_python_version.clone());

    // If no requirements (empty pyproject dependencies), create empty lockfile
    if requirements.is_empty() {
        let lock = Lockfile::new(
            vec![
                target_python_version
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            ],
            vec!["unknown".into()],
        );
        lock.save_to_path(&args.lock)?;
        return Ok(InstallOutcome {
            summary: format!("no dependencies to install -> {}", args.lock.display()),
            packages: vec![],
            lockfile: args.lock.clone(),
            verified: true,
            artifacts: Vec::new(),
            workspace: workspace_detail.clone(),
            installed_count: 0,
        });
    }

    let source_index_url: String;
    let offline = args.offline;
    let resolve_options = ResolveOptions {
        allow_prerelease: args.pre,
        python_version: target_python_version.clone(),
    };
    let resolution = if let Some(index_path) = args.index.clone() {
        source_index_url = index_path.display().to_string();
        let index = load_index_from_path(&index_path).map_err(|e| eyre!(e))?;
        match resolve_with_options(requirements.clone(), &index, resolve_options).await {
            Ok(r) => r,
            Err(e) => {
                for d in crate::self_heal::diagnostics_for_resolve_error(&requirements, &e) {
                    collector.diagnostic(d);
                }
                return Err(eyre!(e.to_string()));
            }
        }
    } else {
        let client = PyPiClient::from_env(offline)
            .map_err(|e| eyre!("failed to init pypi client: {}", e))?;
        source_index_url = client.index_url();
        collector.info(format!(
            "Using PyPI index {} (offline: {})",
            source_index_url, offline
        ));
        let index = PyPiIndex::new(client);
        let resolve_result =
            resolve_with_options(requirements.clone(), &index, resolve_options).await;
        for notice in index.take_stale_cache_notices() {
            collector.warning(notice);
        }
        match resolve_result {
            Ok(r) => r,
            Err(e) => {
                for d in crate::self_heal::diagnostics_for_resolve_error(&requirements, &e) {
                    collector.diagnostic(d);
                }
                return Err(eyre!(e.to_string()));
            }
        }
    };
    warn_on_prerelease_fallback(&resolution, collector);
    collector.event_with(EventType::ResolveComplete, |event| {
        event.message = Some("Resolved dependencies".to_string());
        event.progress = Some(40);
    });

    let platform_tags = current_platform_tags();
    let mut lock = Lockfile::new(
        vec![
            target_python_version
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        ],
        vec![
            platform_tags
                .first()
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
        ],
    );
    let mut verified_artifacts = Vec::new();
    for pkg in resolution.packages.values() {
        let selection = select_artifact_for_platform_with_cp(pkg, &platform_tags, &active_cp_tag);
        if selection.from_source {
            let message = format!(
                "no compatible pre-built wheel for {} {} on {}; source distributions are not supported for install",
                pkg.name,
                pkg.version,
                platform_tags.join(",")
            );
            eprintln!("warning: {}", message);
            collector.warning(message);
        }
        let (verified_hash, artifact) =
            ensure_selection_is_verifiable(pkg, &selection, collector, &source_index_url)?;
        verified_artifacts.push(artifact);
        lock.add_package(Package {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            source: registry_source_for_index(&source_index_url),
            wheel: selection.filename,
            hash: verified_hash,
            dependencies: pkg.dependencies.iter().map(ToString::to_string).collect(),
        });
    }
    lock.save_to_path(&args.lock)?;

    // Download artifacts in parallel.
    // Respect PYBUN_PYPI_CACHE_DIR when present so tests and callers can
    // isolate both index metadata and downloaded wheel artifacts together.
    let cache_dir = if let Ok(dir) = std::env::var("PYBUN_PYPI_CACHE_DIR") {
        PathBuf::from(dir).join("artifacts")
    } else {
        dirs::cache_dir()
            .ok_or_else(|| eyre!("failed to determine cache directory"))?
            .join("pybun")
            .join("artifacts")
    };

    collector.info(format!("Downloading artifacts to {}", cache_dir.display()));

    let mut download_items = Vec::new();
    let mut sdist_only_packages = Vec::new();
    for pkg in resolution.packages.values() {
        let selection = select_artifact_for_platform_with_cp(pkg, &platform_tags, &active_cp_tag);
        if let Some(url) = selection.url {
            // Construct filename from selection
            let filename = PathBuf::from(selection.filename);
            let dest = cache_dir.join(filename);
            // Include hash when available to verify downloads
            download_items.push((url, dest, selection.hash.clone()));
        } else if selection.from_source {
            // sdist-only package - no wheel available
            sdist_only_packages.push(format!("{}=={}", pkg.name, pkg.version));
        }
    }

    // Fail if there are sdist-only packages (source builds not yet supported)
    if !sdist_only_packages.is_empty() {
        let message = format!(
            "The following packages have no pre-built wheel for your platform and require source builds (not yet supported): {}",
            sdist_only_packages.join(", ")
        );
        collector.error_with_code(
            "E_INSTALL_SDIST_ONLY",
            message.clone(),
            "Source builds are not yet supported; choose packages/versions with prebuilt wheels for your platform, or use a different index.",
        );
        return Err(eyre!(message));
    }

    collector.event_with(EventType::DownloadStart, |event| {
        event.message = Some(format!("Downloading {} artifacts", download_items.len()));
        event.progress = Some(50);
    });

    let mut outcome = InstallOutcome {
        summary: format!(
            "resolved {} packages -> {}",
            lock.packages.len(),
            args.lock.display()
        ),
        packages: lock.packages.keys().cloned().collect(),
        lockfile: args.lock.clone(),
        verified: true,
        artifacts: verified_artifacts,
        workspace: workspace_detail,
        installed_count: 0,
    };

    if download_items.is_empty() {
        collector.event_with(EventType::InstallStart, |event| {
            event.message = Some("Installing 0 packages".to_string());
            event.progress = Some(85);
        });
        return Ok(outcome);
    }

    if !download_items.is_empty() {
        use crate::downloader::{DownloadRequest, Downloader};
        let downloader = Downloader::new();
        let concurrency = 10; // Default concurrency
        collector.info(format!(
            "Starting parallel download of {} artifacts...",
            download_items.len()
        ));

        // Keep track of paths to install
        let wheels_to_install: Vec<PathBuf> = download_items
            .iter()
            .map(|(_, path, _)| path.clone())
            .collect();

        let download_requests: Vec<DownloadRequest> =
            download_items.into_iter().map(Into::into).collect();
        let results = downloader
            .download_parallel(download_requests, concurrency)
            .await;

        // Check for failures
        let mut failures = 0;
        for res in results {
            if let Err(e) = res {
                eprintln!("warning: download failed: {}", e);
                failures += 1;
            }
        }

        if failures > 0 {
            collector.warning(format!("{} downloads failed", failures));
            return Err(eyre!("failed to download some artifacts"));
        }

        collector.event_with(EventType::DownloadComplete, |event| {
            event.message = Some("Downloads complete".to_string());
            event.progress = Some(70);
        });

        // Install wheels. Re-resolve the target environment now that we know there is
        // something to install; this is where venv creation / the system-Python guard
        // actually mutates the filesystem (deferred from the cp-tag detection above so
        // a resolve-only or failed install has no such side effect).
        let mut env = crate::env::find_python_env(&working_dir)?;

        if matches!(env.source, crate::env::EnvSource::System) {
            if args.system {
                if let Some(marker) = crate::env::externally_managed_marker(&env.python_path) {
                    let message = format!(
                        "refusing to install into externally-managed system Python (marker: {})",
                        marker.display()
                    );
                    collector.error_with_code(
                        "E_INSTALL_EXTERNALLY_MANAGED",
                        message.clone(),
                        "This interpreter is marked externally-managed (PEP 668). Create a virtual environment (e.g. `python3 -m venv .venv`) and re-run, or install with a non-managed interpreter.",
                    );
                    return Err(eyre!(message));
                }

                let warning =
                    "warning: PyBun is installing into system Python (--system was specified).";
                eprintln!("{}", warning);
                collector.warning(warning.to_string());
            } else {
                collector.info(
                    "No virtual environment found; creating project-local environment at .pybun/venv"
                        .to_string(),
                );
                env = crate::env::create_project_venv(&working_dir)?;
            }
        }

        collector.info(format!(
            "Installing packages into {}",
            env.python_path.display()
        ));

        // Determine the full install scheme (purelib/platlib/scripts/headers/data)
        // so wheel `.data/*` entries (PEP 427) are relocated correctly instead of
        // being left nested under site-packages (Issue #402).
        let output = std::process::Command::new(&env.python_path)
            .args([
                "-c",
                "import sysconfig, json; print(json.dumps(sysconfig.get_paths()))",
            ])
            .output()
            .map_err(|e| eyre!("failed to determine install scheme: {}", e))?;

        if !output.status.success() {
            return Err(eyre!(
                "failed to determine install scheme (python execution failed)"
            ));
        }
        let paths_json: Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| eyre!("invalid sysconfig.get_paths() output: {}", e))?;
        let scheme = crate::installer::InstallScheme::from_sysconfig_json(
            &paths_json,
            env.python_path.clone(),
        )
        .ok_or_else(|| eyre!("sysconfig.get_paths() is missing expected keys"))?;

        collector.info(format!(
            "Target site-packages: {}",
            scheme.purelib.display()
        ));

        collector.event_with(EventType::InstallStart, |event| {
            event.message = Some(format!("Installing {} packages", wheels_to_install.len()));
            event.progress = Some(85);
        });

        for wheel in wheels_to_install {
            if wheel.exists() {
                crate::installer::install_wheel_with_scheme(&wheel, &scheme)
                    .map_err(|e| eyre!("failed to install wheel {}: {}", wheel.display(), e))?;
                outcome.installed_count += 1;
            }
        }

        collector.event_with(EventType::InstallComplete, |event| {
            event.message = Some("Installation complete".to_string());
            event.progress = Some(100);
        });
    }

    Ok(outcome)
}

#[derive(Debug)]
pub(crate) struct InstallOutcome {
    pub(crate) summary: String,
    pub(crate) packages: Vec<String>,
    pub(crate) lockfile: PathBuf,
    pub(crate) verified: bool,
    pub(crate) artifacts: Vec<Value>,
    /// Workspace selection details (scope, selected members, group), present
    /// only when dependencies were gathered from a workspace-aware source.
    pub(crate) workspace: Option<Value>,
    /// Number of wheels actually downloaded and installed into a site-packages
    /// directory during this call. This is distinct from `packages.len()`,
    /// which counts *resolved* packages regardless of whether any wheel was
    /// actually fetched and installed (e.g. when no download URL is available
    /// from the index, or when there was nothing new to install). Callers
    /// (including the MCP `pybun_install` tool) must not claim packages were
    /// "installed" unless this count is greater than zero.
    pub(crate) installed_count: usize,
}

#[derive(Debug)]
pub(super) struct LockOutcome {
    pub(super) summary: String,
    pub(super) lockfile: PathBuf,
    pub(super) packages: Vec<String>,
    pub(super) verified: bool,
    pub(super) artifacts: Vec<Value>,
}

fn is_missing_sha256(hash: Option<&str>) -> bool {
    match hash {
        Some(value) => crate::security::is_placeholder_hash(value),
        None => true,
    }
}

fn registry_source_for_index(index_url: &str) -> PackageSource {
    PackageSource::Registry {
        index: "pypi".into(),
        url: index_url.to_string(),
    }
}

fn verification_artifact_value(
    pkg: &crate::resolver::ResolvedPackage,
    selection: &crate::resolver::ArtifactSelection,
    index_url: &str,
    verified_hash: &str,
) -> Value {
    json!({
        "package": pkg.name,
        "version": pkg.version,
        "sha256": verified_hash,
        "index_url": index_url,
        "artifact_url": selection.url,
        "platform_tag": selection.matched_platform,
        "filename": selection.filename,
        "from_source": selection.from_source,
    })
}

fn missing_hash_diagnostic(
    pkg: &crate::resolver::ResolvedPackage,
    selection: &crate::resolver::ArtifactSelection,
    index_url: &str,
) -> Diagnostic {
    Diagnostic {
        level: crate::schema::DiagnosticLevel::Error,
        code: Some("E_VERIFY_MISSING_HASH".to_string()),
        message: format!(
            "selected artifact for {} {} ({}) is missing sha256 verification metadata",
            pkg.name, pkg.version, selection.filename
        ),
        file: None,
        line: None,
        suggestion: Some(
            "use an index that provides sha256 digests, then rerun install/lock/upgrade"
                .to_string(),
        ),
        context: Some(json!({
            "package": pkg.name,
            "version": pkg.version,
            "filename": selection.filename,
            "artifact_url": selection.url,
            "index_url": index_url,
            "platform_tag": selection.matched_platform,
            "from_source": selection.from_source,
        })),
        exception_type: None,
        location: None,
        next_action: None,
        fix_candidates: None,
    }
}

fn ensure_selection_is_verifiable(
    pkg: &crate::resolver::ResolvedPackage,
    selection: &crate::resolver::ArtifactSelection,
    collector: &mut EventCollector,
    index_url: &str,
) -> Result<(String, Value)> {
    if is_missing_sha256(selection.hash.as_deref()) {
        let diagnostic = missing_hash_diagnostic(pkg, selection, index_url);
        let message = diagnostic.message.clone();
        collector.diagnostic(diagnostic);
        return Err(eyre!(message));
    }

    let Some(verified_hash) = selection.hash.clone() else {
        let message = format!(
            "missing SHA-256 hash for {} {} after verification",
            pkg.name, pkg.version
        );
        collector.error_with_code(
            "E_VERIFY_MISSING_HASH",
            message.clone(),
            "Choose a package artifact that includes a SHA-256 digest or use an index that exposes artifact hashes.",
        );
        return Err(eyre!(message));
    };
    Ok((
        verified_hash.clone(),
        verification_artifact_value(pkg, selection, index_url, &verified_hash),
    ))
}

fn emit_lockfile_verification_drift(lockfile: &Lockfile, collector: &mut EventCollector) {
    let drifted_packages: Vec<Value> = lockfile
        .packages
        .values()
        .filter(|pkg| is_missing_sha256(Some(&pkg.hash)))
        .map(|pkg| {
            json!({
                "package": pkg.name,
                "version": pkg.version,
                "filename": pkg.wheel,
                "hash": pkg.hash,
            })
        })
        .collect();

    if drifted_packages.is_empty() {
        return;
    }

    collector.diagnostic(Diagnostic {
        level: crate::schema::DiagnosticLevel::Warning,
        code: Some("W_LOCK_PLACEHOLDER_HASH".to_string()),
        message: format!(
            "existing lockfile contains {} package(s) without verified hashes",
            drifted_packages.len()
        ),
        file: None,
        line: None,
        suggestion: Some(
            "rerun 'pybun install' or 'pybun lock' with an index that provides sha256 digests"
                .to_string(),
        ),
        context: Some(json!({ "packages": drifted_packages })),
        exception_type: None,
        location: None,
        next_action: None,
        fix_candidates: Some(crate::self_heal::fix_candidates_for_lock_drift()),
    });
}

pub(super) async fn lock_dependencies(
    args: &LockArgs,
    collector: &mut EventCollector,
) -> Result<LockOutcome> {
    let (dep_specs, lock_path): (Vec<String>, PathBuf) =
        if let Some(script_path) = args.script.as_ref() {
            if !script_path.exists() {
                return Err(eyre!("script not found: {}", script_path.display()));
            }

            let pep723_metadata = match pep723::parse_script_metadata(script_path) {
                Ok(metadata) => metadata,
                Err(e) => {
                    return Err(eyre!("failed to parse PEP 723 metadata: {}", e));
                }
            };

            let pep723_deps = pep723_metadata
                .as_ref()
                .map(|m| m.dependencies.clone())
                .unwrap_or_default();

            (pep723_deps, script_lock_path(script_path))
        } else {
            let cwd = std::env::current_dir()?;
            let Ok(project) = Project::discover(&cwd) else {
                let message =
                    "no pyproject.toml found in the current directory or any parent directory"
                        .to_string();
                collector.diagnostic(Diagnostic {
                    level: crate::schema::DiagnosticLevel::Error,
                    code: Some("E_LOCK_TARGET_REQUIRED".to_string()),
                    message: message.clone(),
                    file: None,
                    line: None,
                    suggestion: Some(
                        "Run 'pybun lock --script <path/to/script.py>' to lock a PEP 723 script, \
                     or create a pyproject.toml with [project.dependencies] to lock a project"
                            .to_string(),
                    ),
                    context: None,
                    exception_type: None,
                    location: None,
                    next_action: None,
                    fix_candidates: None,
                });
                return Err(eyre!(message));
            };

            (project.dependencies(), cwd.join("pybun.lockb"))
        };

    let requirements: Vec<Requirement> = dep_specs
        .iter()
        .map(|d| {
            d.parse::<Requirement>()
                .unwrap_or_else(|_| Requirement::any(d.trim()))
        })
        .collect();

    // Canonical target Python version for this lock: shared with `pybun install`
    // (Issue #399) so `requires-python` filtering, resolution, and the lockfile's
    // `python_versions` metadata always agree, for both project and PEP 723
    // `--script` locking. Resolved before the empty-dependency early return below
    // so that path records the real target instead of a hard-coded fallback too.
    let target_python_version = resolve_target_python_version();

    if dep_specs.is_empty() {
        let lock = Lockfile::new(
            vec![
                target_python_version
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            ],
            vec!["unknown".into()],
        );
        lock.save_to_path(&lock_path)?;
        return Ok(LockOutcome {
            summary: format!("no dependencies to lock -> {}", lock_path.display()),
            lockfile: lock_path,
            packages: Vec::new(),
            verified: true,
            artifacts: Vec::new(),
        });
    }

    let source_index_url: String;
    let offline = args.offline;
    let resolve_options = ResolveOptions {
        python_version: target_python_version.clone(),
        ..Default::default()
    };
    let resolution = if let Some(index_path) = args.index.clone() {
        source_index_url = index_path.display().to_string();
        let index = load_index_from_path(&index_path).map_err(|e| eyre!(e))?;
        match resolve_with_options(requirements.clone(), &index, resolve_options).await {
            Ok(r) => r,
            Err(e) => {
                for d in crate::self_heal::diagnostics_for_resolve_error(&requirements, &e) {
                    collector.diagnostic(d);
                }
                return Err(eyre!(e.to_string()));
            }
        }
    } else {
        let client = PyPiClient::from_env(offline)
            .map_err(|e| eyre!("failed to init pypi client: {}", e))?;
        source_index_url = client.index_url();
        collector.info(format!(
            "Using PyPI index {} (offline: {})",
            source_index_url, offline
        ));
        let index = PyPiIndex::new(client);
        let resolve_result =
            resolve_with_options(requirements.clone(), &index, resolve_options).await;
        for notice in index.take_stale_cache_notices() {
            collector.warning(notice);
        }
        match resolve_result {
            Ok(r) => r,
            Err(e) => {
                for d in crate::self_heal::diagnostics_for_resolve_error(&requirements, &e) {
                    collector.diagnostic(d);
                }
                return Err(eyre!(e.to_string()));
            }
        }
    };
    warn_on_prerelease_fallback(&resolution, collector);

    collector.event_with(EventType::ResolveComplete, |event| {
        event.message = Some("Resolved dependencies".to_string());
        event.progress = Some(40);
    });

    // Detect the CPython tag of the actual lock target's Python (PYBUN_ENV / PYBUN_PYTHON /
    // project venv / system Python) *before* selecting wheels, so the wheel filenames recorded
    // in the lockfile match the interpreter that will actually install them. Selecting wheels
    // against whatever `python3`/`python` happens to resolve on PATH (the previous behavior)
    // could silently record wheels for the wrong CPython ABI, producing the kind of
    // `ImportError` #172's runtime compatibility check was built to detect after the fact
    // (Issue #293; same root cause as #291, fixed for `pybun install` in #292). This is
    // read-only detection only and covers both project-mode and `--script` PEP 723 locking,
    // since both resolve the target interpreter relative to the current working directory
    // (honoring PYBUN_ENV/PYBUN_PYTHON regardless of cwd).
    let working_dir = std::env::current_dir()?;
    let target_env_probe = crate::env::find_python_env(&working_dir)?;

    // PYBUN_FORCE_CP_TAG lets tests (and users) pin the CPython tag deterministically,
    // bypassing interpreter detection entirely. Deliberately probes the interpreter
    // directly here rather than falling back through `target_python_version`: that value
    // can come from the `PYBUN_PYPI_PYTHON_VERSION` resolution-target override, which must
    // not silently redirect wheel-ABI selection away from the actual lock target's Python
    // (matching `install()`'s `active_cp_tag`, which has the same property).
    let active_cp_tag = std::env::var("PYBUN_FORCE_CP_TAG")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            get_python_version(&target_env_probe.python_path)
                .ok()
                .and_then(|v| python_version_to_cp_tag(&v))
        })
        .unwrap_or_else(|| "cp311".to_string());

    let platform_tags = current_platform_tags();
    let mut lock = Lockfile::new(
        vec![
            target_python_version
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        ],
        vec![
            platform_tags
                .first()
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
        ],
    );
    let mut verified_artifacts = Vec::new();

    for pkg in resolution.packages.values() {
        let selection = select_artifact_for_platform_with_cp(pkg, &platform_tags, &active_cp_tag);
        if selection.from_source {
            let message = format!(
                "no compatible pre-built wheel for {} {} on {}; falling back to source build",
                pkg.name,
                pkg.version,
                platform_tags.join(",")
            );
            eprintln!("warning: {}", message);
            collector.warning(message);
        }
        let (verified_hash, artifact) =
            ensure_selection_is_verifiable(pkg, &selection, collector, &source_index_url)?;
        verified_artifacts.push(artifact);
        lock.add_package(Package {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            source: registry_source_for_index(&source_index_url),
            wheel: selection.filename,
            hash: verified_hash,
            dependencies: pkg.dependencies.iter().map(ToString::to_string).collect(),
        });
    }

    lock.save_to_path(&lock_path)?;

    Ok(LockOutcome {
        summary: format!(
            "locked {} packages -> {}",
            lock.packages.len(),
            lock_path.display()
        ),
        lockfile: lock_path,
        packages: lock.packages.keys().cloned().collect(),
        verified: true,
        artifacts: verified_artifacts,
    })
}

// ---------------------------------------------------------------------------
// pybun add
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(super) struct AddedPackage {
    pub(super) name: String,
    pub(super) version: Option<String>,
}

#[derive(Debug)]
pub(super) struct AddOutcome {
    pub(super) summary: String,
    pub(super) packages: Vec<AddedPackage>,
    pub(super) added_deps: Vec<String>,
}

pub(super) fn add_package(args: &crate::cli::PackageArgs) -> Result<AddOutcome> {
    if args.packages.is_empty() {
        return Err(eyre!("package name is required"));
    }

    // Find or create pyproject.toml
    let current_dir = std::env::current_dir()?;
    let mut project = match Project::discover(&current_dir) {
        Ok(p) => p,
        Err(_) => {
            // Create new pyproject.toml in current directory
            let path = current_dir.join("pyproject.toml");
            Project::new(&path)
        }
    };

    let mut packages = Vec::with_capacity(args.packages.len());
    for package_spec in &args.packages {
        // Parse the requirement
        let req: Requirement = package_spec
            .parse()
            .map_err(|e: String| eyre!("invalid package spec: {}", e))?;

        // Note: PEP 508 extras (e.g. `typer[all]`) are not yet resolved
        // (Issue #285). `pybun add` always chains into `install()` below,
        // which re-parses the freshly written pyproject.toml dependency and
        // emits the `W_EXTRAS_IGNORED` warning — so we don't duplicate it
        // here.

        // Add to pyproject.toml
        project.add_dependency(package_spec);

        let version = match req.specs.as_slice() {
            [crate::resolver::VersionSpec::Any] => None,
            [crate::resolver::VersionSpec::Exact(v)] => Some(v.clone()),
            specs => Some(
                specs
                    .iter()
                    .map(crate::resolver::VersionSpec::operator_display)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        };

        // A later spec for the same package name replaces the earlier one in
        // pyproject.toml (see `Project::add_dependency`), so keep only the
        // last occurrence here too.
        packages.retain(|p: &AddedPackage| p.name != req.name);
        packages.push(AddedPackage {
            name: req.name.clone(),
            version,
        });
    }

    project.save()?;
    let added_deps = project.dependencies();

    let package_list = args.packages.join(", ");
    let summary = format!("added {} to {}", package_list, project.path().display());

    Ok(AddOutcome {
        summary,
        packages,
        added_deps,
    })
}

// ---------------------------------------------------------------------------
// pybun remove
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(super) struct RemovedPackage {
    pub(super) name: String,
    pub(super) removed: bool,
}

#[derive(Debug)]
pub(super) struct RemoveOutcome {
    pub(super) summary: String,
    pub(super) packages: Vec<RemovedPackage>,
}

pub(super) fn remove_package(args: &crate::cli::PackageArgs) -> Result<RemoveOutcome> {
    if args.packages.is_empty() {
        return Err(eyre!("package name is required"));
    }

    // Find pyproject.toml
    let current_dir = std::env::current_dir()?;
    let mut project = Project::discover(&current_dir).map_err(|_| {
        eyre!(
            "pyproject.toml not found in {} or any parent directory",
            current_dir.display()
        )
    })?;

    let mut packages = Vec::with_capacity(args.packages.len());
    let mut removed_names = Vec::new();
    let mut not_found_names = Vec::new();
    for package_name in &args.packages {
        let removed = project.remove_dependency(package_name);
        if removed {
            removed_names.push(package_name.clone());
        } else {
            not_found_names.push(package_name.clone());
        }
        packages.push(RemovedPackage {
            name: package_name.clone(),
            removed,
        });
    }

    if !removed_names.is_empty() {
        project.save()?;
    }

    let summary = match (removed_names.is_empty(), not_found_names.is_empty()) {
        (false, true) => format!(
            "removed {} from {}",
            removed_names.join(", "),
            project.path().display()
        ),
        (true, false) => format!(
            "{} was not found in dependencies",
            not_found_names.join(", ")
        ),
        (false, false) => format!(
            "removed {} from {}; {} was not found in dependencies",
            removed_names.join(", "),
            project.path().display(),
            not_found_names.join(", ")
        ),
        (true, true) => unreachable!("at least one package is always processed"),
    };

    Ok(RemoveOutcome { summary, packages })
}

// ---------------------------------------------------------------------------
// pybun run
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(super) struct ScriptLockInfo {
    pub(super) lock: Lockfile,
    pub(super) lock_hash: String,
}

#[derive(Debug)]
pub(crate) struct RunOutcome {
    pub(crate) summary: String,
    pub(crate) target: Option<String>,
    pub(crate) exit_code: i32,
    pub(crate) pep723_deps: Vec<String>,
    /// Execution backend for PEP 723 scripts (system/pybun/uv_run).
    pub(crate) pep723_backend: String,
    /// Environment path used for PEP 723 dependencies (cached or temporary)
    pub(crate) temp_env: Option<String>,
    /// Whether the environment was cleaned up (only in no-cache mode)
    pub(crate) cleanup: bool,
    /// Whether the environment was a cache hit
    pub(crate) cache_hit: bool,
    /// Captured stdout (only when `--format=json`).
    pub(crate) stdout: Option<String>,
    /// Captured stderr (only when `--format=json`).
    pub(crate) stderr: Option<String>,
    /// Sandbox information when enabled
    pub(crate) sandbox: Option<SandboxInfo>,
    /// Applied launch profile info
    pub(crate) profile: RunProfileInfo,
}

#[derive(Debug, Clone)]
pub(crate) struct RunProfileInfo {
    pub(super) name: String,
    pub(super) optimization_level: u8,
    pub(super) lazy_imports: bool,
    pub(super) lazy_imports_injected: bool,
    pub(super) timing: bool,
}
// ---------------------------------------------------------------------------
// pybun outdated
// ---------------------------------------------------------------------------

pub(super) async fn run_outdated(
    args: &OutdatedArgs,
    collector: &mut EventCollector,
) -> Result<RenderDetail> {
    let cwd =
        std::env::current_dir().map_err(|e| eyre!("failed to get current directory: {}", e))?;
    let lock_path = cwd.join("pybun.lockb");

    if !lock_path.exists() {
        let message = "pybun.lockb not found. Run 'pybun install' first.".to_string();
        collector.error_with_code(
            "E_LOCKFILE_NOT_FOUND",
            message.clone(),
            "Run `pybun install` to generate pybun.lockb, then re-run `pybun outdated`.",
        );
        return Err(eyre!(message));
    }

    // A pybun.lockb that exists but fails to decode (e.g. truncated by a
    // crash mid-write, or corrupted on disk) is treated the same as a
    // missing lockfile rather than propagated as a fatal error. This
    // mirrors the self-heal behavior already applied to `load_script_lock`
    // (issue #301, itself tracking the same failure mode as #299/#262) and
    // to `run_upgrade`'s `Lockfile::load_from_path(&lock_path).ok()`. We
    // fall back to "no packages currently locked", which naturally reduces
    // `pybun outdated` to reporting nothing outdated rather than crashing.
    let lockfile = match Lockfile::load_from_path(&lock_path) {
        Ok(lockfile) => lockfile,
        Err(e) => {
            collector.warning(format!(
                "discarded unreadable pybun.lockb at {} ({}); treating as no current lock",
                lock_path.display(),
                e
            ));
            Lockfile::new(Vec::new(), Vec::new())
        }
    };

    // Load constraints for "wanted" logic, optionally scoped by --member/--group
    let (constraints, scope_detail) = if let Ok(project) = Project::discover(&cwd) {
        let (dep_strs, scope_detail) = select_scoped_dependencies(
            &project,
            &cwd,
            args.member.as_deref(),
            args.group.as_deref(),
            collector,
        )?;
        let mut map = HashMap::new();
        for dep_str in dep_strs {
            if let Ok(req) = Requirement::from_str(&dep_str) {
                map.insert(req.name.clone(), req);
            }
        }
        (map, scope_detail)
    } else {
        (HashMap::new(), None)
    };

    collector.event(EventType::ResolveStart);

    let mut outdated_packages = Vec::new();
    let mut check_errors = Vec::new();
    let packages_to_check: Vec<(String, Package)> = lockfile.packages.into_iter().collect();

    // Setup client
    let client = PyPiClient::from_env(args.offline)
        .map_err(|e| eyre!("failed to create PyPI client: {}", e))?;

    // Setup local index if needed
    let local_index = if let Some(path) = &args.index {
        Some(Arc::new(
            load_index_from_path(path).map_err(|e| eyre!("{}", e))?,
        ))
    } else {
        None
    };

    // Check versions in parallel
    let constraints_ref = &constraints;

    // Use stream buffering for parallel requests
    let results = stream::iter(packages_to_check)
        .map(|(name, pkg)| {
            let client = client.clone();
            let local_index = local_index.clone();
            async move {
                let all_versions_res = if let Some(index) = local_index {
                    index.all(&name).await
                } else {
                    let pypi = PyPiIndex::new(client);
                    pypi.all(&name).await
                };
                (name, pkg, all_versions_res)
            }
        })
        .buffer_unordered(10) // Concurrency limit
        .collect::<Vec<_>>()
        .await;

    for notice in client.take_stale_cache_notices() {
        collector.warning(notice);
    }

    for (name, pkg, res) in results {
        match res {
            Ok(all_versions) => {
                let latest = all_versions
                    .iter()
                    .max_by(|a, b| compare_versions(&a.version, &b.version))
                    .map(|p| p.version.clone());

                if let Some(latest_version) = latest {
                    let wanted_version = if let Some(req) = constraints_ref.get(&name) {
                        all_versions
                            .iter()
                            .filter(|p| req.is_satisfied_by(&p.version))
                            .max_by(|a, b| compare_versions(&a.version, &b.version)) // Prefer newest matching
                            .map(|p| p.version.clone())
                            .unwrap_or_else(|| latest_version.clone()) // If constraints exclude everything (unlikely if installed), fallback to latest
                    } else {
                        latest_version.clone()
                    };

                    let is_outdated = latest_version != pkg.version;
                    let is_wanted_outdated = wanted_version != pkg.version;

                    if is_outdated || is_wanted_outdated {
                        let update_type = classify_update(&pkg.version, &latest_version);

                        outdated_packages.push(json!({
                            "package": name,
                            "current": pkg.version,
                            "wanted": wanted_version,
                            "latest": latest_version,
                            "type": update_type,
                        }));
                    }
                }
            }
            Err(e) => {
                collector.warning(format!("failed to check {}: {}", name, e));
                check_errors.push(json!({"package": name, "error": e.to_string()}));
            }
        }
    }

    collector.event(EventType::ResolveComplete);

    // Format output (Table for Summary)
    let mut summary = String::new();
    if outdated_packages.is_empty() {
        summary.push_str("All packages are up to date.");
    } else {
        use std::fmt::Write;
        // Header
        let _ = writeln!(
            summary,
            "{: <20} {: <10} {: <10} {: <10} {: <10}",
            "Package", "Current", "Wanted", "Latest", "Type"
        );

        for item in &outdated_packages {
            let name = item["package"].as_str().unwrap_or("?");
            let current = item["current"].as_str().unwrap_or("?");
            let wanted = item["wanted"].as_str().unwrap_or("?");
            let latest = item["latest"].as_str().unwrap_or("?");
            let type_str = item["type"].as_str().unwrap_or("?");

            let color_style = match type_str {
                "major" => Style::new().red(),
                "minor" => Style::new().yellow(),
                "patch" => Style::new().green(),
                _ => Style::new().dim(),
            };

            let _ = writeln!(
                summary,
                "{: <20} {: <10} {: <10} {: <10} {: <10}",
                name,
                current,
                wanted,
                latest,
                color_style.apply_to(type_str)
            );
        }
    }

    Ok(RenderDetail::with_json(
        summary,
        json!({
            "outdated": outdated_packages,
            "errors": check_errors,
            "workspace": scope_detail,
        }),
    ))
}

fn classify_update(current: &str, latest: &str) -> &'static str {
    let cur = parse_version_relaxed(current);
    let lat = parse_version_relaxed(latest);

    match (cur, lat) {
        (Some(c), Some(l)) => {
            if l.major > c.major {
                "major"
            } else if l.minor > c.minor {
                "minor"
            } else if l.patch > c.patch {
                "patch"
            } else {
                "other"
            }
        }
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// pybun upgrade
// ---------------------------------------------------------------------------

pub(super) async fn run_upgrade(
    args: &UpgradeArgs,
    collector: &mut EventCollector,
) -> Result<RenderDetail> {
    let cwd =
        std::env::current_dir().map_err(|e| eyre!("failed to get current directory: {}", e))?;
    let lock_path = if args.lock.is_absolute() {
        args.lock.clone()
    } else {
        cwd.join(&args.lock)
    };

    if !lock_path.exists() {
        let message = format!(
            "lockfile not found at {}. Run 'pybun install' first.",
            lock_path.display()
        );
        collector.error_with_code(
            "E_LOCKFILE_NOT_FOUND",
            message.clone(),
            "Run `pybun install` to generate the lockfile, then re-run `pybun upgrade`.",
        );
        return Err(eyre!(message));
    }

    // Load project to get constraints, optionally scoped by --member/--group
    let project = Project::discover(&cwd).map_err(|e| eyre!("failed to load project: {}", e))?;
    let (dependencies, scope_detail) = select_scoped_dependencies(
        &project,
        &cwd,
        args.member.as_deref(),
        args.group.as_deref(),
        collector,
    )?;
    if dependencies.is_empty() {
        return Ok(RenderDetail::with_json(
            "No dependencies to upgrade",
            json!({
                "upgraded": [],
                "dry_run": args.dry_run,
                "verified": true,
                "artifacts": [],
                "workspace": scope_detail,
            }),
        ));
    }

    // Load current lockfile if exists (for partial updates and comparison)
    let current_lock = Lockfile::load_from_path(&lock_path).ok();
    if let Some(lockfile) = &current_lock {
        emit_lockfile_verification_drift(lockfile, collector);
    }

    // Prepare requirements
    let mut requirements: Vec<Requirement> = Vec::new();

    // Strategy:
    // 1. If args.packages is empty (upgrade all): Use project dependencies.
    // 2. If args.packages is distinct:
    //    - For packages in args.packages: Use project constraints (or Any).
    //    - For others found in lockfile: Pin to lockfile version (Exact).
    //    - For others NOT in lockfile (new deps?): Use project constraints.

    for dep_str in &dependencies {
        if let Ok(req) = dep_str.parse::<Requirement>() {
            let is_target = if args.packages.is_empty() {
                true // Upgrade everything
            } else {
                // Check if this requirement matches any targeted package
                args.packages
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(&req.name))
            };

            if is_target {
                requirements.push(req);
            } else {
                // Not targeted. Check if we should pin it.
                if let Some(lock) = &current_lock {
                    if let Some(pkg) = lock.packages.get(&req.name) {
                        // Pin to currently locked version
                        requirements.push(Requirement::exact(req.name.clone(), &pkg.version));
                    } else {
                        // Not locked yet, strict requirement
                        requirements.push(req);
                    }
                } else {
                    requirements.push(req);
                }
            }
        }
    }

    collector.event(EventType::ResolveStart);

    // Re-resolve dependencies
    let resolve_options = ResolveOptions {
        allow_prerelease: args.pre,
        python_version: resolve_target_python_version(),
    };
    let source_index_url: String;
    let resolution = if let Some(index_path) = &args.index {
        source_index_url = index_path.display().to_string();
        let index = load_index_from_path(index_path)?;
        resolve_with_options(requirements.clone(), &index, resolve_options).await?
    } else {
        let pypi_client = PyPiClient::from_env(args.offline)
            .map_err(|e| eyre!("failed to create PyPI client: {}", e))?;
        source_index_url = pypi_client.index_url();
        let pypi_index = PyPiIndex::new(pypi_client);
        let resolve_result =
            resolve_with_options(requirements.clone(), &pypi_index, resolve_options).await;
        for notice in pypi_index.take_stale_cache_notices() {
            collector.warning(notice);
        }
        resolve_result?
    };
    warn_on_prerelease_fallback(&resolution, collector);

    collector.event(EventType::ResolveComplete);

    let mut upgraded_packages: Vec<Value> = Vec::new();
    let mut verification_artifacts: Vec<Value> = Vec::new();
    let platform_tags = current_platform_tags();

    // Detect the CPython tag of the actual project's Python (PYBUN_ENV / PYBUN_PYTHON /
    // project venv / system Python) *before* re-selecting wheels, so the wheel filenames
    // rewritten into the lockfile match the interpreter that will actually consume it.
    // Selecting wheels against whatever `python3`/`python` happens to resolve on PATH (the
    // previous behavior) could silently record wheels for the wrong CPython ABI, producing
    // the kind of hash/ABI mismatch (or the #172 runtime compatibility warning) that only
    // surfaces later when the rewritten lockfile is consumed (Issue #295; same root cause as
    // #291, fixed for `pybun install` in #292, `pybun lock` in #293, and `pybun run` in #294).
    // This is read-only detection only — `pybun upgrade` doesn't create venvs, so there's no
    // side-effect-ordering concern here (unlike #292's install fix).
    let target_env_probe = crate::env::find_python_env(&cwd)?;

    // PYBUN_FORCE_CP_TAG lets tests (and users) pin the CPython tag deterministically,
    // bypassing interpreter detection entirely.
    let active_cp_tag = std::env::var("PYBUN_FORCE_CP_TAG")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            get_python_version(&target_env_probe.python_path)
                .ok()
                .and_then(|v| python_version_to_cp_tag(&v))
        })
        .unwrap_or_else(|| "cp311".to_string());

    // Use an empty lockfile if none exists for comparison base. The Python version
    // recorded here mirrors `pybun install`/`pybun lock` policy (Issue #399): the
    // detected target interpreter, or an explicit "unknown" rather than a hard-coded
    // minor version presented as factual metadata.
    let base_lock = current_lock.unwrap_or_else(|| {
        Lockfile::new(
            vec![resolve_target_python_version().unwrap_or_else(|| "unknown".to_string())],
            vec!["any".into()],
        )
    });

    // Build new lockfile
    let mut new_lock = Lockfile::new(
        base_lock.python_versions.clone(),
        base_lock.platforms.clone(),
    );

    for (pkg_name, pkg) in &resolution.packages {
        let selection = select_artifact_for_platform_with_cp(pkg, &platform_tags, &active_cp_tag);
        let wheel_name = selection.filename.clone();
        let (hash, artifact) =
            ensure_selection_is_verifiable(pkg, &selection, collector, &source_index_url)?;

        let new_pkg = Package {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            source: pkg
                .source
                .clone()
                .unwrap_or_else(|| registry_source_for_index(&source_index_url)),
            wheel: wheel_name,
            hash,
            dependencies: pkg.dependencies.iter().map(|r| r.to_string()).collect(),
        };

        // Track upgrades
        let from_version = base_lock.packages.get(pkg_name).map(|p| p.version.clone());
        let is_change = match &from_version {
            Some(v) => *v != pkg.version,
            None => true, // New package
        };

        // Only surface artifacts for packages that actually changed. Otherwise
        // `detail.artifacts` includes every resolved package (changed or not),
        // which contradicts `pybun outdated`'s "has an update" definition and
        // misleads agents gating upgrade decisions on `outdated` (Issue #261).
        if is_change {
            verification_artifacts.push(artifact);
            upgraded_packages.push(json!({
                "package": pkg_name,
                "from": from_version,
                "to": pkg.version,
                "new": from_version.is_none()
            }));
        }

        new_lock.add_package(new_pkg);
    }

    // Also track removed packages (if any project dependency was removed/untracked)
    // Note: Since we start from project dependencies, packages no longer in project deps won't be resolved.
    for (name, pkg) in &base_lock.packages {
        if !new_lock.packages.contains_key(name) {
            upgraded_packages.push(json!({
                "package": name,
                "from": pkg.version.clone(),
                "to": null,
                "removed": true
            }));
        }
    }

    // Write lockfile unless dry-run
    if !args.dry_run {
        new_lock
            .save_to_path(&lock_path)
            .map_err(|e| eyre!("failed to save lockfile: {}", e))?;
    }

    // Generate Summary
    let mut summary = String::new();
    if upgraded_packages.is_empty() {
        summary.push_str("All packages are already up to date.");
    } else {
        use std::fmt::Write;
        if args.dry_run {
            writeln!(summary, "Changes (dry-run):")?;
        } else {
            writeln!(summary, "Upgraded packages:")?;
        }

        for item in &upgraded_packages {
            let name = item["package"].as_str().unwrap_or("?");
            let from = item["from"].as_str();
            let to = item["to"].as_str();

            if item.get("new").and_then(|v| v.as_bool()).unwrap_or(false) {
                writeln!(summary, "  + {} {}", name, to.unwrap_or("?"))?;
            } else if item
                .get("removed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                writeln!(summary, "  - {} {}", name, from.unwrap_or("?"))?;
            } else {
                writeln!(
                    summary,
                    "  {} {} -> {}",
                    name,
                    from.unwrap_or("?"),
                    to.unwrap_or("?")
                )?;
            }
        }
    }

    Ok(RenderDetail::with_json(
        summary.trim().to_string(),
        json!({
            "upgraded": upgraded_packages,
            "dry_run": args.dry_run,
            "lockfile": lock_path.display().to_string(),
            "verified": true,
            "artifacts": verification_artifacts,
            "workspace": scope_detail,
        }),
    ))
}
