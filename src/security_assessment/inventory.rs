//! Installed metadata observations without importing the inspected environment.

use super::model::*;
use super::source::{SourcePolicy, normalize_name};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryRequest {
    pub project_root: PathBuf,
    pub environment: Option<PathBuf>,
    pub trusted_python: PathBuf,
    pub target: InventoryTarget,
    pub backend: InventoryBackend,
    pub scope: InventoryScope,
    pub source_policy: SourcePolicy,
    pub limits: ObservationLimits,
}

impl InventoryRequest {
    pub fn installed(project_root: &Path, trusted_python: &Path) -> Self {
        Self {
            project_root: project_root.into(),
            environment: None,
            trusted_python: trusted_python.into(),
            target: InventoryTarget::Installed,
            backend: InventoryBackend::Uv,
            scope: InventoryScope::default(),
            source_policy: SourcePolicy::default(),
            limits: ObservationLimits::default(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectorResult {
    generator_version: String,
    implementation: String,
    python_version: String,
    os: String,
    architecture: String,
    libc: Option<String>,
    deployment: Option<String>,
    tags: Vec<String>,
}

pub fn observe_inventory(request: &InventoryRequest, observed_at: u64) -> InventoryObservation {
    let mut result = InventoryObservation {
        observation_version: 1,
        inventory_id: String::new(),
        observation_id: String::new(),
        observed_at,
        target: None,
        packages: Vec::new(),
        direct_constraints: Vec::new(),
        coverage: ObservationCoverage::default(),
        diagnostics: Vec::new(),
    };
    let started = Instant::now();
    if let Err(diagnostic) = observe(request, started, &mut result) {
        result.coverage.inventory_instances.status = if diagnostic.code.contains("UNSUPPORTED") {
            CoverageStatus::Unsupported
        } else {
            CoverageStatus::Error
        };
        result
            .coverage
            .inventory_instances
            .reasons
            .push(diagnostic.code.clone());
        result.diagnostics.push(diagnostic);
    }
    let semantic_packages: Vec<_> = result
        .packages
        .iter()
        .map(|p| {
            (
                &p.instance_id,
                &p.name,
                &p.version,
                &p.source,
                &p.source_mapping,
                &p.scope_variant,
                p.requires_dist
                    .iter()
                    .map(|c| (&c.requirement, &c.origin))
                    .collect::<Vec<_>>(),
                &p.coverage,
            )
        })
        .collect();
    let semantic_target = result.target.as_ref().map(|target| {
        (
            &target.project_root,
            &target.environment_root,
            &target.interpreter,
            &target.inspector,
            &target.interpreter_digest,
            target.kind,
            target.backend,
            &target.scope,
            &target.tag_profile,
        )
    });
    let semantic_constraints = result
        .direct_constraints
        .iter()
        .map(|c| (&c.requirement, &c.origin))
        .collect::<Vec<_>>();
    result.inventory_id = semantic_digest(&(
        semantic_target,
        semantic_packages,
        semantic_constraints,
        &result.coverage,
    ));
    result.observation_id = semantic_digest(&(
        &result.inventory_id,
        observed_at,
        result.target.as_ref().map(|t| {
            (
                &t.environment_fingerprint,
                &t.project_digest,
                &t.lock_digest,
            )
        }),
        result
            .packages
            .iter()
            .map(|p| (&p.metadata_digest, &p.direct_url_digest))
            .collect::<Vec<_>>(),
    ));
    result
}

fn observe(
    request: &InventoryRequest,
    started: Instant,
    result: &mut InventoryObservation,
) -> Result<(), ObservationDiagnostic> {
    request.limits.validate()?;
    request.source_policy.validate()?;
    if request.target != InventoryTarget::Installed {
        return Err(diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "Only explicitly selected project installed environments are supported by this inventory adapter.",
        ));
    }
    let project = request.project_root.canonicalize().map_err(|_| {
        diag(
            "E_SECURITY_INVENTORY",
            "The selected project directory is unavailable.",
        )
    })?;
    let project_dir =
        Dir::open_ambient_dir(&project, cap_std::ambient_authority()).map_err(|_| {
            diag(
                "E_SECURITY_INVENTORY",
                "The selected project directory cannot be read.",
            )
        })?;
    let project_bytes = read_optional(
        &project_dir,
        Path::new("pyproject.toml"),
        request.limits.max_metadata_bytes,
    )?
    .ok_or_else(|| {
        diag(
            "E_SECURITY_INVENTORY",
            "An explicit project pyproject.toml is required; system fallback is forbidden.",
        )
    })?;
    let parsed_project: toml::Value =
        toml::from_str(std::str::from_utf8(&project_bytes).map_err(|_| {
            diag(
                "E_SECURITY_METADATA",
                "Project metadata must be UTF-8 TOML.",
            )
        })?)
        .map_err(|_| diag("E_SECURITY_METADATA", "Project metadata is malformed."))?;
    let selected = request.environment.clone().unwrap_or_else(|| {
        project.join(match request.backend {
            InventoryBackend::Uv => ".venv",
            InventoryBackend::Native => ".pybun/venv",
        })
    });
    let selected = if selected.is_absolute() {
        selected
    } else {
        project.join(selected)
    };
    let environment = selected.canonicalize().map_err(|_| {
        diag(
            "E_SECURITY_INVENTORY",
            "The selected project environment is missing; system fallback is forbidden.",
        )
    })?;
    let environment_dir = Dir::open_ambient_dir(&environment, cap_std::ambient_authority())
        .map_err(|_| {
            diag(
                "E_SECURITY_INVENTORY",
                "The selected environment cannot be read.",
            )
        })?;
    let config_bytes = read_optional(
        &environment_dir,
        Path::new("pyvenv.cfg"),
        request.limits.max_metadata_bytes,
    )?
    .ok_or_else(|| {
        diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "The selected environment has no supported CPython venv configuration.",
        )
    })?;
    let config = parse_venv_config(&config_bytes)?;
    if config
        .get("include-system-site-packages")
        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
    {
        return Err(diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "System-site environments cannot prove a project-only installed inventory.",
        ));
    }
    if config
        .get("implementation")
        .is_some_and(|v| !v.eq_ignore_ascii_case("cpython"))
    {
        return Err(diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "Only the CPython installed metadata profile is supported.",
        ));
    }
    let version = ["version", "version_info", "python-version"]
        .iter()
        .find_map(|key| config.get(*key))
        .and_then(|v| parse_python_version(v))
        .ok_or_else(|| {
            diag(
                "E_SECURITY_UNSUPPORTED_INVENTORY",
                "The environment does not declare an exact CPython version.",
            )
        })?;
    let inspector = request.trusted_python.canonicalize().map_err(|_| {
        diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "An explicitly trusted CPython inspector is required.",
        )
    })?;
    let probe = inspect_python(&inspector, &request.limits, started)?;
    if probe.implementation != "cpython"
        || parse_python_version(&probe.python_version).as_ref() != Some(&version)
    {
        return Err(diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "The trusted inspector does not match the selected environment's CPython version.",
        ));
    }
    if !matches!(probe.os.as_str(), "linux" | "darwin" | "win32") || probe.tags.is_empty() {
        return Err(diag(
            "E_SECURITY_UNSUPPORTED_SCOPE",
            "The inspector did not produce a supported target tag profile.",
        ));
    }
    let interpreter = environment.join(if probe.os == "win32" {
        "Scripts/python.exe"
    } else {
        "bin/python"
    });
    if !interpreter.is_file() {
        return Err(diag(
            "E_SECURITY_INVENTORY",
            "The selected environment has no interpreter file.",
        ));
    }
    let (interpreter_digest, interpreter_identity_evidence) =
        verify_interpreter(&interpreter, &inspector, &environment, &environment_dir)?;
    let platform_path = if probe.os == "win32" {
        PathBuf::from("Lib/site-packages")
    } else {
        PathBuf::from(format!(
            "lib/python{}.{}/site-packages",
            version.0, version.1
        ))
    };
    // Use a directory capability: metadata symlinks cannot escape this root.
    let packages_dir = environment_dir.open_dir(&platform_path).map_err(|_| {
        diag(
            "E_SECURITY_INVENTORY",
            "The selected environment's distribution directory is unavailable.",
        )
    })?;
    let mut entries = Vec::new();
    for entry in packages_dir.entries().map_err(|_| {
        diag(
            "E_SECURITY_INVENTORY",
            "Installed distributions cannot be enumerated.",
        )
    })? {
        check_deadline(started, &request.limits)?;
        let entry = entry.map_err(|_| {
            diag(
                "E_SECURITY_INVENTORY",
                "Installed distribution enumeration failed.",
            )
        })?;
        if entries.len() >= request.limits.max_inventory_instances.saturating_mul(20) {
            return Err(limit_error());
        }
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.file_name());
    let mut scope = request.scope.clone();
    scope.members.sort();
    scope.members.dedup();
    scope.groups.sort();
    scope.groups.dedup();
    scope.extras.sort();
    scope.extras.dedup();
    let scope_variant = semantic_digest(&scope);
    let mut path_extensions = Vec::new();
    for entry in entries {
        check_deadline(started, &request.limits)?;
        let filename = entry.file_name();
        let Some(name) = filename.to_str() else {
            return Err(diag(
                "E_SECURITY_METADATA",
                "Non-UTF8 distribution paths are unsupported.",
            ));
        };
        if name.ends_with(".pth") || name.ends_with(".egg-link") {
            let bytes = read_optional(
                &packages_dir,
                Path::new(name),
                request.limits.max_metadata_bytes,
            )?
            .ok_or_else(|| {
                diag(
                    "E_SECURITY_INVENTORY_PATH",
                    "A path-extension file changed during inventory.",
                )
            })?;
            path_extensions.push((name.to_owned(), crate::security::sha256_bytes(&bytes)));
            let text = std::str::from_utf8(&bytes).map_err(|_| {
                diag(
                    "E_SECURITY_METADATA",
                    "Path-extension metadata must be UTF-8.",
                )
            })?;
            if text
                .lines()
                .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            {
                result.coverage.inventory_instances.status = CoverageStatus::Partial;
                let reason = "E_SECURITY_UNSUPPORTED_PATH_EXTENSION";
                if !result
                    .coverage
                    .inventory_instances
                    .reasons
                    .iter()
                    .any(|r| r == reason)
                {
                    result
                        .coverage
                        .inventory_instances
                        .reasons
                        .push(reason.into());
                    result.diagnostics.push(diag(reason, "Path-extension metadata may expose additional distributions; it was not executed or traversed."));
                }
            }
            continue;
        }
        if !(name.ends_with(".dist-info") || name.ends_with(".egg-info")) {
            continue;
        }
        result.coverage.inventory_instances.requested += 1;
        if result.coverage.inventory_instances.requested > request.limits.max_inventory_instances {
            return Err(limit_error());
        }
        let outcome =
            read_distribution(&packages_dir, name, &platform_path, &scope_variant, request);
        match outcome {
            Ok(package) => {
                result.coverage.inventory_instances.complete += 1;
                if package.source_mapping.is_none() {
                    result.diagnostics.push(ObservationDiagnostic { code:"E_SECURITY_SOURCE_MAPPING_UNKNOWN".into(),message:"No approved upstream mapping is available for an installed package instance.".into(),instance_id:Some(package.instance_id.clone()) });
                }
                result.packages.push(package);
            }
            Err(error) => {
                result.coverage.inventory_instances.errors += 1;
                result
                    .coverage
                    .inventory_instances
                    .reasons
                    .push(error.code.clone());
                result.diagnostics.push(error);
            }
        }
    }
    if result.coverage.inventory_instances.errors > 0 {
        result.coverage.inventory_instances.status = if result.packages.is_empty() {
            CoverageStatus::Error
        } else {
            CoverageStatus::Partial
        };
    }
    result.direct_constraints = direct_constraints(&parsed_project, &scope, &project_bytes)?;
    let lock_name = match request.backend {
        InventoryBackend::Uv => "uv.lock",
        InventoryBackend::Native => "pybun.lockb",
    };
    let lock_digest = read_optional(
        &project_dir,
        Path::new(lock_name),
        request.limits.max_response_bytes,
    )?
    .map(|b| crate::security::sha256_bytes(&b));
    let mut tags = probe.tags;
    let original = tags.len();
    tags.sort();
    tags.dedup();
    if tags.len() != original
        || tags.len() > 20000
        || tags.iter().any(|tag| {
            tag.len() > 256
                || tag.split('-').count() != 3
                || !tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        })
    {
        return Err(diag(
            "E_SECURITY_UNSUPPORTED_SCOPE",
            "The target tag profile is malformed.",
        ));
    }
    let tag_profile = TargetTagProfile {
        profile_version: 1,
        generator: "pypa-packaging-isolated".into(),
        generator_version: probe.generator_version,
        digest: semantic_digest(&tags),
        tags,
        implementation: probe.implementation,
        python_version: probe.python_version,
        os: probe.os,
        architecture: probe.architecture,
        libc: probe.libc,
        deployment: probe.deployment,
    };
    let environment_fingerprint = semantic_digest(&(
        &environment,
        &config,
        &tag_profile.digest,
        &path_extensions,
        result
            .packages
            .iter()
            .map(|p| (&p.instance_id, &p.metadata_digest, &p.direct_url_digest))
            .collect::<Vec<_>>(),
    ));
    check_deadline(started, &request.limits)?;
    result.target = Some(ObservedTarget {
        project_root: project,
        environment_root: environment,
        interpreter,
        inspector,
        interpreter_digest,
        interpreter_identity_evidence,
        kind: request.target,
        backend: request.backend,
        scope,
        tag_profile,
        environment_fingerprint,
        project_digest: Some(crate::security::sha256_bytes(&project_bytes)),
        lock_digest,
    });
    check_deadline(started, &request.limits)?;
    Ok(())
}

fn read_distribution(
    packages: &Dir,
    name: &str,
    relative: &Path,
    scope_variant: &str,
    request: &InventoryRequest,
) -> Result<PackageInstance, ObservationDiagnostic> {
    let metadata = packages.symlink_metadata(name).map_err(|_| {
        diag(
            "E_SECURITY_METADATA",
            "An installed distribution cannot be inspected.",
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(diag(
            "E_SECURITY_INVENTORY_PATH",
            "Distribution symlinks are not followed.",
        ));
    }
    let (bytes, direct_url, metadata_filename) = if metadata.is_dir() {
        let dir = packages.open_dir(name).map_err(|_| {
            diag(
                "E_SECURITY_INVENTORY_PATH",
                "Distribution metadata is outside the authorized environment.",
            )
        })?;
        let filename = if name.ends_with(".dist-info") {
            "METADATA"
        } else {
            "PKG-INFO"
        };
        let metadata = read_optional(&dir, Path::new(filename), request.limits.max_metadata_bytes)?
            .ok_or_else(|| {
                diag(
                    "E_SECURITY_METADATA",
                    "Installed distribution metadata is missing.",
                )
            })?;
        let origin = read_optional(
            &dir,
            Path::new("direct_url.json"),
            request.limits.max_metadata_bytes,
        )?;
        (metadata, origin, Some(filename))
    } else if metadata.is_file() && name.ends_with(".egg-info") {
        (
            read_optional(packages, Path::new(name), request.limits.max_metadata_bytes)?
                .ok_or_else(|| {
                    diag(
                        "E_SECURITY_METADATA",
                        "Installed distribution metadata is missing.",
                    )
                })?,
            None,
            None,
        )
    } else {
        return Err(diag(
            "E_SECURITY_METADATA",
            "Unsupported installed distribution metadata layout.",
        ));
    };
    let fields = parse_metadata(&bytes)?;
    let get_one = |key: &str| {
        fields
            .get(key)
            .filter(|v| v.len() == 1)
            .and_then(|v| v.first())
            .ok_or_else(|| {
                diag(
                    "E_SECURITY_METADATA",
                    "Distribution name/version metadata is missing or ambiguous.",
                )
            })
    };
    let normalized = normalize_name(get_one("name")?)?;
    let version = get_one("version")?
        .parse::<pep440_rs::Version>()
        .map_err(|_| {
            diag(
                "E_SECURITY_METADATA",
                "Installed metadata has an invalid PEP 440 version.",
            )
        })?
        .to_string();
    let (kind, origin_identity) = if let Some(origin) = &direct_url {
        direct_url_kind(origin)?
    } else {
        (SourceKind::Unknown, None)
    };
    let source = request.source_policy.map_package_with_origin(
        &normalized,
        name,
        kind,
        origin_identity.as_deref(),
    )?;
    let distribution_path = relative.join(name).to_string_lossy().replace('\\', "/");
    let instance_id = semantic_digest(&(
        &normalized,
        &version,
        &source.source,
        scope_variant,
        &distribution_path,
    ));
    let mapping_missing = source.mapping.is_none();
    let metadata_path = match metadata_filename {
        Some(filename) => format!("{distribution_path}/{filename}"),
        None => distribution_path.clone(),
    };
    let requires_dist = fields
        .get("requires-dist")
        .into_iter()
        .flatten()
        .map(|value| ConstraintEvidence {
            requirement: crate::support_bundle::redact_text(value),
            origin: format!("{metadata_path}:Requires-Dist"),
            digest: crate::security::sha256_bytes(value.as_bytes()),
        })
        .collect();
    Ok(PackageInstance {
        instance_id,
        name: normalized,
        version,
        source: source.source,
        source_mapping: source.mapping,
        origin_identity,
        scope_variant: scope_variant.into(),
        distribution_path,
        metadata_digest: crate::security::sha256_bytes(&bytes),
        direct_url_digest: direct_url
            .as_ref()
            .map(|b| crate::security::sha256_bytes(b)),
        requires_dist,
        coverage: CoverageUnit {
            status: if mapping_missing {
                CoverageStatus::Partial
            } else {
                CoverageStatus::Complete
            },
            requested: 1,
            complete: usize::from(!mapping_missing),
            partial: usize::from(mapping_missing),
            reasons: if mapping_missing {
                vec!["E_SECURITY_SOURCE_MAPPING_UNKNOWN".into()]
            } else {
                Vec::new()
            },
            ..Default::default()
        },
    })
}

fn parse_metadata(bytes: &[u8]) -> Result<BTreeMap<String, Vec<String>>, ObservationDiagnostic> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        diag(
            "E_SECURITY_METADATA",
            "Distribution metadata must be UTF-8.",
        )
    })?;
    let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut last = None::<String>;
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            let key = last.as_ref().ok_or_else(|| {
                diag(
                    "E_SECURITY_METADATA",
                    "Distribution metadata contains an invalid folded header.",
                )
            })?;
            let value = fields
                .get_mut(key)
                .and_then(|v| v.last_mut())
                .ok_or_else(|| {
                    diag(
                        "E_SECURITY_METADATA",
                        "Distribution metadata contains an invalid folded header.",
                    )
                })?;
            value.push(' ');
            value.push_str(line.trim());
        } else {
            let (key, value) = line.split_once(':').ok_or_else(|| {
                diag(
                    "E_SECURITY_METADATA",
                    "Distribution metadata has a malformed header.",
                )
            })?;
            if key.is_empty()
                || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || value.len() > 16384
            {
                return Err(diag(
                    "E_SECURITY_METADATA",
                    "Distribution metadata header is invalid or oversized.",
                ));
            }
            let key = key.to_ascii_lowercase();
            fields
                .entry(key.clone())
                .or_default()
                .push(value.trim().into());
            last = Some(key);
        }
    }
    Ok(fields)
}

fn direct_url_kind(bytes: &[u8]) -> Result<(SourceKind, Option<String>), ObservationDiagnostic> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
        diag(
            "E_SECURITY_METADATA",
            "Distribution origin metadata is malformed.",
        )
    })?;
    let url = value
        .get("url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            diag(
                "E_SECURITY_METADATA",
                "Distribution origin metadata has no URL.",
            )
        })?;
    let mut canonical_url = reqwest::Url::parse(url).map_err(|_| {
        diag(
            "E_SECURITY_METADATA",
            "Distribution origin metadata has an invalid URL.",
        )
    })?;
    canonical_url.set_username("").ok();
    canonical_url.set_password(None).ok();
    canonical_url.set_query(None);
    canonical_url.set_fragment(None);
    let origin_identity = semantic_digest(&(
        canonical_url.as_str(),
        value
            .pointer("/vcs_info/vcs")
            .and_then(serde_json::Value::as_str),
        value
            .pointer("/vcs_info/commit_id")
            .and_then(serde_json::Value::as_str),
        value
            .get("subdirectory")
            .and_then(serde_json::Value::as_str),
        value
            .pointer("/dir_info/editable")
            .and_then(serde_json::Value::as_bool),
    ));
    let kind = if value
        .pointer("/dir_info/editable")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        SourceKind::Editable
    } else if value.get("vcs_info").is_some() {
        SourceKind::Vcs
    } else {
        SourceKind::DirectUrl
    };
    Ok((kind, Some(origin_identity)))
}

fn parse_venv_config(bytes: &[u8]) -> Result<BTreeMap<String, String>, ObservationDiagnostic> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "The venv configuration is not UTF-8.",
        )
    })?;
    let mut values = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (key, value) = line.split_once('=').ok_or_else(|| {
            diag(
                "E_SECURITY_UNSUPPORTED_INVENTORY",
                "The venv configuration is malformed.",
            )
        })?;
        let key = key.trim().to_ascii_lowercase();
        if values.insert(key, value.trim().to_string()).is_some() {
            return Err(diag(
                "E_SECURITY_UNSUPPORTED_INVENTORY",
                "The venv configuration has duplicate keys.",
            ));
        }
    }
    Ok(values)
}

fn parse_python_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split('.');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ))
}

fn read_optional(
    dir: &Dir,
    path: &Path,
    limit: usize,
) -> Result<Option<Vec<u8>>, ObservationDiagnostic> {
    match dir.symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(diag(
                "E_SECURITY_INVENTORY",
                "Authorized metadata cannot be inspected.",
            ));
        }
        Ok(m) if m.file_type().is_symlink() || !m.is_file() => {
            return Err(diag(
                "E_SECURITY_INVENTORY_PATH",
                "Metadata must be a regular file inside its authorized directory.",
            ));
        }
        Ok(_) => {}
    }
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = dir.open_with(path, &options).map_err(|_| {
        diag(
            "E_SECURITY_INVENTORY_PATH",
            "Metadata cannot be read within its authorized directory.",
        )
    })?;
    if !file
        .metadata()
        .map_err(|_| {
            diag(
                "E_SECURITY_INVENTORY_PATH",
                "Opened metadata identity cannot be verified.",
            )
        })?
        .is_file()
    {
        return Err(diag(
            "E_SECURITY_INVENTORY_PATH",
            "Opened metadata must be a regular file.",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| diag("E_SECURITY_INVENTORY", "Metadata read failed."))?;
    if bytes.len() > limit {
        return Err(limit_error());
    }
    Ok(Some(bytes))
}

fn verify_interpreter(
    selected: &Path,
    inspector: &Path,
    environment: &Path,
    environment_dir: &Dir,
) -> Result<(String, String), ObservationDiagnostic> {
    let resolved = selected.canonicalize().map_err(|_| {
        diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "The selected interpreter identity cannot be established.",
        )
    })?;
    if resolved == inspector {
        return Ok((
            bounded_trusted_digest(inspector)?,
            "canonical_trusted_interpreter".into(),
        ));
    }
    let relative = resolved.strip_prefix(environment).map_err(|_| diag("E_SECURITY_UNSUPPORTED_INVENTORY", "The selected environment interpreter does not resolve to the explicitly trusted inspector."))?;
    let selected_bytes =
        read_optional(environment_dir, relative, 64 * 1024 * 1024)?.ok_or_else(|| {
            diag(
                "E_SECURITY_UNSUPPORTED_INVENTORY",
                "The selected interpreter identity cannot be established.",
            )
        })?;
    let selected_digest = crate::security::sha256_bytes(&selected_bytes);
    if selected_digest != bounded_trusted_digest(inspector)? {
        return Err(diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "The selected environment interpreter is not byte-identical to the trusted inspector.",
        ));
    }
    Ok((
        selected_digest,
        "byte_identical_trusted_interpreter_copy".into(),
    ))
}

fn bounded_trusted_digest(path: &Path) -> Result<String, ObservationDiagnostic> {
    let file = std::fs::File::open(path).map_err(|_| {
        diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "The trusted interpreter identity cannot be read.",
        )
    })?;
    if !file
        .metadata()
        .map_err(|_| {
            diag(
                "E_SECURITY_UNSUPPORTED_INVENTORY",
                "The trusted interpreter identity cannot be verified.",
            )
        })?
        .is_file()
    {
        return Err(diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "The trusted interpreter must be a regular file.",
        ));
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            diag(
                "E_SECURITY_UNSUPPORTED_INVENTORY",
                "The trusted interpreter identity could not be read.",
            )
        })?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(limit_error());
    }
    Ok(crate::security::sha256_bytes(&bytes))
}

fn direct_constraints(
    project: &toml::Value,
    scope: &InventoryScope,
    bytes: &[u8],
) -> Result<Vec<ConstraintEvidence>, ObservationDiagnostic> {
    let mut result = Vec::new();
    let mut add =
        |value: Option<&toml::Value>, origin: String| -> Result<(), ObservationDiagnostic> {
            if let Some(value) = value {
                for dependency in value.as_array().ok_or_else(|| {
                    diag(
                        "E_SECURITY_METADATA",
                        "Project dependency declarations are malformed.",
                    )
                })? {
                    let requirement = dependency.as_str().ok_or_else(|| {
                        diag(
                            "E_SECURITY_UNSUPPORTED_SCOPE",
                            "Included dependency groups require a supported scope adapter.",
                        )
                    })?;
                    result.push(ConstraintEvidence {
                        requirement: crate::support_bundle::redact_text(requirement),
                        origin: origin.clone(),
                        digest: crate::security::sha256_bytes(bytes),
                    });
                }
            }
            Ok(())
        };
    add(
        project.get("project").and_then(|p| p.get("dependencies")),
        "pyproject.toml:project.dependencies".into(),
    )?;
    for extra in &scope.extras {
        let declaration = project
            .get("project")
            .and_then(|p| p.get("optional-dependencies"))
            .and_then(|p| p.get(extra))
            .ok_or_else(|| {
                diag(
                    "E_SECURITY_UNSUPPORTED_SCOPE",
                    "The selected optional dependency group is unavailable.",
                )
            })?;
        add(
            Some(declaration),
            format!("pyproject.toml:project.optional-dependencies.{extra}"),
        )?;
    }
    for group in &scope.groups {
        let declaration = project
            .get("dependency-groups")
            .and_then(|p| p.get(group))
            .ok_or_else(|| {
                diag(
                    "E_SECURITY_UNSUPPORTED_SCOPE",
                    "The selected dependency group is unavailable.",
                )
            })?;
        add(
            Some(declaration),
            format!("pyproject.toml:dependency-groups.{group}"),
        )?;
    }
    if !scope.members.is_empty() {
        return Err(diag(
            "E_SECURITY_UNSUPPORTED_SCOPE",
            "Explicit workspace member constraints require a supported scope adapter.",
        ));
    }
    result.sort_by(|a, b| (&a.origin, &a.requirement).cmp(&(&b.origin, &b.requirement)));
    Ok(result)
}

fn inspect_python(
    python: &Path,
    limits: &ObservationLimits,
    started: Instant,
) -> Result<InspectorResult, ObservationDiagnostic> {
    let sources = serde_json::json!({
        "26.3":{
        "_elffile":include_str!("vendor/packaging/_elffile.py"),"_manylinux":include_str!("vendor/packaging/_manylinux.py"),
        "_musllinux":include_str!("vendor/packaging/_musllinux.py"),"tags":include_str!("vendor/packaging/tags.py"),
        },
        "25.0":{
        "_elffile":include_str!("vendor/packaging25/_elffile.py"),"_manylinux":include_str!("vendor/packaging25/_manylinux.py"),
        "_musllinux":include_str!("vendor/packaging25/_musllinux.py"),"tags":include_str!("vendor/packaging25/tags.py"),
        },
    });
    let mut command = Command::new(python);
    command
        .args(["-I", "-S", "-B", "-c", include_str!("inspector.py")])
        .env_clear()
        .current_dir(python.parent().unwrap_or(Path::new("/")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", root);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|_| {
        diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "The trusted CPython inspector could not start.",
        )
    })?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| diag("E_SECURITY_INVENTORY", "Inspector input is unavailable."))?;
    let input = serde_json::to_vec(&sources).map_err(|_| {
        diag(
            "E_SECURITY_INVENTORY",
            "Inspector input serialization failed.",
        )
    })?;
    let writer = std::thread::spawn(move || {
        let mut stdin = stdin;
        let _ = stdin.write_all(&input);
    });
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout = bounded_reader(
        child
            .stdout
            .take()
            .ok_or_else(|| diag("E_SECURITY_INVENTORY", "Inspector output is unavailable."))?,
        limits.max_response_bytes,
        overflow.clone(),
    );
    let stderr = bounded_reader(
        child.stderr.take().ok_or_else(|| {
            diag(
                "E_SECURITY_INVENTORY",
                "Inspector error output is unavailable.",
            )
        })?,
        16384,
        overflow.clone(),
    );
    let mut status = None;
    let mut out = None;
    let mut err = None;
    loop {
        if out.is_none() {
            out = stdout.try_recv().ok();
        }
        if err.is_none() {
            err = stderr.try_recv().ok();
        }
        if status.is_none() {
            status = child.try_wait().map_err(|_| {
                diag(
                    "E_SECURITY_INVENTORY",
                    "Inspector execution status is unavailable.",
                )
            })?;
        }
        if overflow.load(Ordering::SeqCst)
            || started.elapsed() >= Duration::from_millis(limits.total_timeout_ms)
        {
            crate::proc_exec::kill_process_tree(&mut child);
            let _ = child.wait();
            let _ = writer.join();
            return Err(diag(
                "E_SECURITY_LIMIT",
                "Inspector exceeded its output or execution deadline.",
            ));
        }
        if status.is_some() && out.is_some() && err.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let _ = writer.join();
    if !status.is_some_and(|s| s.success()) {
        return Err(diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "The trusted CPython inspector does not support this target profile.",
        ));
    }
    serde_json::from_slice(&out.unwrap_or_default()).map_err(|_| {
        diag(
            "E_SECURITY_UNSUPPORTED_INVENTORY",
            "The trusted CPython inspector returned an invalid target profile.",
        )
    })
}

fn bounded_reader<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> mpsc::Receiver<Vec<u8>> {
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = reader
            .by_ref()
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes);
        if bytes.len() > limit {
            overflow.store(true, Ordering::SeqCst);
        }
        let _ = send.send(bytes);
    });
    receive
}

fn check_deadline(
    started: Instant,
    limits: &ObservationLimits,
) -> Result<(), ObservationDiagnostic> {
    if started.elapsed() >= Duration::from_millis(limits.total_timeout_ms) {
        Err(limit_error())
    } else {
        Ok(())
    }
}
fn limit_error() -> ObservationDiagnostic {
    diag(
        "E_SECURITY_LIMIT",
        "Inventory exceeded its authorized size or execution budget.",
    )
}
fn diag(code: &str, message: &str) -> ObservationDiagnostic {
    ObservationDiagnostic::new(code, message)
}
