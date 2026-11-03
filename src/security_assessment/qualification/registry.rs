//! Published file evidence from an approved distribution's JSON Simple index.

use crate::security_assessment::{
    CoverageStatus, CoverageUnit, ObservationDiagnostic, TargetTagProfile, normalize_name,
    semantic_digest,
};
use pep440_rs::{Version, VersionSpecifiers};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseAvailability {
    BinaryWheelAvailable,
    SourceBuildRequired,
    Yanked,
    NoCompatibleWheel,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedFile {
    pub filename: String,
    pub url: Option<String>,
    pub hashes: BTreeMap<String, String>,
    pub size: Option<u64>,
    pub requires_python: Option<String>,
    pub requires_python_declared: bool,
    pub requires_python_satisfied: Option<bool>,
    pub yanked: Option<bool>,
    pub source_distribution: bool,
    pub matched_tags: Vec<String>,
    pub coverage: CoverageUnit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryRelease {
    pub version: String,
    pub prerelease: bool,
    pub availability: ReleaseAvailability,
    pub files: Vec<PublishedFile>,
    pub coverage: CoverageUnit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCatalog {
    pub distribution: String,
    pub enumeration_digest: String,
    pub releases: Vec<RegistryRelease>,
    pub unknown_files: usize,
    pub unknown_versions: usize,
    pub coverage: CoverageUnit,
    pub diagnostics: Vec<ObservationDiagnostic>,
}

/// This pure parser does not authorize an endpoint or fetch file URLs. Its
/// caller must obtain this metadata from the same currently approved source.
pub fn parse_registry_catalog(
    distribution: &str,
    value: &Value,
    target: &TargetTagProfile,
) -> RegistryCatalog {
    let mut result = RegistryCatalog {
        distribution: distribution.into(),
        enumeration_digest: String::new(),
        releases: vec![],
        unknown_files: 0,
        unknown_versions: 0,
        coverage: CoverageUnit::default(),
        diagnostics: vec![],
    };
    let name = normalize_name(distribution).ok();
    let returned_name = value
        .get("name")
        .and_then(Value::as_str)
        .and_then(|name| normalize_name(name).ok());
    let api_minor = value
        .pointer("/meta/api-version")
        .and_then(Value::as_str)
        .and_then(|version| {
            let (major, minor) = version.split_once('.')?;
            if major != "1" || minor.is_empty() || !minor.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            minor.parse::<u32>().ok().filter(|minor| *minor <= 4)
        });
    let python = target.python_version.parse::<Version>();
    let files = value.get("files").and_then(Value::as_array);
    if name.is_none()
        || returned_name != name
        || api_minor.is_none()
        || python.is_err()
        || target.tags.is_empty()
        || files.is_none()
        || (api_minor.is_some_and(|minor| minor >= 1)
            && !value.get("versions").is_some_and(Value::is_array))
        || value
            .get("versions")
            .is_some_and(|versions| !versions.is_array())
    {
        result.coverage.status = CoverageStatus::Error;
        result.coverage.errors = 1;
        result
            .coverage
            .reasons
            .push("E_SECURITY_REGISTRY_SCHEMA".into());
        result.diagnostics.push(schema_error());
        return result;
    }
    let name = name.unwrap();
    let python = python.unwrap();
    let files = files.unwrap();
    let api_minor = api_minor.unwrap();
    result.distribution = name.clone();
    result.coverage.requested = files.len();
    let mut releases: BTreeMap<Version, RegistryRelease> = BTreeMap::new();
    let mut declared_versions = BTreeSet::new();
    let mut raw_versions = BTreeSet::new();
    if let Some(versions) = value.get("versions").and_then(Value::as_array) {
        result.coverage.requested += versions.len();
        for raw in versions {
            let parsed = raw.as_str().and_then(|text| {
                if !raw_versions.insert(text) {
                    return None;
                }
                text.parse::<Version>().ok()
            });
            if let Some(version) = parsed {
                result.coverage.complete += 1;
                declared_versions.insert(version.clone());
                let release = releases
                    .entry(version.clone())
                    .or_insert_with(|| empty_release(&version));
                let spelling = version.to_string();
                if spelling < release.version {
                    release.version = spelling;
                }
            } else {
                result.unknown_versions += 1;
                result.coverage.partial += 1;
            }
        }
    }
    for item in files {
        let parsed = parse_file(&name, item, target, &python, api_minor);
        let Some((version, mut file)) = parsed else {
            result.unknown_files += 1;
            result.coverage.partial += 1;
            continue;
        };
        if value.get("versions").is_some() && !declared_versions.contains(&version) {
            file.coverage = incomplete_file();
        }
        if file.coverage.status == CoverageStatus::Complete {
            result.coverage.complete += 1;
        } else {
            result.coverage.partial += 1;
        }
        let normalized = version.to_string();
        let release = releases
            .entry(version.clone())
            .or_insert_with(|| empty_release(&version));
        // Equivalent PEP 440 spellings may have separate index files. Keep all
        // files and choose a stable representative independent of input order.
        if normalized < release.version {
            release.version = normalized;
        }
        release.files.push(file);
    }
    for release in releases.values_mut() {
        release.files.sort_by(|a, b| {
            a.filename
                .cmp(&b.filename)
                .then_with(|| semantic_digest(a).cmp(&semantic_digest(b)))
        });
        release.coverage.requested = release.files.len();
        release.coverage.complete = release
            .files
            .iter()
            .filter(|f| f.coverage.status == CoverageStatus::Complete)
            .count();
        release.coverage.partial = release.files.len() - release.coverage.complete;
        if release.coverage.partial > 0 {
            release.coverage.status = CoverageStatus::Partial;
        }
        release.availability = availability(&release.files);
    }
    // Traversal depends on version positions, not mutable file metadata.
    // Availability and minimum proofs still use the current complete catalog.
    let version_keys: Vec<_> = releases
        .keys()
        .map(|version| {
            let release = version.release();
            let end = release
                .iter()
                .rposition(|part| *part != 0)
                .map_or(1, |index| index + 1);
            version
                .clone()
                .with_release(release[..end].to_vec())
                .to_string()
        })
        .collect();
    result.enumeration_digest = semantic_digest(&(&result.distribution, version_keys));
    result.releases = releases.into_values().collect();
    if result.coverage.partial > 0 {
        result.coverage.status = CoverageStatus::Partial;
        result
            .coverage
            .reasons
            .push("E_SECURITY_REGISTRY_SCHEMA".into());
        result.diagnostics.push(schema_error());
    }
    result
}

fn parse_file(
    distribution: &str,
    value: &Value,
    target: &TargetTagProfile,
    python: &Version,
    api_minor: u32,
) -> Option<(Version, PublishedFile)> {
    let filename = value.get("filename")?.as_str()?;
    if filename.len() > 1024 || filename.contains(['/', '\\']) {
        return None;
    }
    let (version, source_distribution, matched_tags) =
        parse_filename(distribution, filename, &target.tags)?;
    let mut file = PublishedFile {
        filename: filename.into(),
        url: None,
        hashes: BTreeMap::new(),
        size: value.get("size").and_then(Value::as_u64),
        requires_python: None,
        requires_python_declared: false,
        requires_python_satisfied: Some(true),
        yanked: None,
        source_distribution,
        matched_tags,
        coverage: CoverageUnit {
            requested: 1,
            ..Default::default()
        },
    };
    let mut valid = true;
    file.url = value
        .get("url")
        .and_then(Value::as_str)
        .and_then(file_reference);
    if file.url.is_none() {
        valid = false;
    }
    if let Some(hashes) = value.get("hashes").and_then(Value::as_object) {
        for (kind, hash) in hashes {
            if let Some(hash) = hash.as_str().filter(|hash| valid_hash(kind, hash)) {
                file.hashes.insert(kind.clone(), hash.into());
            } else {
                valid = false;
            }
        }
    } else {
        valid = false;
    }
    if (api_minor >= 1 || value.get("size").is_some()) && file.size.is_none() {
        valid = false;
    }
    file.yanked = match value.get("yanked") {
        None | Some(Value::Bool(false)) => Some(false),
        Some(Value::Bool(true)) => Some(true),
        Some(Value::String(reason)) if !reason.is_empty() => Some(true),
        _ => {
            valid = false;
            None
        }
    };
    match value.get("requires-python") {
        None | Some(Value::Null) => {}
        Some(Value::String(requirement)) => {
            file.requires_python_declared = true;
            file.requires_python = Some(crate::support_bundle::redact_text(requirement));
            file.requires_python_satisfied = requirement
                .parse::<VersionSpecifiers>()
                .ok()
                .map(|spec| spec.contains(python));
            if file.requires_python_satisfied.is_none() {
                valid = false;
            }
        }
        Some(_) => {
            valid = false;
            file.requires_python_declared = true;
            file.requires_python_satisfied = None;
        }
    }
    if valid {
        file.coverage.complete = 1;
    } else {
        file.coverage = incomplete_file();
    }
    Some((version, file))
}

fn parse_filename(
    distribution: &str,
    filename: &str,
    target_tags: &[String],
) -> Option<(Version, bool, Vec<String>)> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let parts: Vec<_> = stem.split('-').collect();
        if !(parts.len() == 5 || parts.len() == 6)
            || normalize_name(parts[0]).ok().as_deref() != Some(distribution)
        {
            return None;
        }
        if parts.len() == 6
            && (!parts[2].as_bytes().first()?.is_ascii_digit()
                || !parts[2]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        {
            return None;
        }
        let version = parts[1].parse::<Version>().ok()?;
        let tags = &parts[parts.len() - 3..];
        if tags.iter().any(|field| {
            field.is_empty()
                || field.split('.').any(|component| {
                    component.is_empty()
                        || !component
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
        }) {
            return None;
        }
        let mut matched: Vec<_> = target_tags
            .iter()
            .filter(|tag| {
                let target: Vec<_> = tag.split('-').collect();
                target.len() == 3
                    && tags
                        .iter()
                        .zip(target)
                        .all(|(pattern, value)| pattern.split('.').any(|part| part == value))
            })
            .cloned()
            .collect();
        matched.sort();
        matched.dedup();
        return Some((version, false, matched));
    }
    let stem = [".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz"]
        .iter()
        .find_map(|suffix| filename.strip_suffix(suffix))?;
    let mut matches = stem.match_indices('-').filter_map(|(index, _)| {
        if normalize_name(&stem[..index]).ok().as_deref() != Some(distribution) {
            return None;
        }
        stem[index + 1..].parse::<Version>().ok()
    });
    let version = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some((version, true, vec![]))
}

fn availability(files: &[PublishedFile]) -> ReleaseAvailability {
    let usable = |file: &&PublishedFile| {
        file.coverage.status == CoverageStatus::Complete
            && file.yanked == Some(false)
            && file.requires_python_satisfied == Some(true)
    };
    if files
        .iter()
        .filter(usable)
        .any(|f| !f.source_distribution && !f.matched_tags.is_empty())
    {
        return ReleaseAvailability::BinaryWheelAvailable;
    }
    if files
        .iter()
        .any(|f| f.coverage.status != CoverageStatus::Complete)
    {
        return ReleaseAvailability::Unknown;
    }
    if files.iter().filter(usable).any(|f| f.source_distribution) {
        return ReleaseAvailability::SourceBuildRequired;
    }
    if files
        .iter()
        .any(|f| !f.source_distribution && !f.matched_tags.is_empty() && f.yanked == Some(true))
    {
        return ReleaseAvailability::Yanked;
    }
    ReleaseAvailability::NoCompatibleWheel
}

fn schema_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_REGISTRY_SCHEMA",
        "Registry metadata is missing, malformed, mismatched, or incomplete; lower releases have not all been conclusively excluded.",
    )
}

fn empty_release(version: &Version) -> RegistryRelease {
    RegistryRelease {
        version: version.to_string(),
        prerelease: version.is_pre() || version.is_dev(),
        availability: ReleaseAvailability::NoCompatibleWheel,
        files: vec![],
        coverage: CoverageUnit::default(),
    }
}

fn incomplete_file() -> CoverageUnit {
    CoverageUnit {
        status: CoverageStatus::Partial,
        requested: 1,
        partial: 1,
        reasons: vec!["E_SECURITY_REGISTRY_SCHEMA".into()],
        ..Default::default()
    }
}

fn valid_hash(kind: &str, digest: &str) -> bool {
    if kind.is_empty()
        || kind.len() > 128
        || digest.is_empty()
        || digest.len() > 512
        || !digest.len().is_multiple_of(2)
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    let expected = match kind.to_ascii_lowercase().as_str() {
        "md5" => Some(32),
        "sha1" => Some(40),
        "sha224" => Some(56),
        "sha256" | "sha3_256" => Some(64),
        "sha384" | "sha3_384" => Some(96),
        "sha512" | "sha3_512" | "blake2b" => Some(128),
        "sha3_224" => Some(56),
        "blake2s" => Some(64),
        _ => None,
    };
    expected.is_none_or(|size| digest.len() == size)
}

// Retain a redacted URI reference for provenance; no archive URL is fetched.
// The static base only validates relative-reference syntax and is never emitted.
fn file_reference(text: &str) -> Option<String> {
    if text.is_empty()
        || text.trim() != text
        || text.contains('\\')
        || text.chars().any(char::is_control)
    {
        return None;
    }
    let base = reqwest::Url::parse("https://reference.invalid/").expect("static reference base");
    let absolute = reqwest::Url::parse(text).is_ok();
    let mut url = base.join(text).ok()?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        return None;
    }
    url.set_username("").ok()?;
    url.set_password(None).ok()?;
    url.set_query(None);
    url.set_fragment(None);
    if absolute {
        Some(url.into())
    } else if text.starts_with("//") {
        url.as_str().strip_prefix("https:").map(str::to_owned)
    } else {
        Some(text.split(['?', '#']).next()?.into())
    }
}
