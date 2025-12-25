use crate::lockfile::PackageSource;
use semver::Version;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionSpec {
    /// ==version
    Exact(String),
    /// >=version
    Minimum(String),
    /// >version
    MinimumExclusive(String),
    /// <=version
    MaximumInclusive(String),
    /// <version
    Maximum(String),
    /// !=version
    NotEqual(String),
    /// ~=version (compatible release - PEP 440)
    Compatible(String),
    /// Any version
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub name: String,
    pub spec: VersionSpec,
}

impl Requirement {
    pub fn exact(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::Exact(version.into()),
        }
    }

    pub fn minimum(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::Minimum(version.into()),
        }
    }

    pub fn minimum_exclusive(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::MinimumExclusive(version.into()),
        }
    }

    pub fn maximum_inclusive(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::MaximumInclusive(version.into()),
        }
    }

    pub fn maximum(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::Maximum(version.into()),
        }
    }

    pub fn not_equal(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::NotEqual(version.into()),
        }
    }

    pub fn compatible(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::Compatible(version.into()),
        }
    }

    pub fn any(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::Any,
        }
    }

    fn constraint_display(&self) -> String {
        match &self.spec {
            VersionSpec::Exact(v) => format!("=={v}"),
            VersionSpec::Minimum(v) => format!(">={v}"),
            VersionSpec::MinimumExclusive(v) => format!(">{v}"),
            VersionSpec::MaximumInclusive(v) => format!("<={v}"),
            VersionSpec::Maximum(v) => format!("<{v}"),
            VersionSpec::NotEqual(v) => format!("!={v}"),
            VersionSpec::Compatible(v) => format!("~={v}"),
            VersionSpec::Any => "*".to_string(),
        }
    }

    fn is_satisfied_by(&self, version: &str) -> bool {
        match &self.spec {
            VersionSpec::Exact(v) => v == version,
            VersionSpec::Minimum(min) => compare_versions(version, min) != Ordering::Less,
            VersionSpec::MinimumExclusive(min) => {
                compare_versions(version, min) == Ordering::Greater
            }
            VersionSpec::MaximumInclusive(max) => {
                compare_versions(version, max) != Ordering::Greater
            }
            VersionSpec::Maximum(max) => compare_versions(version, max) == Ordering::Less,
            VersionSpec::NotEqual(v) => v != version,
            VersionSpec::Compatible(base) => is_compatible_release(version, base),
            VersionSpec::Any => true,
        }
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.spec {
            VersionSpec::Exact(v) => write!(f, "{}=={}", self.name, v),
            VersionSpec::Minimum(v) => write!(f, "{}>={}", self.name, v),
            VersionSpec::MinimumExclusive(v) => write!(f, "{}>{}", self.name, v),
            VersionSpec::MaximumInclusive(v) => write!(f, "{}<={}", self.name, v),
            VersionSpec::Maximum(v) => write!(f, "{}<{}", self.name, v),
            VersionSpec::NotEqual(v) => write!(f, "{}!={}", self.name, v),
            VersionSpec::Compatible(v) => write!(f, "{}~={}", self.name, v),
            VersionSpec::Any => write!(f, "{}", self.name),
        }
    }
}

impl FromStr for Requirement {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim();
        if normalized.is_empty() {
            return Err("requirement cannot be empty".into());
        }

        // Parse operators in order of specificity (longer operators first)
        // ~= must come before other operators
        if let Some((name, version)) = normalized.split_once("~=") {
            return Ok(Requirement::compatible(name.trim(), version.trim()));
        }
        // == exact match
        if let Some((name, version)) = normalized.split_once("==") {
            return Ok(Requirement::exact(name.trim(), version.trim()));
        }
        // != not equal
        if let Some((name, version)) = normalized.split_once("!=") {
            return Ok(Requirement::not_equal(name.trim(), version.trim()));
        }
        // >= minimum inclusive (must come before >)
        if let Some((name, version)) = normalized.split_once(">=") {
            return Ok(Requirement::minimum(name.trim(), version.trim()));
        }
        // <= maximum inclusive (must come before <)
        if let Some((name, version)) = normalized.split_once("<=") {
            return Ok(Requirement::maximum_inclusive(name.trim(), version.trim()));
        }
        // > minimum exclusive
        if let Some((name, version)) = normalized.split_once('>') {
            return Ok(Requirement::minimum_exclusive(name.trim(), version.trim()));
        }
        // < maximum exclusive
        if let Some((name, version)) = normalized.split_once('<') {
            return Ok(Requirement::maximum(name.trim(), version.trim()));
        }
        // No operator - any version
        Ok(Requirement::any(normalized))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub dependencies: Vec<Requirement>,
    pub source: Option<PackageSource>,
    pub artifacts: PackageArtifacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackageArtifacts {
    pub wheels: Vec<Wheel>,
    pub sdist: Option<String>,
}

impl PackageArtifacts {
    pub fn universal(name: &str, version: &str) -> Self {
        Self {
            wheels: vec![Wheel {
                file: format!("{name}-{version}-py3-none-any.whl"),
                platforms: vec!["any".into()],
            }],
            sdist: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wheel {
    pub file: String,
    pub platforms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub packages: BTreeMap<String, ResolvedPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSelection {
    pub filename: String,
    pub matched_platform: Option<String>,
    pub from_source: bool,
    pub available_wheels: usize,
}

/// Determine platform preference list for wheel selection.
pub fn current_platform_tags() -> Vec<String> {
    let mut tags = crate::runtime::current_wheel_tags();
    if !tags.iter().any(|t| t == "any") {
        tags.push("any".into());
    }
    tags
}

/// Select the best artifact for the current platform.
pub fn select_artifact_for_platform(
    pkg: &ResolvedPackage,
    platform_tags: &[String],
) -> ArtifactSelection {
    let mut tags = platform_tags.to_vec();
    if !tags.iter().any(|t| t == "any") {
        tags.push("any".into());
    }

    for tag in &tags {
        if let Some(wheel) = pkg
            .artifacts
            .wheels
            .iter()
            .find(|w| w.platforms.is_empty() || w.platforms.iter().any(|p| p == tag))
        {
            let matched_platform = if wheel.platforms.is_empty() {
                None
            } else {
                Some(tag.clone())
            };
            return ArtifactSelection {
                filename: wheel.file.clone(),
                matched_platform,
                from_source: false,
                available_wheels: pkg.artifacts.wheels.len(),
            };
        }
    }

    if let Some(sdist) = &pkg.artifacts.sdist {
        return ArtifactSelection {
            filename: sdist.clone(),
            matched_platform: None,
            from_source: true,
            available_wheels: pkg.artifacts.wheels.len(),
        };
    }

    let fallback = pkg
        .artifacts
        .wheels
        .first()
        .map(|w| w.file.clone())
        .unwrap_or_else(|| format!("{}-{}-py3-none-any.whl", pkg.name, pkg.version));

    ArtifactSelection {
        filename: fallback,
        matched_platform: None,
        from_source: pkg.artifacts.wheels.is_empty(),
        available_wheels: pkg.artifacts.wheels.len(),
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error("package {name} with constraint {constraint} not found")]
    Missing {
        name: String,
        constraint: String,
        #[allow(dead_code)]
        requested_by: Option<String>,
        #[allow(dead_code)]
        available_versions: Vec<String>,
    },
    #[error("version conflict for {name}: existing {existing} vs requested {requested}")]
    Conflict {
        name: String,
        existing: String,
        requested: String,
        #[allow(dead_code)]
        existing_chain: Vec<String>,
        #[allow(dead_code)]
        requested_chain: Vec<String>,
    },
    #[error("io error: {0}")]
    Io(String),
}

pub trait PackageIndex {
    fn get(
        &self,
        name: &str,
        version: &str,
    ) -> impl std::future::Future<Output = Result<Option<ResolvedPackage>, ResolveError>> + Send;
    fn all(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Vec<ResolvedPackage>, ResolveError>> + Send;
}

/// Deterministic resolver that works with exact-version or minimum requirements in parallel.
pub async fn resolve(
    requirements: Vec<Requirement>,
    index: &impl PackageIndex,
) -> Result<Resolution, ResolveError> {
    let mut resolved: BTreeMap<String, ResolvedPackage> = BTreeMap::new();

    // Requirements to process: (Requirement, RequestedBy)
    let mut pending: Vec<(Requirement, Option<String>)> =
        requirements.into_iter().map(|r| (r, None)).collect();

    // Track parent relationships for conflict error messages
    let mut parents: BTreeMap<String, Option<String>> = BTreeMap::new();
    // Cache available versions to avoid fetching same package multiple times in one run
    // (Though the Index implementation might also cache)
    let mut version_cache: BTreeMap<String, Vec<ResolvedPackage>> = BTreeMap::new();

    while !pending.is_empty() {
        let current_batch = std::mem::take(&mut pending);
        let mut next_batch = Vec::new();

        // 1. Identify unique package names we need to fetch info for (that we don't have yet)
        let mut names_to_fetch = Vec::new();
        for (req, _) in &current_batch {
            // If already resolved, we might skip fetching if we don't need to re-verify
            // But we should check if the existing resolution satisfies the new req
            if resolved.contains_key(&req.name) {
                continue;
            }
            if !version_cache.contains_key(&req.name) {
                names_to_fetch.push(req.name.clone());
            }
        }
        names_to_fetch.sort();
        names_to_fetch.dedup();

        // 2. Fetch metadata in parallel
        if !names_to_fetch.is_empty() {
            let futures = names_to_fetch.iter().map(|name| {
                let name = name.clone();
                async move {
                    let pkgs = index.all(&name).await?;
                    Ok::<(String, Vec<ResolvedPackage>), ResolveError>((name, pkgs))
                }
            });

            let results = futures::future::try_join_all(futures).await?;
            for (name, pkgs) in results {
                version_cache.insert(name, pkgs);
            }
        }

        // 3. Process resolution logic (Synchronous part)
        for (req, requested_by) in current_batch {
            // Check if already resolved
            if let Some(existing) = resolved.get(&req.name) {
                if !req.is_satisfied_by(&existing.version) {
                    let existing_chain = build_chain(&parents, &req.name);
                    let requested_chain = build_requested_chain(&parents, &req.name, requested_by);
                    return Err(ResolveError::Conflict {
                        name: req.name.clone(),
                        existing: existing.version.clone(),
                        requested: req.constraint_display(),
                        existing_chain,
                        requested_chain,
                    });
                }
                continue;
            }

            // Select best version
            let candidates = version_cache
                .get(&req.name)
                .ok_or_else(|| ResolveError::Missing {
                    name: req.name.clone(),
                    constraint: req.constraint_display(),
                    requested_by: requested_by.clone(),
                    available_versions: vec![],
                })?;

            let pkg = select_package_from_candidates(&req, candidates, requested_by.as_deref())?;

            // Add dependencies to next batch
            for dep in &pkg.dependencies {
                next_batch.push((dep.clone(), Some(pkg.name.clone())));
            }

            resolved.insert(req.name.clone(), pkg);
            parents.insert(req.name.clone(), requested_by);
        }

        pending = next_batch;
    }

    Ok(Resolution { packages: resolved })
}

fn select_package_from_candidates(
    req: &Requirement,
    candidates: &[ResolvedPackage],
    requested_by: Option<&str>,
) -> Result<ResolvedPackage, ResolveError> {
    match &req.spec {
        VersionSpec::Exact(version) => candidates
            .iter()
            .find(|p| p.version == *version)
            .cloned()
            .ok_or_else(|| ResolveError::Missing {
                name: req.name.clone(),
                constraint: req.constraint_display(),
                requested_by: requested_by.map(ToString::to_string),
                available_versions: candidates.iter().map(|p| p.version.clone()).collect(),
            }),
        _ => {
            let candidate = candidates
                .iter()
                .filter(|pkg| req.is_satisfied_by(&pkg.version))
                .max_by(|a, b| version_cmp(&a.version, &b.version));

            if let Some(pkg) = candidate {
                Ok(pkg.clone())
            } else {
                Err(ResolveError::Missing {
                    name: req.name.clone(),
                    constraint: req.constraint_display(),
                    requested_by: requested_by.map(ToString::to_string),
                    available_versions: candidates.iter().map(|p| p.version.clone()).collect(),
                })
            }
        }
    }
}

#[derive(Default)]
pub struct InMemoryIndex {
    pkgs: BTreeMap<(String, String), ResolvedPackage>,
}

impl InMemoryIndex {
    pub fn add(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        deps: impl IntoIterator<Item = impl AsRef<str>>,
    ) {
        let name = name.into();
        let version = version.into();
        let artifacts = PackageArtifacts::universal(&name, &version);
        self.add_with_artifacts(name, version, deps, artifacts);
    }

    pub fn add_with_artifacts(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        deps: impl IntoIterator<Item = impl AsRef<str>>,
        artifacts: PackageArtifacts,
    ) {
        let name = name.into();
        let version = version.into();
        let deps = deps
            .into_iter()
            .map(|d| parse_req(d.as_ref()))
            .collect::<Vec<_>>();
        let pkg = ResolvedPackage {
            name: name.clone(),
            version: version.clone(),
            dependencies: deps,
            source: None,
            artifacts,
        };
        self.pkgs.insert((name, version), pkg);
    }
}

impl PackageIndex for InMemoryIndex {
    fn get(
        &self,
        name: &str,
        version: &str,
    ) -> impl std::future::Future<Output = Result<Option<ResolvedPackage>, ResolveError>> + Send
    {
        let result = self
            .pkgs
            .get(&(name.to_string(), version.to_string()))
            .cloned();
        async move { Ok(result) }
    }

    fn all(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Vec<ResolvedPackage>, ResolveError>> + Send {
        let result = self
            .pkgs
            .iter()
            .filter(|((n, _), _)| n == name)
            .map(|(_, pkg)| pkg.clone())
            .collect::<Vec<_>>();
        async move { Ok(result) }
    }
}

fn parse_req(input: &str) -> Requirement {
    Requirement::from_str(input).unwrap_or_else(|_| Requirement::any(input.trim()))
}

fn version_cmp(a: &str, b: &str) -> Ordering {
    compare_versions(a, b)
}

fn build_chain(parents: &BTreeMap<String, Option<String>>, start: &str) -> Vec<String> {
    let mut chain: Vec<String> = Vec::new();
    let mut current: Option<String> = Some(start.to_string());
    while let Some(name) = current {
        chain.push(name.clone());
        current = parents.get(&name).cloned().flatten();
    }
    chain.reverse();
    chain
}

fn build_requested_chain(
    parents: &BTreeMap<String, Option<String>>,
    package: &str,
    requested_by: Option<String>,
) -> Vec<String> {
    match requested_by {
        Some(parent) => {
            let mut chain = build_chain(parents, &parent);
            chain.push(package.to_string());
            chain
        }
        None => vec![package.to_string()],
    }
}

/// Compare two version strings, returning their ordering.
fn compare_versions(a: &str, b: &str) -> Ordering {
    match (parse_version_relaxed(a), parse_version_relaxed(b)) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => a.cmp(b),
    }
}

fn parse_version_relaxed(input: &str) -> Option<Version> {
    if let Ok(v) = Version::parse(input) {
        return Some(v);
    }
    // Split into numeric prefix and optional suffix (rc, a, b, etc.)
    let mut prefix = String::new();
    let mut suffix = String::new();
    for (idx, ch) in input.char_indices() {
        if ch.is_ascii_digit() || ch == '.' {
            prefix.push(ch);
        } else {
            suffix = input[idx..].to_string();
            break;
        }
    }
    if prefix.is_empty() {
        return None;
    }
    let mut parts: Vec<&str> = prefix
        .trim_matches('.')
        .split('.')
        .filter(|p| !p.is_empty())
        .collect();
    while parts.len() < 3 {
        parts.push("0");
    }
    let prefix_norm = parts[..3].join(".");
    let suffix_norm = suffix
        .trim_start_matches(|c| c == '-' || c == '_' || c == '.')
        .to_ascii_lowercase();
    let semver_str = if suffix_norm.is_empty() {
        prefix_norm
    } else {
        format!("{}-{}", prefix_norm, suffix_norm)
    };
    Version::parse(&semver_str).ok()
}

/// Check if a version satisfies the compatible release constraint (~=).
fn is_compatible_release(version: &str, base: &str) -> bool {
    // First check if version meets the minimum
    if compare_versions(version, base) == Ordering::Less {
        return false;
    }

    let base_parts: Vec<&str> = base.split('.').collect();
    let version_parts: Vec<&str> = version.split('.').collect();

    if base_parts.len() >= 3 {
        // ~=X.Y.Z -> >=X.Y.Z, <X.(Y+1).0
        // Check major version matches
        if version_parts.first() != base_parts.first() {
            return false;
        }
        // Parse minor versions
        let base_minor: u64 = base_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let version_minor: u64 = version_parts
            .get(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        // Version minor must be <= base minor (same minor series)
        version_minor == base_minor
    } else if base_parts.len() == 2 {
        // ~=X.Y -> >=X.Y, <(X+1).0
        // Check major version matches
        version_parts.first() == base_parts.first()
    } else if base_parts.len() == 1 {
        // ~=X -> treated as >=X (unusual but valid)
        compare_versions(version, base) != Ordering::Less
    } else {
        false
    }
}
