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
    pub marker: Option<String>,
}

impl Requirement {
    pub fn exact(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::Exact(version.into()),
            marker: None,
        }
    }

    pub fn minimum(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::Minimum(version.into()),
            marker: None,
        }
    }

    pub fn minimum_exclusive(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::MinimumExclusive(version.into()),
            marker: None,
        }
    }

    pub fn maximum_inclusive(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::MaximumInclusive(version.into()),
            marker: None,
        }
    }

    pub fn maximum(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::Maximum(version.into()),
            marker: None,
        }
    }

    pub fn not_equal(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::NotEqual(version.into()),
            marker: None,
        }
    }

    pub fn compatible(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::Compatible(version.into()),
            marker: None,
        }
    }

    pub fn any(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            spec: VersionSpec::Any,
            marker: None,
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

    pub fn is_satisfied_by(&self, version: &str) -> bool {
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

    /// Evaluate if the environment marker applies to the current platform.
    /// Returns true if no marker is present or if the marker matches the current environment.
    pub fn marker_applies(&self) -> bool {
        let Some(marker) = &self.marker else {
            // No marker means requirement always applies
            return true;
        };

        evaluate_marker(marker)
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

        // Split by ';' to separate requirement from marker (PEP 508)
        let (requirement_part, marker_part) = if let Some(idx) = normalized.find(';') {
            let (req, marker) = normalized.split_at(idx);
            (req.trim(), Some(marker[1..].trim().to_string()))
        } else {
            (normalized, None)
        };

        // Parse version spec (handle "package (>=1.0)" format)
        // First, try to split by space to separate name from version spec in parentheses
        let (name_part, version_part) = if let Some(idx) = requirement_part.find('(') {
            // Format: "package (>=1.0)" or "package(>=1.0)"
            let name = requirement_part[..idx].trim();
            let version_with_parens = requirement_part[idx..].trim();
            let version = version_with_parens
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim();
            (name, version)
        } else {
            // Format: "package>=1.0" (no space, no parentheses)
            (requirement_part, requirement_part)
        };

        // Parse version spec operators in order of specificity (longer operators first)
        let mut req = if let Some((name, version)) = version_part.split_once("~=") {
            Requirement::compatible(
                if name.is_empty() { name_part } else { name },
                version.trim(),
            )
        } else if let Some((name, version)) = version_part.split_once("==") {
            Requirement::exact(
                if name.is_empty() { name_part } else { name },
                version.trim(),
            )
        } else if let Some((name, version)) = version_part.split_once("!=") {
            Requirement::not_equal(
                if name.is_empty() { name_part } else { name },
                version.trim(),
            )
        } else if let Some((name, version)) = version_part.split_once(">=") {
            Requirement::minimum(
                if name.is_empty() { name_part } else { name },
                version.trim(),
            )
        } else if let Some((name, version)) = version_part.split_once("<=") {
            Requirement::maximum_inclusive(
                if name.is_empty() { name_part } else { name },
                version.trim(),
            )
        } else if let Some((name, version)) = version_part.split_once('>') {
            Requirement::minimum_exclusive(
                if name.is_empty() { name_part } else { name },
                version.trim(),
            )
        } else if let Some((name, version)) = version_part.split_once('<') {
            Requirement::maximum(
                if name.is_empty() { name_part } else { name },
                version.trim(),
            )
        } else {
            // No operator - any version
            Requirement::any(name_part)
        };

        // Attach marker if present
        req.marker = marker_part;
        Ok(req)
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
                url: None,
                hash: None,
                platforms: vec!["any".into()],
            }],
            sdist: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wheel {
    pub file: String,
    pub url: Option<String>,
    pub hash: Option<String>,
    pub platforms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub packages: BTreeMap<String, ResolvedPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSelection {
    pub filename: String,
    pub url: Option<String>,
    pub hash: Option<String>,
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

/// Rank a wheel for selection priority.
/// Higher score = better preference.
/// Prefers: native platform wheels > abi3 wheels > any-platform wheels
fn rank_wheel(wheel: &Wheel, platform_tags: &[String]) -> u32 {
    let mut score: u32 = 100; // Base score for being a wheel (vs sdist)

    // Check platform match
    if wheel.platforms.is_empty() {
        // Universal wheel (any platform)
        score += 10;
    } else {
        for (priority, tag) in platform_tags.iter().enumerate() {
            if wheel.platforms.iter().any(|p| p == tag) {
                // Native platform match - higher priority = lower index = higher score
                score += 50 - (priority as u32).min(40);
                break;
            }
        }
    }

    // Prefer abi3 wheels (stable ABI, faster to select)
    if wheel.file.contains("-abi3-") || wheel.file.contains("-cp3") {
        score += 20;
    }

    // Prefer wheels with fewer platform restrictions (more portable)
    if wheel.platforms.len() <= 1 {
        score += 5;
    }

    score
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

    // Find the best matching wheel using ranking
    if !pkg.artifacts.wheels.is_empty() {
        let mut scored_wheels: Vec<_> = pkg
            .artifacts
            .wheels
            .iter()
            .filter_map(|w| {
                let matches_platform = w.platforms.is_empty()
                    || tags.iter().any(|t| w.platforms.iter().any(|p| p == t));
                if matches_platform {
                    Some((rank_wheel(w, &tags), w))
                } else {
                    None
                }
            })
            .collect();

        // Sort by score descending
        scored_wheels.sort_by(|a, b| b.0.cmp(&a.0));

        // Take the best wheel if it matches the platform
        if let Some((_, wheel)) = scored_wheels.first() {
            // This is the highest-ranked matching wheel for the platform.
            let matched_platform = if wheel.platforms.is_empty() {
                None
            } else {
                tags.iter()
                    .find(|t| wheel.platforms.iter().any(|p| p == *t))
                    .cloned()
            };
            return ArtifactSelection {
                filename: wheel.file.clone(),
                url: wheel.url.clone(),
                hash: wheel.hash.clone(),
                matched_platform,
                from_source: false,
                available_wheels: pkg.artifacts.wheels.len(),
            };
        }
    }

    // Fallback: try platform matching the old way
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
                url: wheel.url.clone(),
                hash: wheel.hash.clone(),
                matched_platform,
                from_source: false,
                available_wheels: pkg.artifacts.wheels.len(),
            };
        }
    }

    if let Some(sdist) = &pkg.artifacts.sdist {
        return ArtifactSelection {
            filename: sdist.clone(),
            url: None,
            hash: None, // sdist hash not yet tracked in PackageArtifacts struct
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
        url: None,
        hash: None,
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
    let mut constraints: BTreeMap<String, Vec<Requirement>> = BTreeMap::new();

    // Requirements to process: (Requirement, RequestedBy)
    // Filter out top-level requirements whose environment markers don't apply.
    let mut pending: Vec<(Requirement, Option<String>)> = requirements
        .into_iter()
        .filter(|r| r.marker_applies())
        .map(|r| (r, None))
        .collect();

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
            constraints
                .entry(req.name.clone())
                .or_default()
                .push(req.clone());

            // Check if already resolved
            if let Some(existing) = resolved.get(&req.name) {
                if !req.is_satisfied_by(&existing.version) {
                    // Try to select a version that satisfies all constraints seen so far
                    let candidates = version_cache.get(&req.name).cloned().unwrap_or_default();
                    if let Ok(mut pkg) = select_with_constraints(
                        &constraints,
                        &req.name,
                        &candidates,
                        requested_by.as_deref(),
                    ) {
                        if let Some(fetched) = index.get(&pkg.name, &pkg.version).await? {
                            pkg = fetched;
                        }
                        resolved.insert(req.name.clone(), pkg.clone());
                        // push dependencies of the newly selected package
                        for dep in &pkg.dependencies {
                            next_batch.push((dep.clone(), Some(pkg.name.clone())));
                        }
                        parents.insert(req.name.clone(), requested_by.clone());
                    } else {
                        let existing_chain = build_chain(&parents, &req.name);
                        let requested_chain =
                            build_requested_chain(&parents, &req.name, requested_by);
                        return Err(ResolveError::Conflict {
                            name: req.name.clone(),
                            existing: existing.version.clone(),
                            requested: req.constraint_display(),
                            existing_chain,
                            requested_chain,
                        });
                    }
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

            let mut pkg = select_with_constraints(
                &constraints,
                &req.name,
                candidates,
                requested_by.as_deref(),
            )?;

            if let Some(fetched) = index.get(&pkg.name, &pkg.version).await? {
                pkg = fetched;
            }

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

fn select_with_constraints(
    reqs: &BTreeMap<String, Vec<Requirement>>,
    name: &str,
    candidates: &[ResolvedPackage],
    requested_by: Option<&str>,
) -> Result<ResolvedPackage, ResolveError> {
    let constraints = reqs.get(name).cloned().unwrap_or_default();
    let candidate = candidates
        .iter()
        .filter(|pkg| constraints.iter().all(|r| r.is_satisfied_by(&pkg.version)))
        .max_by(|a, b| version_cmp(&a.version, &b.version));

    if let Some(pkg) = candidate {
        Ok(pkg.clone())
    } else {
        let constraint_display = if constraints.is_empty() {
            "*".to_string()
        } else {
            constraints
                .iter()
                .map(|r| r.constraint_display())
                .collect::<Vec<_>>()
                .join(" & ")
        };
        Err(ResolveError::Missing {
            name: name.to_string(),
            constraint: constraint_display,
            requested_by: requested_by.map(ToString::to_string),
            available_versions: candidates.iter().map(|p| p.version.clone()).collect(),
        })
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
            .filter(|req| req.marker_applies()) // Filter out non-applicable markers
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
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    match (parse_version_relaxed(a), parse_version_relaxed(b)) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => a.cmp(b),
    }
}

pub fn parse_version_relaxed(input: &str) -> Option<Version> {
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
        .trim_start_matches(['-', '_', '.'])
        .to_ascii_lowercase();
    let semver_str = if suffix_norm.is_empty() {
        prefix_norm
    } else {
        format!("{}-{}", prefix_norm, suffix_norm)
    };
    Version::parse(&semver_str).ok()
}

/// Evaluate a PEP 508 environment marker against the current platform.
/// This is a simplified implementation that supports basic marker evaluation.
fn evaluate_marker(marker: &str) -> bool {
    let marker = marker.trim();

    // Get current environment values
    let platform_machine = get_platform_machine();
    let sys_platform = get_sys_platform();
    let platform_system = get_platform_system();

    // Handle 'or' operator - split and check if any condition matches
    if marker.contains(" or ") {
        return marker
            .split(" or ")
            .any(|part| evaluate_marker(part.trim()));
    }

    // Handle 'and' operator - split and check if all conditions match
    if marker.contains(" and ") {
        return marker
            .split(" and ")
            .all(|part| evaluate_marker(part.trim()));
    }

    // Remove parentheses if present
    let marker = marker.trim_start_matches('(').trim_end_matches(')').trim();

    // Parse comparisons with two-character operators first (!=, ==, >=, <=)
    // then single-character operators (>, <).
    for op in &["==", "!=", ">=", "<=", ">", "<"] {
        let Some(idx) = marker.find(op) else {
            continue;
        };
        let (var, rest) = marker.split_at(idx);
        let var = var.trim();
        let val = rest[op.len()..].trim().trim_matches('\'').trim_matches('"');

        return match (var, *op) {
            ("platform_machine", "==") => platform_machine == val,
            ("platform_machine", "!=") => platform_machine != val,
            ("sys_platform", "==") => sys_platform == val,
            ("sys_platform", "!=") => sys_platform != val,
            ("platform_system", "==") => platform_system == val,
            ("platform_system", "!=") => platform_system != val,
            // python_version comparisons: compare against the compile-time Python version.
            // We conservatively include (return true) when the condition cannot be
            // disproved at compile time, since we do not know the runtime Python version.
            ("python_version", _) => {
                // If we can't evaluate the exact Python version at compile time, be
                // inclusive: assume the marker applies so we don't silently drop packages.
                true
            }
            // Unknown variable with == → we don't know → be inclusive
            (_, "==") | (_, "!=") => true,
            // Unknown variable with ordering operator → be inclusive
            _ => true,
        };
    }

    // If we can't parse the marker at all, be inclusive (don't silently drop packages)
    true
}

/// Get the platform machine architecture (e.g., 'x86_64', 'arm64', 'i386').
fn get_platform_machine() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    return "x86_64";

    #[cfg(target_arch = "aarch64")]
    {
        // Python on macOS reports aarch64 as 'arm64'
        #[cfg(target_os = "macos")]
        return "arm64";

        #[cfg(not(target_os = "macos"))]
        return "aarch64";
    }

    #[cfg(target_arch = "x86")]
    return "i386";

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")))]
    return "unknown";
}

/// Get the system platform (e.g., 'darwin', 'linux', 'win32').
fn get_sys_platform() -> &'static str {
    #[cfg(target_os = "macos")]
    return "darwin";

    #[cfg(target_os = "linux")]
    return "linux";

    #[cfg(target_os = "windows")]
    return "win32";

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return "unknown";
}

/// Get the platform system (e.g., 'Darwin', 'Linux', 'Windows').
fn get_platform_system() -> &'static str {
    #[cfg(target_os = "macos")]
    return "Darwin";

    #[cfg(target_os = "linux")]
    return "Linux";

    #[cfg(target_os = "windows")]
    return "Windows";

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return "Unknown";
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_requirement_with_marker() {
        // Test parsing PEP 508 requirement with environment marker
        let req_str = "polars-runtime-32 (==1.39.2) ; platform_machine == 'i386'";
        let req = Requirement::from_str(req_str).unwrap();

        assert_eq!(req.name, "polars-runtime-32");
        assert_eq!(req.spec, VersionSpec::Exact("1.39.2".to_string()));
        assert_eq!(req.marker, Some("platform_machine == 'i386'".to_string()));
    }

    #[test]
    fn test_parse_requirement_without_marker() {
        let req_str = "requests>=2.28.0";
        let req = Requirement::from_str(req_str).unwrap();

        assert_eq!(req.name, "requests");
        assert_eq!(req.spec, VersionSpec::Minimum("2.28.0".to_string()));
        assert_eq!(req.marker, None);
    }

    #[test]
    fn test_marker_evaluation_platform_machine() {
        // Test that marker evaluation correctly filters based on platform_machine
        let req_32bit =
            Requirement::from_str("polars-runtime-32==1.39.2 ; platform_machine == 'i386'")
                .unwrap();

        // On macOS arm64, only the arm64 requirement should apply
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            let req_arm64 =
                Requirement::from_str("polars-runtime-64==1.39.2 ; platform_machine == 'arm64'")
                    .unwrap();
            assert!(!req_32bit.marker_applies());
            assert!(req_arm64.marker_applies());
        }

        // On Linux x86_64, neither should apply (unless we add x86_64 markers)
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            assert!(!req_32bit.marker_applies());
        }
    }

    #[test]
    fn test_marker_evaluation_no_marker_always_applies() {
        let req = Requirement::from_str("requests>=2.28.0").unwrap();
        assert!(req.marker_applies()); // No marker means always applies
    }

    #[test]
    fn test_complex_marker_with_parentheses() {
        let req_str =
            "package (>=1.0) ; (platform_machine == 'x86_64' or platform_machine == 'arm64')";
        let req = Requirement::from_str(req_str).unwrap();

        assert_eq!(req.name, "package");
        assert!(req.marker.is_some());
    }

    #[test]
    fn test_parse_requirement_plain_marker_no_version() {
        // "requests; python_version < '4.0'" — no version spec, just a marker
        let req = Requirement::from_str("requests; python_version < '4.0'").unwrap();
        assert_eq!(req.name, "requests");
        assert_eq!(req.spec, VersionSpec::Any);
        assert_eq!(req.marker, Some("python_version < '4.0'".to_string()));
    }

    #[test]
    fn test_python_version_marker_applies() {
        // python_version < '4.0' should apply (Python 4 doesn't exist)
        let req = Requirement::from_str("requests; python_version < '4.0'").unwrap();
        assert!(
            req.marker_applies(),
            "python_version < '4.0' should apply since Python 4 does not exist"
        );

        // python_version >= '3.0' should apply (we're always on Python 3+)
        let req2 = Requirement::from_str("requests; python_version >= '3.0'").unwrap();
        assert!(
            req2.marker_applies(),
            "python_version >= '3.0' should apply"
        );
    }

    #[tokio::test]
    async fn test_resolve_skips_non_applicable_platform_markers() {
        let mut index = InMemoryIndex::default();
        index.add("requests", "2.28.0", Vec::<String>::new());

        // A requirement targeting a fake arch that never matches
        let req =
            Requirement::from_str("requests; platform_machine == 'nonexistent_arch_xyz'").unwrap();
        assert!(!req.marker_applies(), "sanity: marker must not apply");

        let resolution = resolve(vec![req], &index).await.unwrap();
        assert!(
            resolution.packages.is_empty(),
            "packages with non-applicable markers should not be resolved; got: {:?}",
            resolution.packages.keys().collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_resolve_includes_applicable_markers() {
        let mut index = InMemoryIndex::default();
        index.add("requests", "2.28.0", Vec::<String>::new());

        // No marker — always included
        let req = Requirement::from_str("requests>=2.0").unwrap();
        assert!(req.marker_applies());

        let resolution = resolve(vec![req], &index).await.unwrap();
        assert!(
            resolution.packages.contains_key("requests"),
            "requirements without markers must be resolved"
        );
    }

    #[tokio::test]
    async fn test_resolve_python_version_marker_inclusive() {
        let mut index = InMemoryIndex::default();
        index.add("requests", "2.28.0", Vec::<String>::new());

        // python_version < '4.0' is always true
        let req = Requirement::from_str("requests; python_version < '4.0'").unwrap();

        let resolution = resolve(vec![req], &index).await.unwrap();
        assert!(
            resolution.packages.contains_key("requests"),
            "requests with python_version < '4.0' marker should be resolved"
        );
    }
}
