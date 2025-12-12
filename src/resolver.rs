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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub packages: BTreeMap<String, ResolvedPackage>,
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
}

pub trait PackageIndex {
    fn get(&self, name: &str, version: &str) -> Option<ResolvedPackage>;
    fn all(&self, name: &str) -> Vec<ResolvedPackage>;
}

/// Deterministic resolver that works with exact-version or minimum requirements.
pub fn resolve(
    requirements: Vec<Requirement>,
    index: &impl PackageIndex,
) -> Result<Resolution, ResolveError> {
    let mut resolved: BTreeMap<String, ResolvedPackage> = BTreeMap::new();
    // Track where each requirement came from (None = direct/user requirement).
    let mut stack: Vec<(Requirement, Option<String>)> =
        requirements.into_iter().map(|r| (r, None)).collect();
    // Track which package introduced (required) a given resolved package.
    let mut parents: BTreeMap<String, Option<String>> = BTreeMap::new();

    while let Some((req, requested_by)) = stack.pop() {
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

        let pkg = select_package(&req, index, requested_by.as_deref())?;

        // queue dependencies before inserting to keep deterministic traversal order
        for dep in pkg.dependencies.iter().rev() {
            stack.push((dep.clone(), Some(pkg.name.clone())));
        }

        resolved.insert(req.name.clone(), pkg);
        parents.insert(req.name.clone(), requested_by);
    }

    Ok(Resolution { packages: resolved })
}

fn select_package(
    req: &Requirement,
    index: &impl PackageIndex,
    requested_by: Option<&str>,
) -> Result<ResolvedPackage, ResolveError> {
    match &req.spec {
        VersionSpec::Exact(version) => {
            index
                .get(&req.name, version)
                .ok_or_else(|| ResolveError::Missing {
                    name: req.name.clone(),
                    constraint: req.constraint_display(),
                    requested_by: requested_by.map(ToString::to_string),
                    available_versions: available_versions(index, &req.name),
                })
        }
        // All other specifiers: filter candidates and pick the highest matching version
        VersionSpec::Minimum(_)
        | VersionSpec::MinimumExclusive(_)
        | VersionSpec::MaximumInclusive(_)
        | VersionSpec::Maximum(_)
        | VersionSpec::NotEqual(_)
        | VersionSpec::Compatible(_)
        | VersionSpec::Any => {
            let candidates = index.all(&req.name);
            let candidate = candidates
                .into_iter()
                .filter(|pkg| req.is_satisfied_by(&pkg.version))
                .max_by(|a, b| version_cmp(&a.version, &b.version));
            if let Some(pkg) = candidate {
                Ok(pkg)
            } else {
                Err(ResolveError::Missing {
                    name: req.name.clone(),
                    constraint: req.constraint_display(),
                    requested_by: requested_by.map(ToString::to_string),
                    available_versions: available_versions(index, &req.name),
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
        let deps = deps
            .into_iter()
            .map(|d| parse_req(d.as_ref()))
            .collect::<Vec<_>>();
        let pkg = ResolvedPackage {
            name: name.clone(),
            version: version.clone(),
            dependencies: deps,
        };
        self.pkgs.insert((name, version), pkg);
    }
}

impl PackageIndex for InMemoryIndex {
    fn get(&self, name: &str, version: &str) -> Option<ResolvedPackage> {
        self.pkgs
            .get(&(name.to_string(), version.to_string()))
            .cloned()
    }

    fn all(&self, name: &str) -> Vec<ResolvedPackage> {
        self.pkgs
            .iter()
            .filter(|((n, _), _)| n == name)
            .map(|(_, pkg)| pkg.clone())
            .collect()
    }
}

fn parse_req(input: &str) -> Requirement {
    Requirement::from_str(input).unwrap_or_else(|_| Requirement::any(input.trim()))
}

fn version_cmp(a: &str, b: &str) -> Ordering {
    compare_versions(a, b)
}

fn available_versions(index: &impl PackageIndex, name: &str) -> Vec<String> {
    let mut versions: Vec<String> = index.all(name).into_iter().map(|p| p.version).collect();
    versions.sort_by(|a, b| version_cmp(b, a));
    versions.dedup();
    versions
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
    match (Version::parse(a), Version::parse(b)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => a.cmp(b),
    }
}

/// Check if a version satisfies the compatible release constraint (~=).
/// PEP 440 compatible release:
/// - ~=X.Y.Z is equivalent to >=X.Y.Z, <X.(Y+1).0
/// - ~=X.Y is equivalent to >=X.Y, <(X+1).0
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
