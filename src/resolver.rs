use semver::Version;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionSpec {
    Exact(String),
    Minimum(String),
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
            VersionSpec::Any => "*".to_string(),
        }
    }

    fn is_satisfied_by(&self, version: &str) -> bool {
        match &self.spec {
            VersionSpec::Exact(v) => v == version,
            VersionSpec::Minimum(min) => meets_minimum(version, min),
            VersionSpec::Any => true,
        }
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.spec {
            VersionSpec::Exact(v) => write!(f, "{}=={}", self.name, v),
            VersionSpec::Minimum(v) => write!(f, "{}>={}", self.name, v),
            VersionSpec::Any => write!(f, "{}", self.name),
        }
    }
}

impl FromStr for Requirement {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim();
        if let Some((name, version)) = normalized.split_once("==") {
            Ok(Requirement::exact(name.trim(), version.trim()))
        } else if let Some((name, version)) = normalized.split_once(">=") {
            Ok(Requirement::minimum(name.trim(), version.trim()))
        } else if normalized.is_empty() {
            Err("requirement cannot be empty".into())
        } else {
            Ok(Requirement::any(normalized))
        }
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
    Missing { name: String, constraint: String },
    #[error("version conflict for {name}: existing {existing} vs requested {requested}")]
    Conflict {
        name: String,
        existing: String,
        requested: String,
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
    let mut stack: Vec<Requirement> = requirements;

    while let Some(req) = stack.pop() {
        if let Some(existing) = resolved.get(&req.name) {
            if !req.is_satisfied_by(&existing.version) {
                return Err(ResolveError::Conflict {
                    name: req.name.clone(),
                    existing: existing.version.clone(),
                    requested: req.constraint_display(),
                });
            }
            continue;
        }

        let pkg = select_package(&req, index)?;

        // queue dependencies before inserting to keep deterministic traversal order
        for dep in pkg.dependencies.iter().rev() {
            stack.push(dep.clone());
        }

        resolved.insert(req.name.clone(), pkg);
    }

    Ok(Resolution { packages: resolved })
}

fn select_package(
    req: &Requirement,
    index: &impl PackageIndex,
) -> Result<ResolvedPackage, ResolveError> {
    match &req.spec {
        VersionSpec::Exact(version) => {
            index
                .get(&req.name, version)
                .ok_or_else(|| ResolveError::Missing {
                    name: req.name.clone(),
                    constraint: req.constraint_display(),
                })
        }
        VersionSpec::Minimum(_) | VersionSpec::Any => {
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
    match (Version::parse(a), Version::parse(b)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => a.cmp(b),
    }
}

fn meets_minimum(version: &str, minimum: &str) -> bool {
    match (Version::parse(version), Version::parse(minimum)) {
        (Ok(parsed_version), Ok(parsed_min)) => parsed_version >= parsed_min,
        _ => version >= minimum,
    }
}
