use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub name: String,
    pub version: String,
}

impl Requirement {
    pub fn exact(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
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
    #[error("package {name}=={version} not found")]
    Missing { name: String, version: String },
    #[error("version conflict for {name}: existing {existing} vs requested {requested}")]
    Conflict {
        name: String,
        existing: String,
        requested: String,
    },
}

pub trait PackageIndex {
    fn get(&self, name: &str, version: &str) -> Option<ResolvedPackage>;
}

/// Deterministic resolver that works with exact-version requirements.
pub fn resolve(
    requirements: Vec<Requirement>,
    index: &impl PackageIndex,
) -> Result<Resolution, ResolveError> {
    let mut resolved: BTreeMap<String, ResolvedPackage> = BTreeMap::new();
    let mut stack: Vec<Requirement> = requirements;

    while let Some(req) = stack.pop() {
        if let Some(existing) = resolved.get(&req.name) {
            if existing.version != req.version {
                return Err(ResolveError::Conflict {
                    name: req.name,
                    existing: existing.version.clone(),
                    requested: req.version,
                });
            }
            continue;
        }

        let pkg = index
            .get(&req.name, &req.version)
            .ok_or_else(|| ResolveError::Missing {
                name: req.name.clone(),
                version: req.version.clone(),
            })?;

        // queue dependencies before inserting to keep deterministic traversal order
        for dep in pkg.dependencies.iter().rev() {
            stack.push(dep.clone());
        }

        resolved.insert(req.name.clone(), pkg);
    }

    Ok(Resolution { packages: resolved })
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
}

fn parse_req(input: &str) -> Requirement {
    if let Some((name, version)) = input.split_once("==") {
        Requirement::exact(name.trim(), version.trim())
    } else {
        Requirement::exact(input.trim(), "*")
    }
}
