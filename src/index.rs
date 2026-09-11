use crate::resolver::{InMemoryIndex, PackageArtifacts, Wheel};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Package record as stored in the simple JSON index fixture.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct IndexPackage {
    pub name: String,
    pub version: String,
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub wheels: Vec<IndexWheel>,
    #[serde(default)]
    pub sdist: Option<String>,
    /// PEP 440 `requires-python` specifier for this release (Issue #342).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_python: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct IndexWheel {
    pub file: String,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub hash: Option<String>,
}

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("failed to read index {path}: {source}")]
    Io {
        source: std::io::Error,
        path: PathBuf,
    },
    #[error("failed to parse index json: {0}")]
    Parse(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, IndexError>;

/// Load a JSON index file into an in-memory index usable by the resolver.
pub fn load_index_from_path(path: impl AsRef<Path>) -> Result<InMemoryIndex> {
    let path = path.as_ref();
    let data = fs::read_to_string(path).map_err(|source| IndexError::Io {
        source,
        path: path.to_path_buf(),
    })?;
    let packages: Vec<IndexPackage> = serde_json::from_str(&data)?;
    Ok(build_index(packages))
}

fn build_index(packages: Vec<IndexPackage>) -> InMemoryIndex {
    let mut index = InMemoryIndex::default();
    for pkg in packages {
        let artifacts = if pkg.wheels.is_empty() && pkg.sdist.is_none() {
            PackageArtifacts::universal(&pkg.name, &pkg.version)
        } else {
            let wheels = pkg
                .wheels
                .iter()
                .map(|w| {
                    let (python_tag, abi_tag) = crate::resolver::parse_wheel_tags(&w.file);
                    Wheel {
                        file: w.file.clone(),
                        url: None,
                        hash: w.hash.clone(),
                        platforms: if w.platforms.is_empty() {
                            vec!["any".into()]
                        } else {
                            w.platforms.clone()
                        },
                        python_tag,
                        abi_tag,
                    }
                })
                .collect();
            PackageArtifacts {
                wheels,
                sdist: pkg.sdist.clone(),
            }
        };
        index.add_entry(
            pkg.name,
            pkg.version,
            pkg.dependencies,
            artifacts,
            pkg.requires_python.as_deref(),
        );
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::PackageIndex;

    #[tokio::test]
    async fn builds_inmemory_index() {
        let index = build_index(vec![IndexPackage {
            name: "app".into(),
            version: "1.0.0".into(),
            dependencies: vec!["dep==2.0.0".into()],
            ..Default::default()
        }]);
        let pkg = index
            .get("app", "1.0.0")
            .await
            .expect("no error")
            .expect("package");
        assert_eq!(pkg.dependencies.len(), 1);
        assert_eq!(pkg.dependencies[0].to_string(), "dep==2.0.0");
        assert_eq!(pkg.requires_python, None);
    }

    #[tokio::test]
    async fn index_fixture_carries_requires_python() {
        let index = build_index(vec![IndexPackage {
            name: "app".into(),
            version: "1.0.0".into(),
            requires_python: Some(">=3.10".into()),
            ..Default::default()
        }]);
        let pkg = index
            .get("app", "1.0.0")
            .await
            .expect("no error")
            .expect("package");
        assert_eq!(pkg.requires_python.as_deref(), Some(">=3.10"));
    }
}
