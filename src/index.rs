use crate::resolver::InMemoryIndex;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Package record as stored in the simple JSON index fixture.
#[derive(Debug, Deserialize)]
pub struct IndexPackage {
    pub name: String,
    pub version: String,
    pub dependencies: Vec<String>,
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
        index.add(pkg.name, pkg.version, pkg.dependencies);
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::PackageIndex;

    #[test]
    fn builds_inmemory_index() {
        let index = build_index(vec![IndexPackage {
            name: "app".into(),
            version: "1.0.0".into(),
            dependencies: vec!["dep==2.0.0".into()],
        }]);
        let pkg = index.get("app", "1.0.0").expect("package");
        assert_eq!(pkg.dependencies.len(), 1);
        assert_eq!(pkg.dependencies[0].to_string(), "dep==2.0.0");
    }
}
