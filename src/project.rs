//! pyproject.toml support for PyBun.
//!
//! Handles reading and writing project dependencies in [project.dependencies]
//! and [tool.pybun] sections.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use toml::Value;

const PYPROJECT_FILENAME: &str = "pyproject.toml";

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("pyproject.toml not found in {0}")]
    NotFound(PathBuf),
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse pyproject.toml: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("failed to serialize pyproject.toml: {0}")]
    Serialize(#[from] toml::ser::Error),
}

pub type Result<T> = std::result::Result<T, ProjectError>;

/// Represents a pyproject.toml file with relevant sections.
#[derive(Debug, Clone)]
pub struct Project {
    path: PathBuf,
    raw: Value,
}

/// Project metadata from [project] section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectMetadata {
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub dependencies: Vec<String>,
}

/// PyBun-specific configuration from [tool.pybun].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PybunConfig {
    #[serde(default)]
    pub python: Option<String>,
    #[serde(default)]
    pub lazy_imports: Vec<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileConfig {
    #[serde(default)]
    pub hot_reload: Option<bool>,
    #[serde(default)]
    pub lazy_import: Option<bool>,
    #[serde(default)]
    pub log_level: Option<String>,
}

impl Project {
    /// Find and load pyproject.toml from the current directory or ancestors.
    pub fn discover(start_dir: impl AsRef<Path>) -> Result<Self> {
        let start = start_dir.as_ref();
        let mut current = start.to_path_buf();

        loop {
            let candidate = current.join(PYPROJECT_FILENAME);
            if candidate.exists() {
                return Self::load(&candidate);
            }

            if !current.pop() {
                return Err(ProjectError::NotFound(start.to_path_buf()));
            }
        }
    }

    /// Load pyproject.toml from a specific path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let content = fs::read_to_string(&path).map_err(|source| ProjectError::Read {
            path: path.clone(),
            source,
        })?;
        let raw: Value = content.parse()?;
        Ok(Self { path, raw })
    }

    /// Create a new empty pyproject.toml.
    pub fn new(path: impl AsRef<Path>) -> Self {
        let mut raw = Value::Table(toml::map::Map::new());
        // Initialize with empty project section
        if let Value::Table(ref mut t) = raw {
            let mut project = toml::map::Map::new();
            project.insert("dependencies".into(), Value::Array(vec![]));
            t.insert("project".into(), Value::Table(project));
        }
        Self {
            path: path.as_ref().to_path_buf(),
            raw,
        }
    }

    /// Path to the pyproject.toml file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Directory containing pyproject.toml.
    pub fn root(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new("."))
    }

    /// Get project metadata.
    pub fn metadata(&self) -> ProjectMetadata {
        self.raw
            .get("project")
            .and_then(|v| v.clone().try_into().ok())
            .unwrap_or_default()
    }

    /// Get list of dependencies.
    pub fn dependencies(&self) -> Vec<String> {
        self.raw
            .get("project")
            .and_then(|p| p.get("dependencies"))
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Add a dependency to [project.dependencies].
    pub fn add_dependency(&mut self, dep: &str) {
        if let Value::Table(ref mut root) = self.raw {
            let project = root
                .entry("project")
                .or_insert_with(|| Value::Table(toml::map::Map::new()));

            if let Value::Table(project_table) = project {
                let deps = project_table
                    .entry("dependencies")
                    .or_insert_with(|| Value::Array(vec![]));

                if let Value::Array(arr) = deps {
                    // Extract package name (before any version specifier)
                    let pkg_name = extract_package_name(dep);

                    // Remove existing entry for same package
                    arr.retain(|v| {
                        v.as_str()
                            .map(|s| extract_package_name(s) != pkg_name)
                            .unwrap_or(true)
                    });

                    // Add new entry
                    arr.push(Value::String(dep.to_string()));

                    // Sort for deterministic output
                    arr.sort_by(|a, b| {
                        let a_str = a.as_str().unwrap_or("");
                        let b_str = b.as_str().unwrap_or("");
                        a_str.cmp(b_str)
                    });
                }
            }
        }
    }

    /// Remove a dependency from [project.dependencies].
    pub fn remove_dependency(&mut self, name: &str) -> bool {
        let mut removed = false;
        let name_lower = name.to_lowercase();

        if let Value::Table(ref mut root) = self.raw {
            if let Some(Value::Table(project)) = root.get_mut("project") {
                if let Some(Value::Array(deps)) = project.get_mut("dependencies") {
                    let before = deps.len();
                    deps.retain(|v| {
                        v.as_str()
                            .map(|s| extract_package_name(s).to_lowercase() != name_lower)
                            .unwrap_or(true)
                    });
                    removed = deps.len() < before;
                }
            }
        }

        removed
    }

    /// Check if a dependency exists.
    pub fn has_dependency(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.dependencies()
            .iter()
            .any(|d| extract_package_name(d).to_lowercase() == name_lower)
    }

    /// Get pybun-specific configuration.
    pub fn pybun_config(&self) -> PybunConfig {
        self.raw
            .get("tool")
            .and_then(|t| t.get("pybun"))
            .and_then(|v| v.clone().try_into().ok())
            .unwrap_or_default()
    }

    /// Save the project file.
    pub fn save(&self) -> Result<()> {
        let content = toml::to_string_pretty(&self.raw)?;
        fs::write(&self.path, content).map_err(|source| ProjectError::Write {
            path: self.path.clone(),
            source,
        })?;
        Ok(())
    }
}

/// Extract package name from a dependency specifier.
/// e.g., "requests>=2.28.0" -> "requests"
fn extract_package_name(dep: &str) -> &str {
    let dep = dep.trim();
    // Find first version specifier character
    let end = dep
        .find(|c: char| c == '=' || c == '>' || c == '<' || c == '!' || c == '~' || c == '[')
        .unwrap_or(dep.len());
    dep[..end].trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn extract_package_name_works() {
        assert_eq!(extract_package_name("requests"), "requests");
        assert_eq!(extract_package_name("requests>=2.28.0"), "requests");
        assert_eq!(extract_package_name("requests==2.28.0"), "requests");
        assert_eq!(extract_package_name("requests[socks]>=2.28.0"), "requests");
        assert_eq!(extract_package_name("  numpy  "), "numpy");
    }

    #[test]
    fn new_project_has_empty_deps() {
        let temp = tempdir().unwrap();
        let project = Project::new(temp.path().join("pyproject.toml"));
        assert!(project.dependencies().is_empty());
    }

    #[test]
    fn add_dependency_works() {
        let temp = tempdir().unwrap();
        let mut project = Project::new(temp.path().join("pyproject.toml"));

        project.add_dependency("requests>=2.28.0");
        assert!(project.has_dependency("requests"));
        assert_eq!(project.dependencies(), vec!["requests>=2.28.0"]);
    }

    #[test]
    fn add_dependency_replaces_existing() {
        let temp = tempdir().unwrap();
        let mut project = Project::new(temp.path().join("pyproject.toml"));

        project.add_dependency("requests>=2.28.0");
        project.add_dependency("requests>=2.31.0");

        let deps = project.dependencies();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0], "requests>=2.31.0");
    }

    #[test]
    fn remove_dependency_works() {
        let temp = tempdir().unwrap();
        let mut project = Project::new(temp.path().join("pyproject.toml"));

        project.add_dependency("requests>=2.28.0");
        project.add_dependency("numpy>=1.24.0");

        assert!(project.remove_dependency("requests"));
        assert!(!project.has_dependency("requests"));
        assert!(project.has_dependency("numpy"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("pyproject.toml");

        let mut project = Project::new(&path);
        project.add_dependency("requests>=2.28.0");
        project.save().unwrap();

        let loaded = Project::load(&path).unwrap();
        assert_eq!(loaded.dependencies(), vec!["requests>=2.28.0"]);
    }
}
