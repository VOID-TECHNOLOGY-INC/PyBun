use crate::project::{Project, ProjectError, extract_package_name};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("workspace configuration missing")]
    MissingWorkspaceConfig,
    #[error("member {path} not found")]
    MemberNotFound { path: PathBuf },
    #[error("project error: {0}")]
    Project(#[from] ProjectError),
}

pub type Result<T> = std::result::Result<T, WorkspaceError>;

/// Represents a PyBun workspace with multiple member projects.
#[derive(Debug, Clone)]
pub struct Workspace {
    pub root: Project,
    pub members: Vec<Project>,
}

impl Workspace {
    /// Discover a workspace starting from a directory.
    pub fn discover(start_dir: impl AsRef<Path>) -> Result<Option<Self>> {
        let project = match Project::discover(start_dir) {
            Ok(p) => p,
            Err(ProjectError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if project.workspace_config().is_none() {
            return Ok(None);
        }
        Self::from_root(project).map(Some)
    }

    /// Build a workspace from a root project that already contains a workspace config.
    pub fn from_root(root: Project) -> Result<Self> {
        let Some(config) = root.workspace_config() else {
            return Err(WorkspaceError::MissingWorkspaceConfig);
        };

        let mut members = Vec::new();
        for member in config.members {
            let member_path = root.root().join(member).join("pyproject.toml");
            if !member_path.exists() {
                return Err(WorkspaceError::MemberNotFound {
                    path: member_path.clone(),
                });
            }
            members.push(Project::load(member_path)?);
        }

        Ok(Self { root, members })
    }

    /// Merge dependencies from root and all members, de-duplicating by package name.
    pub fn merged_dependencies(&self) -> Vec<String> {
        let mut merged: BTreeMap<String, String> = BTreeMap::new();

        for dep in self
            .root
            .dependencies()
            .into_iter()
            .chain(self.members.iter().flat_map(|p| p.dependencies()))
        {
            let key = extract_package_name(&dep).to_lowercase();
            merged.entry(key).or_insert(dep);
        }

        merged.values().cloned().collect()
    }
}
