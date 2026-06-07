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
    /// Discover a workspace starting from a directory. Returns `Ok(None)` if
    /// the nearest project does not declare `[tool.pybun.workspace]`.
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

    /// Discover a workspace by walking up from `start_dir`, continuing past
    /// projects that don't declare a workspace (e.g. when run from inside a
    /// member directory). Returns `Ok(None)` if no ancestor declares
    /// `[tool.pybun.workspace]`.
    pub fn discover_root(start_dir: impl AsRef<Path>) -> Result<Option<Self>> {
        let mut current = start_dir.as_ref().to_path_buf();
        loop {
            let candidate = current.join("pyproject.toml");
            if candidate.exists() {
                let project = Project::load(&candidate)?;
                if project.workspace_config().is_some() {
                    return Self::from_root(project).map(Some);
                }
            }
            if !current.pop() {
                return Ok(None);
            }
        }
    }

    /// Build a workspace from a root project that already contains a workspace config.
    pub fn from_root(root: Project) -> Result<Self> {
        let Some(config) = root.workspace_config() else {
            return Err(WorkspaceError::MissingWorkspaceConfig);
        };

        let mut members = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for pattern in &config.members {
            let matches = expand_member_pattern(root.root(), pattern);

            if matches.is_empty() {
                if pattern.contains('*') {
                    // Glob patterns may legitimately match nothing yet.
                    continue;
                }
                return Err(WorkspaceError::MemberNotFound {
                    path: root.root().join(pattern).join("pyproject.toml"),
                });
            }

            for member_dir in matches {
                let member_path = member_dir.join("pyproject.toml");
                if !member_path.exists() {
                    if pattern.contains('*') {
                        continue;
                    }
                    return Err(WorkspaceError::MemberNotFound { path: member_path });
                }
                if seen.insert(member_path.clone()) {
                    members.push(Project::load(&member_path)?);
                }
            }
        }

        Ok(Self { root, members })
    }

    /// Names of all workspace members, derived from `[project.name]` and
    /// falling back to the member's directory name when unset.
    pub fn member_names(&self) -> Vec<String> {
        self.members.iter().map(member_display_name).collect()
    }

    /// Find a member project by its `[project.name]` (or directory name fallback).
    pub fn member_by_name(&self, name: &str) -> Option<&Project> {
        self.members
            .iter()
            .find(|member| member_display_name(member) == name)
    }

    /// Merge dependencies from root and all members, de-duplicating by package name.
    pub fn merged_dependencies(&self) -> Vec<String> {
        merge_dependencies(
            self.root
                .dependencies()
                .into_iter()
                .chain(self.members.iter().flat_map(|p| p.dependencies())),
        )
    }

    /// Merge dependencies for a named group (checked via `[project.optional-dependencies]`
    /// then `[dependency-groups]`) across the root and all members,
    /// de-duplicating by package name.
    pub fn dependencies_for_group(&self, group: &str) -> Vec<String> {
        merge_dependencies(
            self.root.group_dependencies(group).into_iter().chain(
                self.members
                    .iter()
                    .flat_map(|p| p.group_dependencies(group)),
            ),
        )
    }
}

/// Display name for a member project: its declared `[project.name]`, falling
/// back to the containing directory name.
fn member_display_name(member: &Project) -> String {
    member.metadata().name.unwrap_or_else(|| {
        member
            .root()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| member.root().display().to_string())
    })
}

/// De-duplicate dependency specifiers by package name (case-insensitive),
/// keeping the first occurrence and returning a sorted, stable result.
fn merge_dependencies(deps: impl Iterator<Item = String>) -> Vec<String> {
    let mut merged: BTreeMap<String, String> = BTreeMap::new();
    for dep in deps {
        let key = extract_package_name(&dep).to_lowercase();
        merged.entry(key).or_insert(dep);
    }
    merged.values().cloned().collect()
}

/// Expand a workspace member path pattern relative to `root` into concrete
/// directories. Patterns without `*` are returned as-is (single entry);
/// patterns containing `*` are matched against directory entries one path
/// segment at a time (e.g. `apps/*`, `packages/*/services`).
fn expand_member_pattern(root: &Path, pattern: &str) -> Vec<PathBuf> {
    if !pattern.contains('*') {
        return vec![root.join(pattern)];
    }

    let mut current: Vec<PathBuf> = vec![PathBuf::new()];
    for component in Path::new(pattern).components() {
        let segment = component.as_os_str().to_string_lossy().into_owned();
        let mut next = Vec::new();

        if segment.contains('*') {
            for base in &current {
                let dir = root.join(base);
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                let mut matches: Vec<PathBuf> = entries
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.path().is_dir())
                    .filter(|entry| {
                        glob_segment_matches(&segment, &entry.file_name().to_string_lossy())
                    })
                    .map(|entry| base.join(entry.file_name()))
                    .collect();
                matches.sort();
                next.extend(matches);
            }
        } else {
            for base in &current {
                next.push(base.join(&segment));
            }
        }

        current = next;
    }

    current.into_iter().map(|rel| root.join(rel)).collect()
}

/// Match a single path segment containing at most simple `*` wildcards
/// (prefix, suffix, contains, or "match anything").
fn glob_segment_matches(pattern: &str, name: &str) -> bool {
    match pattern {
        "*" => true,
        p if p.starts_with('*') && p.ends_with('*') && p.len() > 1 => {
            name.contains(&p[1..p.len() - 1])
        }
        p if p.starts_with('*') => name.ends_with(&p[1..]),
        p if p.ends_with('*') => name.starts_with(&p[..p.len() - 1]),
        p => p == name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_project(path: &Path, name: &str, deps: &[&str]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let deps_toml = deps
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(
            path,
            format!(
                "[project]\nname = \"{name}\"\nversion = \"0.1.0\"\ndependencies = [{deps_toml}]\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn from_root_expands_glob_member_patterns() {
        let temp = tempdir().unwrap();
        let root_dir = temp.path();

        fs::write(
            root_dir.join("pyproject.toml"),
            r#"[project]
name = "root"
version = "0.1.0"

[tool.pybun.workspace]
members = ["apps/*"]
"#,
        )
        .unwrap();

        write_project(&root_dir.join("apps/api/pyproject.toml"), "api", &["lib-a"]);
        write_project(&root_dir.join("apps/web/pyproject.toml"), "web", &["lib-b"]);
        // Non-directory entries and dirs without pyproject.toml should be skipped.
        fs::create_dir_all(root_dir.join("apps/empty")).unwrap();
        fs::write(root_dir.join("apps/.gitkeep"), "").unwrap();

        let root = Project::load(root_dir.join("pyproject.toml")).unwrap();
        let workspace = Workspace::from_root(root).unwrap();

        let mut names = workspace.member_names();
        names.sort();
        assert_eq!(names, vec!["api".to_string(), "web".to_string()]);
    }

    #[test]
    fn from_root_errors_on_missing_literal_member() {
        let temp = tempdir().unwrap();
        let root_dir = temp.path();
        fs::write(
            root_dir.join("pyproject.toml"),
            r#"[project]
name = "root"
version = "0.1.0"

[tool.pybun.workspace]
members = ["packages/missing"]
"#,
        )
        .unwrap();

        let root = Project::load(root_dir.join("pyproject.toml")).unwrap();
        let err = Workspace::from_root(root).unwrap_err();
        assert!(matches!(err, WorkspaceError::MemberNotFound { .. }));
    }

    #[test]
    fn member_by_name_finds_declared_project_name() {
        let temp = tempdir().unwrap();
        let root_dir = temp.path();
        fs::write(
            root_dir.join("pyproject.toml"),
            r#"[project]
name = "root"
version = "0.1.0"

[tool.pybun.workspace]
members = ["packages/sdk"]
"#,
        )
        .unwrap();
        write_project(&root_dir.join("packages/sdk/pyproject.toml"), "sdk", &[]);

        let root = Project::load(root_dir.join("pyproject.toml")).unwrap();
        let workspace = Workspace::from_root(root).unwrap();

        assert!(workspace.member_by_name("sdk").is_some());
        assert!(workspace.member_by_name("missing").is_none());
    }

    #[test]
    fn dependencies_for_group_merges_across_members() {
        let temp = tempdir().unwrap();
        let root_dir = temp.path();
        fs::write(
            root_dir.join("pyproject.toml"),
            r#"[project]
name = "root"
version = "0.1.0"
dependencies = []

[tool.pybun.workspace]
members = ["packages/api", "packages/sdk"]

[dependency-groups]
dev = ["ruff>=0.1.0"]
"#,
        )
        .unwrap();

        fs::create_dir_all(root_dir.join("packages/api")).unwrap();
        fs::write(
            root_dir.join("packages/api/pyproject.toml"),
            r#"[project]
name = "api"
version = "0.1.0"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=7.0.0"]
"#,
        )
        .unwrap();
        write_project(&root_dir.join("packages/sdk/pyproject.toml"), "sdk", &[]);

        let root = Project::load(root_dir.join("pyproject.toml")).unwrap();
        let workspace = Workspace::from_root(root).unwrap();

        let mut deps = workspace.dependencies_for_group("dev");
        deps.sort();
        assert_eq!(
            deps,
            vec!["pytest>=7.0.0".to_string(), "ruff>=0.1.0".to_string()]
        );
        assert!(workspace.dependencies_for_group("missing").is_empty());
    }

    #[test]
    fn discover_root_walks_up_past_member_projects() {
        let temp = tempdir().unwrap();
        let root_dir = temp.path();
        fs::write(
            root_dir.join("pyproject.toml"),
            r#"[project]
name = "root"
version = "0.1.0"

[tool.pybun.workspace]
members = ["packages/api"]
"#,
        )
        .unwrap();
        write_project(&root_dir.join("packages/api/pyproject.toml"), "api", &[]);

        let workspace = Workspace::discover_root(root_dir.join("packages/api"))
            .unwrap()
            .expect("workspace should be discovered from member directory");
        assert_eq!(workspace.member_names(), vec!["api".to_string()]);

        // Plain `discover` should not find a workspace from inside a member.
        assert!(
            Workspace::discover(root_dir.join("packages/api"))
                .unwrap()
                .is_none()
        );
    }
}
