//! Server-authorized project boundaries; CLI calls retain their existing scope.
use super::*;

pub(crate) fn check_scope(path: &Path, roots: &[PathBuf]) -> Result<(), BackendError> {
    if roots.is_empty() {
        return Ok(());
    }
    let mut existing = path.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !existing.pop() {
                    return Err(denied());
                }
            }
            Err(_) => return Err(denied()),
        }
    }
    let actual = existing.canonicalize().map_err(|_| denied())?;
    if roots.iter().any(|root| actual.starts_with(root)) {
        Ok(())
    } else {
        Err(denied())
    }
}
fn denied() -> BackendError {
    error(
        "E_MCP_POLICY_PATH_DENIED",
        "Backend-derived project or output path is outside the operator boundary.",
    )
}
impl UvBackend {
    pub(super) fn scoped(mut self, roots: Vec<PathBuf>) -> Self {
        self.authorized_roots = roots;
        self
    }
    pub(super) fn check_project_scope(&self, root: &Path) -> Result<(), BackendError> {
        check_scope(root, &self.authorized_roots)?;
        for output in ["uv.lock", "pyproject.toml", ".venv", ".pybun/receipts"] {
            check_scope(&root.join(output), &self.authorized_roots)?;
        }
        if let Some(environment) = std::env::var_os("UV_PROJECT_ENVIRONMENT") {
            check_scope(&root.join(environment), &self.authorized_roots)?;
        }
        Ok(())
    }
}
