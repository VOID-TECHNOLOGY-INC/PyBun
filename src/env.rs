//! Environment selection and Python interpreter management.
//!
//! Priority order for environment selection:
//! 1. PYBUN_ENV environment variable (explicit path to venv)
//! 2. PYBUN_PYTHON environment variable (explicit Python binary)
//! 3. Project-local `.pybun/venv` directory
//! 4. `.python-version` file (pyenv-style version selection)
//! 5. System Python (python3 / python in PATH)

use color_eyre::eyre::{Result, eyre};
use std::path::{Path, PathBuf};

/// Represents a discovered Python environment.
#[derive(Debug, Clone)]
pub struct PythonEnv {
    /// Path to the Python interpreter binary.
    pub python_path: PathBuf,
    /// Version string (e.g., "3.11.5"), if known.
    pub version: Option<String>,
    /// Source of this environment selection.
    pub source: EnvSource,
}

/// Describes how the environment was selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvSource {
    /// PYBUN_ENV environment variable pointing to a venv.
    PybunEnv,
    /// PYBUN_PYTHON environment variable pointing to a binary.
    PybunPython,
    /// Project-local `.pybun/venv` directory.
    ProjectLocal,
    /// `.python-version` file in project or parent directories.
    PythonVersionFile(PathBuf),
    /// System Python found in PATH.
    System,
}

impl std::fmt::Display for EnvSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvSource::PybunEnv => write!(f, "PYBUN_ENV"),
            EnvSource::PybunPython => write!(f, "PYBUN_PYTHON"),
            EnvSource::ProjectLocal => write!(f, "project-local (.pybun/venv)"),
            EnvSource::PythonVersionFile(p) => write!(f, ".python-version ({})", p.display()),
            EnvSource::System => write!(f, "system PATH"),
        }
    }
}

/// Find the best Python environment for the given working directory.
///
/// # Priority
/// 1. `PYBUN_ENV` - explicit venv path
/// 2. `PYBUN_PYTHON` - explicit Python binary
/// 3. `.pybun/venv` - project-local environment
/// 4. `.python-version` - pyenv-style version file
/// 5. System Python (python3/python in PATH)
pub fn find_python_env(working_dir: &Path) -> Result<PythonEnv> {
    // 1. Check PYBUN_ENV (explicit venv path)
    if let Ok(venv_path) = std::env::var("PYBUN_ENV") {
        let venv = PathBuf::from(&venv_path);
        if let Some(python) = find_venv_python(&venv) {
            return Ok(PythonEnv {
                python_path: python,
                version: get_python_version_from_venv(&venv),
                source: EnvSource::PybunEnv,
            });
        }
        // If PYBUN_ENV is set but invalid, warn and continue
        eprintln!(
            "warning: PYBUN_ENV={} is not a valid venv, ignoring",
            venv_path
        );
    }

    // 2. Check PYBUN_PYTHON (explicit binary)
    if let Ok(python_path) = std::env::var("PYBUN_PYTHON") {
        let python = PathBuf::from(&python_path);
        if python.exists() || which_executable(&python_path).is_some() {
            return Ok(PythonEnv {
                python_path: if python.exists() {
                    python
                } else {
                    PathBuf::from(&python_path)
                },
                version: None,
                source: EnvSource::PybunPython,
            });
        }
        eprintln!("warning: PYBUN_PYTHON={} not found, ignoring", python_path);
    }

    // 3. Check project-local .pybun/venv
    if let Some(project_venv) = find_project_venv(working_dir)
        && let Some(python) = find_venv_python(&project_venv)
    {
        return Ok(PythonEnv {
            python_path: python,
            version: get_python_version_from_venv(&project_venv),
            source: EnvSource::ProjectLocal,
        });
    }

    // 4. Check .python-version file
    if let Some((version_file, version)) = find_python_version_file(working_dir) {
        if let Some(python) = find_python_for_version(&version) {
            return Ok(PythonEnv {
                python_path: python,
                version: Some(version),
                source: EnvSource::PythonVersionFile(version_file),
            });
        }
        // Version file exists but no matching Python found
        eprintln!(
            "warning: .python-version requests {} but it's not installed",
            version
        );
    }

    // 5. Fall back to system Python
    if let Some(python) = find_system_python() {
        return Ok(PythonEnv {
            python_path: python,
            version: None,
            source: EnvSource::System,
        });
    }

    Err(eyre!(
        "No Python interpreter found. Set PYBUN_PYTHON or ensure python3/python is in PATH"
    ))
}

/// Find Python binary inside a virtual environment.
fn find_venv_python(venv_path: &Path) -> Option<PathBuf> {
    // Unix: venv/bin/python
    let unix_python = venv_path.join("bin").join("python");
    if unix_python.exists() {
        return Some(unix_python);
    }

    // Windows: venv/Scripts/python.exe
    let windows_python = venv_path.join("Scripts").join("python.exe");
    if windows_python.exists() {
        return Some(windows_python);
    }

    None
}

/// Try to get Python version from venv's pyvenv.cfg.
fn get_python_version_from_venv(venv_path: &Path) -> Option<String> {
    let cfg_path = venv_path.join("pyvenv.cfg");
    if let Ok(content) = std::fs::read_to_string(&cfg_path) {
        for line in content.lines() {
            if let Some(stripped) = line.strip_prefix("version") {
                let value = stripped.trim().trim_start_matches(['=', ' ']);
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// Find project-local .pybun/venv directory.
fn find_project_venv(start_dir: &Path) -> Option<PathBuf> {
    let mut current = start_dir;
    loop {
        let venv_path = current.join(".pybun").join("venv");
        if venv_path.is_dir() {
            return Some(venv_path);
        }

        // Also check for pyproject.toml as project root marker
        let pyproject = current.join("pyproject.toml");
        if pyproject.exists() {
            // If we found pyproject.toml but no .pybun/venv, stop searching
            return None;
        }

        current = current.parent()?;
    }
}

/// Find .python-version file and read its content.
fn find_python_version_file(start_dir: &Path) -> Option<(PathBuf, String)> {
    let mut current = start_dir;
    loop {
        let version_file = current.join(".python-version");
        if version_file.exists()
            && let Ok(content) = std::fs::read_to_string(&version_file)
        {
            let version = content.trim().to_string();
            if !version.is_empty() && !version.starts_with('#') {
                return Some((version_file, version));
            }
        }

        current = current.parent()?;
    }
}

/// Find Python interpreter for a specific version.
/// Supports pyenv-style installations and common system paths.
fn find_python_for_version(version: &str) -> Option<PathBuf> {
    // Parse version parts
    let parts: Vec<&str> = version.split('.').collect();
    let (major, minor) = match parts.as_slice() {
        [maj, min, ..] => (maj.to_string(), Some(min.to_string())),
        [maj] => (maj.to_string(), None),
        _ => return None,
    };

    // Try pyenv first (if PYENV_ROOT is set or ~/.pyenv exists)
    if let Some(python) = find_pyenv_python(version) {
        return Some(python);
    }

    // Try versioned system Python (e.g., python3.11)
    if let Some(minor) = &minor {
        let versioned = format!("python{}.{}", major, minor);
        if let Some(path) = which_executable(&versioned) {
            return Some(path);
        }
    }

    // Try major version only (e.g., python3)
    let major_only = format!("python{}", major);
    if let Some(path) = which_executable(&major_only) {
        return Some(path);
    }

    None
}

/// Find Python installed via pyenv.
fn find_pyenv_python(version: &str) -> Option<PathBuf> {
    let pyenv_root = std::env::var("PYENV_ROOT")
        .map(PathBuf::from)
        .ok()
        .or_else(|| dirs::home_dir().map(|h| h.join(".pyenv")))?;

    if !pyenv_root.exists() {
        return None;
    }

    // Check exact version
    let exact_path = pyenv_root
        .join("versions")
        .join(version)
        .join("bin")
        .join("python");
    if exact_path.exists() {
        return Some(exact_path);
    }

    // Check for matching prefix (e.g., "3.11" matches "3.11.5")
    let versions_dir = pyenv_root.join("versions");
    if versions_dir.is_dir()
        && let Ok(entries) = std::fs::read_dir(&versions_dir)
    {
        let mut matching: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(version))
            .collect();

        // Sort to get the latest matching version
        matching.sort_by_key(|e| std::cmp::Reverse(e.file_name()));

        if let Some(entry) = matching.first() {
            let python = entry.path().join("bin").join("python");
            if python.exists() {
                return Some(python);
            }
        }
    }

    None
}

/// Find system Python (python3 or python).
fn find_system_python() -> Option<PathBuf> {
    // Prefer python3
    if let Some(path) = which_executable("python3") {
        return Some(path);
    }

    // Fall back to python
    if let Some(path) = which_executable("python") {
        return Some(path);
    }

    None
}

/// Check if an executable exists in PATH.
fn which_executable(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let full_path = dir.join(name);
            if full_path.is_file() {
                return Some(full_path);
            }

            // On Windows, also check with .exe extension
            #[cfg(windows)]
            {
                let with_ext = dir.join(format!("{}.exe", name));
                if with_ext.is_file() {
                    return Some(with_ext);
                }
            }

            None
        })
    })
}

/// Get the pybun home directory for caches and environments.
/// Uses PYBUN_HOME if set, otherwise defaults to ~/.cache/pybun.
pub fn pybun_home() -> PathBuf {
    if let Ok(home) = std::env::var("PYBUN_HOME") {
        return PathBuf::from(home);
    }

    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pybun")
}

/// Get the global environments directory.
pub fn global_envs_dir() -> PathBuf {
    pybun_home().join("envs")
}

/// Get the global packages/wheel cache directory.
pub fn global_packages_dir() -> PathBuf {
    pybun_home().join("packages")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_find_venv_python_unix() {
        let temp = TempDir::new().unwrap();
        let venv = temp.path().join("venv");
        let bin = venv.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let python = bin.join("python");
        fs::write(&python, "fake python").unwrap();

        assert_eq!(find_venv_python(&venv), Some(python));
    }

    #[test]
    fn test_python_version_file_parsing() {
        let temp = TempDir::new().unwrap();
        let version_file = temp.path().join(".python-version");
        fs::write(&version_file, "3.11.5\n").unwrap();

        let result = find_python_version_file(temp.path());
        assert!(result.is_some());
        let (path, version) = result.unwrap();
        assert_eq!(path, version_file);
        assert_eq!(version, "3.11.5");
    }

    #[test]
    fn test_python_version_file_with_comment() {
        let temp = TempDir::new().unwrap();
        let version_file = temp.path().join(".python-version");
        fs::write(&version_file, "# comment\n").unwrap();

        // Should not match comment lines
        let result = find_python_version_file(temp.path());
        assert!(result.is_none());
    }

    #[test]
    fn test_pybun_home_default() {
        // Note: We avoid modifying environment variables in this test to prevent
        // race conditions with other parallel tests. Instead, we verify the return
        // value is a valid path ending with "pybun".
        let home = pybun_home();
        // The path should either come from PYBUN_HOME env var or end with "pybun"
        // from the cache_dir().join("pybun") fallback
        let home_str = home.to_string_lossy();
        assert!(
            home_str.ends_with("pybun") || home_str.contains("pybun"),
            "Expected path to contain 'pybun', got: {}",
            home_str
        );
    }

    #[test]
    #[ignore = "Modifies environment variables, run with --ignored in single-threaded mode"]
    fn test_pybun_home_override() {
        // SAFETY: test runs in isolation, no concurrent env access concerns
        unsafe { std::env::set_var("PYBUN_HOME", "/custom/path") };
        let home = pybun_home();
        assert_eq!(home, PathBuf::from("/custom/path"));
        unsafe { std::env::remove_var("PYBUN_HOME") };
    }

    #[test]
    fn test_env_source_display() {
        assert_eq!(format!("{}", EnvSource::PybunEnv), "PYBUN_ENV");
        assert_eq!(format!("{}", EnvSource::PybunPython), "PYBUN_PYTHON");
        assert_eq!(format!("{}", EnvSource::System), "system PATH");
    }

    #[test]
    fn test_project_venv_discovery() {
        let temp = TempDir::new().unwrap();
        let pybun_dir = temp.path().join(".pybun").join("venv");
        fs::create_dir_all(&pybun_dir).unwrap();

        // Create bin/python for Unix
        let bin = pybun_dir.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("python"), "fake").unwrap();

        let result = find_project_venv(temp.path());
        assert_eq!(result, Some(pybun_dir));
    }
}
