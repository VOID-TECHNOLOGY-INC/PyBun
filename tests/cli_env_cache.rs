#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn fake_python(path: &Path, version: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, format!("#!/bin/sh\necho Python {version}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn version_file_changes_match_cold_and_warm_discovery() {
    let root = tempdir().unwrap();
    let project = root.path().join("project");
    let home = root.path().join("home");
    let tools = root.path().join("tools");
    let pyenv = root.path().join("pyenv");
    fs::create_dir_all(&project).unwrap();
    let system = tools.join("python3");
    fake_python(&system, "3.10.0");
    let first = pyenv.join("versions/3.11.11/bin/python");
    let second = pyenv.join("versions/3.12.12/bin/python");
    fake_python(&first, "3.11.11");
    fake_python(&second, "3.12.12");
    let discover = || {
        let output = Command::new(env!("CARGO_BIN_EXE_pybun"))
            .current_dir(&project)
            .env("PYBUN_HOME", &home)
            .env("PATH", &tools)
            .env("PYENV_ROOT", &pyenv)
            .env_remove("PYBUN_ENV")
            .env_remove("PYBUN_PYTHON")
            .args(["--format=json", "python", "which"])
            .output()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        (output.status.success(), value["detail"].clone())
    };
    for (ancestor, local, expected) in [
        (None, None, Some(&system)),
        (Some("3.11.11"), None, Some(&first)),
        (Some("3.12.12"), None, Some(&second)),
        (Some("3.12.12"), Some("3.11.11"), Some(&first)),
        (Some("3.12.12"), Some("9.99.99"), None),
        (Some("3.12.12"), None, Some(&second)),
        (None, None, Some(&system)),
    ] {
        for (path, version) in [
            (root.path().join(".python-version"), ancestor),
            (project.join(".python-version"), local),
        ] {
            if let Some(version) = version {
                fs::write(path, version).unwrap();
            } else if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
        let warm = discover();
        assert_eq!(
            warm.0,
            expected.is_some(),
            "ancestor={ancestor:?}, local={local:?}: {warm:?}"
        );
        if let Some(expected) = expected {
            assert_eq!(warm.1["path"], expected.display().to_string(), "{warm:?}");
        }
        assert_eq!(discover(), warm, "repeated warm discovery differs");
        let cache = home.join("env_cache.json");
        if cache.exists() {
            fs::remove_file(cache).unwrap();
        }
        assert_eq!(
            discover(),
            warm,
            "cold discovery differs after selector change"
        );
    }
}
