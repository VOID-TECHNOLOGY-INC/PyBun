use pybun::security_assessment::qualification::registry::{
    ReleaseAvailability, parse_registry_catalog,
};
use pybun::security_assessment::{CoverageStatus, InventoryRequest, observe_inventory};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

fn interpreter(name: &Path) -> (PathBuf, String, String, String) {
    let out = Command::new(name).args(["-I", "-S", "-B", "-c", "import sys,json; v=sys.version_info; suffix={'alpha':'a','beta':'b','candidate':'rc','final':''}[v.releaselevel]; full='.'.join(map(str,v[:3])) + (suffix+str(v.serial) if suffix else ''); print(json.dumps([sys.executable,full,'.'.join(map(str,v[:3])),'.'.join(map(str,v))]))"]).output().unwrap();
    assert!(out.status.success());
    let values: Vec<String> = serde_json::from_slice(&out.stdout).unwrap();
    (
        PathBuf::from(&values[0]),
        values[1].clone(),
        values[2].clone(),
        values[3].clone(),
    )
}
fn project(python: &Path, uv: bool) -> (TempDir, InventoryRequest) {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='test'\nversion='1'\n",
    )
    .unwrap();
    let status = if uv {
        Command::new("uv")
            .args(["venv", "--no-project", "--no-python-downloads", "--python"])
            .arg(python)
            .arg(dir.path().join(".venv"))
            .status()
            .unwrap()
    } else {
        Command::new(python)
            .args(["-I", "-B", "-m", "venv", "--without-pip"])
            .arg(dir.path().join(".venv"))
            .status()
            .unwrap()
    };
    assert!(status.success());
    let request = InventoryRequest::installed(dir.path(), python);
    (dir, request)
}

#[test]
fn explicit_prerelease_or_junk_config_cannot_be_truncated_to_stable() {
    let name = std::env::var_os("PYBUN_SECURITY_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let (python, full, release, legacy) = interpreter(Path::new(&name));
    assert_eq!(full, release, "this fixture requires stable CPython");
    let (dir, request) = project(&python, false);
    for suffix in [".candidate.1", ".junk", ".final.0.junk", ".final.1", "rc1"] {
        fs::write(
            dir.path().join(".venv/pyvenv.cfg"),
            format!("version = {release}{suffix}\ninclude-system-site-packages = false\n"),
        )
        .unwrap();
        let observed = observe_inventory(&request, 0);
        assert_eq!(
            observed.coverage.inventory_instances.status,
            CoverageStatus::Unsupported,
            "config suffix {suffix} was accepted as stable"
        );
        assert!(observed.target.is_none());
    }
    let config = dir.path().join(".venv/pyvenv.cfg");
    fs::write(
        &config,
        format!("version_info = {legacy}\ninclude-system-site-packages = false\n"),
    )
    .unwrap();
    let valid_legacy = observe_inventory(&request, 0);
    assert_eq!(
        valid_legacy.coverage.inventory_instances.status,
        CoverageStatus::Complete
    );
    assert_eq!(
        valid_legacy.target.unwrap().tag_profile.python_version,
        full
    );
    fs::write(&config, format!("version = {release}\nversion_info = {release}.candidate.1\ninclude-system-site-packages = false\n")).unwrap();
    let conflicting = observe_inventory(&request, 0);
    assert_eq!(
        conflicting.coverage.inventory_instances.status,
        CoverageStatus::Unsupported
    );
    assert!(conflicting.target.is_none());
}

fn assert_prerelease_target(uv: bool) {
    let requested = std::env::var_os("PYBUN_SECURITY_PRERELEASE_PYTHON")
        .expect("set the explicitly installed test-only prerelease interpreter path");
    let (python, full, release, legacy) = interpreter(Path::new(&requested));
    assert_ne!(
        full, release,
        "fixture must execute a real CPython prerelease"
    );
    let (dir, request) = project(&python, uv);
    let observed = observe_inventory(&request, 0);
    let target = observed
        .target
        .as_ref()
        .expect("real prerelease venv must retain a proven target");
    let major_minor = release.rsplit_once('.').unwrap().0;
    let catalog = parse_registry_catalog(
        "demo",
        &json!({"meta":{"api-version":"1.0"},"name":"demo","files":[
            {"filename":"demo-2-py3-none-any.whl","url":"https://files.example.invalid/demo-2-py3-none-any.whl","requires-python":format!(">={major_minor}"),"hashes":{},"yanked":false},
            {"filename":"demo-3-py3-none-any.whl","url":"https://files.example.invalid/demo-3-py3-none-any.whl","requires-python":format!(">={full}"),"hashes":{},"yanked":false}
        ]}),
        &target.tag_profile,
    );
    assert_eq!(
        catalog.releases[0].files[0].requires_python_satisfied,
        Some(false),
        "actual CPython {full}, observed profile {}, registry availability {:?}",
        target.tag_profile.python_version,
        catalog.releases[0].availability
    );
    assert_eq!(
        catalog.releases[0].availability,
        ReleaseAvailability::NoCompatibleWheel
    );
    assert_eq!(
        catalog.releases[1].files[0].requires_python_satisfied,
        Some(true)
    );
    assert_eq!(
        catalog.releases[1].availability,
        ReleaseAvailability::BinaryWheelAvailable
    );
    assert_eq!(target.tag_profile.python_version, full);
    assert!(!target.interpreter_digest.is_empty());
    fs::write(
        dir.path().join(".venv/pyvenv.cfg"),
        format!("version_info = {legacy}\ninclude-system-site-packages = false\n"),
    )
    .unwrap();
    let legacy_observation = observe_inventory(&request, 0);
    assert_eq!(
        legacy_observation
            .target
            .unwrap()
            .tag_profile
            .python_version,
        full
    );
}

#[test]
#[ignore = "requires an explicitly selected test-only CPython prerelease runtime"]
fn actual_prerelease_stdlib_venv_preserves_full_version_for_requires_python() {
    assert_prerelease_target(false);
}

#[test]
#[ignore = "requires an explicitly selected test-only CPython prerelease runtime and uv"]
fn actual_prerelease_uv_venv_preserves_full_version_for_requires_python() {
    assert_prerelease_target(true);
}
