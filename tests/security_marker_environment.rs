use pep508_rs::{MarkerEnvironment, MarkerEnvironmentBuilder, Requirement, VerbatimUrl};
#[cfg(unix)]
use pybun::security_assessment::CoverageStatus;
use pybun::security_assessment::{InventoryRequest, observe_inventory};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use tempfile::TempDir;

fn trusted_python() -> PathBuf {
    let name = std::env::var_os("PYBUN_SECURITY_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let out = Command::new(name)
        .args(["-I", "-S", "-B", "-c", "import sys;print(sys.executable)"])
        .output()
        .unwrap();
    assert!(out.status.success());
    PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
}
fn project(python: &Path) -> (TempDir, InventoryRequest) {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='test'\nversion='1'\n",
    )
    .unwrap();
    assert!(
        Command::new(python)
            .args(["-I", "-B", "-m", "venv", "--without-pip"])
            .arg(dir.path().join(".venv"))
            .status()
            .unwrap()
            .success()
    );
    let request = InventoryRequest::installed(dir.path(), python);
    (dir, request)
}
fn marker_environment(value: &Value) -> MarkerEnvironment {
    let get = |key| value.get(key).and_then(Value::as_str).unwrap();
    MarkerEnvironmentBuilder {
        implementation_name: get("implementation_name"),
        implementation_version: get("implementation_version"),
        os_name: get("os_name"),
        platform_machine: get("platform_machine"),
        platform_python_implementation: get("platform_python_implementation"),
        platform_release: get("platform_release"),
        platform_system: get("platform_system"),
        platform_version: get("platform_version"),
        python_full_version: get("python_full_version"),
        python_version: get("python_version"),
        sys_platform: get("sys_platform"),
    }
    .try_into()
    .unwrap()
}
#[test]
fn actual_inventory_marker_environment_matches_fixed_stdlib_observation() {
    let python = trusted_python();
    let (_dir, request) = project(&python);
    let observed = observe_inventory(&request, 0);
    let target = observed.target.as_ref().unwrap();
    let serialized = serde_json::to_value(target).unwrap();
    let markers = serialized
        .get("marker_environment")
        .expect("an actual target needs all PEP508 environment observations");
    let expected=Command::new(&python).args(["-I","-S","-B","-c",r#"import json,os,platform,sys
print(json.dumps(dict(implementation_name=sys.implementation.name,implementation_version=platform.python_version(),os_name=os.name,platform_machine=platform.machine(),platform_python_implementation=platform.python_implementation(),platform_release=platform.release(),platform_system=platform.system(),platform_version=platform.version(),python_full_version=platform.python_version(),python_version=str(sys.version_info.major)+'.'+str(sys.version_info.minor),sys_platform=sys.platform)))"#]).output().unwrap();
    assert!(expected.status.success());
    let expected: Value = serde_json::from_slice(&expected.stdout).unwrap();
    assert_eq!(markers, &expected);
    assert_eq!(markers.as_object().unwrap().len(), 11);
    assert_eq!(
        markers["python_full_version"],
        target.tag_profile.python_version
    );
    let _parsed = marker_environment(markers);
}

fn controlled_helper(python: &Path) -> Value {
    let bootstrap = format!(
        "import platform\nplatform.machine=lambda:'AMD64'\n{}",
        include_str!("../src/security_assessment/inspector.py")
    );
    let sources = json!({
        "26.3":{"_elffile":include_str!("../src/security_assessment/vendor/packaging/_elffile.py"),"_manylinux":include_str!("../src/security_assessment/vendor/packaging/_manylinux.py"),"_musllinux":include_str!("../src/security_assessment/vendor/packaging/_musllinux.py"),"tags":include_str!("../src/security_assessment/vendor/packaging/tags.py")},
        "25.0":{"_elffile":include_str!("../src/security_assessment/vendor/packaging25/_elffile.py"),"_manylinux":include_str!("../src/security_assessment/vendor/packaging25/_manylinux.py"),"_musllinux":include_str!("../src/security_assessment/vendor/packaging25/_musllinux.py"),"tags":include_str!("../src/security_assessment/vendor/packaging25/tags.py")}
    });
    let mut child = Command::new(python)
        .args(["-I", "-S", "-B", "-c", &bootstrap])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&sources).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn controlled_helper_preserves_reported_machine_case_for_marker_evaluation() {
    // This controls one stdlib value to test formatting. It does not claim an
    // AMD64 runtime or use a fabricated profile as actual machine evidence.
    let output = controlled_helper(&trusted_python());
    assert_eq!(output["architecture"], "amd64");
    let values = output
        .get("marker_environment")
        .expect("helper must retain raw marker values");
    assert_eq!(values["platform_machine"], "AMD64");
    let environment = marker_environment(values);
    let upper: Requirement<VerbatimUrl> = "demo; platform_machine == 'AMD64'".parse().unwrap();
    let lower: Requirement<VerbatimUrl> = "demo; platform_machine == 'amd64'".parse().unwrap();
    assert!(upper.evaluate_markers(&environment, &[]));
    assert!(!lower.evaluate_markers(&environment, &[]));
}

#[cfg(unix)]
#[test]
fn missing_or_malformed_marker_values_never_become_empty_or_valid_defaults() {
    use std::os::unix::fs::PermissionsExt;
    let python = trusted_python();
    let (dir, mut request) = project(&python);
    let observed = observe_inventory(&request, 0);
    let profile = &observed.target.as_ref().unwrap().tag_profile;
    let serialized = serde_json::to_value(observed.target.as_ref().unwrap()).unwrap();
    let markers = serialized
        .get("marker_environment")
        .expect("actual marker data is required for this negative protocol fixture")
        .clone();
    let template = json!({"generator_version":profile.generator_version,"implementation":profile.implementation,"python_version":profile.python_version,"os":profile.os,"architecture":profile.architecture,"libc":profile.libc,"deployment":profile.deployment,"tags":profile.tags,"marker_environment":markers});
    let data = dir.path().join("fixture.json");
    let mock = dir.path().join("trusted-protocol-fixture");
    fs::write(
        &mock,
        format!("#!/bin/sh\nexec /bin/cat '{}'\n", data.display()),
    )
    .unwrap();
    fs::set_permissions(&mock, fs::Permissions::from_mode(0o700)).unwrap();
    request.trusted_python = mock;
    for key in [
        "implementation_version",
        "python_full_version",
        "sys_platform",
    ] {
        let mut value = template.clone();
        value["marker_environment"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        fs::write(&data, serde_json::to_vec(&value).unwrap()).unwrap();
        let observed = observe_inventory(&request, 0);
        assert_eq!(
            observed.coverage.inventory_instances.status,
            CoverageStatus::Unsupported
        );
        assert!(observed.target.is_none());
    }
    for key in [
        "implementation_version",
        "python_full_version",
        "python_version",
    ] {
        let mut value = template.clone();
        value["marker_environment"][key] = json!("private-secret-invalid-version");
        fs::write(&data, serde_json::to_vec(&value).unwrap()).unwrap();
        let observed = observe_inventory(&request, 0);
        assert_eq!(
            observed.coverage.inventory_instances.status,
            CoverageStatus::Unsupported
        );
        assert!(observed.target.is_none());
        assert!(
            !serde_json::to_string(&observed)
                .unwrap()
                .contains("private-secret")
        );
    }
}
