//! Explicit trusted helper instrumentation shared by CLI and MCP conformance tests.
use serde_json::json;
use std::{fs, process::Command};

pub fn fixture(
    server: &httpmock::MockServer,
    installed_package: bool,
) -> (tempfile::TempDir, String) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("pyproject.toml"),
        "[project]\nname='app'\nversion='1'\ndependencies=['six>=1']\n",
    )
    .unwrap();
    let python_name =
        std::env::var_os("PYBUN_SECURITY_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let python=Command::new(python_name).args(["-I","-S","-B","-c","import sys,json; print(json.dumps([sys.executable,str(sys.version_info.major)+'.'+str(sys.version_info.minor)]))"])
        .output().unwrap();
    assert!(python.status.success());
    let python: Vec<String> = serde_json::from_slice(&python.stdout).unwrap();
    assert!(
        Command::new(&python[0])
            .args(["-I", "-B", "-m", "venv", "--without-pip"])
            .arg(root.path().join(".venv"))
            .status()
            .unwrap()
            .success()
    );
    let site = root
        .path()
        .join(format!(".venv/lib/python{}/site-packages", python[1]));
    if installed_package {
        let metadata = site.join("six-1.0.dist-info");
        fs::create_dir(&metadata).unwrap();
        fs::write(
            metadata.join("METADATA"),
            "Metadata-Version: 2.1\nName: six\nVersion: 1.0\n",
        )
        .unwrap();
    }
    let sentinel = root.path().join("startup-hook-ran");
    let hook = format!(
        "open({:?}, 'w').write('forbidden')",
        sentinel.to_string_lossy()
    );
    fs::write(site.join("sitecustomize.py"), &hook).unwrap();
    fs::write(root.path().join("sysconfig.py"), &hook).unwrap();
    let helper = root.path().join("trusted-python");
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\nprintf 'called\\n' >> '{}/helper-ran'\nexec '{}' \"$@\"\n",
            root.path().display(),
            python[0].replace('\'', "'\\''")
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
    // Inventory requires the selected interpreter's identity to match the
    // operator-granted inspector; this wrapper is trusted test instrumentation.
    fs::remove_file(root.path().join(".venv/bin/python")).unwrap();
    std::os::unix::fs::symlink(&helper, root.path().join(".venv/bin/python")).unwrap();
    fs::create_dir(root.path().join("cache")).unwrap();
    fs::set_permissions(root.path().join("cache"), fs::Permissions::from_mode(0o700)).unwrap();
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/simple/six/");
        then.json_body(json!({"meta":{"api-version":"1.4"},"name":"six","versions":[],"files":[]}));
    });
    let config=r#"
[mcp.policy]
default_sandbox=false
require_sandbox=false
allow_network=true
max_execution_time_s=5
allowed_backends=["uv"]
allowed_security_capabilities=["authorized_target_metadata_read","approved_provider_http"]
allowed_security_profiles=["app"]
[security_assessment]
config_version=1
default_profile="app"
[[security_assessment.profiles]]
id="app"
project_root="."
environment=".venv"
backend="uv"
trusted_python="trusted-python"
provider_ids=["advisory"]
registry_source_ids=["public"]
source_policy_id="explicit"
cache_root="cache"
allowed_modes=["online","offline","online_with_cache_fallback"]
[[security_assessment.providers]]
id="advisory"
url="__ADVISORY__"
auth_scope_id="public"
allow_insecure_loopback=true
[[security_assessment.registries]]
source_id="public"
provider={id="registry",url="__REGISTRY__",auth_scope_id="public",allow_insecure_loopback=true}
[security_assessment.source_policies.explicit]
sources=[{id="public",auth_scope_id="public",kind="public_registry"}]
rules=[{name="six",source_id="public",upstream_name="six",ecosystem="PyPI",assumption="Explicit operator mapping."}]
disclosure=[{provider_id="advisory",source_id="public",packages=["six"]},{provider_id="registry",source_id="public",packages=["six"]}]
[security_assessment.limits]
total_timeout_ms=5000
max_output_bytes=65536
"#.replace("__ADVISORY__",&server.url("/v1/querybatch")).replace("__REGISTRY__",&server.url("/simple/"));
    (root, config)
}
