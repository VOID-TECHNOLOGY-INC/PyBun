#![cfg(unix)]

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn fixture(body: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname = 'demo'\nversion = '0.1.0'\ndependencies = []\n",
    )
    .unwrap();
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = '--version' ]; then echo 'uv 0.12.13'; exit 0; fi\nif [ \"$1\" = 'workspace' ]; then pwd; exit 0; fi\n{body}\n"
    );
    let uv = dir.path().join("uv");
    fs::write(&uv, script).unwrap();
    fs::set_permissions(&uv, fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

fn run(dir: &TempDir, args: &[&str]) -> (bool, Value) {
    let output = cargo_bin_cmd!("pybun")
        .current_dir(dir.path())
        .env("PYBUN_BACKEND", "uv")
        .env("PYBUN_UV", dir.path().join("uv"))
        .arg("--format=json")
        .args(args)
        .output()
        .unwrap();
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

#[test]
fn default_lock_uses_uv_and_preserves_legacy_lock() {
    let dir = fixture(
        "printf '%s\\n' \"$@\" > argv; printf \"version = 1\\n[[package]]\\nname = 'demo'\\nversion = '0.1.0'\\nsource = { virtual = '.' }\\n\" > uv.lock",
    );
    fs::write(dir.path().join("pybun.lockb"), b"legacy").unwrap();
    let (ok, value) = run(&dir, &["lock", "--offline"]);
    assert!(ok, "{value}");
    assert_eq!(value["version"], "2");
    assert_eq!(value["detail"]["backend"]["name"], "uv");
    assert_eq!(value["detail"]["backend"]["operation"], "lock");
    assert_eq!(fs::read(dir.path().join("pybun.lockb")).unwrap(), b"legacy");
    assert!(
        !value["detail"]["lock"]["digest"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    assert!(
        fs::read_to_string(dir.path().join("argv"))
            .unwrap()
            .contains("--offline")
    );
}

#[test]
fn successful_exit_without_valid_lock_is_an_error() {
    for body in [
        "exit 0",
        "echo 'not = [valid' > uv.lock",
        "echo 'version = 99' > uv.lock",
        "printf \"version=1\\n[[package]]\\nname='demo'\\nversion='0.1.0'\\nsource={}\\n\" > uv.lock",
    ] {
        let dir = fixture(body);
        let (ok, value) = run(&dir, &["lock"]);
        assert!(!ok, "{value}");
        assert_eq!(value["diagnostics"][0]["code"], "E_BACKEND_ARTIFACT");
        assert!(value["detail"]["receipt_id"].is_null());
        assert!(!dir.path().join(".pybun/receipts").exists());
    }
}

#[test]
fn backend_errors_do_not_emit_untrusted_diagnostics() {
    let dir = fixture(
        "echo 'password=netrc-secret https://user:pass@example.org token=secret' >&2; exit 1",
    );
    let (ok, value) = run(&dir, &["lock"]);
    assert!(!ok);
    assert_eq!(value["diagnostics"][0]["code"], "E_BACKEND_FAILED");
    let text = value.to_string();
    for secret in ["netrc-secret", "user:pass", "token=secret"] {
        assert!(!text.contains(secret));
    }
}

#[test]
fn uv_absence_is_structured_without_native_fallback() {
    let dir = fixture("exit 0");
    fs::remove_file(dir.path().join("uv")).unwrap();
    let (ok, value) = run(&dir, &["lock"]);
    assert!(!ok);
    assert_eq!(value["diagnostics"][0]["code"], "E_BACKEND_MISSING");
    assert!(!dir.path().join("pybun.lockb").exists());
}

#[test]
fn malformed_and_unsupported_version_are_rejected_before_mutation() {
    for version in ["garbage SECRET", "uv 0.1.0", "uv 9.0.0"] {
        let dir = fixture("touch mutated");
        let uv = dir.path().join("uv");
        fs::write(&uv, format!("#!/bin/sh\nif [ \"$1\" = '--version' ]; then echo '{version}'; exit 0; fi\ntouch mutated\n")).unwrap();
        let (ok, value) = run(&dir, &["lock"]);
        assert!(!ok, "{value}");
        assert!(!dir.path().join("mutated").exists());
        assert!(!value.to_string().contains("SECRET"));
    }
}

#[test]
fn add_cannot_claim_success_without_changing_project() {
    let dir = fixture(
        "printf \"version = 1\\n[[package]]\\nname = 'demo'\\nversion = '0.1.0'\\nsource = { virtual = '.' }\\n\" > uv.lock; mkdir -p .venv/bin; printf '#!/bin/sh\\nexit 0\\n' > .venv/bin/python; chmod +x .venv/bin/python",
    );
    let (ok, value) = run(&dir, &["add", "requests"]);
    assert!(!ok, "{value}");
    assert_eq!(value["diagnostics"][0]["code"], "E_BACKEND_ARTIFACT");
}

#[test]
fn cli_and_mcp_use_the_same_lock_contract() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = fixture(
        "printf \"version = 1\\n[[package]]\\nname = 'demo'\\nversion = '0.1.0'\\nsource = { virtual = '.' }\\n\" > uv.lock",
    );
    let (_, cli) = run(&dir, &["lock"]);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(dir.path())
        .env("PYBUN_BACKEND", "uv")
        .env("PYBUN_UV", dir.path().join("uv"))
        .env(
            "PYBUN_MCP_POLICY",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mcp-permissive-policy.toml"),
        )
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pybun_lock","arguments":{}}})).unwrap();
    let output = child.wait_with_output().unwrap();
    let rpc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(rpc["result"]["isError"], true, "{rpc}");
    let mcp: Value =
        serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    for field in [
        "backend",
        "lock",
        "packages",
        "environment",
        "effective_policy",
        "contract_version",
    ] {
        assert_eq!(cli["detail"][field], mcp[field], "{field}");
    }
}

#[test]
fn real_uv_project_and_pep723_run_use_versioned_backend() {
    if !std::env::var("PYBUN_E2E_NETWORK").is_ok_and(|v| v == "1") {
        return;
    }
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='demo'\nversion='0.1.0'\ndependencies=[]\n",
    )
    .unwrap();
    fs::write(dir.path().join("hello.py"), "print('project-ok')\n").unwrap();
    fs::write(
        dir.path().join("inline.py"),
        "# /// script\n# dependencies = []\n# ///\nprint('script-ok')\n",
    )
    .unwrap();
    for (target, output) in [("hello.py", "project-ok"), ("inline.py", "script-ok")] {
        let result = cargo_bin_cmd!("pybun")
            .current_dir(dir.path())
            .env("PYBUN_BACKEND", "uv")
            .args(["run", target, "--format=json"])
            .output()
            .unwrap();
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(result.status.success(), "{value}");
        assert_eq!(value["version"], "2");
        assert_eq!(value["detail"]["backend"]["operation"], "run");
        assert!(value["detail"]["stdout"].as_str().unwrap().contains(output));
        assert!(!dir.path().join("pybun.lockb").exists());
    }
}

#[test]
fn real_uv_run_preserves_sandbox_network_denial() {
    if !std::env::var("PYBUN_E2E_NETWORK").is_ok_and(|v| v == "1") {
        return;
    }
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='demo'\nversion='0.1.0'\ndependencies=[]\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("network.py"),
        "import socket\nsocket.create_connection(('127.0.0.1', 80))\n",
    )
    .unwrap();
    let output = cargo_bin_cmd!("pybun")
        .current_dir(dir.path())
        .env("PYBUN_BACKEND", "uv")
        .args(["run", "network.py", "--sandbox", "--format=json"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!output.status.success(), "{value}");
    assert_eq!(value["version"], "2");
    assert_eq!(value["detail"]["sandboxed"], true);
    assert_eq!(value["detail"]["effective_policy"]["allow_network"], false);
    assert!(
        value["detail"]["stderr"]
            .as_str()
            .unwrap()
            .contains("blocked")
    );
}

#[test]
fn run_rejects_interpreter_flags_as_script_targets() {
    let dir = fixture("exit 0");
    let (ok, value) = run(&dir, &["run", "--sandbox", "-S", "--", "-c", "print(42)"]);
    assert!(!ok, "{value}");
    assert_eq!(value["diagnostics"][0]["code"], "E_BACKEND_ARGUMENT");
}

#[test]
fn mcp_context_inspects_uv_lock_without_binary_conversion() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = fixture(
        "printf \"version = 1\\n[[package]]\\nname = 'demo'\\nversion = '0.1.0'\\nsource = { virtual = '.' }\\n\" > uv.lock",
    );
    assert!(run(&dir, &["lock"]).0);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(dir.path())
        .env("PYBUN_BACKEND", "uv")
        .env(
            "PYBUN_MCP_POLICY",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mcp-permissive-policy.toml"),
        )
        .args(["mcp", "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pybun_context","arguments":{}}})).unwrap();
    let output = child.wait_with_output().unwrap();
    let rpc: Value = serde_json::from_slice(&output.stdout).unwrap();
    let context: Value =
        serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(context["lockfile_status"], "in_sync", "{context}");
    assert_eq!(context["contract_version"], "2");
    assert!(!dir.path().join("pybun.lockb").exists());
}

#[test]
fn real_uv_package_lifecycle_and_existing_project_adoption() {
    if !std::env::var("PYBUN_E2E_NETWORK").is_ok_and(|v| v == "1") {
        return;
    }
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='demo'\nversion='0.1.0'\nrequires-python='>=3.10'\ndependencies=[]\n",
    )
    .unwrap();
    let run = |args: &[&str]| {
        let output = cargo_bin_cmd!("pybun")
            .current_dir(dir.path())
            .env("PYBUN_BACKEND", "uv")
            .arg("--format=json")
            .args(args)
            .output()
            .unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(output.status.success(), "{args:?}: {value}");
        value
    };
    run(&["lock"]);
    let original = fs::read(dir.path().join("uv.lock")).unwrap();
    run(&["install"]);
    assert_eq!(fs::read(dir.path().join("uv.lock")).unwrap(), original);
    run(&["add", "requests>=2.32"]);
    let value = run(&[
        "run",
        "--code",
        "import requests; print(requests.__version__)",
    ]);
    assert!(!value["detail"]["stdout"].as_str().unwrap().is_empty());
    run(&["upgrade", "requests"]);
    run(&["remove", "requests"]);
    assert!(
        !fs::read_to_string(dir.path().join("pyproject.toml"))
            .unwrap()
            .contains("requests")
    );
    assert!(!dir.path().join("pybun.lockb").exists());
    let receipts = fs::read_dir(dir.path().join(".pybun/receipts"))
        .unwrap()
        .count();
    assert_eq!(receipts, 6);
}

#[test]
fn real_uv_local_path_add_reports_the_actual_mutation() {
    if !std::env::var("PYBUN_E2E_NETWORK").is_ok_and(|v| v == "1") {
        return;
    }
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='demo'\nversion='0.1.0'\ndependencies=[]\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join("dep")).unwrap();
    fs::write(
        dir.path().join("dep/pyproject.toml"),
        "[project]\nname='local-demo'\nversion='0.1.0'\n[tool.uv]\npackage=false\n",
    )
    .unwrap();
    let output = cargo_bin_cmd!("pybun")
        .current_dir(dir.path())
        .env("PYBUN_BACKEND", "uv")
        .args(["add", "./dep", "--offline", "--format=json"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output.status.success(), "{value}");
    assert!(
        fs::read_to_string(dir.path().join("pyproject.toml"))
            .unwrap()
            .contains("local-demo")
    );
    assert!(value["detail"]["receipt_id"].is_string());
}

#[test]
fn real_uv_workspace_member_uses_shared_root_lock() {
    if !std::env::var("PYBUN_E2E_NETWORK").is_ok_and(|v| v == "1") {
        return;
    }
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='root'\nversion='0.1.0'\n[tool.uv.workspace]\nmembers=['member']\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join("member")).unwrap();
    fs::write(
        dir.path().join("member/pyproject.toml"),
        "[project]\nname='member'\nversion='0.1.0'\ndependencies=[]\n",
    )
    .unwrap();
    let output = cargo_bin_cmd!("pybun")
        .current_dir(dir.path().join("member"))
        .env("PYBUN_BACKEND", "uv")
        .args(["install", "--offline", "--format=json"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output.status.success(), "{value}");
    assert!(dir.path().join("uv.lock").exists());
    assert!(!dir.path().join("member/uv.lock").exists());
}

#[test]
fn add_and_remove_forward_dependency_group_flags() {
    for (args, expected, unexpected) in [
        (vec!["add", "requests", "--dev"], "--dev", "--group"),
        (
            vec!["add", "pytest", "--group", "test"],
            "--group",
            "--optional",
        ),
        (
            vec!["add", "sphinx", "--optional", "docs"],
            "--optional",
            "--dev",
        ),
        (vec!["remove", "requests", "--dev"], "--dev", "--group"),
    ] {
        let dir = fixture(
            "printf '%s\\n' \"$@\" > argv; printf \"version = 1\\n[[package]]\\nname = 'demo'\\nversion = '0.1.0'\\nsource = { virtual = '.' }\\n\" > uv.lock; mkdir -p .venv/bin; printf '#!/bin/sh\\nexit 0\\n' > .venv/bin/python; chmod +x .venv/bin/python",
        );
        let (_ok, value) = run(&dir, &args);
        let argv = fs::read_to_string(dir.path().join("argv")).unwrap();
        assert!(argv.contains(expected), "{args:?}: {argv}\n{value}");
        assert!(!argv.contains(unexpected), "{args:?}: {argv}");
    }
}

#[test]
fn backend_failures_have_actionable_codes() {
    for (body, code) in [
        (
            "echo 'x No solution found when resolving dependencies' >&2; exit 1",
            "E_BACKEND_RESOLUTION",
        ),
        (
            "echo \"error: The dependency 'requests' could not be found in 'project.dependencies'\" >&2; exit 2",
            "E_BACKEND_RESOLUTION",
        ),
        (
            "echo 'error: Failed to fetch: 401 Unauthorized' >&2; exit 1",
            "E_BACKEND_AUTH",
        ),
        (
            "echo 'error: network error: connection refused' >&2; exit 1",
            "E_BACKEND_NETWORK",
        ),
        (
            "echo 'error: project.name field is not set' >&2; exit 2",
            "E_BACKEND_ARGUMENT",
        ),
    ] {
        let dir = fixture(body);
        let (ok, value) = run(&dir, &["lock"]);
        assert!(!ok, "{value}");
        assert_eq!(value["diagnostics"][0]["code"], code, "{value}");
        assert!(
            !value["diagnostics"][0]["suggestion"]
                .as_str()
                .unwrap_or_default()
                .contains("PYBUN_BACKEND=native"),
            "{value}"
        );
    }
}

#[test]
fn uv_run_promotes_the_traceback_diagnostic() {
    let dir = fixture("");
    let real_python = String::from_utf8(
        std::process::Command::new("sh")
            .args(["-c", "command -v python3"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    let script = r#"#!/bin/sh
if [ "$1" = '--version' ]; then echo 'uv 0.12.13'; exit 0; fi
if [ "$1" = 'workspace' ]; then pwd; exit 0; fi
if [ "$1" = 'lock' ]; then printf "version = 1\n[[package]]\nname = 'demo'\nversion = '0.1.0'\nsource = { virtual = '.' }\n" > uv.lock; exit 0; fi
if [ "$1" = 'sync' ]; then exit 0; fi
echo "unexpected uv args: $*" >&2
exit 2
"#;
    let uv = dir.path().join("uv");
    fs::write(&uv, script).unwrap();
    fs::set_permissions(&uv, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        std::process::Command::new(&real_python)
            .args(["-m", "venv", "--without-pip"])
            .arg(dir.path().join(".venv"))
            .status()
            .unwrap()
            .success()
    );

    let output = cargo_bin_cmd!("pybun")
        .current_dir(dir.path())
        .env("PYBUN_BACKEND", "uv")
        .env("PYBUN_UV", &uv)
        .arg("--format=json")
        .args(["run", "-c", "import definitely_missing_pkg_zz9"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!output.status.success(), "{value}");
    assert_eq!(
        value["diagnostics"][0]["code"], "E_RUNTIME_MODULE_NOT_FOUND",
        "{value}"
    );
    assert!(
        value["diagnostics"][0]["suggestion"]
            .as_str()
            .unwrap_or_default()
            .contains("pybun add definitely_missing_pkg_zz9"),
        "{value}"
    );
    assert_eq!(
        value["detail"]["diagnostics"][0]["code"], "E_RUNTIME_MODULE_NOT_FOUND",
        "{value}"
    );
}
