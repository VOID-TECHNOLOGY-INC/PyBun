//! Offline regressions for warm script/tool execution (Issue #580).

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use std::io::{Cursor, Write};
use std::path::Path;
use tempfile::TempDir;

fn wheel(dir: &Path, name: &str, version: &str, console: bool) {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let metadata = format!("{name}-{version}.dist-info");
    let source = format!(
        "import json,sys\ndef main():\n print(json.dumps({{'prefix':sys.prefix,'version':'{version}','args':sys.argv[1:]}}))\n print('tool-stderr',file=sys.stderr)\n return int(sys.argv[1]) if len(sys.argv)>1 and sys.argv[1].isdigit() else 0\nif __name__=='__main__':\n sys.exit(main())\n"
    );
    let mut files = vec![
        (format!("{name}.py"), source),
        (
            format!("{metadata}/METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
        ),
        (
            format!("{metadata}/WHEEL"),
            "Wheel-Version: 1.0\nGenerator: pybun-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                .into(),
        ),
    ];
    if console {
        files.push((
            format!("{metadata}/entry_points.txt"),
            format!("[console_scripts]\n{name} = {name}:main\n"),
        ));
    }
    let record = files
        .iter()
        .map(|(path, _)| format!("{path},,\n"))
        .collect::<String>();
    files.push((format!("{metadata}/RECORD"), record));
    for (path, content) in files {
        archive
            .start_file(path, zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(content.as_bytes()).unwrap();
    }
    std::fs::write(
        dir.join(format!("{name}-{version}-py3-none-any.whl")),
        archive.finish().unwrap().into_inner(),
    )
    .unwrap();
}

fn command(dir: &TempDir) -> assert_cmd::Command {
    let mut command = cargo_bin_cmd!("pybun");
    command
        .current_dir(dir.path())
        .args(["--format=json"])
        .env("PYBUN_HOME", dir.path().join("home"))
        .env("PYBUN_HISTORY", "0")
        .env("UV_CACHE_DIR", dir.path().join("uv-cache"))
        .env("UV_NO_INDEX", "1")
        .env("UV_FIND_LINKS", dir.path())
        .env("UV_PYTHON_DOWNLOADS", "never")
        .env("PYBUN_PYTHON", "python3")
        .env("PYBUN_BACKEND", "uv")
        .env_remove("PYBUN_X_DRY_RUN")
        .env_remove("PYBUN_UV")
        .env_remove("VIRTUAL_ENV");
    command
}

fn stages(value: &Value) {
    let events = value["events"].as_array().unwrap();
    let mut previous = 0;
    for event in events {
        let timestamp = event["timestamp_ms"].as_u64().unwrap();
        assert!(timestamp >= previous, "{events:?}");
        previous = timestamp;
    }
    let indices = ["env_lookup", "env_create", "spawn"].map(|name| {
        events.iter().position(|event| {
            event["type"] == name || (event["type"] == "custom" && event["data"]["stage"] == name)
        })
    });
    assert!(indices.iter().all(Option::is_some), "{events:?}");
    assert!(indices[0] < indices[1] && indices[1] < indices[2]);
}

#[test]
fn x_reuses_uv_environment_without_project_or_version_leakage() {
    let dir = TempDir::new().unwrap();
    wheel(dir.path(), "warm_demo", "1.0.0", true);
    wheel(dir.path(), "warm_demo", "2.0.0", true);
    // The tool must not resolve or install the current project's dependencies.
    std::fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='unrelated'\nversion='0.1.0'\ndependencies=['missing-project-dependency']\n",
    )
    .unwrap();
    let mut first_prefix = None;
    for (spec, version) in [
        ("warm_demo==1.0.0", "1.0.0"),
        ("warm_demo==1.0.0", "1.0.0"),
        ("warm_demo==2.0.0", "2.0.0"),
    ] {
        let output = command(&dir)
            .args(["x", spec, "--", "argument with spaces"])
            .output()
            .unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(output.status.success(), "{value}");
        let tool: Value =
            serde_json::from_str(value["detail"]["stdout"].as_str().unwrap().trim()).unwrap();
        assert_eq!(tool["version"], version);
        assert_eq!(tool["args"], serde_json::json!(["argument with spaces"]));
        assert!(
            value["detail"]["stderr"]
                .as_str()
                .unwrap()
                .contains("tool-stderr")
        );
        if version == "1.0.0" {
            if let Some(prefix) = &first_prefix {
                assert_eq!(&tool["prefix"], prefix, "warm execution recreated the env");
            } else {
                first_prefix = Some(tool["prefix"].clone());
            }
        } else {
            assert_ne!(Some(tool["prefix"].clone()), first_prefix);
        }
        assert!(value["detail"]["temp_env"].is_null());
        assert_eq!(value["detail"]["cleanup"], false);
        assert!(value["detail"]["cache_hit"].is_null());
        stages(&value);
    }
    assert!(!dir.path().join("uv.lock").exists());
    assert!(!dir.path().join(".venv").exists());
}

#[test]
fn x_cached_module_fallback_preserves_output_and_exit_code() {
    let dir = TempDir::new().unwrap();
    wheel(dir.path(), "warm_module", "1.0.0", false);
    std::fs::write(dir.path().join("warm_module.py"), "raise SystemExit(99)\n").unwrap();
    for _ in 0..2 {
        let output = command(&dir)
            .args(["x", "warm_module==1.0.0", "--", "7"])
            .output()
            .unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(7), "{value}");
        assert_eq!(value["detail"]["exit_code"], 7);
        assert_eq!(value["status"], "error");
        assert!(
            value["detail"]["stdout"]
                .as_str()
                .unwrap()
                .contains("1.0.0")
        );
        assert!(
            value["detail"]["stderr"]
                .as_str()
                .unwrap()
                .contains("tool-stderr")
        );
        stages(&value);
    }
}

#[test]
fn x_resolution_failure_is_not_reported_as_a_tool_exit() {
    let dir = TempDir::new().unwrap();
    let output = command(&dir)
        .args(["x", "missing-warm-tool==1.0.0"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!output.status.success(), "{value}");
    assert_eq!(value["diagnostics"][0]["code"], "E_X_FAILED");
    assert!(value["detail"]["exit_code"].is_null());
}

#[cfg(unix)]
#[test]
fn x_preparation_error_redacts_backend_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let uv = dir.path().join("uv");
    std::fs::write(
        &uv,
        "#!/bin/sh\necho 'https://user:password@example.org/simple token=private-token' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&uv, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = command(&dir)
        .env("PYBUN_UV", uv)
        .args(["x", "warm_demo"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["diagnostics"][0]["code"], "E_X_FAILED");
    let text = value.to_string();
    assert!(!text.contains("user:password"), "{text}");
    assert!(!text.contains("private-token"), "{text}");
}

#[test]
fn pep723_default_backend_exposes_preparation_and_spawn_stages() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("script.py"),
        "# /// script\n# dependencies=[]\n# ///\nprint('stage-ok')\n",
    )
    .unwrap();
    for _ in 0..2 {
        let output = command(&dir).args(["run", "script.py"]).output().unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(output.status.success(), "{value}");
        assert_eq!(value["detail"]["stdout"], "stage-ok\n");
        assert_eq!(value["detail"]["backend"]["name"], "uv");
        assert!(value["detail"]["cache_hit"].is_null());
        stages(&value);
    }
}

#[cfg(unix)]
#[test]
fn pep723_sync_refreshes_dependencies_without_a_separate_lock_process() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    wheel(dir.path(), "warm_demo", "1.0.0", true);
    // Distinct source sizes avoid CPython's same-second, equal-size .pyc
    // collision in synthetic wheels (also reproducible with plain uv run).
    // https://github.com/python/cpython/issues/75953
    wheel(dir.path(), "warm_demo", "2.0.123", true);
    let wrapper = dir.path().join("uv-wrapper");
    let trace = dir.path().join("trace");
    std::fs::write(
        &wrapper,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$TRACE\"\nexec \"$REAL_UV\" \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let real_uv = pybun::env::find_uv_executable().expect("supported uv must be installed");
    let script = dir.path().join("script.py");
    for (iteration, version) in ["1.0.0", "1.0.0", "2.0.123"].into_iter().enumerate() {
        std::fs::write(&script, format!("# /// script\n# dependencies=['warm_demo=={version}']\n# ///\nimport warm_demo; warm_demo.main()\nopen('executed','w').write('ran')\n")).unwrap();
        std::fs::write(&trace, "").unwrap();
        let output = command(&dir)
            .env("PYBUN_UV", &wrapper)
            .env("REAL_UV", &real_uv)
            .env("TRACE", &trace)
            .args(["run", "script.py"])
            .output()
            .unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(output.status.success(), "{value}");
        assert!(
            value["detail"]["stdout"]
                .as_str()
                .unwrap()
                .contains(version),
            "iteration {iteration}, expected {version}: {value}"
        );
        assert_eq!(
            value["detail"]["environment"]["preparation"],
            if iteration == 0 {
                "uv sync --script --locked --inexact"
            } else {
                "uv sync --script --inexact"
            }
        );
        let trace = std::fs::read_to_string(&trace).unwrap();
        let operations: Vec<_> = trace
            .lines()
            .map(|line| line.split_whitespace().next().unwrap())
            .collect();
        if iteration == 0 {
            assert_eq!(
                operations,
                ["--version", "lock", "sync", "python"],
                "{trace}"
            );
        } else {
            assert_eq!(operations, ["--version", "sync", "python"], "{trace}");
        }
        stages(&value);
    }
    let lock = dir.path().join("script.py.lock");
    let legacy = b"PYBUNLOCK\0legacy binary data";
    std::fs::write(&lock, legacy).unwrap();
    std::fs::remove_file(dir.path().join("executed")).unwrap();
    std::fs::write(&trace, "").unwrap();
    let output = command(&dir)
        .env("PYBUN_UV", &wrapper)
        .env("REAL_UV", real_uv)
        .env("TRACE", &trace)
        .args(["run", "script.py"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!output.status.success(), "{value}");
    assert_eq!(value["diagnostics"][0]["code"], "E_BACKEND_ARTIFACT");
    assert_eq!(std::fs::read(lock).unwrap(), legacy);
    assert!(!dir.path().join("executed").exists());
    assert_eq!(std::fs::read_to_string(trace).unwrap(), "--version\n");
}
