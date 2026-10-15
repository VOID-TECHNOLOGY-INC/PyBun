#![cfg(unix)]
use assert_cmd::cargo::cargo_bin_cmd;
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn pip_index_environment_is_delegated_to_uv() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='demo'\nversion='0.1.0'\ndependencies=[]\n",
    )
    .unwrap();
    let uv = dir.path().join("uv");
    fs::write(&uv, "#!/bin/sh\nif [ \"$1\" = '--version' ]; then echo 'uv 0.12.13'; exit 0; fi\nif [ \"$1\" = 'workspace' ]; then pwd; exit 0; fi\n[ \"$UV_DEFAULT_INDEX\" = 'https://auth-user:auth-password@example.org/simple' ] || exit 1\n[ \"$UV_INDEX\" = 'https://extra.example.org/simple' ] || exit 1\nprintf \"version=1\\n[[package]]\\nname='demo'\\nversion='0.1.0'\\nsource={virtual='.'}\\n\" > uv.lock\n").unwrap();
    fs::set_permissions(&uv, fs::Permissions::from_mode(0o755)).unwrap();
    cargo_bin_cmd!("pybun")
        .current_dir(dir.path())
        .env("PYBUN_BACKEND", "uv")
        .env("PYBUN_UV", uv)
        .env_remove("UV_DEFAULT_INDEX")
        .env_remove("UV_INDEX_URL")
        .env_remove("UV_INDEX")
        .env_remove("UV_EXTRA_INDEX_URL")
        .env(
            "PIP_INDEX_URL",
            "https://auth-user:auth-password@example.org/simple",
        )
        .env("PIP_EXTRA_INDEX_URL", "https://extra.example.org/simple")
        .args(["--format=json", "lock"])
        .assert()
        .success();
    cargo_bin_cmd!("pybun")
        .current_dir(dir.path())
        .env("PYBUN_BACKEND", "uv")
        .env("PYBUN_UV", dir.path().join("uv"))
        .env(
            "UV_DEFAULT_INDEX",
            "https://auth-user:auth-password@example.org/simple",
        )
        .env("UV_INDEX", "https://extra.example.org/simple")
        .env("PIP_INDEX_URL", "https://ignored.example.org/simple")
        .env(
            "PIP_EXTRA_INDEX_URL",
            "https://ignored-extra.example.org/simple",
        )
        .args(["--format=json", "lock"])
        .assert()
        .success();
}

#[test]
fn clap_errors_redact_authenticated_urls() {
    for url in [
        "https://user:prefix=httpsecret@example.org/simple",
        "HTTPS://user:prefix=httpsecret@example.org/simple",
    ] {
        let output = cargo_bin_cmd!("pybun")
            .env("PIP_INDEX_URL", url)
            .args(["--format", "prefix=httpsecret", "lock"])
            .output()
            .unwrap();
        assert!(!String::from_utf8_lossy(&output.stderr).contains("prefix=httpsecret"));
    }
    for url in [
        "https://sentinel-user:sentinel-password@example.org/simple",
        "https://sentinel-user:sentinel-password@secret-tail@example.org/simple",
        "https://sentinel-user:sentinel-password%40secret-tail@example.org/simple",
    ] {
        let output = cargo_bin_cmd!("pybun")
            .args(["--format", url, "lock"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("sentinel-password"), "{stderr}");
        assert!(!stderr.contains("sentinel-user"), "{stderr}");
        assert!(!stderr.contains("secret-tail"), "{stderr}");
    }
}

#[test]
fn native_index_selector_is_rejected_before_project_mutation() {
    let dir = tempfile::tempdir().unwrap();
    cargo_bin_cmd!("pybun")
        .current_dir(dir.path())
        .env("PYBUN_BACKEND", "native")
        .args([
            "--format=json",
            "add",
            "demo",
            "--index",
            "https://example.org/simple",
        ])
        .assert()
        .failure();
    assert!(!dir.path().join("pyproject.toml").exists());
}

#[test]
fn real_uv_authenticates_private_index_without_persisting_credentials() {
    if std::env::var("PYBUN_E2E_NETWORK").as_deref() != Ok("1") {
        return;
    }
    use httpmock::prelude::*;
    use std::io::{Cursor, Write};
    let server = MockServer::start();
    let mut wheel = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let files = [
        ("secret_demo.py", "value = 42\n"),
        (
            "secret_demo-1.0.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: secret-demo\nVersion: 1.0.0\n",
        ),
        (
            "secret_demo-1.0.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        ),
        (
            "secret_demo-1.0.0.dist-info/RECORD",
            "secret_demo.py,,\nsecret_demo-1.0.0.dist-info/METADATA,,\nsecret_demo-1.0.0.dist-info/WHEEL,,\nsecret_demo-1.0.0.dist-info/RECORD,,\n",
        ),
    ];
    for (name, data) in files {
        wheel
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        wheel.write_all(data.as_bytes()).unwrap();
    }
    let bytes = wheel.finish().unwrap().into_inner();
    let authorization = "Basic c2VudGluZWwtdXNlcjpzZW50aW5lbC1wYXNzd29yZA==";
    let listing = server.mock(|when, then| {
        when.method(GET).path("/simple/secret-demo/").header("authorization", authorization);
        then.status(200).header("content-type", "text/html").body("<a href='/files/secret_demo-1.0.0-py3-none-any.whl'>secret_demo-1.0.0-py3-none-any.whl</a>");
    });
    let download = server.mock(|when, then| {
        when.method(GET)
            .path("/files/secret_demo-1.0.0-py3-none-any.whl")
            .header("authorization", authorization);
        then.status(200).body(bytes);
    });
    for named in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let index = format!("{}/simple", server.base_url());
        let config = if named {
            format!(
                "\n[[tool.uv.index]]\nname='private'\nurl='{index}'\ndefault=true\nauthenticate='always'\n"
            )
        } else {
            String::new()
        };
        fs::write(dir.path().join("pyproject.toml"), format!("[project]\nname='demo'\nversion='0.1.0'\nrequires-python='>=3.10'\ndependencies=['secret-demo']\n{config}")).unwrap();
        let invoke = |args: &[&str], password: &str| {
            let mut cmd = cargo_bin_cmd!("pybun");
            cmd.current_dir(dir.path())
                .env("PYBUN_BACKEND", "uv")
                .env_remove("PYBUN_UV")
                .env_remove("UV_INDEX_URL")
                .env_remove("UV_DEFAULT_INDEX")
                .env_remove("UV_INDEX")
                .env_remove("UV_EXTRA_INDEX_URL")
                .env_remove("PIP_INDEX_URL")
                .env_remove("PIP_EXTRA_INDEX_URL")
                .env("UV_CACHE_DIR", dir.path().join(format!("cache-{password}")))
                .env("UV_NO_CONFIG", "false")
                .env("UV_INDEX_PRIVATE_USERNAME", "sentinel-user")
                .env("UV_INDEX_PRIVATE_PASSWORD", password);
            if !named {
                cmd.env(
                    "PIP_INDEX_URL",
                    index.replace("http://", &format!("http://sentinel-user:{password}@")),
                );
            }
            cmd.arg("--format=json").args(args).output().unwrap()
        };
        let failed = invoke(&["install"], "incorrect-password");
        assert!(!failed.status.success(), "wrong credentials succeeded");
        assert!(!dir.path().join(".pybun/receipts").exists());
        let output = invoke(&["install"], "sentinel-password");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let run = invoke(
            &[
                "run",
                "--sandbox",
                "--allow-network",
                "--allow-env",
                "UV_INDEX_PRIVATE_PASSWORD",
                "--allow-env",
                "PIP_INDEX_URL",
                "--code",
                "import secret_demo, os; print(secret_demo.value); print(os.getenv('UV_INDEX_PRIVATE_PASSWORD')); print(os.getenv('PIP_INDEX_URL')); print('sentinel-password')",
            ],
            "sentinel-password",
        );
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stdout)
        );
        let value: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
        assert_eq!(value["detail"]["stdout"], "42\nNone\nNone\n<redacted>\n");
        for path in [
            dir.path().join("pyproject.toml"),
            dir.path().join("uv.lock"),
        ] {
            let text = fs::read_to_string(path).unwrap();
            assert!(
                !text.contains("sentinel-password") && !text.contains("sentinel-user"),
                "{text}"
            );
        }
        for receipt in fs::read_dir(dir.path().join(".pybun/receipts")).unwrap() {
            let text = fs::read_to_string(receipt.unwrap().path()).unwrap();
            assert!(!text.contains("sentinel-password") && !text.contains("sentinel-user"));
        }
    }
    assert!(listing.calls() >= 2);
    assert!(download.calls() >= 2);
}

#[test]
fn mcp_audit_and_support_bundle_redact_index_credentials() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.jsonl");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_pybun"));
    command
        .current_dir(dir.path())
        .env("PYBUN_AUDIT_LOG", &log)
        .env("UV_INDEX_PRIVATE_USERNAME", "sentinel-user")
        .env("UV_INDEX_PRIVATE_PASSWORD", "sentinel-password")
        .env(
            "PYBUN_MCP_POLICY",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mcp-permissive-policy.toml"),
        )
        .args(["mcp", "serve", "--stdio"]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"https://sentinel-user:sentinel-password@example.org/unknown","arguments":{"index":"https://sentinel-user:sentinel-password@example.org/simple", "data":"sentinel-password", "UV_INDEX_PRIVATE_USERNAME":"sentinel-user"}}});
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let audit = fs::read_to_string(log).unwrap();
    assert!(audit.contains("redacted"));
    assert!(
        !audit.contains("sentinel-user") && !audit.contains("sentinel-password"),
        "{audit}"
    );
    let context = pybun::support_bundle::BundleContext {
        checks: vec![
            serde_json::json!({"index":"https://sentinel-user:sentinel-password@example.org/simple", "password":"sentinel-password", "UV_INDEX_PRIVATE_USERNAME":"sentinel-user"}),
        ],
        verbose_logs: false,
        trace_id: None,
        command: "doctor".into(),
    };
    let bundle =
        pybun::support_bundle::build_support_bundle(&dir.path().join("bundle"), &context).unwrap();
    for file in bundle.files {
        let text = fs::read_to_string(bundle.path.join(file.path)).unwrap();
        assert!(
            !text.contains("sentinel-user") && !text.contains("sentinel-password"),
            "{text}"
        );
    }
}

#[test]
fn authentication_values_preserve_bundled_schema_identity() {
    for format in ["json", "text"] {
        let output = cargo_bin_cmd!("pybun")
            .env("UV_INDEX_PRIVATE_USERNAME", "uv")
            .args([
                "--format",
                format,
                "schema",
                "print",
                "--schema-version",
                "2",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let schema = if format == "json" {
            &value["detail"]["schema"]
        } else {
            &value
        };
        assert_eq!(schema, &pybun::schema::schema_v2_json());
    }
}
