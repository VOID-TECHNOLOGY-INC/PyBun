#![cfg(unix)]
use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

fn fixture() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let mut nodes = json!({
        "root":{"name":"root","version":"1","kind":"package","source":{"virtual":"."},"dependencies":[{"id":"a"},{"id":"b"}],"optional_dependencies":[{"name":"feature","id":"extra"}],"dependency_groups":[{"name":"dev","id":"group"}]},
        "extra":{"name":"root","version":"1","kind":{"extra":"feature"},"source":{"virtual":"."},"dependencies":[{"id":"root"},{"id":"target"}]},
        "group":{"name":"root","version":"1","kind":{"group":"dev"},"source":{"virtual":"."},"dependencies":[{"id":"target"}]},
        "a":{"name":"a","version":"1","kind":"package","dependencies":[{"id":"shared"}]},
        "b":{"name":"b","version":"1","kind":"package","dependencies":[{"id":"shared"}]},
        "shared":{"name":"shared","version":"1","kind":"package","dependencies":[{"id":"a"},{"id":"target","marker":"sys_platform == 'linux'"}]},
        "target":{"name":"target","version":"1","kind":"package","dependencies":[]}
    });
    for (_, node) in nodes.as_object_mut().unwrap() {
        if node.get("source").is_none() {
            node["source"] =
                json!({"registry":{"url":"https://user:private-secret@example.org/simple"}});
        }
    }
    let metadata = json!({"schema":{"version":"preview"},"workspace_root":root,"workspace":{"path":root,"id":"workspace"},"members":[{"name":"root","path":root,"id":"root"}],"resolution":{
        "workspace":{"kind":"workspace","dependencies":[]}
    }});
    let mut metadata = metadata;
    metadata["resolution"]
        .as_object_mut()
        .unwrap()
        .extend(nodes.as_object().unwrap().clone());
    fs::write(temp.path().join("metadata.json"), metadata.to_string()).unwrap();
    let mut lock = "version=1\n".to_string();
    for name in ["root", "a", "b", "shared", "target"] {
        lock += &format!(
            "[[package]]\nname='{name}'\nversion='1'\nsource={{registry='https://example.org/simple'}}\n"
        );
    }
    fs::write(temp.path().join("uv.lock"), lock).unwrap();
    fs::write(
        temp.path().join("pyproject.toml"),
        "[project]\nname='root'\nversion='1'\n",
    )
    .unwrap();
    let uv = temp.path().join("uv");
    fs::write(&uv,"#!/bin/sh\nprintf '%s\\n' \"$*\" >> uv.calls\ncase \"$*\" in\n*--version*) echo 'uv 0.12.13';;\n*metadata*) cat metadata.json;;\n*dir*) pwd;;\n*) exit 8;;\nesac\n").unwrap();
    fs::set_permissions(uv, fs::Permissions::from_mode(0o755)).unwrap();
    temp
}
fn cli(root: &Path, package: &str) -> (bool, Value) {
    let output = cargo_bin_cmd!("pybun")
        .current_dir(root)
        .env("PYBUN_HISTORY", "0")
        .env("PYBUN_BACKEND", "uv")
        .env("PYBUN_UV", root.join("uv"))
        .args(["--format=json", "why", package])
        .output()
        .unwrap();
    (output.status.success(),serde_json::from_slice(&output.stdout).unwrap_or_else(|_|json!({"stdout":String::from_utf8_lossy(&output.stdout),"stderr":String::from_utf8_lossy(&output.stderr)})))
}
fn mcp(root: &Path, package: &str) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pybun"))
        .current_dir(root)
        .env("PYBUN_HISTORY", "0")
        .env("PYBUN_BACKEND", "uv")
        .env("PYBUN_UV", root.join("uv"))
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
    let mut input = child.stdin.take().unwrap();
    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pybun_why","arguments":{"package":package}}}),
    ] {
        writeln!(input, "{request}").unwrap();
    }
    drop(input);
    let out = child.wait_with_output().unwrap();
    let rpc = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["id"] == 2)
        .unwrap();
    {
        let mut value: Value =
            serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(value["policy_applied"]["authorized"], true);
        value.as_object_mut().unwrap().remove("policy_applied");
        value
    }
}
#[test]
fn why_shares_every_path_and_provenance_without_mutating_the_lock() {
    let temp = fixture();
    let before = fs::read(temp.path().join("uv.lock")).unwrap();
    let (success, value) = cli(temp.path(), "TARGET");
    assert!(success, "{value}");
    let detail = &value["detail"];
    assert_eq!(*detail, mcp(temp.path(), "target"));
    let paths = detail["paths"].as_array().unwrap();
    assert_eq!(paths.len(), 6, "{detail}");
    for provenance in [
        "direct",
        "transitive",
        "optional-extra",
        "dependency-group",
        "workspace",
    ] {
        assert!(
            paths.iter().any(|path| path["provenance"]
                .as_array()
                .unwrap()
                .contains(&json!(provenance))),
            "{detail}"
        );
    }
    assert_eq!(detail["backend"]["name"], "uv");
    assert!(
        detail["lock"]["digest"]
            .as_str()
            .is_some_and(|value| value.len() == 64)
    );
    assert!(!detail.to_string().contains("private-secret"));
    assert_eq!(before, fs::read(temp.path().join("uv.lock")).unwrap());
    let calls = fs::read_to_string(temp.path().join("uv.calls")).unwrap();
    for call in calls.lines().filter(|line| line.contains("metadata")) {
        for flag in [
            "--frozen",
            "--offline",
            "--no-build",
            "--no-python-downloads",
        ] {
            assert!(call.contains(flag), "{call}");
        }
        assert!(!call.contains("--sync"));
    }
    assert_eq!(detail, &cli(temp.path(), "target").1["detail"]);
}
#[test]
fn why_missing_and_invalid_graphs_have_structured_diagnostics() {
    let temp = fixture();
    let (success, value) = cli(temp.path(), "absent");
    assert!(!success);
    assert!(
        value["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["code"] == "E_WHY_PACKAGE_NOT_FOUND"),
        "{value}"
    );
    fs::write(temp.path().join("metadata.json"), "{private-secret").unwrap();
    let (success, value) = cli(temp.path(), "target");
    assert!(!success);
    assert!(!value.to_string().contains("private-secret"));
    assert!(
        value["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["code"] == "E_WHY_GRAPH_INVALID"),
        "{value}"
    );
}

#[test]
fn why_detects_backend_lock_mutation_and_missing_references() {
    let temp = fixture();
    let path = temp.path().join("metadata.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    data["resolution"]["root"]["dependencies"] = json!([{"id":"missing"}]);
    fs::write(&path, data.to_string()).unwrap();
    let (success, result) = cli(temp.path(), "target");
    assert!(!success);
    assert_eq!(result["diagnostics"][0]["code"], "E_WHY_GRAPH_INVALID");
    let temp = fixture();
    let uv = temp.path().join("uv");
    let script = fs::read_to_string(&uv).unwrap().replace(
        "*metadata*) cat metadata.json;;",
        "*metadata*) printf '\\n# changed\\n' >> uv.lock; cat metadata.json;;",
    );
    fs::write(uv, script).unwrap();
    let (success, result) = cli(temp.path(), "target");
    assert!(!success);
    assert_eq!(result["diagnostics"][0]["code"], "E_WHY_LOCK_CHANGED");
    assert!(!temp.path().join(".pybun/receipts").exists());
}

#[test]
fn native_why_preserves_known_paths_and_labels_partial_declaration_evidence() {
    use pybun::lockfile::{Lockfile, Package, PackageSource};
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("pyproject.toml"),"[project]\nname='native-root'\nversion='1'\ndependencies=['a']\n[project.optional-dependencies]\nfeature=['target']\n[dependency-groups]\ndev=['target']\n").unwrap();
    let mut lock = Lockfile::new(vec![], vec![]);
    for (name, deps) in [("a", vec!["target".into()]), ("target", vec![])] {
        lock.add_package(Package {
            name: name.into(),
            version: "1".into(),
            source: PackageSource::Registry {
                index: "private".into(),
                url: "https://user:private-secret@example.org".into(),
            },
            wheel: "unused.whl".into(),
            hash: "unused".into(),
            dependencies: deps,
        });
    }
    lock.save_to_path(temp.path().join("pybun.lockb")).unwrap();
    let output = cargo_bin_cmd!("pybun")
        .current_dir(temp.path())
        .env("PYBUN_HISTORY", "0")
        .env("PYBUN_BACKEND", "native")
        .args(["--format=json", "why", "target"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    let detail = &result["detail"];
    assert_eq!(detail["backend"]["name"], "native");
    assert_eq!(detail["complete"], false);
    assert!(detail["paths"].as_array().unwrap().len() >= 3);
    assert!(!detail.to_string().contains("private-secret"));
    let text = cargo_bin_cmd!("pybun")
        .current_dir(temp.path())
        .env("PYBUN_HISTORY", "0")
        .env("PYBUN_BACKEND", "native")
        .args(["why", "target"])
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("native-root -> a -> target"), "{text}");
    assert!(text.contains("Some provenance is unavailable"));
}
