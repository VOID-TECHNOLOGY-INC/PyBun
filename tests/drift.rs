use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn pybun() -> Command {
    Command::cargo_bin("pybun").unwrap()
}

fn write_pyproject(dir: &TempDir, deps: &[&str]) {
    let deps_toml = deps
        .iter()
        .map(|d| format!("  \"{d}\""))
        .collect::<Vec<_>>()
        .join(",\n");
    fs::write(
        dir.path().join("pyproject.toml"),
        format!(
            "[project]\nname = \"test\"\nversion = \"0.1.0\"\ndependencies = [\n{deps_toml}\n]\n"
        ),
    )
    .unwrap();
}

// ── CLI tests ────────────────────────────────────────────────────────────────

#[test]
fn drift_detects_undeclared_import() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &["requests"]);
    // script imports pandas which is NOT declared
    fs::write(
        dir.path().join("main.py"),
        "import pandas\nimport requests\n",
    )
    .unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "ok");
    let undeclared = &json["detail"]["undeclared_imports"];
    assert!(undeclared.is_array(), "undeclared_imports must be array");
    let pkgs: Vec<&str> = undeclared
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["package"].as_str().unwrap())
        .collect();
    assert!(pkgs.contains(&"pandas"), "pandas should be undeclared");
    assert!(
        !pkgs.contains(&"requests"),
        "requests is declared, should not appear"
    );
}

#[test]
fn drift_detects_unused_declaration() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &["requests", "numpy"]);
    // script only imports requests, numpy is unused
    fs::write(dir.path().join("main.py"), "import requests\n").unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "ok");
    let unused = &json["detail"]["unused_declarations"];
    assert!(unused.is_array());
    let pkgs: Vec<&str> = unused
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["package"].as_str().unwrap())
        .collect();
    assert!(pkgs.contains(&"numpy"), "numpy should be unused");
    assert!(
        !pkgs.contains(&"requests"),
        "requests is used, should not appear"
    );
}

#[test]
fn drift_clean_project_reports_empty_lists() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &["requests"]);
    fs::write(dir.path().join("main.py"), "import requests\n").unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(
        json["detail"]["undeclared_imports"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        json["detail"]["unused_declarations"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn drift_excludes_stdlib_modules() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &[]);
    // os, sys, json are stdlib — should not appear in undeclared
    fs::write(
        dir.path().join("main.py"),
        "import os\nimport sys\nimport json\n",
    )
    .unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "ok");
    let undeclared = json["detail"]["undeclared_imports"].as_array().unwrap();
    let pkgs: Vec<&str> = undeclared
        .iter()
        .map(|v| v["package"].as_str().unwrap())
        .collect();
    assert!(!pkgs.contains(&"os"), "os is stdlib");
    assert!(!pkgs.contains(&"sys"), "sys is stdlib");
    assert!(!pkgs.contains(&"json"), "json is stdlib");
}

#[test]
fn drift_uses_import_alias_mapping() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &["Pillow"]);
    // PIL is the import name for Pillow
    fs::write(dir.path().join("main.py"), "from PIL import Image\n").unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "ok");
    // Pillow is declared and PIL maps to it, so undeclared should be empty
    let undeclared = json["detail"]["undeclared_imports"].as_array().unwrap();
    assert!(
        undeclared.is_empty(),
        "PIL should resolve to Pillow which is declared"
    );
}

#[test]
fn drift_handles_from_import_syntax() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &["requests"]);
    fs::write(
        dir.path().join("main.py"),
        "from requests import get\nfrom requests.auth import HTTPBasicAuth\n",
    )
    .unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "ok");
    let undeclared = json["detail"]["undeclared_imports"].as_array().unwrap();
    assert!(undeclared.is_empty(), "requests is declared");
}

#[test]
fn drift_includes_import_location_in_output() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &[]);
    fs::write(dir.path().join("main.py"), "import pandas\n").unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let undeclared = json["detail"]["undeclared_imports"].as_array().unwrap();
    assert!(!undeclared.is_empty());
    let entry = &undeclared[0];
    assert_eq!(entry["package"], "pandas");
    let locations = entry["imported_in"].as_array().unwrap();
    assert!(!locations.is_empty());
    let loc = &locations[0];
    assert!(loc["file"].as_str().unwrap().contains("main.py"));
    assert_eq!(loc["line"], 1);
    assert!(loc["statement"].as_str().unwrap().contains("import pandas"));
}

#[test]
fn drift_includes_next_action_for_undeclared() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &[]);
    fs::write(dir.path().join("main.py"), "import pandas\n").unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let undeclared = json["detail"]["undeclared_imports"].as_array().unwrap();
    let entry = &undeclared[0];
    let next_action = &entry["next_action"];
    assert_eq!(next_action["tool"], "pybun_add");
    assert_eq!(next_action["args"]["package"], "pandas");
}

#[test]
fn drift_includes_next_action_for_unused() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &["numpy"]);
    fs::write(dir.path().join("main.py"), "# no imports\n").unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let unused = json["detail"]["unused_declarations"].as_array().unwrap();
    let entry = &unused[0];
    let next_action = &entry["next_action"];
    assert_eq!(next_action["tool"], "pybun_remove");
    assert_eq!(next_action["args"]["package"], "numpy");
}

#[test]
fn drift_without_pyproject_returns_error() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("main.py"), "import requests\n").unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "error");
    let diags = json["diagnostics"].as_array().unwrap();
    assert!(!diags.is_empty());
    let codes: Vec<&str> = diags
        .iter()
        .map(|d| d["code"].as_str().unwrap_or(""))
        .collect();
    assert!(codes.iter().any(|c| c.contains("DRIFT")));
}

#[test]
fn drift_text_output_mentions_undeclared_and_unused() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &["numpy"]);
    fs::write(dir.path().join("main.py"), "import pandas\n").unwrap();

    pybun()
        .args(["drift"])
        .current_dir(dir.path())
        .assert()
        .stdout(
            contains("undeclared")
                .or(contains("unused"))
                .or(contains("drift")),
        );
}

#[test]
fn drift_scans_subdirectories() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &[]);
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src/util.py"), "import pandas\n").unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let undeclared = json["detail"]["undeclared_imports"].as_array().unwrap();
    let pkgs: Vec<&str> = undeclared
        .iter()
        .map(|v| v["package"].as_str().unwrap())
        .collect();
    assert!(
        pkgs.contains(&"pandas"),
        "pandas in subdirectory should be detected"
    );
}

#[test]
fn drift_analysis_notes_are_present() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &[]);
    fs::write(dir.path().join("main.py"), "# empty\n").unwrap();

    let output = pybun()
        .args(["drift", "--format=json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let notes = &json["detail"]["analysis_notes"];
    assert!(notes.is_array(), "analysis_notes must be present");
}

// ── MCP tests ─────────────────────────────────────────────────────────────────

fn mcp_request(id: u64, method: &str, params: Value) -> String {
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": id
    }))
    .unwrap()
        + "\n"
}

fn run_mcp(requests: &[String]) -> Vec<Value> {
    let input = requests.join("");
    let output = Command::cargo_bin("pybun")
        .unwrap()
        .args(["mcp", "serve", "--stdio"])
        .write_stdin(input)
        .output()
        .unwrap();

    output
        .stdout
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

#[test]
fn mcp_tools_list_includes_pybun_drift() {
    let responses = run_mcp(&[mcp_request(1, "tools/list", serde_json::json!({}))]);
    let tools = responses[0]["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(
        names.contains(&"pybun_drift"),
        "pybun_drift must be in tools list"
    );
}

#[test]
fn mcp_pybun_drift_returns_structured_result() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &["requests"]);
    fs::write(
        dir.path().join("main.py"),
        "import pandas\nimport requests\n",
    )
    .unwrap();

    let req = mcp_request(
        1,
        "tools/call",
        serde_json::json!({
            "name": "pybun_drift",
            "arguments": {
                "cwd": dir.path().to_str().unwrap()
            }
        }),
    );
    let responses = run_mcp(&[req]);
    let text = responses[0]["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    let result: Value = serde_json::from_str(text).unwrap();
    assert!(result["undeclared_imports"].is_array());
    assert!(result["unused_declarations"].is_array());
    let undeclared_pkgs: Vec<&str> = result["undeclared_imports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["package"].as_str().unwrap())
        .collect();
    assert!(undeclared_pkgs.contains(&"pandas"));
}

#[test]
fn mcp_pybun_context_includes_drift_summary_when_include_drift_true() {
    let dir = TempDir::new().unwrap();
    write_pyproject(&dir, &["requests"]);
    fs::write(
        dir.path().join("main.py"),
        "import pandas\nimport requests\n",
    )
    .unwrap();

    let req = mcp_request(
        1,
        "tools/call",
        serde_json::json!({
            "name": "pybun_context",
            "arguments": {
                "cwd": dir.path().to_str().unwrap(),
                "include_drift": true
            }
        }),
    );
    let responses = run_mcp(&[req]);
    let text = responses[0]["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    let result: Value = serde_json::from_str(text).unwrap();
    let drift_summary = &result["drift_summary"];
    assert!(
        drift_summary["undeclared_imports"].is_array(),
        "drift_summary.undeclared_imports should be populated when include_drift=true"
    );
}
