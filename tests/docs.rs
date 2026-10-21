use std::fs;
use std::path::PathBuf;
use std::process::Command;

use pybun::release_manifest::current_release_target;
use regex::Regex;
use tempfile::tempdir;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn upgrade_guide_exists_for_ga() {
    let path = project_root().join("docs/UPGRADE.md");
    let contents = fs::read_to_string(&path)
        .expect("GA launch should include docs/UPGRADE.md with migration notes");

    let lower = contents.to_lowercase();
    assert!(
        lower.contains("upgrade") && lower.contains("ga"),
        "upgrade guide should mention GA upgrade path"
    );
    assert!(
        lower.contains("breaking"),
        "upgrade guide should call out breaking changes"
    );
}

#[test]
fn readme_has_ga_docs_sections() {
    let readme = fs::read_to_string(project_root().join("README.md"))
        .expect("README.md should exist at repo root");

    for section in [
        "Quick Start",
        "JSON output examples",
        "Sandbox usage",
        "MCP server (stdio)",
        "Upgrade guide",
    ] {
        assert!(
            readme.contains(section),
            "README.md should include GA docs section: {}",
            section
        );
    }
}

#[test]
fn readme_maturity_and_backend_claims_match_current_behavior() {
    let readme = fs::read_to_string(project_root().join("README.md"))
        .expect("README.md should exist at repo root");

    assert!(
        readme.contains("`pybun install` | **Stable for common cases**")
            && readme.contains("`uv sync`"),
        "install should be documented through its uv sync execution path"
    );
    assert!(
        readme.contains(">=0.12.0,<0.13.0"),
        "README should state the supported uv range"
    );
    assert!(
        readme.contains("PYBUN_BACKEND=native"),
        "README should document the explicit native compatibility opt-in"
    );
    assert!(
        readme.contains("`pybun add` / `pybun remove`")
            && readme.contains("`pybun lock` | **Stable for common cases**")
            && readme.contains("`pybun upgrade` | **Stable for common cases**"),
        "README should describe delegated dependency commands consistently"
    );
    assert!(
        readme.contains(
            "`pybun install`, `pybun add`, `pybun remove`, `pybun lock`, and `pybun upgrade`"
        ),
        "Why PyBun should describe the delegated command set"
    );
    assert!(
        readme.contains("`.data/{purelib,platlib,scripts,headers,data}` routing is implemented"),
        "the closed Issue #402 work should be described as implemented"
    );
    assert!(
        readme.contains("Issue #239](https://github.com/VOID-TECHNOLOGY-INC/PyBun/issues/239)"),
        "resolver performance should link to Issue #239"
    );
    assert!(
        readme.contains("schema-version 2"),
        "README should document how to print the delegated JSON v2 schema"
    );
    assert!(
        readme.contains("contract_version") || readme.contains("envelope version `2`"),
        "README should distinguish the delegated JSON v2 contract"
    );
    assert!(
        readme.contains("pybun_add") && readme.contains("pybun_upgrade"),
        "MCP tool list should include the delegated project tools"
    );
    assert!(
        !readme.contains("No runtime dependencies."),
        "the single-binary claim must state the uv runtime requirement"
    );
    assert!(
        !readme.contains("where uv is available PyBun delegates to it directly"),
        "README should not make a blanket uv-delegation claim"
    );
    assert!(
        !readme.contains("does not yet implement the full PEP 427 `.data` installation semantics"),
        "README should not describe closed Issue #402 as unimplemented"
    );
    assert!(
        !readme.contains("automatic dependency installation, and isolated-environment execution are all implemented and stable"),
        "PEP 723 maturity should distinguish direct uv and native fallback paths"
    );
    assert!(
        !readme.contains("If `uv` is available, it is used for faster environment creation."),
        "pybun x creates its environment with Python, not uv"
    );
    assert!(
        !readme.contains("ordinary dependency commands still use PyBun's native path")
            && !readme
                .contains("`pybun install`, `pybun lock`, and `pybun upgrade` use PyBun's native"),
        "README should not claim dependency commands still use the native path by default"
    );
    assert!(
        !readme.contains("v0.2.0 target architecture broadens uv delegation"),
        "v0.2 delegation is the current behavior, not a future target"
    );
    assert!(
        readme.contains("PyBun-managed PEP 723 environments may still use `uv pip install`"),
        "README should document uv package installation inside PyBun orchestration"
    );
}

#[test]
fn install_one_liner_reports_release_notes_from_manifest() {
    let target = current_release_target().expect("supported release target");
    let archive_ext = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    let asset_name = format!("pybun-{}.{}", target, archive_ext);

    let manifest = serde_json::json!({
        "version": "9.9.9",
        "channel": "stable",
        "published_at": "2025-01-01T00:00:00Z",
        "assets": [
            {
                "name": asset_name,
                "target": target,
                "url": "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v9.9.9/pybun.tar.gz",
                "sha256": "abc123",
                "signature": {
                    "type": "ed25519",
                    "value": "ZmFrZS1zaWduYXR1cmU=",
                    "public_key": "ZmFrZS1wdWJsaWMta2V5"
                }
            }
        ],
        "release_notes": {
            "name": "RELEASE_NOTES.md",
            "url": "https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v9.9.9/notes",
            "sha256": "deadbeef"
        }
    });

    let temp = tempdir().expect("tempdir");
    let manifest_path = temp.path().join("pybun-release.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    let output = Command::new("sh")
        .current_dir(project_root())
        .arg("scripts/install.sh")
        .arg("--dry-run")
        .arg("--format")
        .arg("json")
        .env("PYBUN_INSTALL_MANIFEST", &manifest_path)
        .env("HOME", temp.path())
        .output()
        .expect("run installer");

    assert!(
        output.status.success(),
        "installer dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("installer output should be JSON");
    let manifest_json = json
        .get("manifest")
        .expect("manifest object should be present in JSON");
    let release_notes = manifest_json
        .get("release_notes")
        .expect("manifest should include release_notes attachment");

    assert_eq!(
        release_notes.get("url").and_then(|v| v.as_str()),
        Some("https://github.com/VOID-TECHNOLOGY-INC/PyBun/releases/download/v9.9.9/notes")
    );
    assert_eq!(
        json.get("asset")
            .and_then(|asset| asset.get("name"))
            .and_then(|v| v.as_str()),
        Some(asset_name.as_str())
    );
}

fn markdown_anchors(content: &str) -> Vec<String> {
    let mut slugs = Vec::new();
    let mut in_fence = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix('#') else {
            continue;
        };
        let heading = rest.trim_start_matches('#');
        let Some(heading) = heading.strip_prefix(' ') else {
            continue;
        };
        let mut slug = String::new();
        for ch in heading.trim().chars() {
            if ch.is_alphanumeric() {
                slug.extend(ch.to_lowercase());
            } else if ch == ' ' {
                slug.push('-');
            } else if ch == '-' || ch == '_' {
                slug.push(ch);
            }
        }
        slugs.push(slug);
    }
    slugs
}

#[test]
fn relative_markdown_links_resolve() {
    let root = project_root();
    let files = [
        "README.md",
        "docs/UPGRADE.md",
        "docs/UV_BACKEND.md",
        "docs/SPECS.md",
    ];
    let link_re = Regex::new(r"\[[^\]]+\]\(([^)#]*)(#[^)]*)?\)").expect("valid regex");

    for file in files {
        let content = fs::read_to_string(root.join(file))
            .unwrap_or_else(|_| panic!("failed to read {}", file));
        for caps in link_re.captures_iter(&content) {
            let target = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let anchor = caps.get(2).map(|m| m.as_str().trim_start_matches('#'));
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
            {
                continue;
            }
            let base = root.join(file).parent().unwrap_or(&root).to_path_buf();
            let path = base.join(target.trim_start_matches("./"));
            assert!(
                path.exists(),
                "missing markdown target {} referenced from {}",
                target,
                file
            );
            if let Some(anchor) = anchor {
                let linked = if target.is_empty() {
                    content.clone()
                } else {
                    fs::read_to_string(&path).unwrap_or_else(|_| {
                        panic!("failed to read linked markdown target {}", target)
                    })
                };
                let anchors = markdown_anchors(&linked);
                assert!(
                    anchors.iter().any(|slug| slug == anchor),
                    "missing anchor #{} in {} referenced from {}",
                    anchor,
                    target,
                    file
                );
            }
        }
    }
}
