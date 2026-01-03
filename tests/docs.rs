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
                "url": "https://example.com/pybun.tar.gz",
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
            "url": "https://example.com/notes",
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
        Some("https://example.com/notes")
    );
    assert_eq!(
        json.get("asset")
            .and_then(|asset| asset.get("name"))
            .and_then(|v| v.as_str()),
        Some(asset_name.as_str())
    );
}

#[test]
fn relative_markdown_links_resolve() {
    let root = project_root();
    let files = ["README.md", "docs/UPGRADE.md"];
    let link_re = Regex::new(r"\[[^\]]+\]\(([^)#]+)(#[^)]+)?\)").expect("valid regex");

    for file in files {
        let content = fs::read_to_string(root.join(file))
            .unwrap_or_else(|_| panic!("failed to read {}", file));
        for caps in link_re.captures_iter(&content) {
            let target = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
                || target.starts_with('#')
            {
                continue;
            }
            let path = root.join(target.trim_start_matches("./"));
            assert!(
                path.exists(),
                "missing markdown target {} referenced from {}",
                target,
                file
            );
        }
    }
}
