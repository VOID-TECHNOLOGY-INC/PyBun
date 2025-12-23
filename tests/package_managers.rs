use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use tempfile::tempdir;

fn python_available() -> bool {
    Command::new("python3").arg("--version").output().is_ok()
}

fn write_manifest(path: &Path, version: &str, assets: &[(&str, &str)]) {
    let assets_json: Vec<Value> = assets
        .iter()
        .map(|(name, target)| {
            serde_json::json!({
                "name": name,
                "target": target,
                "url": format!("https://example.com/{name}"),
                "sha256": "placeholder",
            })
        })
        .collect();
    let manifest = serde_json::json!({
        "version": version,
        "channel": "stable",
        "published_at": "2025-01-01T00:00:00Z",
        "assets": assets_json,
    });
    fs::write(path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
}

fn write_checksums(path: &Path, entries: &[(&str, &str)]) {
    let mut lines = Vec::new();
    for (sha, name) in entries {
        lines.push(format!("{sha}  {name}"));
    }
    fs::write(path, lines.join("\n") + "\n").unwrap();
}

#[test]
fn package_manager_python_unit_tests() {
    if !python_available() {
        eprintln!("python3 not available; skipping package manager unit tests");
        return;
    }

    let output = Command::new("python3")
        .arg("scripts/release/tests/test_package_managers.py")
        .output()
        .expect("run python unit tests");

    assert!(
        output.status.success(),
        "python unit tests failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn generate_package_manager_files() {
    if !python_available() {
        eprintln!("python3 not available; skipping package manager generation test");
        return;
    }

    let temp = tempdir().unwrap();
    let manifest_path = temp.path().join("pybun-release.json");
    let checksums_path = temp.path().join("SHA256SUMS");
    let homebrew_path = temp.path().join("pybun.rb");
    let scoop_path = temp.path().join("pybun.json");
    let winget_path = temp.path().join("pybun.yaml");

    let assets = [
        ("pybun-aarch64-apple-darwin.tar.gz", "aarch64-apple-darwin"),
        ("pybun-x86_64-apple-darwin.tar.gz", "x86_64-apple-darwin"),
        (
            "pybun-aarch64-unknown-linux-gnu.tar.gz",
            "aarch64-unknown-linux-gnu",
        ),
        (
            "pybun-x86_64-unknown-linux-gnu.tar.gz",
            "x86_64-unknown-linux-gnu",
        ),
        ("pybun-x86_64-pc-windows-msvc.zip", "x86_64-pc-windows-msvc"),
    ];
    let checksums = [
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "pybun-aarch64-apple-darwin.tar.gz",
        ),
        (
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "pybun-x86_64-apple-darwin.tar.gz",
        ),
        (
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "pybun-aarch64-unknown-linux-gnu.tar.gz",
        ),
        (
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "pybun-x86_64-unknown-linux-gnu.tar.gz",
        ),
        (
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "pybun-x86_64-pc-windows-msvc.zip",
        ),
    ];

    write_manifest(&manifest_path, "1.2.3", &assets);
    write_checksums(&checksums_path, &checksums);

    let output = Command::new("python3")
        .arg("scripts/release/generate_package_managers.py")
        .arg("--manifest")
        .arg(&manifest_path)
        .arg("--checksums")
        .arg(&checksums_path)
        .arg("--homebrew")
        .arg(&homebrew_path)
        .arg("--scoop")
        .arg(&scoop_path)
        .arg("--winget")
        .arg(&winget_path)
        .output()
        .expect("run generator");

    assert!(
        output.status.success(),
        "generator failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let homebrew = fs::read_to_string(&homebrew_path).unwrap();
    assert!(homebrew.contains("version \"1.2.3\""));
    assert!(homebrew.contains("PYBUN_HOMEBREW_TEST_TARBALL"));
    assert!(
        homebrew.contains(
            "sha256 \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
        )
    );

    let scoop: Value = serde_json::from_str(&fs::read_to_string(&scoop_path).unwrap()).unwrap();
    assert_eq!(scoop["version"].as_str(), Some("1.2.3"));
    assert_eq!(
        scoop["architecture"]["64bit"]["url"].as_str(),
        Some("https://example.com/pybun-x86_64-pc-windows-msvc.zip")
    );
    assert_eq!(
        scoop["architecture"]["64bit"]["hash"].as_str(),
        Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
    );
    assert_eq!(scoop["bin"].as_str(), Some("pybun.exe"));

    let winget = fs::read_to_string(&winget_path).unwrap();
    assert!(winget.contains("PackageVersion: 1.2.3"));
    assert!(winget.contains("InstallerUrl: https://example.com/pybun-x86_64-pc-windows-msvc.zip"));
    assert!(winget.contains(
        "InstallerSha256: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    ));
}
