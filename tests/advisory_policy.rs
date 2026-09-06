use std::fs;

use regex::Regex;
use toml::Value;

const BINCODE_ADVISORY: &str = "RUSTSEC-2025-0141";
const BINCODE_TRACKING_URL: &str = "https://github.com/VOID-TECHNOLOGY-INC/PyBun/issues/434";

fn read_toml(path: &str) -> (String, Value) {
    let contents = fs::read_to_string(path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let parsed = toml::from_str(&contents).unwrap_or_else(|error| panic!("{path}: {error}"));
    (contents, parsed)
}

fn lockfile_version(package_name: &str) -> String {
    let (_, lockfile) = read_toml("Cargo.lock");
    lockfile["package"]
        .as_array()
        .expect("Cargo.lock should contain packages")
        .iter()
        .find(|package| package["name"].as_str() == Some(package_name))
        .unwrap_or_else(|| panic!("Cargo.lock should contain {package_name}"))["version"]
        .as_str()
        .expect("package version should be a string")
        .to_owned()
}

#[test]
fn cargo_audit_has_only_the_time_boxed_bincode_suppression() {
    let (contents, config) = read_toml(".cargo/audit.toml");
    let ignored = config["advisories"]["ignore"]
        .as_array()
        .expect("cargo-audit ignores should be an array")
        .iter()
        .map(|entry| entry.as_str().expect("cargo-audit ignores should be IDs"))
        .collect::<Vec<_>>();

    assert_eq!(ignored, [BINCODE_ADVISORY]);
    assert!(contents.contains(BINCODE_TRACKING_URL));
    assert!(contents.contains("owner: release/security maintainers"));
    assert!(
        Regex::new(r"review-by: 20\d{2}-\d{2}-\d{2}")
            .unwrap()
            .is_match(&contents)
    );
    assert!(contents.contains("reason:"));
}

#[test]
fn cargo_deny_blocks_all_unsound_advisories_and_stale_suppressions() {
    let (contents, config) = read_toml("deny.toml");
    let advisories = &config["advisories"];

    assert_eq!(advisories["unsound"].as_str(), Some("all"));
    assert_eq!(advisories["unused-ignored-advisory"].as_str(), Some("deny"));

    let ignored = advisories["ignore"]
        .as_array()
        .expect("cargo-deny ignores should be an array");
    assert_eq!(ignored.len(), 1);
    assert_eq!(ignored[0]["id"].as_str(), Some(BINCODE_ADVISORY));
    assert!(
        ignored[0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("#434") && reason.contains("2026-12-07"))
    );
    assert!(contents.contains(BINCODE_TRACKING_URL));
}

#[test]
fn ci_enforces_both_advisory_scanners() {
    let workflow = fs::read_to_string(".github/workflows/ci.yml").unwrap();

    assert!(workflow.contains("run: cargo audit --deny unsound"));
    assert!(workflow.contains("run: cargo deny --all-features check advisories"));
}

#[test]
fn known_unsound_dependencies_are_patched() {
    let requirements = [
        ("rand", "0.9.3"),
        ("anyhow", "1.0.103"),
        ("event-listener", "5.4.2"),
    ];

    for (package, minimum) in requirements {
        let actual = lockfile_version(package);
        assert!(
            semver::Version::parse(&actual).unwrap() >= semver::Version::parse(minimum).unwrap(),
            "{package} {actual} is below the patched floor {minimum}"
        );
    }
}
