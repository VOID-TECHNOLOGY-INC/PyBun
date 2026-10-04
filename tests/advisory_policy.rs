use std::fs;

use toml::Value;

const BINCODE_ADVISORY: &str = "RUSTSEC-2025-0141";

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
fn cargo_audit_has_no_advisory_suppressions() {
    let (_, config) = read_toml(".cargo/audit.toml");
    let ignored = config["advisories"]["ignore"]
        .as_array()
        .expect("cargo-audit ignores should be an array");

    assert!(ignored.is_empty(), "unexpected suppressions: {ignored:?}");
}

#[test]
fn cargo_deny_blocks_all_unsound_advisories_and_has_no_suppressions() {
    let (_, config) = read_toml("deny.toml");
    let advisories = &config["advisories"];

    assert_eq!(advisories["unsound"].as_str(), Some("all"));
    assert_eq!(advisories["unused-ignored-advisory"].as_str(), Some("deny"));
    assert!(
        advisories["ignore"]
            .as_array()
            .expect("cargo-deny ignores should be an array")
            .is_empty()
    );
}

#[test]
fn unmaintained_bincode_is_not_a_dependency() {
    let (_, lockfile) = read_toml("Cargo.lock");
    let has_bincode = lockfile["package"]
        .as_array()
        .expect("Cargo.lock should contain packages")
        .iter()
        .any(|package| package["name"].as_str() == Some("bincode"));
    assert!(
        !has_bincode,
        "{BINCODE_ADVISORY}: bincode must not be locked"
    );
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
