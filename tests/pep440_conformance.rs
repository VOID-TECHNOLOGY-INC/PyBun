//! PEP 440 conformance suite (Issue #350) — acceptance tests for the
//! resolver's version ordering (Issue #340) and specifier matching
//! (Issue #339), driven by the canonical corpus vendored from
//! pypa/packaging (see the fixture headers for provenance and the list of
//! excluded rows).

use pybun::pep440::Pep440Version;
use pybun::resolver::{Requirement, compare_versions};
use std::cmp::Ordering;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Non-comment, non-empty lines of a fixture file.
fn fixture_lines(name: &str) -> Vec<String> {
    let raw = std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|e| panic!("read fixture {name}: {e}"));
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

fn corpus_versions() -> Vec<String> {
    let versions = fixture_lines("pep440_versions.txt");
    assert!(
        versions.len() > 50,
        "corpus unexpectedly small ({} entries) — fixture damaged?",
        versions.len()
    );
    versions
}

#[test]
fn corpus_versions_all_parse_as_pep440() {
    for version in corpus_versions() {
        assert!(
            Pep440Version::parse(&version).is_some(),
            "{version:?} from the pypa/packaging corpus must parse as PEP 440"
        );
    }
}

/// Every pair from the reference corpus (which is in strictly ascending
/// PEP 440 order) must agree with `compare_versions`, in both directions.
/// This mirrors pypa/packaging's `test_version_comparison`.
#[test]
fn corpus_total_order_matches_reference() {
    let versions = corpus_versions();
    let mut failures = Vec::new();
    for (i, lower) in versions.iter().enumerate() {
        for higher in &versions[i + 1..] {
            if compare_versions(lower, higher) != Ordering::Less {
                failures.push(format!("expected {lower} < {higher}"));
            }
            if compare_versions(higher, lower) != Ordering::Greater {
                failures.push(format!("expected {higher} > {lower}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} ordering disagreements with the pypa/packaging corpus:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Every version must compare equal to itself.
#[test]
fn corpus_ordering_is_reflexive() {
    for version in corpus_versions() {
        assert_eq!(
            compare_versions(&version, &version),
            Ordering::Equal,
            "{version} != itself"
        );
    }
}

/// Each `(specifier, version, expected)` triple from the pypa/packaging
/// match table must agree with the resolver's parse + match pipeline.
#[test]
fn specifier_table_matches_reference() {
    let rows = fixture_lines("pep440_specifiers.tsv");
    assert!(
        rows.len() > 100,
        "specifier table unexpectedly small ({} rows) — fixture damaged?",
        rows.len()
    );

    let mut failures = Vec::new();
    for row in &rows {
        let mut cols = row.split('\t');
        let (Some(spec), Some(version), Some(expected)) = (cols.next(), cols.next(), cols.next())
        else {
            panic!("malformed fixture row: {row:?}");
        };
        let expected: bool = expected.parse().unwrap_or_else(|_| {
            panic!("malformed expected column in fixture row: {row:?}");
        });

        // Exercise the real requirement-parsing path, exactly as a
        // dependency string from an index or pyproject would.
        let requirement: Requirement = format!("pkg{spec}")
            .parse()
            .unwrap_or_else(|e| panic!("specifier {spec:?} failed to parse: {e:?}"));
        let actual = requirement.is_satisfied_by(version);
        if actual != expected {
            failures.push(format!(
                "`{spec}` matching {version:?}: expected {expected}, got {actual}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} specifier disagreements with the pypa/packaging table:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
