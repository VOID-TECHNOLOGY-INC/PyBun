//! Property-based PEP 440 invariants (Issue #350).
//!
//! Generates structured PEP 440 versions (epoch, release segments,
//! pre/post/dev, local labels) plus randomized *spellings* of the same
//! version (case, `-`/`_`/`.` separators, `alpha`/`beta`/`c`/`rev`
//! aliases, implicit `-N` post form, `v` prefix) and checks the
//! invariants that hand-picked example tests structurally cannot cover.

use proptest::prelude::*;
use pybun::pep440::Pep440Version;
use pybun::resolver::{VersionSpec, compare_versions};
use std::cmp::Ordering;

/// Pre-release phase index: 0 = a, 1 = b, 2 = rc.
type Parts = (
    Option<u64>,       // epoch
    Vec<u64>,          // release segments
    Option<(u8, u64)>, // pre-release (phase, number)
    Option<u64>,       // post
    Option<u64>,       // dev
    Vec<String>,       // local segments
);

fn local_segment() -> impl Strategy<Value = String> {
    prop_oneof![
        (0u64..1000).prop_map(|n| n.to_string()),
        "[a-z][a-z0-9]{0,5}".prop_map(|s| s),
    ]
}

fn parts() -> impl Strategy<Value = Parts> {
    (
        proptest::option::of(0u64..5),
        proptest::collection::vec(0u64..1000, 1..5),
        proptest::option::of((0u8..3, 0u64..100)),
        proptest::option::of(0u64..100),
        proptest::option::of(0u64..100),
        proptest::collection::vec(local_segment(), 0..3),
    )
}

/// Canonical spelling: `E!R(.R)*[{a|b|rc}N][.postN][.devN][+local]`.
fn canonical(p: &Parts) -> String {
    let (epoch, release, pre, post, dev, local) = p;
    let mut s = String::new();
    if let Some(e) = epoch {
        s.push_str(&format!("{e}!"));
    }
    s.push_str(
        &release
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    );
    if let Some((phase, n)) = pre {
        s.push_str(&format!("{}{n}", ["a", "b", "rc"][*phase as usize]));
    }
    if let Some(n) = post {
        s.push_str(&format!(".post{n}"));
    }
    if let Some(n) = dev {
        s.push_str(&format!(".dev{n}"));
    }
    if !local.is_empty() {
        s.push('+');
        s.push_str(&local.join("."));
    }
    s
}

/// Style knobs for an alternative spelling of the same version.
type Style = (bool, u8, u8, u8, bool, u8);

fn style() -> impl Strategy<Value = Style> {
    (
        any::<bool>(), // leading `v`
        0u8..4,        // separator before pre/post/dev: "", ".", "-", "_"
        0u8..4,        // pre spelling variant
        0u8..3,        // post spelling variant (post, rev, r)
        any::<bool>(), // uppercase everything
        0u8..3,        // local separator: ".", "-", "_"
    )
}

/// A differently-spelled but PEP 440-equal rendering of the same parts.
fn messy(p: &Parts, style: &Style) -> String {
    let (epoch, release, pre, post, dev, local) = p;
    let (v_prefix, sep_idx, pre_idx, post_idx, upper, local_sep_idx) = style;
    let sep = ["", ".", "-", "_"][*sep_idx as usize];
    let local_sep = [".", "-", "_"][*local_sep_idx as usize];

    let mut s = String::new();
    if *v_prefix {
        s.push('v');
    }
    if let Some(e) = epoch {
        s.push_str(&format!("{e}!"));
    }
    s.push_str(
        &release
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    );
    if let Some((phase, n)) = pre {
        let spelling = match phase {
            0 => ["a", "alpha", "a", "alpha"][*pre_idx as usize],
            1 => ["b", "beta", "b", "beta"][*pre_idx as usize],
            _ => ["rc", "c", "pre", "preview"][*pre_idx as usize],
        };
        s.push_str(&format!("{sep}{spelling}{sep}{n}"));
    }
    if let Some(n) = post {
        let spelling = ["post", "rev", "r"][*post_idx as usize];
        s.push_str(&format!("{sep}{spelling}{sep}{n}"));
    }
    if let Some(n) = dev {
        s.push_str(&format!("{sep}dev{sep}{n}"));
    }
    if !local.is_empty() {
        s.push('+');
        s.push_str(&local.join(local_sep));
    }
    if *upper { s.to_ascii_uppercase() } else { s }
}

/// Same parts with an extra `0` release segment (`1.4` -> `1.4.0`).
fn zero_padded(p: &Parts) -> Parts {
    let mut padded = p.clone();
    padded.1.push(0);
    padded
}

proptest! {
    /// Every generated canonical spelling is inside the PEP 440 grammar.
    #[test]
    fn generated_versions_parse(p in parts()) {
        let s = canonical(&p);
        prop_assert!(
            Pep440Version::parse(&s).is_some(),
            "{:?} should parse", s
        );
    }

    /// The parsed struct round-trips the generated parts exactly.
    #[test]
    fn parse_roundtrips_structure(p in parts()) {
        let s = canonical(&p);
        let parsed = Pep440Version::parse(&s).unwrap();
        prop_assert_eq!(parsed.epoch, p.0.unwrap_or(0));
        prop_assert_eq!(&parsed.release, &p.1);
        prop_assert_eq!(parsed.pre.map(|(ph, n)| (ph as u8, n)), p.2);
        prop_assert_eq!(parsed.post, p.3);
        prop_assert_eq!(parsed.dev, p.4);
        prop_assert_eq!(parsed.local.len(), p.5.len());
        prop_assert_eq!(
            parsed.is_prerelease(),
            p.2.is_some() || p.4.is_some(),
            "is_prerelease must reflect pre/dev segments"
        );
    }

    /// Ordering is antisymmetric: cmp(a, b) == cmp(b, a).reverse().
    #[test]
    fn ordering_is_antisymmetric(a in parts(), b in parts()) {
        let (a, b) = (canonical(&a), canonical(&b));
        prop_assert_eq!(
            compare_versions(&a, &b),
            compare_versions(&b, &a).reverse(),
            "cmp({}, {}) must mirror cmp({}, {})", a, b, b, a
        );
    }

    /// Ordering is transitive: a <= b and b <= c imply a <= c.
    #[test]
    fn ordering_is_transitive(a in parts(), b in parts(), c in parts()) {
        let mut v = [canonical(&a), canonical(&b), canonical(&c)];
        v.sort_by(|x, y| compare_versions(x, y));
        let (a, b, c) = (&v[0], &v[1], &v[2]);
        prop_assert_ne!(compare_versions(a, b), Ordering::Greater);
        prop_assert_ne!(compare_versions(b, c), Ordering::Greater);
        prop_assert_ne!(compare_versions(a, c), Ordering::Greater);
    }

    /// `==v` matches `v` itself, and its zero-padded release form; `!=` is
    /// the exact complement of `==` for every generated pair.
    #[test]
    fn exact_matches_self_and_padded_form(p in parts()) {
        let v = canonical(&p);
        let padded = canonical(&zero_padded(&p));
        prop_assert!(
            VersionSpec::Exact(v.clone()).matches(&v),
            "=={} must match itself", v
        );
        prop_assert!(
            VersionSpec::Exact(v.clone()).matches(&padded),
            "=={} must match {}", v, padded
        );
        prop_assert!(
            VersionSpec::Exact(padded.clone()).matches(&v),
            "=={} must match {}", padded, v
        );
        prop_assert!(!VersionSpec::NotEqual(v.clone()).matches(&v));
        prop_assert!(!VersionSpec::NotEqual(v).matches(&padded));
    }

    /// `!=a` matches `b` exactly when `==a` does not.
    #[test]
    fn not_equal_is_complement_of_equal(a in parts(), b in parts()) {
        let (a, b) = (canonical(&a), canonical(&b));
        prop_assert_eq!(
            VersionSpec::NotEqual(a.clone()).matches(&b),
            !VersionSpec::Exact(a.clone()).matches(&b),
            "!= vs == disagree: spec {} candidate {}", a, b
        );
    }

    /// Every alternative spelling (case, separators, aliases, `v` prefix)
    /// parses and compares equal to the canonical spelling.
    #[test]
    fn normalization_maps_spellings_to_same_version(p in parts(), st in style()) {
        let canon = canonical(&p);
        let alt = messy(&p, &st);
        let parsed_alt = Pep440Version::parse(&alt);
        prop_assert!(parsed_alt.is_some(), "{:?} should parse", alt);
        prop_assert_eq!(
            compare_versions(&canon, &alt),
            Ordering::Equal,
            "{} and {} are spellings of the same version", canon, alt
        );
    }
}
