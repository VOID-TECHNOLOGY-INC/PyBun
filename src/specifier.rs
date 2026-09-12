//! PEP 440 specifier parsing and matching.

use crate::pep440::Pep440Version;
use semver::Version;
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionSpec {
    /// ==version
    Exact(String),
    /// >=version
    Minimum(String),
    /// >version
    MinimumExclusive(String),
    /// <=version
    MaximumInclusive(String),
    /// <version
    Maximum(String),
    /// !=version
    NotEqual(String),
    /// ~=version (compatible release - PEP 440)
    Compatible(String),
    /// Any version
    Any,
}

impl VersionSpec {
    /// Render the operator and version, e.g. `>=1.0` or `*` for [`VersionSpec::Any`].
    pub fn operator_display(&self) -> String {
        match self {
            VersionSpec::Exact(v) => format!("=={v}"),
            VersionSpec::Minimum(v) => format!(">={v}"),
            VersionSpec::MinimumExclusive(v) => format!(">{v}"),
            VersionSpec::MaximumInclusive(v) => format!("<={v}"),
            VersionSpec::Maximum(v) => format!("<{v}"),
            VersionSpec::NotEqual(v) => format!("!={v}"),
            VersionSpec::Compatible(v) => format!("~={v}"),
            VersionSpec::Any => "*".to_string(),
        }
    }

    /// Check whether `version` satisfies this single constraint.
    pub fn matches(&self, version: &str) -> bool {
        match self {
            VersionSpec::Exact(v) => versions_equal(version, v),
            VersionSpec::Minimum(min) => inclusive_greater_equal(version, min),
            VersionSpec::MinimumExclusive(min) => exclusive_greater_than(version, min),
            VersionSpec::MaximumInclusive(max) => inclusive_less_equal(version, max),
            VersionSpec::Maximum(max) => exclusive_less_than(version, max),
            VersionSpec::NotEqual(v) => !versions_equal(version, v),
            VersionSpec::Compatible(base) => is_compatible_release(version, base),
            VersionSpec::Any => true,
        }
    }
}

pub(crate) fn parse_version_spec(s: &str) -> Result<VersionSpec, String> {
    let s = s.trim();
    if let Some(v) = s.strip_prefix("~=") {
        Ok(VersionSpec::Compatible(v.trim().to_string()))
    } else if let Some(v) = s.strip_prefix("==") {
        Ok(VersionSpec::Exact(v.trim().to_string()))
    } else if let Some(v) = s.strip_prefix("!=") {
        Ok(VersionSpec::NotEqual(v.trim().to_string()))
    } else if let Some(v) = s.strip_prefix(">=") {
        Ok(VersionSpec::Minimum(v.trim().to_string()))
    } else if let Some(v) = s.strip_prefix("<=") {
        Ok(VersionSpec::MaximumInclusive(v.trim().to_string()))
    } else if let Some(v) = s.strip_prefix('>') {
        Ok(VersionSpec::MinimumExclusive(v.trim().to_string()))
    } else if let Some(v) = s.strip_prefix('<') {
        Ok(VersionSpec::Maximum(v.trim().to_string()))
    } else {
        Err(format!("unrecognized version specifier: {s}"))
    }
}

/// Report whether a `requires-python` specifier admits `python_version`.
///
/// Comma-separated PEP 440 clauses are all required to match. Clauses this
/// resolver cannot evaluate — wildcards (`!=3.0.*`) or otherwise unparseable
/// parts — are treated as satisfied, so imperfect metadata can only ever
/// widen the candidate set, never wrongly exclude a version (Issue #342).
pub fn requires_python_allows(requires_python: &str, python_version: &str) -> bool {
    requires_python.split(',').all(|part| {
        let part = part.trim();
        if part.is_empty() || part.contains('*') {
            return true;
        }
        match parse_version_spec(part) {
            Ok(spec) => spec.matches(python_version),
            Err(_) => true,
        }
    })
}

/// Report whether `version` is a PEP 440 pre-release or dev release.
///
/// Detects pre-release segments (`a`/`alpha`, `b`/`beta`, `c`, `rc`, `pre`,
/// `preview`) and dev segments (`dev`) case-insensitively, with `.`/`-`/`_`
/// or no separator. Post-releases (`post`/`rev`/`r`) are NOT pre-releases,
/// but a version with both a pre and a post segment (e.g. `1.0a1.post2`) is.
/// Epoch prefixes (`N!`) and local version labels (`+...`) are ignored.
///
/// Versions inside the PEP 440 grammar are classified by [`Pep440Version`];
/// the scanner below is the fallback for strings outside it (Issue #340).
pub fn is_prerelease(version: &str) -> bool {
    if let Some(parsed) = Pep440Version::parse(version) {
        return parsed.is_prerelease();
    }
    let lower = version.trim().to_ascii_lowercase();
    // Local version labels (`+...`) never affect pre-release status.
    let without_local = lower.split('+').next().unwrap_or("");
    // Strip an epoch prefix (`N!`).
    let core = match without_local.split_once('!') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            rest
        }
        _ => without_local,
    };

    let bytes = core.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            match &core[start..i] {
                // Pre-release spellings (PEP 440 normalizes alpha -> a,
                // beta -> b, c/pre/preview -> rc) plus dev releases.
                "a" | "b" | "c" | "rc" | "alpha" | "beta" | "pre" | "preview" | "dev" => {
                    return true;
                }
                // Post-release spellings (post/rev/r) and anything else are
                // not pre-release markers.
                _ => {}
            }
        } else {
            i += 1;
        }
    }
    false
}

/// Compare two version strings, returning their ordering.
///
/// Uses PEP 440 ordering (epochs, post-releases above their base, numeric
/// pre-release ordering, `dev < a < b < rc < final < post`) when both sides
/// parse as PEP 440 versions (Issue #340). Falls back to the legacy relaxed
/// semver comparison, then raw string ordering, for strings outside the
/// PEP 440 grammar.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    if let (Some(left), Some(right)) = (Pep440Version::parse(a), Pep440Version::parse(b)) {
        return left.cmp(&right);
    }
    match (parse_version_relaxed(a), parse_version_relaxed(b)) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => a.cmp(b),
    }
}

pub fn parse_version_relaxed(input: &str) -> Option<Version> {
    if let Ok(v) = Version::parse(input) {
        return Some(v);
    }
    // Split into numeric prefix and optional suffix (rc, a, b, etc.)
    let mut prefix = String::new();
    let mut suffix = String::new();
    for (idx, ch) in input.char_indices() {
        if ch.is_ascii_digit() || ch == '.' {
            prefix.push(ch);
        } else {
            suffix = input[idx..].to_string();
            break;
        }
    }
    if prefix.is_empty() {
        return None;
    }
    let mut parts: Vec<&str> = prefix
        .trim_matches('.')
        .split('.')
        .filter(|p| !p.is_empty())
        .collect();
    while parts.len() < 3 {
        parts.push("0");
    }
    let prefix_norm = parts[..3].join(".");
    let suffix_norm = suffix
        .trim_start_matches(['-', '_', '.'])
        .to_ascii_lowercase();
    let semver_str = if suffix_norm.is_empty() {
        prefix_norm
    } else {
        format!("{}-{}", prefix_norm, suffix_norm)
    };
    Version::parse(&semver_str).ok()
}

/// PEP 440-aware equality used by the `==` / `!=` specifiers (Issue #339).
///
/// Release segments are compared numerically with zero padding of the shorter
/// release (`1.4` == `1.4.0`, `2024.01` == `2024.1`, but `1.2.3` != `1.2.3.4`),
/// and any trailing suffix (pre/post/dev/local) is normalized for case and
/// `-`/`_`/`.` separators so `1.0.POST1` == `1.0.post1`. Falls back to raw
/// string equality when either side cannot be parsed as a release-shaped
/// version.
///
/// `spec` is the version literal written in the specifier. Per PEP 440, when
/// the specifier has no local version label, local labels on candidates are
/// ignored (`==1.0` matches `1.0+cpu`); when it has one, the labels must
/// match exactly (Issue #340).
/// PEP 440 exclusive ordered comparison `>V` (Issue #350).
///
/// Beyond plain ordering, PEP 440 requires that `>V` "MUST NOT allow a
/// post-release of the given version unless V itself is a post release" and
/// "MUST NOT match a local version of the specified version". Semantics
/// verified against pypa/packaging 26.2 (see
/// `tests/fixtures/pep440_specifiers_generated.tsv`): "post-release of V"
/// means the candidate's *post base* — epoch, release, and pre-release
/// segment — is exactly V, so `>1.0a1` still admits `1.0.post1` and
/// `1.0b1.post1`. Falls back to plain ordering when either side is outside
/// the PEP 440 grammar.
fn exclusive_greater_than(candidate: &str, spec: &str) -> bool {
    if compare_versions(candidate, spec) != Ordering::Greater {
        return false;
    }
    let (Some(cand), Some(spec)) = (Pep440Version::parse(candidate), Pep440Version::parse(spec))
    else {
        return true;
    };
    // `2.0.post1` does not satisfy `>2.0`, but `2.1.post1` / `1.0b1.post1`
    // vs `>1.0a1` do; any post-release satisfies `>2.0.post0`, and a spec
    // carrying dev/local segments is not a bare post base, so it excludes
    // nothing.
    if cand.post.is_some()
        && spec.post.is_none()
        && spec.dev.is_none()
        && !spec.has_local()
        && cand.pre == spec.pre
        && cand.base_cmp(&spec) == Ordering::Equal
    {
        return false;
    }
    // `2.0+local` does not satisfy `>2.0` (but `2.1+local` does, and a
    // spec that itself carries a local label excludes nothing).
    if cand.has_local() && !spec.has_local() && cand.public_cmp(&spec) == Ordering::Equal {
        return false;
    }
    true
}

/// PEP 440 exclusive ordered comparison `<V` (Issue #350).
///
/// Beyond plain ordering, PEP 440 requires that `<V` "MUST NOT allow a
/// pre-release of the specified version unless the specified version is
/// itself a pre-release". Semantics verified against pypa/packaging 26.2:
/// the excluded region is every pre-release at or above V's *earliest
/// pre-release* (V with a `.dev0` segment appended and local label
/// stripped) — so `2.0rc1` and `2.0.dev1` do not satisfy `<2.0`, while
/// `2.0a1` still satisfies `<2.0.post1` and `1.9rc1` satisfies `<2.0`.
/// Falls back to plain ordering when either side is outside the PEP 440
/// grammar.
fn exclusive_less_than(candidate: &str, spec: &str) -> bool {
    if compare_versions(candidate, spec) != Ordering::Less {
        return false;
    }
    let (Some(cand), Some(spec)) = (Pep440Version::parse(candidate), Pep440Version::parse(spec))
    else {
        return true;
    };
    // Final/post-release candidates below V are always fine, and a spec
    // that is itself a pre-release excludes nothing (`3.0.0a7` satisfies
    // `<3.0.0a8`).
    if !cand.is_prerelease() || spec.is_prerelease() {
        return true;
    }
    let mut earliest_prerelease = spec.clone();
    earliest_prerelease.dev = Some(0);
    earliest_prerelease.local = Vec::new();
    cand.cmp(&earliest_prerelease) == Ordering::Less
}

/// PEP 440 inclusive ordered comparison `>=V` (Issue #350): the candidate's
/// *public* version is compared, so local labels never affect the outcome.
/// Falls back to plain ordering outside the PEP 440 grammar.
fn inclusive_greater_equal(candidate: &str, spec: &str) -> bool {
    if let (Some(cand), Some(spec)) = (Pep440Version::parse(candidate), Pep440Version::parse(spec))
    {
        cand.public_cmp(&spec) != Ordering::Less
    } else {
        compare_versions(candidate, spec) != Ordering::Less
    }
}

/// PEP 440 inclusive ordered comparison `<=V` (Issue #350): the candidate's
/// *public* version is compared, so `<=2` matches `2.0+local`. Falls back
/// to plain ordering outside the PEP 440 grammar.
fn inclusive_less_equal(candidate: &str, spec: &str) -> bool {
    if let (Some(cand), Some(spec)) = (Pep440Version::parse(candidate), Pep440Version::parse(spec))
    {
        cand.public_cmp(&spec) != Ordering::Greater
    } else {
        compare_versions(candidate, spec) != Ordering::Greater
    }
}

fn versions_equal(candidate: &str, spec: &str) -> bool {
    if let (Some(cand), Some(spec)) = (Pep440Version::parse(candidate), Pep440Version::parse(spec))
    {
        if spec.has_local() {
            return cand == spec;
        }
        return cand.public_cmp(&spec) == Ordering::Equal;
    }
    versions_equal_relaxed(candidate, spec)
}

/// Legacy release-plus-suffix equality (Issue #339), kept as the fallback for
/// strings outside the PEP 440 grammar.
fn versions_equal_relaxed(a: &str, b: &str) -> bool {
    match (split_release_suffix(a), split_release_suffix(b)) {
        (Some((rel_a, suf_a)), Some((rel_b, suf_b))) => {
            let len = rel_a.len().max(rel_b.len());
            let seg = |rel: &[u64], i: usize| rel.get(i).copied().unwrap_or(0);
            (0..len).all(|i| seg(&rel_a, i) == seg(&rel_b, i)) && suf_a == suf_b
        }
        _ => a == b,
    }
}

/// Split a version string into its numeric release segments and a normalized
/// suffix (lowercased, with `-`/`_`/`.` separators stripped). Returns `None`
/// when the string does not start with a numeric release segment or a segment
/// is not a plain number, letting callers fall back to string comparison.
fn split_release_suffix(input: &str) -> Option<(Vec<u64>, String)> {
    let input = input.trim();
    let boundary = input
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii_digit() && *ch != '.')
        .map(|(idx, _)| idx)
        .unwrap_or(input.len());
    let (release, suffix) = input.split_at(boundary);
    let segments = release
        .split('.')
        .filter(|part| !part.is_empty())
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<u64>>>()?;
    if segments.is_empty() {
        return None;
    }
    let normalized_suffix: String = suffix
        .chars()
        .filter(|ch| !matches!(ch, '-' | '_' | '.'))
        .map(|ch| ch.to_ascii_lowercase())
        .collect();
    Some((segments, normalized_suffix))
}

/// Check if a version satisfies the compatible release constraint (~=).
fn is_compatible_release(version: &str, base: &str) -> bool {
    // First check if version meets the minimum
    if compare_versions(version, base) == Ordering::Less {
        return false;
    }

    let base_parts: Vec<&str> = base.split('.').collect();
    let version_parts: Vec<&str> = version.split('.').collect();

    if base_parts.len() >= 3 {
        // ~=X.Y.Z -> >=X.Y.Z, <X.(Y+1).0
        // Check major version matches
        if version_parts.first() != base_parts.first() {
            return false;
        }
        // Parse minor versions
        let base_minor: u64 = base_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let version_minor: u64 = version_parts
            .get(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        // Version minor must be <= base minor (same minor series)
        version_minor == base_minor
    } else if base_parts.len() == 2 {
        // ~=X.Y -> >=X.Y, <(X+1).0
        // Check major version matches
        version_parts.first() == base_parts.first()
    } else if base_parts.len() == 1 {
        // ~=X -> treated as >=X (unusual but valid)
        compare_versions(version, base) != Ordering::Less
    } else {
        false
    }
}
