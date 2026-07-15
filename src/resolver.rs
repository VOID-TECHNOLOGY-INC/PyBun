use crate::lockfile::PackageSource;
use futures::StreamExt;
use semver::Version;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

/// Maximum number of package-metadata fetches (`PackageIndex::all` /
/// `PackageIndex::get`) allowed to run concurrently while resolving a batch of
/// sibling dependencies. Bounds fan-out against the index/registry so a large
/// dependency frontier doesn't open unbounded concurrent HTTP connections.
/// See Issue #239 (Phase 1: parallel metadata fetching).
const MAX_CONCURRENT_METADATA_FETCHES: usize = 16;

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
            VersionSpec::Minimum(min) => compare_versions(version, min) != Ordering::Less,
            VersionSpec::MinimumExclusive(min) => {
                compare_versions(version, min) == Ordering::Greater
            }
            VersionSpec::MaximumInclusive(max) => {
                compare_versions(version, max) != Ordering::Greater
            }
            VersionSpec::Maximum(max) => compare_versions(version, max) == Ordering::Less,
            VersionSpec::NotEqual(v) => !versions_equal(version, v),
            VersionSpec::Compatible(base) => is_compatible_release(version, base),
            VersionSpec::Any => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub name: String,
    /// All version constraints that must hold simultaneously (e.g. `>=1.0,<2.0`
    /// becomes `[Minimum("1.0"), Maximum("2.0")]`). A bare requirement with no
    /// operator is represented as `[VersionSpec::Any]`.
    pub specs: Vec<VersionSpec>,
    pub marker: Option<String>,
    /// PEP 508 extras requested on this requirement (e.g. `typer[all]` yields
    /// `["all"]`). PyBun does not yet resolve or install the extra's
    /// dependencies (tracked as PR-A5 / Issue #285) — callers that surface
    /// diagnostics should warn when this is non-empty so the omission is not
    /// silent. See `docs/PLAN.md`.
    pub extras: Vec<String>,
}

impl Requirement {
    pub fn exact(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            specs: vec![VersionSpec::Exact(version.into())],
            marker: None,
            extras: Vec::new(),
        }
    }

    pub fn minimum(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            specs: vec![VersionSpec::Minimum(version.into())],
            marker: None,
            extras: Vec::new(),
        }
    }

    pub fn minimum_exclusive(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            specs: vec![VersionSpec::MinimumExclusive(version.into())],
            marker: None,
            extras: Vec::new(),
        }
    }

    pub fn maximum_inclusive(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            specs: vec![VersionSpec::MaximumInclusive(version.into())],
            marker: None,
            extras: Vec::new(),
        }
    }

    pub fn maximum(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            specs: vec![VersionSpec::Maximum(version.into())],
            marker: None,
            extras: Vec::new(),
        }
    }

    pub fn not_equal(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            specs: vec![VersionSpec::NotEqual(version.into())],
            marker: None,
            extras: Vec::new(),
        }
    }

    pub fn compatible(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            specs: vec![VersionSpec::Compatible(version.into())],
            marker: None,
            extras: Vec::new(),
        }
    }

    pub fn any(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            specs: vec![VersionSpec::Any],
            marker: None,
            extras: Vec::new(),
        }
    }

    fn constraint_display(&self) -> String {
        if self.specs.iter().all(|s| *s == VersionSpec::Any) {
            return "*".to_string();
        }
        self.specs
            .iter()
            .filter(|s| **s != VersionSpec::Any)
            .map(VersionSpec::operator_display)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Check whether `version` satisfies **all** constraints in this requirement.
    pub fn is_satisfied_by(&self, version: &str) -> bool {
        self.specs.iter().all(|spec| spec.matches(version))
    }

    /// Evaluate if the environment marker applies to the current platform.
    ///
    /// Returns `true` if no marker is present or if the marker matches the current environment.
    ///
    /// # Inclusive fallback
    ///
    /// When a marker expression cannot be evaluated (unknown variable, unsupported operator
    /// such as `in`/`not in`, or Python version detection failure), this method returns `true`
    /// so that packages are never silently dropped. Callers should treat `true` as "may apply"
    /// rather than "definitely applies" for unknown expressions.
    #[must_use]
    pub fn marker_applies(&self) -> bool {
        let Some(marker) = &self.marker else {
            // No marker means requirement always applies
            return true;
        };

        evaluate_marker(marker)
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.specs.iter().all(|s| *s == VersionSpec::Any) {
            write!(f, "{}", self.name)
        } else {
            write!(f, "{}{}", self.name, self.constraint_display())
        }
    }
}

/// Find the byte index where a version constraint operator begins, e.g. the
/// `>` in `"requests>=2.0"`. Returns `None` if no operator is present.
fn find_constraint_start(s: &str) -> Option<usize> {
    const OPERATORS: [&str; 7] = ["~=", "==", "!=", ">=", "<=", ">", "<"];
    OPERATORS.iter().filter_map(|op| s.find(op)).min()
}

/// Strip a PEP 508 extras suffix (e.g. `typer[all]` or `typer[all,test]`) from
/// `s`, returning the requirement text with the bracketed segment removed and
/// the list of requested extras (trimmed, empty entries dropped).
///
/// Extras are not resolved by PyBun today (see `Requirement::extras` docs) —
/// this only prevents the extras syntax from corrupting the package name
/// (e.g. leaking into the PyPI metadata URL), it does not resolve them.
fn extract_extras(s: &str) -> (String, Vec<String>) {
    let Some(start) = s.find('[') else {
        return (s.to_string(), Vec::new());
    };
    let Some(end_rel) = s[start..].find(']') else {
        // Unterminated bracket — leave the string untouched and let downstream
        // parsing surface a clear error rather than guessing.
        return (s.to_string(), Vec::new());
    };
    let end = start + end_rel;
    let extras: Vec<String> = s[start + 1..end]
        .split(',')
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect();

    let mut rebuilt = String::with_capacity(s.len());
    rebuilt.push_str(&s[..start]);
    rebuilt.push_str(&s[end + 1..]);
    (rebuilt, extras)
}

/// Parse a single comma-separated version specifier such as `>=1.0` or `!=1.4.*`.
fn parse_version_spec(s: &str) -> Result<VersionSpec, String> {
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

impl FromStr for Requirement {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim();
        if normalized.is_empty() {
            return Err("requirement cannot be empty".into());
        }

        // Split by ';' to separate requirement from marker (PEP 508)
        let (requirement_part, marker_part) = if let Some(idx) = normalized.find(';') {
            let (req, marker) = normalized.split_at(idx);
            (req.trim(), Some(marker[1..].trim().to_string()))
        } else {
            (normalized, None)
        };

        // Extract PEP 508 extras (e.g. `typer[all]`) before parsing the name
        // and version constraints, so the brackets don't leak into `name`
        // (which would otherwise corrupt PyPI metadata lookups). Extras are
        // recorded but not resolved — see `Requirement::extras`.
        let (requirement_part, extras) = extract_extras(requirement_part);
        let requirement_part = requirement_part.as_str();

        // Split into package name and the (possibly compound, comma-separated)
        // constraint string, handling both "package (>=1.0,<2.0)" and
        // "package>=1.0,<2.0" forms.
        let (name, constraint_str) = if let Some(idx) = requirement_part.find('(') {
            let name = requirement_part[..idx].trim();
            let version_with_parens = requirement_part[idx..].trim();
            let constraints = version_with_parens
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim();
            (name, constraints)
        } else {
            match find_constraint_start(requirement_part) {
                Some(idx) => (
                    requirement_part[..idx].trim(),
                    requirement_part[idx..].trim(),
                ),
                None => (requirement_part, ""),
            }
        };

        let specs = if constraint_str.is_empty() {
            vec![VersionSpec::Any]
        } else {
            constraint_str
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(parse_version_spec)
                .collect::<Result<Vec<_>, _>>()?
        };
        let specs = if specs.is_empty() {
            vec![VersionSpec::Any]
        } else {
            specs
        };

        Ok(Requirement {
            name: name.to_string(),
            specs,
            marker: marker_part,
            extras,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub dependencies: Vec<Requirement>,
    pub source: Option<PackageSource>,
    pub artifacts: PackageArtifacts,
    /// PEP 440 specifier from the package's `requires-python` metadata
    /// (PyPI `requires_python` / index fixture `requires_python`). `None`
    /// means the package declares no interpreter constraint (Issue #342).
    pub requires_python: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackageArtifacts {
    pub wheels: Vec<Wheel>,
    pub sdist: Option<String>,
}

impl PackageArtifacts {
    pub fn universal(name: &str, version: &str) -> Self {
        Self {
            wheels: vec![Wheel {
                file: format!("{name}-{version}-py3-none-any.whl"),
                url: None,
                hash: None,
                platforms: vec!["any".into()],
                python_tag: Some("py3".into()),
                abi_tag: Some("none".into()),
            }],
            sdist: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wheel {
    pub file: String,
    pub url: Option<String>,
    pub hash: Option<String>,
    pub platforms: Vec<String>,
    /// Python interpreter tag from the wheel filename (e.g., "cp311", "py3", "cp37").
    /// None means the tag could not be parsed; treated as compatible with all Python versions.
    pub python_tag: Option<String>,
    /// ABI tag from the wheel filename (e.g., "cp311", "abi3", "none").
    /// None means the tag could not be parsed.
    pub abi_tag: Option<String>,
}

/// Parse Python interpreter tag and ABI tag from a wheel filename.
///
/// Wheel filename format: `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`
/// The last three dash-separated components before `.whl` are always platform, abi, python
/// (reading right-to-left), regardless of how many dashes appear in the package name.
///
/// Returns `(None, None)` for filenames that cannot be parsed, including malformed names
/// or filenames with fewer than five dash-separated components.
pub fn parse_wheel_tags(filename: &str) -> (Option<String>, Option<String>) {
    let stem = filename
        .trim_end_matches(".whl")
        .rsplit('/')
        .next()
        .unwrap_or(filename);
    let parts: Vec<&str> = stem.split('-').collect();
    if parts.len() >= 5 {
        let python_tag = parts[parts.len() - 3];
        let abi_tag = parts[parts.len() - 2];
        // Reject empty tags produced by double-dash sequences in malformed filenames
        if python_tag.is_empty() || abi_tag.is_empty() {
            return (None, None);
        }
        (Some(python_tag.to_string()), Some(abi_tag.to_string()))
    } else {
        (None, None)
    }
}

/// Convert a Python version string (e.g., "3.11.5" or "3.11") to a CPython wheel tag
/// (e.g., "cp311"). Returns None if the version string cannot be parsed.
pub fn python_version_to_cp_tag(version: &str) -> Option<String> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() >= 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
            Some(format!("cp{}{}", major, minor))
        } else {
            None
        }
    } else {
        None
    }
}

/// Convert a CPython wheel tag (e.g., `"cp310"`) back to a dotted `MAJOR.MINOR`
/// version string (e.g., `"3.10"`). Returns `None` for non-CPython tags
/// (e.g., `"py3"`, `"abi3"`) or tags that don't fit the `cp{major}{minor}` shape.
///
/// The major version is always exactly one digit, mirroring [`cp_tag_ge`].
pub fn cp_tag_to_dotted_version(tag: &str) -> Option<String> {
    let digits = tag.strip_prefix("cp")?;
    if digits.len() < 2 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let (major, minor) = digits.split_at(1);
    Some(format!("{major}.{minor}"))
}

/// Compare two CPython tags version-wise: returns true if `a` >= `b`.
///
/// Tags use the format `cp{major}{minor}` (e.g., `cp311`, `cp37`, `cp312`).
/// The major version is always exactly one digit; the minor is the remaining digits.
/// This handles all current CPython versions (3.x through 3.19) and remains correct
/// for hypothetical future versions (Python 4.x, Python 10.x with 4-digit tags).
fn cp_tag_ge(a: &str, b: &str) -> bool {
    fn parse(s: &str) -> Option<(u32, u32)> {
        let digits = s.strip_prefix("cp")?;
        if digits.is_empty() {
            return None;
        }
        // Major is always 1 digit; minor is everything after the first digit.
        let (major_str, minor_str) = digits.split_at(1);
        Some((major_str.parse().ok()?, minor_str.parse().ok()?))
    }
    match (parse(a), parse(b)) {
        (Some((a_maj, a_min)), Some((b_maj, b_min))) => (a_maj, a_min) >= (b_maj, b_min),
        _ => false,
    }
}

/// Check whether a wheel is compatible with the given active CPython tag (e.g., `"cp311"`).
///
/// Compatibility rules (PEP 425):
/// - `py2`, `py3`, or `py2.py3` python tags: compatible with any Python 3.
/// - Wheels with `abi3` ABI tag: stable ABI, compatible with any CPython >= the version
///   encoded in the python tag. The python tag may be a compressed set (e.g., `cp37.cp38`);
///   the minimum version is taken as the oldest component.
/// - CPython-specific wheels (e.g., `cp311` or compressed `cp310.cp311`): compatible if
///   the active CPython tag matches any component in the set.
/// - `None` python tag (unparseable filename): treated as compatible to avoid breaking
///   older index formats. **Known limitation**: an unparseable tag scores the same as
///   an `abi3` wheel, which may allow a malformed wheel to supersede a pure-Python one.
pub fn is_wheel_python_compatible(
    python_tag: Option<&str>,
    abi_tag: Option<&str>,
    active_cp_tag: &str,
) -> bool {
    let Some(ptag) = python_tag else {
        return true; // unknown → assume compatible (legacy index compat)
    };

    // Compressed tags: split on '.' and check each component.
    // e.g., "cp310.cp311" matches if active_cp_tag is either "cp310" or "cp311".
    // e.g., "py3" or "py2.py3" — any component starting with "py" is pure-Python.
    let components: Vec<&str> = ptag.split('.').collect();

    // Pure-Python: any component starts with "py"
    if components.iter().any(|c| c.starts_with("py")) {
        return true;
    }

    // Stable ABI (abi3): compatible if active CPython >= the *oldest* version in the set
    if abi_tag == Some("abi3") {
        return components.iter().all(|c| c.starts_with("cp"))
            && components.iter().any(|c| cp_tag_ge(active_cp_tag, c));
    }

    // CPython-specific: compatible if active_cp_tag matches any component
    components.contains(&active_cp_tag)
}

/// Return the CPython tag for the active Python interpreter, e.g. `"cp311"`.
///
/// Detection order:
/// 1. `PYBUN_FORCE_CP_TAG` environment variable — overrides detection entirely (for testing).
/// 2. The output of `python3 --version` / `python --version` on PATH.
/// 3. Fallback: `"cp311"` (most common deployment target).
///
/// The result is cached in a `OnceLock` so detection runs at most once per process.
fn active_python_cp_tag() -> &'static str {
    static CP_TAG: OnceLock<String> = OnceLock::new();
    CP_TAG.get_or_init(|| {
        // Allow tests (and users) to pin the CPython tag without changing the Python on PATH.
        if let Ok(forced) = std::env::var("PYBUN_FORCE_CP_TAG") {
            let trimmed = forced.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        python_version_to_cp_tag(get_python_version()).unwrap_or_else(|| "cp311".to_string())
    })
}

/// Select the best artifact for a given Python version — exposed for testing.
///
/// This is the canonical selection logic; [`select_artifact_for_platform`] is a
/// thin wrapper that supplies the auto-detected CP tag.
pub fn select_artifact_for_platform_with_cp(
    pkg: &ResolvedPackage,
    platform_tags: &[String],
    active_cp_tag: &str,
) -> ArtifactSelection {
    let mut tags = platform_tags.to_vec();
    if !tags.iter().any(|t| t == "any") {
        tags.push("any".into());
    }

    if !pkg.artifacts.wheels.is_empty() {
        let mut scored_wheels: Vec<_> = pkg
            .artifacts
            .wheels
            .iter()
            .filter_map(|w| {
                let matches_platform = w.platforms.is_empty()
                    || tags.iter().any(|t| w.platforms.iter().any(|p| p == t));
                let matches_python = is_wheel_python_compatible(
                    w.python_tag.as_deref(),
                    w.abi_tag.as_deref(),
                    active_cp_tag,
                );
                if matches_platform && matches_python {
                    Some((rank_wheel(w, &tags, active_cp_tag), w))
                } else {
                    None
                }
            })
            .collect();

        scored_wheels.sort_by_key(|w| std::cmp::Reverse(w.0));

        if let Some((_, wheel)) = scored_wheels.first() {
            let matched_platform = if wheel.platforms.is_empty() {
                None
            } else {
                tags.iter()
                    .find(|t| wheel.platforms.iter().any(|p| p == *t))
                    .cloned()
            };
            return ArtifactSelection {
                filename: wheel.file.clone(),
                url: wheel.url.clone(),
                hash: wheel.hash.clone(),
                matched_platform,
                from_source: false,
                available_wheels: pkg.artifacts.wheels.len(),
            };
        }
    }

    // Fallback: sdist
    ArtifactSelection {
        filename: pkg
            .artifacts
            .sdist
            .clone()
            .unwrap_or_else(|| format!("{}-{}.tar.gz", pkg.name, pkg.version)),
        url: None,
        hash: None,
        matched_platform: None,
        from_source: true,
        available_wheels: pkg.artifacts.wheels.len(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub packages: BTreeMap<String, ResolvedPackage>,
    /// Packages that resolved to a pre-release version via the fallback path
    /// (only pre-releases satisfied the constraints) without an explicit
    /// opt-in. Callers surface these as `W_PRERELEASE_SELECTED` warnings
    /// (Issue #341).
    pub prerelease_fallbacks: Vec<PrereleaseFallback>,
}

/// A package that resolved to a pre-release version only because no stable
/// version satisfied the constraints (Issue #341).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrereleaseFallback {
    pub name: String,
    pub version: String,
}

/// Options controlling dependency resolution behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolveOptions {
    /// Allow pre-release/dev versions to be selected for every package
    /// (CLI `--pre` / MCP `pre`). Defaults to `false`, matching the PEP 440
    /// rule that pre-releases are excluded unless opted in (Issue #341).
    pub allow_prerelease: bool,
    /// Python version of the resolution target interpreter (e.g. `3.9.18`).
    /// When set, candidates whose `requires-python` specifier does not match
    /// are skipped during selection; `None` disables the filter (Issue #342).
    pub python_version: Option<String>,
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
/// This is a deliberately small scanner; the full PEP 440 version type is
/// tracked separately in Issue #340.
pub fn is_prerelease(version: &str) -> bool {
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

/// The version literal a [`VersionSpec`] compares against, if any.
fn spec_version(spec: &VersionSpec) -> Option<&str> {
    match spec {
        VersionSpec::Exact(v)
        | VersionSpec::Minimum(v)
        | VersionSpec::MinimumExclusive(v)
        | VersionSpec::MaximumInclusive(v)
        | VersionSpec::Maximum(v)
        | VersionSpec::NotEqual(v)
        | VersionSpec::Compatible(v) => Some(v),
        VersionSpec::Any => None,
    }
}

/// PEP 440: a specifier that itself mentions a pre-release version opts the
/// package into pre-release candidates (e.g. `pkg>=2.0rc1`).
fn constraints_mention_prerelease(reqs: &[Requirement]) -> bool {
    reqs.iter().any(|r| {
        r.specs
            .iter()
            .any(|s| spec_version(s).is_some_and(is_prerelease))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSelection {
    pub filename: String,
    pub url: Option<String>,
    pub hash: Option<String>,
    pub matched_platform: Option<String>,
    pub from_source: bool,
    pub available_wheels: usize,
}

/// Determine platform preference list for wheel selection.
pub fn current_platform_tags() -> Vec<String> {
    let mut tags = crate::runtime::current_wheel_tags();
    if !tags.iter().any(|t| t == "any") {
        tags.push("any".into());
    }
    tags
}

/// Rank a wheel for selection priority.
/// Higher score = better preference.
/// Prefers: native platform + exact Python version > abi3 > pure-Python > any-platform.
fn rank_wheel(wheel: &Wheel, platform_tags: &[String], active_cp_tag: &str) -> u32 {
    let mut score: u32 = 100; // base score for being a wheel (vs sdist)

    // Platform scoring
    if wheel.platforms.is_empty() {
        score += 10; // universal wheel
    } else {
        for (priority, tag) in platform_tags.iter().enumerate() {
            if wheel.platforms.iter().any(|p| p == tag) {
                score += 50 - (priority as u32).min(40);
                break;
            }
        }
    }

    // Python version scoring
    match (wheel.python_tag.as_deref(), wheel.abi_tag.as_deref()) {
        (Some(ptag), _) if ptag == active_cp_tag => score += 30, // exact match
        (_, Some("abi3")) => score += 15,                        // stable ABI
        (Some(ptag), _) if ptag.starts_with("py") => score += 10, // pure Python
        (None, _) => score += 15, // unknown tag — treat like abi3 for legacy-index compat
        // Non-CPython interpreters (e.g., PyPy "pp311") that passed compatibility
        // checking have no specific bonus; they rank below abi3 and pure-Python.
        _ => {}
    }

    if wheel.platforms.len() <= 1 {
        score += 5;
    }

    score
}

/// Select the best artifact for the current platform.
///
/// Delegates to [`select_artifact_for_platform_with_cp`] using the auto-detected
/// CPython tag of the active Python interpreter.
pub fn select_artifact_for_platform(
    pkg: &ResolvedPackage,
    platform_tags: &[String],
) -> ArtifactSelection {
    select_artifact_for_platform_with_cp(pkg, platform_tags, active_python_cp_tag())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error("package {name} with constraint {constraint} not found")]
    Missing {
        name: String,
        constraint: String,
        #[allow(dead_code)]
        requested_by: Option<String>,
        #[allow(dead_code)]
        available_versions: Vec<String>,
    },
    #[error("version conflict for {name}: existing {existing} vs requested {requested}")]
    Conflict {
        name: String,
        existing: String,
        requested: String,
        #[allow(dead_code)]
        existing_chain: Vec<String>,
        #[allow(dead_code)]
        requested_chain: Vec<String>,
    },
    #[error("io error: {0}")]
    Io(String),
    #[error(
        "no version of {} matching {} supports Python {} (newest matching release {} requires Python {})",
        .0.name, .0.constraint, .0.python_version, .0.rejected_version, .0.rejected_requires_python
    )]
    PythonIncompatible(Box<PythonIncompatibility>),
}

/// Details of a `requires-python` resolution failure (Issue #342). Boxed in
/// [`ResolveError::PythonIncompatible`] to keep the error type small.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonIncompatibility {
    pub name: String,
    pub constraint: String,
    /// The resolution target interpreter version the candidates were
    /// checked against.
    pub python_version: String,
    pub requested_by: Option<String>,
    /// Highest version that satisfied the version constraints but was
    /// rejected by its `requires-python` specifier.
    pub rejected_version: String,
    pub rejected_requires_python: String,
    /// Newest release (ignoring the version constraints) that does support
    /// the target Python, for the diagnostic hint.
    pub newest_compatible: Option<String>,
}

pub trait PackageIndex {
    fn get(
        &self,
        name: &str,
        version: &str,
    ) -> impl std::future::Future<Output = Result<Option<ResolvedPackage>, ResolveError>> + Send;
    fn all(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Vec<ResolvedPackage>, ResolveError>> + Send;
}

/// Deterministic resolver that works with exact-version or minimum requirements in parallel.
///
/// Pre-release/dev versions are excluded by default per PEP 440; use
/// [`resolve_with_options`] with [`ResolveOptions::allow_prerelease`] to opt
/// in (Issue #341).
pub async fn resolve(
    requirements: Vec<Requirement>,
    index: &impl PackageIndex,
) -> Result<Resolution, ResolveError> {
    resolve_with_options(requirements, index, ResolveOptions::default()).await
}

/// [`resolve`] with explicit [`ResolveOptions`].
pub async fn resolve_with_options(
    requirements: Vec<Requirement>,
    index: &impl PackageIndex,
    options: ResolveOptions,
) -> Result<Resolution, ResolveError> {
    let mut resolved: BTreeMap<String, ResolvedPackage> = BTreeMap::new();
    let mut constraints: BTreeMap<String, Vec<Requirement>> = BTreeMap::new();

    // Requirements to process: (Requirement, RequestedBy)
    // Filter out top-level requirements whose environment markers don't apply.
    let mut pending: Vec<(Requirement, Option<String>)> = requirements
        .into_iter()
        .filter(|r| r.marker_applies())
        .map(|r| (r, None))
        .collect();

    // Track parent relationships for conflict error messages
    let mut parents: BTreeMap<String, Option<String>> = BTreeMap::new();
    // Cache available versions to avoid fetching same package multiple times in one run
    // (Though the Index implementation might also cache)
    let mut version_cache: BTreeMap<String, Vec<ResolvedPackage>> = BTreeMap::new();

    while !pending.is_empty() {
        let current_batch = std::mem::take(&mut pending);
        let mut next_batch = Vec::new();

        // 1. Identify unique package names we need to fetch info for (that we don't have yet)
        let mut names_to_fetch = Vec::new();
        for (req, _) in &current_batch {
            // If already resolved, we might skip fetching if we don't need to re-verify
            // But we should check if the existing resolution satisfies the new req
            if resolved.contains_key(&req.name) {
                continue;
            }
            if !version_cache.contains_key(&req.name) {
                names_to_fetch.push(req.name.clone());
            }
        }
        names_to_fetch.sort();
        names_to_fetch.dedup();

        // 2. Fetch version-list metadata for sibling packages in parallel, bounded to
        // MAX_CONCURRENT_METADATA_FETCHES concurrent requests (Issue #239 Phase 1).
        //
        // Fail-fast note: `buffer_unordered` still runs up to
        // MAX_CONCURRENT_METADATA_FETCHES fetches concurrently, but we drive the
        // stream with a manual `while let` loop instead of collecting the whole
        // batch first. This returns to the caller as soon as the first error is
        // observed (whichever fetch happens to complete first — not necessarily
        // submission order) instead of waiting for every in-flight fetch to
        // finish. Futures already queued but not yet polled are dropped (and
        // therefore cancelled) when we return early.
        if !names_to_fetch.is_empty() {
            let mut stream =
                futures::stream::iter(names_to_fetch.into_iter().map(|name| async move {
                    let pkgs = index.all(&name).await?;
                    Ok::<(String, Vec<ResolvedPackage>), ResolveError>((name, pkgs))
                }))
                .buffer_unordered(MAX_CONCURRENT_METADATA_FETCHES);

            while let Some(result) = stream.next().await {
                let (name, pkgs) = result?;
                version_cache.insert(name, pkgs);
            }
        }

        // 3a. Synchronous version-selection pass: decide, for every requirement in
        // this batch, which package version should be selected. This must stay
        // sequential because constraint accumulation (`constraints`) and
        // conflict detection depend on processing order — but it performs no
        // I/O, so it's fast.
        //
        // `fetch_events` records one entry per *selection event* in strict
        // processing order (not deduped by package name). This matters for
        // diamond dependencies: if two requirements in the same batch target the
        // same newly-seen package with different constraints (e.g. `c<3.0.0` and
        // `c<1.6.0`), the original serial resolver would select+fetch the first
        // candidate (`c==2.0.0`), queue *its* dependencies, and only then
        // reconcile to the second, narrower candidate (`c==1.5.0`) and queue
        // *its* dependencies too — leaving both sets of dependencies in
        // `next_batch` even though only the reconciled version ends up in
        // `resolved`. Deduping by name (as an earlier version of this function
        // did) silently drops the first candidate's dependencies, changing the
        // resolved package set. Keeping a ordered Vec of events and replaying
        // them in order after the concurrent fetch reproduces that exact
        // behavior while still fetching metadata concurrently.
        enum FetchKind {
            /// Newly selected package — dependencies are filtered by marker on push.
            New,
            /// Re-selected to satisfy an additional constraint within this batch —
            /// dependencies are pushed unfiltered, matching prior behavior.
            Reconcile,
        }
        struct FetchEvent {
            name: String,
            candidate: ResolvedPackage,
            requested_by: Option<String>,
            kind: FetchKind,
        }
        // Tracks the latest selection per package name within this batch, purely
        // for constraint-satisfaction lookups by subsequent requirements in the
        // same batch (mirrors what `resolved` would contain in the serial
        // implementation at each point in the loop).
        let mut batch_resolved: BTreeMap<String, ResolvedPackage> = BTreeMap::new();
        let mut fetch_events: Vec<FetchEvent> = Vec::new();

        for (req, requested_by) in &current_batch {
            constraints
                .entry(req.name.clone())
                .or_default()
                .push(req.clone());

            let existing = batch_resolved
                .get(&req.name)
                .or_else(|| resolved.get(&req.name));

            if let Some(existing) = existing {
                if req.is_satisfied_by(&existing.version) {
                    continue;
                }
                // Try to select a version that satisfies all constraints seen so far
                let candidates = version_cache.get(&req.name).cloned().unwrap_or_default();
                match select_with_constraints(
                    &constraints,
                    &req.name,
                    &candidates,
                    requested_by.as_deref(),
                    options.allow_prerelease,
                    options.python_version.as_deref(),
                ) {
                    Ok(pkg) => {
                        batch_resolved.insert(req.name.clone(), pkg.clone());
                        fetch_events.push(FetchEvent {
                            name: req.name.clone(),
                            candidate: pkg,
                            requested_by: requested_by.clone(),
                            kind: FetchKind::Reconcile,
                        });
                    }
                    // Keep the interpreter-conflict detail instead of
                    // degrading it to a generic version conflict (Issue #342).
                    Err(err @ ResolveError::PythonIncompatible(_)) => return Err(err),
                    Err(_) => {
                        let existing_chain = build_chain(&parents, &req.name);
                        let requested_chain =
                            build_requested_chain(&parents, &req.name, requested_by.clone());
                        return Err(ResolveError::Conflict {
                            name: req.name.clone(),
                            existing: existing.version.clone(),
                            requested: req.constraint_display(),
                            existing_chain,
                            requested_chain,
                        });
                    }
                }
                continue;
            }

            // Select best version
            let candidates = version_cache
                .get(&req.name)
                .ok_or_else(|| ResolveError::Missing {
                    name: req.name.clone(),
                    constraint: req.constraint_display(),
                    requested_by: requested_by.clone(),
                    available_versions: vec![],
                })?;

            let pkg = select_with_constraints(
                &constraints,
                &req.name,
                candidates,
                requested_by.as_deref(),
                options.allow_prerelease,
                options.python_version.as_deref(),
            )?;

            batch_resolved.insert(req.name.clone(), pkg.clone());
            fetch_events.push(FetchEvent {
                name: req.name.clone(),
                candidate: pkg,
                requested_by: requested_by.clone(),
                kind: FetchKind::New,
            });
        }

        // 3b. Fetch full metadata (dependencies) for every selection event in this
        // batch concurrently instead of one at a time — this is the network-bound
        // step that dominated resolve time (Issue #239 Phase 1). Events are keyed
        // by their position in `fetch_events`, not by package name, so a package
        // selected twice in one batch (diamond reconciliation) gets fetched twice
        // — matching the serial implementation, which called `index.get` once per
        // selection, not once per package name.
        //
        // Fail-fast note: see the comment on the version-list fetch above — this
        // uses the same manual `while let` drive-to-first-error pattern instead of
        // collecting the whole batch, so a bad fetch short-circuits the return
        // instead of being masked by whichever error happens to finish last.
        let mut fetched: Vec<Option<ResolvedPackage>> = vec![None; fetch_events.len()];
        if !fetch_events.is_empty() {
            let mut stream =
                futures::stream::iter(fetch_events.iter().enumerate().map(|(idx, event)| {
                    let name = event.candidate.name.clone();
                    let version = event.candidate.version.clone();
                    async move {
                        let result = index.get(&name, &version).await;
                        (idx, result)
                    }
                }))
                .buffer_unordered(MAX_CONCURRENT_METADATA_FETCHES);

            while let Some((idx, result)) = stream.next().await {
                fetched[idx] = result?;
            }
        }

        // 3c. Commit selections in original processing order: insert into
        // `resolved`, enqueue dependencies for the next frontier, and record
        // parent chains for diagnostics. Replaying strictly in `fetch_events`
        // order (rather than deduped by name) preserves the diamond-dependency
        // semantics described above — later events for the same name overwrite
        // `resolved`/`parents`, but earlier events' dependencies still get
        // queued.
        for (idx, event) in fetch_events.into_iter().enumerate() {
            let pkg = fetched[idx].take().unwrap_or(event.candidate);

            match event.kind {
                FetchKind::New => {
                    // Filter by environment markers at resolve time so the index
                    // retains the full dependency list for potential reuse.
                    for dep in pkg.dependencies.iter().filter(|d| d.marker_applies()) {
                        next_batch.push((dep.clone(), Some(pkg.name.clone())));
                    }
                }
                FetchKind::Reconcile => {
                    for dep in &pkg.dependencies {
                        next_batch.push((dep.clone(), Some(pkg.name.clone())));
                    }
                }
            }

            resolved.insert(event.name.clone(), pkg);
            parents.insert(event.name, event.requested_by);
        }

        pending = next_batch;
    }

    // Report packages that ended up on a pre-release version without an
    // explicit opt-in (neither `--pre` nor a specifier mentioning a
    // pre-release): these were selected via the only-pre-releases-satisfy
    // fallback and callers surface them as `W_PRERELEASE_SELECTED`
    // (Issue #341).
    let prerelease_fallbacks = if options.allow_prerelease {
        Vec::new()
    } else {
        resolved
            .iter()
            .filter(|(name, pkg)| {
                is_prerelease(&pkg.version)
                    && !constraints
                        .get(name.as_str())
                        .is_some_and(|reqs| constraints_mention_prerelease(reqs))
            })
            .map(|(name, pkg)| PrereleaseFallback {
                name: name.clone(),
                version: pkg.version.clone(),
            })
            .collect()
    };

    Ok(Resolution {
        packages: resolved,
        prerelease_fallbacks,
    })
}

fn select_with_constraints(
    reqs: &BTreeMap<String, Vec<Requirement>>,
    name: &str,
    candidates: &[ResolvedPackage],
    requested_by: Option<&str>,
    allow_prerelease: bool,
    python_version: Option<&str>,
) -> Result<ResolvedPackage, ResolveError> {
    let constraints = reqs.get(name).cloned().unwrap_or_default();
    let matching: Vec<&ResolvedPackage> = candidates
        .iter()
        .filter(|pkg| constraints.iter().all(|r| r.is_satisfied_by(&pkg.version)))
        .collect();

    // Drop candidates whose `requires-python` metadata excludes the
    // resolution target interpreter (Issue #342). Packages without the
    // metadata are always kept.
    let python_compatible = |pkg: &ResolvedPackage| {
        python_version.is_none_or(|py| {
            pkg.requires_python
                .as_deref()
                .is_none_or(|spec| requires_python_allows(spec, py))
        })
    };
    let satisfying: Vec<&ResolvedPackage> = matching
        .iter()
        .copied()
        .filter(|pkg| python_compatible(pkg))
        .collect();

    // PEP 440: pre-release/dev versions are excluded by default. They are
    // considered when the caller opted in (`--pre`), when a specifier for
    // this package itself mentions a pre-release version, or as a fallback
    // when only pre-releases satisfy the constraints (Issue #341).
    let prereleases_allowed = allow_prerelease || constraints_mention_prerelease(&constraints);
    let candidate = if prereleases_allowed {
        satisfying
            .iter()
            .max_by(|a, b| version_cmp(&a.version, &b.version))
    } else {
        satisfying
            .iter()
            .filter(|pkg| !is_prerelease(&pkg.version))
            .max_by(|a, b| version_cmp(&a.version, &b.version))
            .or_else(|| {
                // Fallback: only pre-releases satisfy the constraints.
                satisfying
                    .iter()
                    .max_by(|a, b| version_cmp(&a.version, &b.version))
            })
    }
    .copied();

    if let Some(pkg) = candidate {
        return Ok(pkg.clone());
    }

    let constraint_display = if constraints.is_empty() {
        "*".to_string()
    } else {
        constraints
            .iter()
            .map(|r| r.constraint_display())
            .collect::<Vec<_>>()
            .join(" & ")
    };

    // Versions matched the constraints but every one of them was rejected
    // by `requires-python`: report the interpreter conflict, not a generic
    // "missing" error (Issue #342).
    if let (Some(py), Some(rejected)) = (
        python_version,
        matching
            .iter()
            .max_by(|a, b| version_cmp(&a.version, &b.version)),
    ) {
        let newest_compatible = candidates
            .iter()
            .filter(|pkg| python_compatible(pkg))
            .max_by(|a, b| version_cmp(&a.version, &b.version))
            .map(|pkg| pkg.version.clone());
        return Err(ResolveError::PythonIncompatible(Box::new(
            PythonIncompatibility {
                name: name.to_string(),
                constraint: constraint_display,
                python_version: py.to_string(),
                requested_by: requested_by.map(ToString::to_string),
                rejected_version: rejected.version.clone(),
                rejected_requires_python: rejected
                    .requires_python
                    .clone()
                    .unwrap_or_else(|| "*".to_string()),
                newest_compatible,
            },
        )));
    }

    Err(ResolveError::Missing {
        name: name.to_string(),
        constraint: constraint_display,
        requested_by: requested_by.map(ToString::to_string),
        available_versions: candidates.iter().map(|p| p.version.clone()).collect(),
    })
}

#[derive(Default)]
pub struct InMemoryIndex {
    pkgs: BTreeMap<(String, String), ResolvedPackage>,
}

impl InMemoryIndex {
    pub fn add(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        deps: impl IntoIterator<Item = impl AsRef<str>>,
    ) {
        let name = name.into();
        let version = version.into();
        let artifacts = PackageArtifacts::universal(&name, &version);
        self.add_with_artifacts(name, version, deps, artifacts);
    }

    pub fn add_with_requires_python(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        deps: impl IntoIterator<Item = impl AsRef<str>>,
        requires_python: Option<&str>,
    ) {
        let name = name.into();
        let version = version.into();
        let artifacts = PackageArtifacts::universal(&name, &version);
        self.add_entry(name, version, deps, artifacts, requires_python);
    }

    pub fn add_with_artifacts(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        deps: impl IntoIterator<Item = impl AsRef<str>>,
        artifacts: PackageArtifacts,
    ) {
        self.add_entry(name, version, deps, artifacts, None);
    }

    pub fn add_entry(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        deps: impl IntoIterator<Item = impl AsRef<str>>,
        artifacts: PackageArtifacts,
        requires_python: Option<&str>,
    ) {
        let name = name.into();
        let version = version.into();
        let deps = deps
            .into_iter()
            .map(|d| parse_req(d.as_ref()))
            .collect::<Vec<_>>();
        let pkg = ResolvedPackage {
            name: name.clone(),
            version: version.clone(),
            dependencies: deps,
            source: None,
            artifacts,
            requires_python: requires_python.map(ToString::to_string),
        };
        self.pkgs.insert((name, version), pkg);
    }
}

impl PackageIndex for InMemoryIndex {
    fn get(
        &self,
        name: &str,
        version: &str,
    ) -> impl std::future::Future<Output = Result<Option<ResolvedPackage>, ResolveError>> + Send
    {
        let result = self
            .pkgs
            .get(&(name.to_string(), version.to_string()))
            .cloned();
        async move { Ok(result) }
    }

    fn all(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Vec<ResolvedPackage>, ResolveError>> + Send {
        let result = self
            .pkgs
            .iter()
            .filter(|((n, _), _)| n == name)
            .map(|(_, pkg)| pkg.clone())
            .collect::<Vec<_>>();
        async move { Ok(result) }
    }
}

fn parse_req(input: &str) -> Requirement {
    Requirement::from_str(input).unwrap_or_else(|_| Requirement::any(input.trim()))
}

fn version_cmp(a: &str, b: &str) -> Ordering {
    compare_versions(a, b)
}

fn build_chain(parents: &BTreeMap<String, Option<String>>, start: &str) -> Vec<String> {
    let mut chain: Vec<String> = Vec::new();
    let mut current: Option<String> = Some(start.to_string());
    while let Some(name) = current {
        chain.push(name.clone());
        current = parents.get(&name).cloned().flatten();
    }
    chain.reverse();
    chain
}

fn build_requested_chain(
    parents: &BTreeMap<String, Option<String>>,
    package: &str,
    requested_by: Option<String>,
) -> Vec<String> {
    match requested_by {
        Some(parent) => {
            let mut chain = build_chain(parents, &parent);
            chain.push(package.to_string());
            chain
        }
        None => vec![package.to_string()],
    }
}

/// Compare two version strings, returning their ordering.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
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
/// version. Ordering semantics are deliberately untouched (PEP 440 ordering is
/// tracked separately in Issue #340).
fn versions_equal(a: &str, b: &str) -> bool {
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

/// A single token in a tokenized PEP 508 environment marker expression.
#[derive(Debug, Clone, PartialEq)]
enum MarkerToken {
    LParen,
    RParen,
    And,
    Or,
    Op(&'static str),
    Var(String),
    Str(String),
}

/// Tokenize a PEP 508 marker expression. Returns `None` if the input contains
/// syntax this tokenizer doesn't understand (unterminated strings, stray
/// operators, a bare `not` not followed by `in`, etc.) so the caller can fall
/// back to the inclusive default.
fn tokenize_marker(input: &str) -> Option<Vec<MarkerToken>> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        match c {
            '(' => {
                tokens.push(MarkerToken::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(MarkerToken::RParen);
                i += 1;
            }
            '\'' | '"' => {
                let quote = c;
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && chars[j] != quote {
                    j += 1;
                }
                if j >= chars.len() {
                    return None; // unterminated string literal
                }
                tokens.push(MarkerToken::Str(chars[start..j].iter().collect()));
                i = j + 1;
            }
            '=' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(MarkerToken::Op("=="));
                i += 2;
            }
            '!' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(MarkerToken::Op("!="));
                i += 2;
            }
            '>' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(MarkerToken::Op(">="));
                i += 2;
            }
            '<' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(MarkerToken::Op("<="));
                i += 2;
            }
            '>' => {
                tokens.push(MarkerToken::Op(">"));
                i += 1;
            }
            '<' => {
                tokens.push(MarkerToken::Op("<"));
                i += 1;
            }
            c if c.is_alphanumeric() || c == '_' || c == '.' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.')
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                match word.as_str() {
                    "and" => tokens.push(MarkerToken::And),
                    "or" => tokens.push(MarkerToken::Or),
                    "in" => tokens.push(MarkerToken::Op("in")),
                    "not" => {
                        // PEP 508 only allows a bare `not` as part of `not in`.
                        let mut j = i;
                        while j < chars.len() && chars[j].is_whitespace() {
                            j += 1;
                        }
                        let word_start = j;
                        while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                            j += 1;
                        }
                        if chars[word_start..j].iter().collect::<String>() != "in" {
                            return None;
                        }
                        tokens.push(MarkerToken::Op("not in"));
                        i = j;
                    }
                    _ => tokens.push(MarkerToken::Var(word)),
                }
            }
            _ => return None, // unrecognized character
        }
    }

    Some(tokens)
}

/// One side of a marker comparison: either an environment variable
/// (e.g. `sys_platform`) or a quoted literal value (e.g. `"win32"`).
enum MarkerValue {
    Variable(String),
    Literal(String),
}

/// Recursive-descent parser over [`MarkerToken`]s implementing the PEP 508
/// `marker_or := marker_and ('or' marker_and)*` /
/// `marker_and := marker_expr ('and' marker_expr)*` grammar, with `and`
/// binding tighter than `or` and parentheses for grouping.
struct MarkerParser<'a> {
    tokens: &'a [MarkerToken],
    pos: usize,
}

impl MarkerParser<'_> {
    fn parse_or(&mut self) -> Option<bool> {
        let mut result = self.parse_and()?;
        while matches!(self.tokens.get(self.pos), Some(MarkerToken::Or)) {
            self.pos += 1;
            let rhs = self.parse_and()?;
            result = result || rhs;
        }
        Some(result)
    }

    fn parse_and(&mut self) -> Option<bool> {
        let mut result = self.parse_primary()?;
        while matches!(self.tokens.get(self.pos), Some(MarkerToken::And)) {
            self.pos += 1;
            let rhs = self.parse_primary()?;
            result = result && rhs;
        }
        Some(result)
    }

    fn parse_primary(&mut self) -> Option<bool> {
        if matches!(self.tokens.get(self.pos), Some(MarkerToken::LParen)) {
            self.pos += 1;
            let inner = self.parse_or()?;
            if !matches!(self.tokens.get(self.pos), Some(MarkerToken::RParen)) {
                return None;
            }
            self.pos += 1;
            return Some(inner);
        }
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Option<bool> {
        let left = self.parse_value()?;
        let op = match self.tokens.get(self.pos) {
            Some(MarkerToken::Op(op)) => *op,
            _ => return None,
        };
        self.pos += 1;
        let right = self.parse_value()?;
        Some(evaluate_comparison(&left, op, &right))
    }

    fn parse_value(&mut self) -> Option<MarkerValue> {
        match self.tokens.get(self.pos) {
            Some(MarkerToken::Var(name)) => {
                self.pos += 1;
                Some(MarkerValue::Variable(name.clone()))
            }
            Some(MarkerToken::Str(s)) => {
                self.pos += 1;
                Some(MarkerValue::Literal(s.clone()))
            }
            _ => None,
        }
    }
}

/// Look up the current environment's value for a PEP 508 marker variable.
/// Returns `None` for variables this evaluator doesn't know about (e.g. `extra`,
/// which is handled separately since the resolver doesn't track active extras).
fn lookup_marker_variable(name: &str) -> Option<String> {
    match name {
        "os_name" => Some(get_os_name().to_string()),
        "sys_platform" => Some(get_sys_platform().to_string()),
        "platform_machine" => Some(get_platform_machine().to_string()),
        "platform_system" => Some(get_platform_system().to_string()),
        "platform_release" => Some(get_platform_release()),
        "platform_version" => Some(get_platform_version()),
        "platform_python_implementation" => Some(get_python_implementation().to_string()),
        "implementation_name" => Some(get_python_implementation().to_lowercase()),
        "python_version" => Some(get_python_version().to_string()),
        "python_full_version" | "implementation_version" => {
            Some(get_python_full_version().to_string())
        }
        _ => None,
    }
}

/// Marker variables whose values are dotted version numbers and should be
/// compared numerically (via [`compare_versions`]) rather than lexically.
fn is_version_variable(value: &MarkerValue) -> bool {
    matches!(
        value,
        MarkerValue::Variable(name)
            if matches!(
                name.as_str(),
                "python_version" | "python_full_version" | "implementation_version"
            )
    )
}

fn is_extra_variable(value: &MarkerValue) -> bool {
    matches!(value, MarkerValue::Variable(name) if name == "extra")
}

fn resolve_marker_value(value: &MarkerValue) -> Option<String> {
    match value {
        MarkerValue::Literal(s) => Some(s.clone()),
        MarkerValue::Variable(name) => lookup_marker_variable(name),
    }
}

/// Evaluate a single `marker_var marker_op marker_var` comparison.
fn evaluate_comparison(left: &MarkerValue, op: &str, right: &MarkerValue) -> bool {
    // The resolver does not currently track which extras were requested, so
    // `extra == "..."` markers are treated as "extra not active" — consistent
    // with `marker_allows` in pypi.rs, which excludes all `extra ==` markers.
    if is_extra_variable(left) || is_extra_variable(right) {
        return match op {
            "==" | "in" => false,
            "!=" | "not in" => true,
            // Unsupported ordering operators on `extra` — be inclusive.
            _ => true,
        };
    }

    let (Some(lhs), Some(rhs)) = (resolve_marker_value(left), resolve_marker_value(right)) else {
        // Unknown variable → we don't know → be inclusive (don't silently drop packages).
        return true;
    };

    let version_aware = is_version_variable(left) || is_version_variable(right);

    match op {
        "==" => lhs == rhs,
        "!=" => lhs != rhs,
        // PEP 508 `in`/`not in`: true if the left value is a substring of the right value.
        "in" => rhs.contains(&lhs),
        "not in" => !rhs.contains(&lhs),
        ">=" | "<=" | ">" | "<" => {
            let ord = if version_aware {
                compare_versions(&lhs, &rhs)
            } else {
                lhs.cmp(&rhs)
            };
            match op {
                ">=" => ord != Ordering::Less,
                "<=" => ord != Ordering::Greater,
                ">" => ord == Ordering::Greater,
                "<" => ord == Ordering::Less,
                _ => unreachable!(),
            }
        }
        // Unsupported operator (e.g. `~=` in a marker) → be inclusive.
        _ => true,
    }
}

/// Evaluate a PEP 508 environment marker against the current platform.
///
/// Supports the full marker variable set (`os_name`, `sys_platform`,
/// `platform_machine`, `platform_system`, `platform_release`, `platform_version`,
/// `platform_python_implementation`, `implementation_name`, `python_version`,
/// `python_full_version`, `implementation_version`), all comparison operators
/// including `in`/`not in`, and quote-aware `and`/`or`/parentheses grouping.
///
/// If the marker can't be parsed, or contains a variable/operator this evaluator
/// doesn't understand, it returns `true` (inclusive) so packages are never
/// silently dropped due to an unrecognized marker.
fn evaluate_marker(marker: &str) -> bool {
    let marker = marker.trim();
    let Some(tokens) = tokenize_marker(marker) else {
        return true;
    };
    let mut parser = MarkerParser {
        tokens: &tokens,
        pos: 0,
    };
    match parser.parse_or() {
        Some(result) if parser.pos == tokens.len() => result,
        _ => true,
    }
}

/// Get the OS name in `os.name` form (`posix` or `nt`).
fn get_os_name() -> &'static str {
    #[cfg(windows)]
    return "nt";

    #[cfg(not(windows))]
    return "posix";
}

/// Detect the runtime Python version as a MAJOR.MINOR string (e.g. `"3.11"`).
///
/// Derived from [`get_python_full_version`], so no extra subprocess is spawned.
/// If Python cannot be detected, returns `"3.0"` as a conservative inclusive fallback.
fn get_python_version() -> &'static str {
    static PYTHON_VERSION: OnceLock<String> = OnceLock::new();
    PYTHON_VERSION.get_or_init(|| {
        let full = get_python_full_version();
        let parts: Vec<&str> = full.split('.').collect();
        if parts.len() >= 2 {
            format!("{}.{}", parts[0], parts[1])
        } else {
            "3.0".to_string()
        }
    })
}

/// Detect the full runtime Python version as `MAJOR.MINOR.PATCH` (e.g. `"3.11.4"`).
///
/// The result is cached in a `OnceLock` so the subprocess is only spawned once per process.
/// If Python cannot be detected, returns `"3.0.0"` as a conservative inclusive fallback.
fn get_python_full_version() -> &'static str {
    static FULL_VERSION: OnceLock<String> = OnceLock::new();
    FULL_VERSION.get_or_init(|| {
        for cmd in &["python3", "python"] {
            let Ok(output) = std::process::Command::new(cmd).arg("--version").output() else {
                continue;
            };
            if !output.status.success() {
                continue;
            }
            // Python 2 prints to stderr; Python 3 prints to stdout.
            let raw = if output.stdout.is_empty() {
                output.stderr
            } else {
                output.stdout
            };
            let text = String::from_utf8_lossy(&raw);
            if let Some(ver) = text.trim().strip_prefix("Python ")
                && !ver.is_empty()
            {
                return ver.to_string();
            }
        }
        // Fallback: inclusive — do not silently drop packages.
        "3.0.0".to_string()
    })
}

/// Detect the running Python implementation (e.g. `"CPython"`, `"PyPy"`).
///
/// The result is cached in a `OnceLock` so the subprocess is only spawned once per process.
/// If Python cannot be detected, returns `"CPython"` — the overwhelmingly common case,
/// which keeps CPython-targeted markers inclusive while still letting
/// implementation-specific markers (e.g. PyPy-only deps) evaluate correctly when detection
/// succeeds.
fn get_python_implementation() -> &'static str {
    static IMPLEMENTATION: OnceLock<String> = OnceLock::new();
    IMPLEMENTATION.get_or_init(|| {
        for cmd in &["python3", "python"] {
            let Ok(output) = std::process::Command::new(cmd)
                .args([
                    "-c",
                    "import platform; print(platform.python_implementation())",
                ])
                .output()
            else {
                continue;
            };
            if !output.status.success() {
                continue;
            }
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !text.is_empty() {
                return text;
            }
        }
        "CPython".to_string()
    })
}

/// Get the OS release version via `uname -r` (e.g. `"23.1.0"`).
///
/// Returns an empty string on platforms where this can't be determined, which compares
/// as "less than" any non-empty release string in ordering comparisons.
fn get_platform_release() -> String {
    static RELEASE: OnceLock<String> = OnceLock::new();
    RELEASE
        .get_or_init(|| {
            #[cfg(unix)]
            {
                if let Ok(output) = std::process::Command::new("uname").arg("-r").output()
                    && output.status.success()
                {
                    return String::from_utf8_lossy(&output.stdout).trim().to_string();
                }
            }
            String::new()
        })
        .clone()
}

/// Get the detailed OS version string via `uname -v`.
///
/// Returns an empty string on platforms where this can't be determined.
fn get_platform_version() -> String {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            #[cfg(unix)]
            {
                if let Ok(output) = std::process::Command::new("uname").arg("-v").output()
                    && output.status.success()
                {
                    return String::from_utf8_lossy(&output.stdout).trim().to_string();
                }
            }
            String::new()
        })
        .clone()
}

/// Get the platform machine architecture (e.g., 'x86_64', 'arm64', 'i386').
fn get_platform_machine() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    return "x86_64";

    #[cfg(target_arch = "aarch64")]
    {
        // Python on macOS reports aarch64 as 'arm64'
        #[cfg(target_os = "macos")]
        return "arm64";

        #[cfg(not(target_os = "macos"))]
        return "aarch64";
    }

    #[cfg(target_arch = "x86")]
    return "i386";

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")))]
    return "unknown";
}

/// Get the system platform (e.g., 'darwin', 'linux', 'win32').
fn get_sys_platform() -> &'static str {
    #[cfg(target_os = "macos")]
    return "darwin";

    #[cfg(target_os = "linux")]
    return "linux";

    #[cfg(target_os = "windows")]
    return "win32";

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return "unknown";
}

/// Get the platform system (e.g., 'Darwin', 'Linux', 'Windows').
fn get_platform_system() -> &'static str {
    #[cfg(target_os = "macos")]
    return "Darwin";

    #[cfg(target_os = "linux")]
    return "Linux";

    #[cfg(target_os = "windows")]
    return "Windows";

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return "Unknown";
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_requirement_with_marker() {
        // Test parsing PEP 508 requirement with environment marker
        let req_str = "polars-runtime-32 (==1.39.2) ; platform_machine == 'i386'";
        let req = Requirement::from_str(req_str).unwrap();

        assert_eq!(req.name, "polars-runtime-32");
        assert_eq!(req.specs, vec![VersionSpec::Exact("1.39.2".to_string())]);
        assert_eq!(req.marker, Some("platform_machine == 'i386'".to_string()));
    }

    #[test]
    fn test_parse_requirement_without_marker() {
        let req_str = "requests>=2.28.0";
        let req = Requirement::from_str(req_str).unwrap();

        assert_eq!(req.name, "requests");
        assert_eq!(req.specs, vec![VersionSpec::Minimum("2.28.0".to_string())]);
        assert_eq!(req.marker, None);
    }

    // ====================================================================
    // Issue #285: PEP 508 extras must not be silently dropped without a
    // trace — the name must come out clean (no bracket leakage into PyPI
    // metadata lookups) and the requested extras must be recorded so
    // callers can emit a `W_EXTRAS_IGNORED` diagnostic.
    // ====================================================================

    #[test]
    fn test_parse_requirement_with_single_extra() {
        let req = Requirement::from_str("typer[all]").unwrap();

        assert_eq!(req.name, "typer");
        assert_eq!(req.specs, vec![VersionSpec::Any]);
        assert_eq!(req.extras, vec!["all".to_string()]);
    }

    #[test]
    fn test_parse_requirement_with_multiple_extras() {
        let req = Requirement::from_str("requests[socks,security]").unwrap();

        assert_eq!(req.name, "requests");
        assert_eq!(
            req.extras,
            vec!["socks".to_string(), "security".to_string()]
        );
    }

    #[test]
    fn test_parse_requirement_with_extras_and_version_constraint() {
        let req = Requirement::from_str("typer[all]>=0.9.0").unwrap();

        assert_eq!(req.name, "typer");
        assert_eq!(req.specs, vec![VersionSpec::Minimum("0.9.0".to_string())]);
        assert_eq!(req.extras, vec!["all".to_string()]);
    }

    #[test]
    fn test_parse_requirement_with_extras_and_marker() {
        let req = Requirement::from_str("typer[all]; python_version >= '3.8'").unwrap();

        assert_eq!(req.name, "typer");
        assert_eq!(req.extras, vec!["all".to_string()]);
        assert_eq!(req.marker, Some("python_version >= '3.8'".to_string()));
    }

    #[test]
    fn test_parse_requirement_without_extras_has_empty_vec() {
        let req = Requirement::from_str("requests>=2.28.0").unwrap();
        assert!(req.extras.is_empty());
    }

    // ====================================================================
    // Issue #181: compound version constraints (e.g. >=1.0,<2.0)
    // ====================================================================

    #[test]
    fn test_parse_requirement_compound_constraints() {
        let req = Requirement::from_str("foo>=1.0,<2.0").unwrap();

        assert_eq!(req.name, "foo");
        assert_eq!(
            req.specs,
            vec![
                VersionSpec::Minimum("1.0".to_string()),
                VersionSpec::Maximum("2.0".to_string()),
            ]
        );
        assert!(req.is_satisfied_by("1.5.0"));
        assert!(req.is_satisfied_by("1.0.0"));
        assert!(!req.is_satisfied_by("2.0.0"));
        assert!(!req.is_satisfied_by("3.0.0"));
        assert!(!req.is_satisfied_by("0.9.0"));
    }

    #[test]
    fn test_parse_requirement_compound_constraints_with_parens() {
        let req = Requirement::from_str("package (>=1.20, <2.0)").unwrap();

        assert_eq!(req.name, "package");
        assert_eq!(
            req.specs,
            vec![
                VersionSpec::Minimum("1.20".to_string()),
                VersionSpec::Maximum("2.0".to_string()),
            ]
        );
        assert!(req.is_satisfied_by("1.20.0"));
        assert!(!req.is_satisfied_by("2.0.0"));
    }

    #[test]
    fn test_parse_requirement_three_way_compound_constraint() {
        let req = Requirement::from_str("foo>=1.0,<2.0,!=1.5.0").unwrap();

        assert!(req.is_satisfied_by("1.4.0"));
        assert!(!req.is_satisfied_by("1.5.0"));
        assert!(!req.is_satisfied_by("2.0.0"));
    }

    #[test]
    fn test_compound_requirement_display_roundtrip() {
        let req = Requirement::from_str("foo>=1.0,<2.0").unwrap();
        assert_eq!(req.to_string(), "foo>=1.0,<2.0");
    }

    #[test]
    fn test_single_spec_requirement_still_parses_and_roundtrips() {
        let req = Requirement::from_str("requests>=2.28.0").unwrap();
        assert_eq!(req.specs, vec![VersionSpec::Minimum("2.28.0".to_string())]);
        assert_eq!(req.to_string(), "requests>=2.28.0");

        let req = Requirement::from_str("requests").unwrap();
        assert_eq!(req.specs, vec![VersionSpec::Any]);
        assert_eq!(req.to_string(), "requests");
    }

    #[tokio::test]
    async fn test_resolve_respects_compound_constraint_upper_bound() {
        let mut index = InMemoryIndex::default();
        index.add("pkg", "1.0.0", Vec::<String>::new());
        index.add("pkg", "1.5.0", Vec::<String>::new());
        index.add("pkg", "2.5.0", Vec::<String>::new());

        // Without an upper bound, the resolver would pick 2.5.0.
        let req = Requirement::from_str("pkg>=1.0,<2.0").unwrap();
        let resolution = resolve(vec![req], &index).await.unwrap();

        assert_eq!(
            resolution.packages.get("pkg").map(|p| p.version.as_str()),
            Some("1.5.0"),
            "resolver must respect the <2.0 upper bound and not select 2.5.0"
        );
    }

    #[test]
    fn test_marker_evaluation_platform_machine() {
        // Test that marker evaluation correctly filters based on platform_machine
        let req_32bit =
            Requirement::from_str("polars-runtime-32==1.39.2 ; platform_machine == 'i386'")
                .unwrap();

        // On macOS arm64, only the arm64 requirement should apply
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            let req_arm64 =
                Requirement::from_str("polars-runtime-64==1.39.2 ; platform_machine == 'arm64'")
                    .unwrap();
            assert!(!req_32bit.marker_applies());
            assert!(req_arm64.marker_applies());
        }

        // On Linux x86_64, neither should apply (unless we add x86_64 markers)
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            assert!(!req_32bit.marker_applies());
        }
    }

    #[test]
    fn test_marker_evaluation_no_marker_always_applies() {
        let req = Requirement::from_str("requests>=2.28.0").unwrap();
        assert!(req.marker_applies()); // No marker means always applies
    }

    #[test]
    fn test_complex_marker_with_parentheses() {
        let req_str =
            "package (>=1.0) ; (platform_machine == 'x86_64' or platform_machine == 'arm64')";
        let req = Requirement::from_str(req_str).unwrap();

        assert_eq!(req.name, "package");
        assert!(req.marker.is_some());
    }

    #[test]
    fn test_parse_requirement_plain_marker_no_version() {
        // "requests; python_version < '4.0'" — no version spec, just a marker
        let req = Requirement::from_str("requests; python_version < '4.0'").unwrap();
        assert_eq!(req.name, "requests");
        assert_eq!(req.specs, vec![VersionSpec::Any]);
        assert_eq!(req.marker, Some("python_version < '4.0'".to_string()));
    }

    #[test]
    fn test_python_version_marker_applies() {
        // python_version < '4.0' should apply (Python 4 doesn't exist yet)
        let req = Requirement::from_str("requests; python_version < '4.0'").unwrap();
        assert!(
            req.marker_applies(),
            "python_version < '4.0' should apply since Python 4 does not exist"
        );

        // python_version >= '3.0' should apply (we're always on Python 3+)
        let req2 = Requirement::from_str("requests; python_version >= '3.0'").unwrap();
        assert!(
            req2.marker_applies(),
            "python_version >= '3.0' should apply"
        );

        // python_version < '2.0' should NOT apply (Python 2 is ancient; detected version is 3.x+)
        let req3 = Requirement::from_str("requests; python_version < '2.0'").unwrap();
        assert!(
            !req3.marker_applies(),
            "python_version < '2.0' should not apply on any supported Python 3.x host"
        );
    }

    // ====================================================================
    // Issue #183: PEP 508 marker evaluation completeness
    // ====================================================================

    #[test]
    #[cfg(unix)]
    fn test_marker_os_name_posix() {
        let req = Requirement::from_str("requests; os_name == 'posix'").unwrap();
        assert!(
            req.marker_applies(),
            "os_name == 'posix' should apply on macOS/Linux"
        );

        let req_nt = Requirement::from_str("requests; os_name == 'nt'").unwrap();
        assert!(
            !req_nt.marker_applies(),
            "os_name == 'nt' should not apply on macOS/Linux"
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_marker_os_name_nt() {
        let req = Requirement::from_str("requests; os_name == 'nt'").unwrap();
        assert!(
            req.marker_applies(),
            "os_name == 'nt' should apply on Windows"
        );

        let req_posix = Requirement::from_str("requests; os_name == 'posix'").unwrap();
        assert!(
            !req_posix.marker_applies(),
            "os_name == 'posix' should not apply on Windows"
        );
    }

    #[test]
    fn test_marker_platform_python_implementation_cpython() {
        // Falls back to "CPython" / "cpython" if detection fails, so this is
        // expected to hold on every CI host that runs this test suite.
        let req =
            Requirement::from_str("requests; platform_python_implementation == 'CPython'").unwrap();
        assert!(req.marker_applies());

        let req2 = Requirement::from_str("requests; implementation_name == 'cpython'").unwrap();
        assert!(req2.marker_applies());

        let req_pypy =
            Requirement::from_str("requests; platform_python_implementation == 'PyPy'").unwrap();
        assert!(!req_pypy.marker_applies());
    }

    #[test]
    fn test_marker_in_operator() {
        // sys_platform is "darwin", "linux", or "win32" on supported hosts — all
        // appear as substrings of this comma-separated list.
        let req = Requirement::from_str("requests; sys_platform in 'darwin,linux,win32'").unwrap();
        assert!(req.marker_applies(), "sys_platform in '...' should match");
    }

    #[test]
    fn test_marker_not_in_operator() {
        let req = Requirement::from_str("requests; sys_platform not in 'win32'").unwrap();

        #[cfg(not(target_os = "windows"))]
        assert!(
            req.marker_applies(),
            "sys_platform not in 'win32' should apply on non-Windows hosts"
        );

        #[cfg(target_os = "windows")]
        assert!(
            !req.marker_applies(),
            "sys_platform not in 'win32' should not apply on Windows"
        );
    }

    #[test]
    fn test_marker_quote_aware_comparison_value_containing_or() {
        // The literal value "linux or win32" contains " or " — a naive
        // string-split on " or " would mis-tokenize this and produce an
        // incorrect (inclusive) result. The real sys_platform value never
        // equals this literal, so the marker must not apply.
        let req = Requirement::from_str(r#"requests; sys_platform == "linux or win32""#).unwrap();
        assert!(
            !req.marker_applies(),
            "sys_platform never literally equals 'linux or win32'"
        );
    }

    #[test]
    fn test_marker_quote_aware_and_or_combination() {
        // Quoted values containing "and"/"or" must not be split by the and/or
        // tokenizer; only unquoted `and`/`or` keywords should act as operators.
        let req = Requirement::from_str(
            r#"requests; sys_platform == "and or" or python_version < '4.0'"#,
        )
        .unwrap();
        assert!(
            req.marker_applies(),
            "second branch (python_version < '4.0') should make this true"
        );
    }

    #[test]
    fn test_marker_extra_agrees_with_pypi_marker_allows() {
        // resolver::evaluate_marker and pypi::marker_allows must agree on
        // `extra ==` markers: since neither tracks which extras were
        // requested, both treat the extra as "not active".
        let req = Requirement::from_str("requests; extra == 'test'").unwrap();
        assert!(
            !req.marker_applies(),
            "extra == 'test' should not apply when no extras are tracked"
        );
        assert!(!crate::pypi::marker_allows("extra == 'test'", "3.11"));

        let req_ne = Requirement::from_str("requests; extra != 'test'").unwrap();
        assert!(
            req_ne.marker_applies(),
            "extra != 'test' should apply when no extras are tracked"
        );
    }

    #[test]
    fn test_marker_unknown_variable_is_inclusive() {
        // A genuinely unrecognized variable falls back to inclusive (true).
        let req = Requirement::from_str("requests; some_future_marker_var == 'value'").unwrap();
        assert!(req.marker_applies());
    }

    #[test]
    fn test_marker_unparseable_marker_is_inclusive() {
        // Malformed syntax (unterminated string) falls back to inclusive (true).
        let req = Requirement::from_str(r#"requests; sys_platform == "unterminated"#);
        // The requirement itself may or may not parse depending on Requirement::from_str,
        // but if it does, the marker must be inclusive.
        if let Ok(req) = req {
            assert!(req.marker_applies());
        }
    }

    #[tokio::test]
    async fn test_resolve_skips_non_applicable_platform_markers() {
        let mut index = InMemoryIndex::default();
        index.add("requests", "2.28.0", Vec::<String>::new());

        // A requirement targeting a fake arch that never matches
        let req =
            Requirement::from_str("requests; platform_machine == 'nonexistent_arch_xyz'").unwrap();
        assert!(!req.marker_applies(), "sanity: marker must not apply");

        let resolution = resolve(vec![req], &index).await.unwrap();
        assert!(
            resolution.packages.is_empty(),
            "packages with non-applicable markers should not be resolved; got: {:?}",
            resolution.packages.keys().collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_resolve_includes_applicable_markers() {
        let mut index = InMemoryIndex::default();
        index.add("requests", "2.28.0", Vec::<String>::new());

        // No marker — always included
        let req = Requirement::from_str("requests>=2.0").unwrap();
        assert!(req.marker_applies());

        let resolution = resolve(vec![req], &index).await.unwrap();
        assert!(
            resolution.packages.contains_key("requests"),
            "requirements without markers must be resolved"
        );
    }

    #[tokio::test]
    async fn test_resolve_python_version_marker_inclusive() {
        let mut index = InMemoryIndex::default();
        index.add("requests", "2.28.0", Vec::<String>::new());

        // python_version < '4.0' applies on all current Python hosts (Python 4 does not exist)
        let req = Requirement::from_str("requests; python_version < '4.0'").unwrap();

        let resolution = resolve(vec![req], &index).await.unwrap();
        assert!(
            resolution.packages.contains_key("requests"),
            "requests with python_version < '4.0' marker should be resolved"
        );
    }

    // ====================================================================
    // Issue #161: ABI resolution — Python version tag tests
    // ====================================================================

    #[test]
    fn parse_wheel_tags_cp311_wheel() {
        let (python, abi) = parse_wheel_tags("pyarrow-14.0.0-cp311-cp311-macosx_14_0_arm64.whl");
        assert_eq!(python.as_deref(), Some("cp311"));
        assert_eq!(abi.as_deref(), Some("cp311"));
    }

    #[test]
    fn parse_wheel_tags_cp310_wheel() {
        let (python, abi) = parse_wheel_tags("pyarrow-14.0.0-cp310-cp310-macosx_11_0_arm64.whl");
        assert_eq!(python.as_deref(), Some("cp310"));
        assert_eq!(abi.as_deref(), Some("cp310"));
    }

    #[test]
    fn parse_wheel_tags_py3_none_any_wheel() {
        let (python, abi) = parse_wheel_tags("requests-2.28.0-py3-none-any.whl");
        assert_eq!(python.as_deref(), Some("py3"));
        assert_eq!(abi.as_deref(), Some("none"));
    }

    #[test]
    fn parse_wheel_tags_abi3_wheel() {
        let (python, abi) = parse_wheel_tags("cryptography-41.0.0-cp37-abi3-macosx_14_0_arm64.whl");
        assert_eq!(python.as_deref(), Some("cp37"));
        assert_eq!(abi.as_deref(), Some("abi3"));
    }

    #[test]
    fn parse_wheel_tags_hyphenated_name() {
        // Package names with hyphens — positions from the right must still work
        let (python, abi) =
            parse_wheel_tags("some-package-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl");
        assert_eq!(python.as_deref(), Some("cp311"));
        assert_eq!(abi.as_deref(), Some("cp311"));
    }

    #[test]
    fn parse_wheel_tags_url_path() {
        // Filenames preceded by a URL path segment
        let (python, abi) =
            parse_wheel_tags("https://example.com/pkg-1.0-cp311-cp311-linux_x86_64.whl");
        assert_eq!(python.as_deref(), Some("cp311"));
        assert_eq!(abi.as_deref(), Some("cp311"));
    }

    #[test]
    fn python_version_to_cp_tag_three_component() {
        assert_eq!(python_version_to_cp_tag("3.11.5").as_deref(), Some("cp311"));
        assert_eq!(python_version_to_cp_tag("3.10.0").as_deref(), Some("cp310"));
    }

    #[test]
    fn python_version_to_cp_tag_two_component() {
        assert_eq!(python_version_to_cp_tag("3.11").as_deref(), Some("cp311"));
        assert_eq!(python_version_to_cp_tag("3.9").as_deref(), Some("cp39"));
    }

    #[test]
    fn python_version_to_cp_tag_invalid_returns_none() {
        assert_eq!(python_version_to_cp_tag("invalid"), None);
        assert_eq!(python_version_to_cp_tag(""), None);
    }

    #[test]
    fn cp_tag_to_dotted_version_two_digit_minor() {
        assert_eq!(cp_tag_to_dotted_version("cp310").as_deref(), Some("3.10"));
        assert_eq!(cp_tag_to_dotted_version("cp312").as_deref(), Some("3.12"));
    }

    #[test]
    fn cp_tag_to_dotted_version_single_digit_minor() {
        assert_eq!(cp_tag_to_dotted_version("cp39").as_deref(), Some("3.9"));
    }

    #[test]
    fn cp_tag_to_dotted_version_rejects_non_cpython_tags() {
        assert_eq!(cp_tag_to_dotted_version("py3"), None);
        assert_eq!(cp_tag_to_dotted_version("abi3"), None);
        assert_eq!(cp_tag_to_dotted_version("cp"), None);
        assert_eq!(cp_tag_to_dotted_version("cpXY"), None);
    }

    #[test]
    fn cp_tag_to_dotted_version_round_trips_with_python_version_to_cp_tag() {
        let tag = python_version_to_cp_tag("3.13.1").unwrap();
        assert_eq!(cp_tag_to_dotted_version(&tag).as_deref(), Some("3.13"));
    }

    #[test]
    fn is_wheel_python_compatible_exact_match() {
        assert!(is_wheel_python_compatible(
            Some("cp311"),
            Some("cp311"),
            "cp311"
        ));
    }

    #[test]
    fn is_wheel_python_compatible_different_version_rejected() {
        assert!(!is_wheel_python_compatible(
            Some("cp310"),
            Some("cp310"),
            "cp311"
        ));
        assert!(!is_wheel_python_compatible(
            Some("cp311"),
            Some("cp311"),
            "cp310"
        ));
    }

    #[test]
    fn is_wheel_python_compatible_py3_always_matches() {
        assert!(is_wheel_python_compatible(
            Some("py3"),
            Some("none"),
            "cp311"
        ));
        assert!(is_wheel_python_compatible(
            Some("py3"),
            Some("none"),
            "cp310"
        ));
        assert!(is_wheel_python_compatible(
            Some("py3"),
            Some("none"),
            "cp39"
        ));
    }

    #[test]
    fn is_wheel_python_compatible_abi3_matches_newer_cp() {
        // cp37-abi3 wheel: compatible with cp37, cp38, cp39, cp310, cp311
        assert!(is_wheel_python_compatible(
            Some("cp37"),
            Some("abi3"),
            "cp311"
        ));
        assert!(is_wheel_python_compatible(
            Some("cp37"),
            Some("abi3"),
            "cp310"
        ));
        assert!(is_wheel_python_compatible(
            Some("cp37"),
            Some("abi3"),
            "cp39"
        ));
        assert!(is_wheel_python_compatible(
            Some("cp37"),
            Some("abi3"),
            "cp37"
        ));
    }

    #[test]
    fn is_wheel_python_compatible_abi3_rejects_older_cp() {
        // cp38-abi3 wheel: NOT compatible with cp37
        assert!(!is_wheel_python_compatible(
            Some("cp38"),
            Some("abi3"),
            "cp37"
        ));
    }

    #[test]
    fn is_wheel_python_compatible_none_tag_is_compatible() {
        // Unknown tag → treated as compatible (legacy index compat)
        assert!(is_wheel_python_compatible(None, None, "cp311"));
    }

    #[test]
    fn select_artifact_prefers_cp311_wheel_over_cp310_on_python_311() {
        let pkg = ResolvedPackage {
            requires_python: None,
            name: "pyarrow".to_string(),
            version: "14.0.0".to_string(),
            dependencies: vec![],
            source: None,
            artifacts: PackageArtifacts {
                wheels: vec![
                    Wheel {
                        file: "pyarrow-14.0.0-cp310-cp310-macosx_14_0_arm64.whl".to_string(),
                        url: None,
                        hash: None,
                        platforms: vec!["macosx_14_0_arm64".to_string()],
                        python_tag: Some("cp310".to_string()),
                        abi_tag: Some("cp310".to_string()),
                    },
                    Wheel {
                        file: "pyarrow-14.0.0-cp311-cp311-macosx_14_0_arm64.whl".to_string(),
                        url: None,
                        hash: None,
                        platforms: vec!["macosx_14_0_arm64".to_string()],
                        python_tag: Some("cp311".to_string()),
                        abi_tag: Some("cp311".to_string()),
                    },
                ],
                sdist: None,
            },
        };
        let platform_tags = vec!["macosx_14_0_arm64".to_string(), "any".to_string()];
        let selection = select_artifact_for_platform_with_cp(&pkg, &platform_tags, "cp311");
        assert_eq!(
            selection.filename, "pyarrow-14.0.0-cp311-cp311-macosx_14_0_arm64.whl",
            "should select cp311 wheel when active Python is 3.11"
        );
    }

    #[test]
    fn select_artifact_prefers_cp310_wheel_over_cp311_on_python_310() {
        let pkg = ResolvedPackage {
            requires_python: None,
            name: "pyarrow".to_string(),
            version: "14.0.0".to_string(),
            dependencies: vec![],
            source: None,
            artifacts: PackageArtifacts {
                wheels: vec![
                    Wheel {
                        file: "pyarrow-14.0.0-cp310-cp310-macosx_14_0_arm64.whl".to_string(),
                        url: None,
                        hash: None,
                        platforms: vec!["macosx_14_0_arm64".to_string()],
                        python_tag: Some("cp310".to_string()),
                        abi_tag: Some("cp310".to_string()),
                    },
                    Wheel {
                        file: "pyarrow-14.0.0-cp311-cp311-macosx_14_0_arm64.whl".to_string(),
                        url: None,
                        hash: None,
                        platforms: vec!["macosx_14_0_arm64".to_string()],
                        python_tag: Some("cp311".to_string()),
                        abi_tag: Some("cp311".to_string()),
                    },
                ],
                sdist: None,
            },
        };
        let platform_tags = vec!["macosx_14_0_arm64".to_string(), "any".to_string()];
        let selection = select_artifact_for_platform_with_cp(&pkg, &platform_tags, "cp310");
        assert_eq!(
            selection.filename, "pyarrow-14.0.0-cp310-cp310-macosx_14_0_arm64.whl",
            "should select cp310 wheel when active Python is 3.10"
        );
    }

    #[test]
    fn select_artifact_excludes_incompatible_python_version() {
        // Only cp310 wheel available, but we're on cp311
        let pkg = ResolvedPackage {
            requires_python: None,
            name: "pyarrow".to_string(),
            version: "14.0.0".to_string(),
            dependencies: vec![],
            source: None,
            artifacts: PackageArtifacts {
                wheels: vec![Wheel {
                    file: "pyarrow-14.0.0-cp310-cp310-macosx_14_0_arm64.whl".to_string(),
                    url: None,
                    hash: None,
                    platforms: vec!["macosx_14_0_arm64".to_string()],
                    python_tag: Some("cp310".to_string()),
                    abi_tag: Some("cp310".to_string()),
                }],
                sdist: Some("pyarrow-14.0.0.tar.gz".to_string()),
            },
        };
        let platform_tags = vec!["macosx_14_0_arm64".to_string(), "any".to_string()];
        let selection = select_artifact_for_platform_with_cp(&pkg, &platform_tags, "cp311");
        assert!(
            selection.from_source,
            "should fall back to sdist when no compatible wheel is available"
        );
    }

    #[test]
    fn select_artifact_uses_abi3_wheel_as_fallback() {
        // abi3 wheel available in addition to cp311
        let pkg = ResolvedPackage {
            requires_python: None,
            name: "cryptography".to_string(),
            version: "41.0.0".to_string(),
            dependencies: vec![],
            source: None,
            artifacts: PackageArtifacts {
                wheels: vec![
                    Wheel {
                        file: "cryptography-41.0.0-cp37-abi3-macosx_14_0_arm64.whl".to_string(),
                        url: None,
                        hash: None,
                        platforms: vec!["macosx_14_0_arm64".to_string()],
                        python_tag: Some("cp37".to_string()),
                        abi_tag: Some("abi3".to_string()),
                    },
                    Wheel {
                        file: "cryptography-41.0.0-cp311-cp311-macosx_14_0_arm64.whl".to_string(),
                        url: None,
                        hash: None,
                        platforms: vec!["macosx_14_0_arm64".to_string()],
                        python_tag: Some("cp311".to_string()),
                        abi_tag: Some("cp311".to_string()),
                    },
                ],
                sdist: None,
            },
        };
        let platform_tags = vec!["macosx_14_0_arm64".to_string(), "any".to_string()];
        // On cp311, exact match should win over abi3
        let selection = select_artifact_for_platform_with_cp(&pkg, &platform_tags, "cp311");
        assert_eq!(
            selection.filename,
            "cryptography-41.0.0-cp311-cp311-macosx_14_0_arm64.whl"
        );
        // On cp312 (no exact match), abi3 should be selected
        let selection312 = select_artifact_for_platform_with_cp(&pkg, &platform_tags, "cp312");
        assert_eq!(
            selection312.filename,
            "cryptography-41.0.0-cp37-abi3-macosx_14_0_arm64.whl"
        );
    }

    #[test]
    fn select_artifact_py3_wheel_is_always_compatible() {
        let pkg = ResolvedPackage {
            requires_python: None,
            name: "requests".to_string(),
            version: "2.28.0".to_string(),
            dependencies: vec![],
            source: None,
            artifacts: PackageArtifacts {
                wheels: vec![Wheel {
                    file: "requests-2.28.0-py3-none-any.whl".to_string(),
                    url: None,
                    hash: None,
                    platforms: vec!["any".to_string()],
                    python_tag: Some("py3".to_string()),
                    abi_tag: Some("none".to_string()),
                }],
                sdist: None,
            },
        };
        let platform_tags = vec!["macosx_14_0_arm64".to_string(), "any".to_string()];
        for cp_tag in &["cp311", "cp310", "cp39"] {
            let selection = select_artifact_for_platform_with_cp(&pkg, &platform_tags, cp_tag);
            assert!(
                !selection.from_source,
                "py3 wheel should be compatible with {cp_tag}"
            );
        }
    }

    // --- Pre-release handling (Issue #341) ---

    #[test]
    fn test_is_prerelease_classification() {
        // Pre-release / dev versions (PEP 440): must be detected.
        for v in [
            "1.0rc1",
            "1.0.rc1",
            "1.0.0rc1",
            "1.0-alpha2",
            "1.0.alpha2",
            "1.0b3",
            "1.0.0b3",
            "1.0.beta3",
            "1.0c1",
            "1.0.preview1",
            "1.0.pre1",
            "1.0.dev1",
            "1.0.0.dev0",
            "1.0a1",
            "1.0a1.post2",
            "1.0.post1.dev2",
            "1.0.0RC1",
            "1.0.0A1",
            "2.0.0.DEV3",
            "1!2.0a1",
            "1.0rc1+local.tag",
        ] {
            assert!(is_prerelease(v), "{v} should be classified as pre-release");
        }

        // Final and post releases: NOT pre-releases.
        for v in [
            "1.0",
            "1.0.0",
            "2.5.0",
            "1.0.post1",
            "1.0.0.post2",
            "1.0.POST1",
            "1.0.rev1",
            "1.0.r1",
            "1!2.0",
            "1.0+local.abc",
            "1.0.post1+local",
        ] {
            assert!(
                !is_prerelease(v),
                "{v} should NOT be classified as pre-release"
            );
        }
    }

    #[tokio::test]
    async fn test_resolve_excludes_prereleases_by_default() {
        let mut index = InMemoryIndex::default();
        index.add("pkg", "1.0.0", Vec::<String>::new());
        index.add("pkg", "2.0.0rc1", Vec::<String>::new());

        let req = Requirement::any("pkg");
        let resolution = resolve(vec![req], &index).await.unwrap();

        assert_eq!(
            resolution.packages.get("pkg").map(|p| p.version.as_str()),
            Some("1.0.0"),
            "pre-release 2.0.0rc1 must be excluded by default"
        );
        assert!(
            resolution.prerelease_fallbacks.is_empty(),
            "no fallback warning expected when a stable version is selected"
        );
    }

    #[tokio::test]
    async fn test_resolve_allows_prereleases_with_opt_in() {
        let mut index = InMemoryIndex::default();
        index.add("pkg", "1.0.0", Vec::<String>::new());
        index.add("pkg", "2.0.0rc1", Vec::<String>::new());

        let req = Requirement::any("pkg");
        let resolution = resolve_with_options(
            vec![req],
            &index,
            ResolveOptions {
                allow_prerelease: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            resolution.packages.get("pkg").map(|p| p.version.as_str()),
            Some("2.0.0rc1"),
            "--pre opt-in must allow selecting the pre-release"
        );
        assert!(
            resolution.prerelease_fallbacks.is_empty(),
            "explicit opt-in is not a fallback; no warning expected"
        );
    }

    #[tokio::test]
    async fn test_resolve_allows_prerelease_when_specifier_mentions_one() {
        let mut index = InMemoryIndex::default();
        index.add("pkg", "1.0.0", Vec::<String>::new());
        index.add("pkg", "2.0.0rc1", Vec::<String>::new());

        // The specifier itself mentions a pre-release version, which opts this
        // package into pre-release candidates (PEP 440 / pip behavior).
        let req = Requirement::from_str("pkg>=2.0.0rc1").unwrap();
        let resolution = resolve(vec![req], &index).await.unwrap();

        assert_eq!(
            resolution.packages.get("pkg").map(|p| p.version.as_str()),
            Some("2.0.0rc1"),
            "a specifier mentioning a pre-release must allow pre-release candidates"
        );
        assert!(
            resolution.prerelease_fallbacks.is_empty(),
            "specifier-mentioned pre-release is not a fallback; no warning expected"
        );
    }

    #[tokio::test]
    async fn test_resolve_falls_back_to_prerelease_when_only_prereleases_exist() {
        let mut index = InMemoryIndex::default();
        index.add("pkg", "1.0.0rc1", Vec::<String>::new());
        index.add("pkg", "1.0.0rc2", Vec::<String>::new());

        let req = Requirement::any("pkg");
        let resolution = resolve(vec![req], &index).await.unwrap();

        assert_eq!(
            resolution.packages.get("pkg").map(|p| p.version.as_str()),
            Some("1.0.0rc2"),
            "when only pre-releases satisfy the constraints, the highest must be selected"
        );
        assert_eq!(
            resolution.prerelease_fallbacks,
            vec![PrereleaseFallback {
                name: "pkg".to_string(),
                version: "1.0.0rc2".to_string(),
            }],
            "fallback selection must be reported so callers can emit W_PRERELEASE_SELECTED"
        );
    }

    #[tokio::test]
    async fn test_resolve_prerelease_dependency_of_stable_package() {
        // A stable top-level package whose dependency only ships pre-releases:
        // the dependency should fall back and be reported.
        let mut index = InMemoryIndex::default();
        index.add("app", "1.0.0", vec!["libpre"]);
        index.add("libpre", "0.9.0b1", Vec::<String>::new());

        let req = Requirement::any("app");
        let resolution = resolve(vec![req], &index).await.unwrap();

        assert_eq!(
            resolution
                .packages
                .get("libpre")
                .map(|p| p.version.as_str()),
            Some("0.9.0b1")
        );
        assert_eq!(
            resolution.prerelease_fallbacks,
            vec![PrereleaseFallback {
                name: "libpre".to_string(),
                version: "0.9.0b1".to_string(),
            }]
        );
    }

    // ====================================================================
    // Issue #339: `==` / `!=` must use PEP 440-aware equality (zero-padded
    // release segments, case/separator normalization), not raw string
    // equality.
    // ====================================================================

    #[test]
    fn exact_spec_matches_zero_padded_release() {
        // PEP 440: `==1.4` must match `1.4.0` (zero padding).
        assert!(VersionSpec::Exact("1.4".to_string()).matches("1.4.0"));
    }

    #[test]
    fn exact_spec_normalizes_leading_zero_segments() {
        // PEP 440: `==2024.01` must match `2024.1`.
        assert!(VersionSpec::Exact("2024.01".to_string()).matches("2024.1"));
        assert!(VersionSpec::Exact("2024.1".to_string()).matches("2024.01"));
    }

    #[test]
    fn not_equal_spec_excludes_zero_padded_release() {
        // PEP 440: `!=1.0` must exclude `1.0.0` (the dangerous direction).
        assert!(!VersionSpec::NotEqual("1.0".to_string()).matches("1.0.0"));
    }

    #[test]
    fn exact_spec_is_case_insensitive_for_suffixes() {
        // PEP 440: `==1.0.POST1` must match `1.0.post1`.
        assert!(VersionSpec::Exact("1.0.POST1".to_string()).matches("1.0.post1"));
    }

    #[test]
    fn exact_spec_still_matches_identical_version() {
        assert!(VersionSpec::Exact("1.0".to_string()).matches("1.0"));
    }

    #[test]
    fn not_equal_spec_allows_different_version() {
        assert!(VersionSpec::NotEqual("1.0".to_string()).matches("1.1"));
    }

    #[test]
    fn exact_spec_falls_back_to_string_equality_when_unparseable() {
        // Versions without a numeric release segment fall back to raw
        // string equality.
        assert!(VersionSpec::Exact("not-a-version".to_string()).matches("not-a-version"));
        assert!(!VersionSpec::Exact("not-a-version".to_string()).matches("other"));
        assert!(!VersionSpec::NotEqual("not-a-version".to_string()).matches("not-a-version"));
        assert!(!VersionSpec::Exact("not-a-version".to_string()).matches("1.0.0"));
    }

    #[test]
    fn exact_spec_wildcard_behavior_unchanged() {
        // Wildcard specifiers are not supported by the resolver today
        // (`==1.4.*` never matched under string equality); the PEP 440
        // equality fix must not silently change that.
        assert!(!VersionSpec::Exact("1.4.*".to_string()).matches("1.4.2"));
        assert!(!VersionSpec::Exact("1.4.*".to_string()).matches("1.4.0"));
    }

    #[test]
    fn exact_spec_does_not_truncate_extra_release_segments() {
        // Zero padding pads the *shorter* release; `==1.2.3` must NOT
        // match `1.2.3.4` and `!=1.2.3` must not exclude it.
        assert!(!VersionSpec::Exact("1.2.3".to_string()).matches("1.2.3.4"));
        assert!(VersionSpec::NotEqual("1.2.3".to_string()).matches("1.2.3.4"));
        assert!(VersionSpec::Exact("1.2.3.0".to_string()).matches("1.2.3"));
    }

    #[test]
    fn requires_python_allows_basic_specifiers() {
        assert!(requires_python_allows(">=3.8", "3.9.18"));
        assert!(!requires_python_allows(">=3.10", "3.9.18"));
        assert!(requires_python_allows(">=3.8,<3.13", "3.12.1"));
        assert!(!requires_python_allows(">=3.8,<3.13", "3.13.0"));
        assert!(requires_python_allows("<=3.9", "3.9"));
        assert!(!requires_python_allows("!=3.9", "3.9.0"));
    }

    #[test]
    fn requires_python_allows_is_lenient_on_unsupported_clauses() {
        // Wildcards are outside this resolver's specifier support: skip
        // the clause rather than wrongly reject the candidate.
        assert!(requires_python_allows("!=3.0.*, >=2.7", "3.9.18"));
        // Unparseable clauses (bad metadata) must never exclude a version.
        assert!(requires_python_allows("garbage", "3.9.18"));
        assert!(requires_python_allows("", "3.9.18"));
        // ...but valid clauses alongside them still apply.
        assert!(!requires_python_allows("garbage, >=3.10", "3.9.18"));
    }
}
