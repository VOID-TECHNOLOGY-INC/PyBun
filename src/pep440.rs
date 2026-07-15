//! PEP 440 version parsing and ordering (Issue #340).
//!
//! Purpose-built replacement for the semver shim previously used by the
//! resolver. Implements the canonical PEP 440 sort key: epoch dominates,
//! release segments compare numerically with zero padding, and the
//! `dev < a < b < rc < final < post` chain is honoured with numeric
//! (not lexical) ordering inside each segment. Local version labels sort
//! above their public counterpart, numeric local segments above
//! alphanumeric ones.
//!
//! Parsing is strict against the PEP 440 grammar (after normalization:
//! case, `v` prefix, `-`/`_`/`.` separators, spelling aliases like
//! `alpha`→`a` and `rev`→`post`). Strings that do not fit the grammar
//! return `None` so callers can fall back to legacy comparison paths.

use std::cmp::Ordering;

/// Pre-release phase in canonical spelling. Variant order gives PEP 440
/// ordering: `a < b < rc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PreReleasePhase {
    Alpha,
    Beta,
    ReleaseCandidate,
}

/// One dot-separated segment of a local version label. Variant order gives
/// PEP 440 ordering: alphanumeric segments sort below numeric ones.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LocalSegment {
    Alpha(String),
    Num(u64),
}

/// A parsed PEP 440 version. Ordering follows the canonical sort key from
/// the spec; equality is `cmp == Equal`, so `1.4` == `1.4.0` and
/// `1.0rc1` == `1.0c1`.
#[derive(Debug, Clone)]
pub struct Pep440Version {
    pub epoch: u64,
    pub release: Vec<u64>,
    pub pre: Option<(PreReleasePhase, u64)>,
    pub post: Option<u64>,
    pub dev: Option<u64>,
    pub local: Vec<LocalSegment>,
}

/// Sort key for the pre-release slot, mirroring pypa/packaging `_cmpkey`:
/// a dev-only release sorts below every pre-release of the same release
/// (`MinSentinel`), a version with no pre-segment sorts above all of them
/// (`MaxSentinel`).
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum PreKey {
    MinSentinel,
    Value(PreReleasePhase, u64),
    MaxSentinel,
}

/// Sort key for the dev slot: `None` (no dev segment) sorts above any
/// `.devN`.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum DevKey {
    Value(u64),
    MaxSentinel,
}

impl Pep440Version {
    /// Parse a version string against the PEP 440 grammar. Returns `None`
    /// when the string does not fit (e.g. wildcards like `1.4.*`, plain
    /// words, trailing garbage).
    pub fn parse(input: &str) -> Option<Self> {
        let lower = input.trim().to_ascii_lowercase();
        let mut s = lower.as_str();
        s = s.strip_prefix('v').unwrap_or(s);
        if s.is_empty() {
            return None;
        }

        // Epoch: `N!`
        let mut epoch = 0u64;
        if let Some((head, rest)) = s.split_once('!') {
            if head.is_empty() || !head.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            epoch = head.parse().ok()?;
            s = rest;
        }

        // Release: `N(.N)*`
        let mut release = Vec::new();
        loop {
            let digits = leading_digits(s);
            if digits.is_empty() {
                return None;
            }
            release.push(digits.parse().ok()?);
            s = &s[digits.len()..];
            match s.as_bytes().first() {
                Some(b'.') if s.as_bytes().get(1).is_some_and(u8::is_ascii_digit) => {
                    s = &s[1..];
                }
                _ => break,
            }
        }

        // Pre-release: `[.-_]? (a|b|c|rc|alpha|beta|pre|preview) [.-_]? N?`
        let mut pre = None;
        if let Some((phase, rest)) = take_alpha_segment(
            s,
            &[
                ("alpha", PreReleasePhase::Alpha),
                ("a", PreReleasePhase::Alpha),
                ("beta", PreReleasePhase::Beta),
                ("b", PreReleasePhase::Beta),
                ("preview", PreReleasePhase::ReleaseCandidate),
                ("pre", PreReleasePhase::ReleaseCandidate),
                ("rc", PreReleasePhase::ReleaseCandidate),
                ("c", PreReleasePhase::ReleaseCandidate),
            ],
        ) {
            let (num, rest) = take_optional_number(rest)?;
            pre = Some((phase, num));
            s = rest;
        }

        // Post-release: `[.-_]? (post|rev|r) [.-_]? N?` or the implicit
        // `-N` spelling.
        let mut post = None;
        if let Some(((), rest)) = take_alpha_segment(s, &[("post", ()), ("rev", ()), ("r", ())]) {
            let (num, rest) = take_optional_number(rest)?;
            post = Some(num);
            s = rest;
        } else if let Some(rest) = s.strip_prefix('-') {
            let digits = leading_digits(rest);
            if digits.is_empty() {
                return None;
            }
            post = Some(digits.parse().ok()?);
            s = &rest[digits.len()..];
        }

        // Dev release: `[.-_]? dev [.-_]? N?`
        let mut dev = None;
        if let Some(((), rest)) = take_alpha_segment(s, &[("dev", ())]) {
            let (num, rest) = take_optional_number(rest)?;
            dev = Some(num);
            s = rest;
        }

        // Local version label: `+seg([.-_]seg)*`
        let mut local = Vec::new();
        if let Some(rest) = s.strip_prefix('+') {
            if rest.is_empty() {
                return None;
            }
            for seg in rest.split(['.', '-', '_']) {
                if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return None;
                }
                if seg.bytes().all(|b| b.is_ascii_digit()) {
                    local.push(LocalSegment::Num(seg.parse().ok()?));
                } else {
                    local.push(LocalSegment::Alpha(seg.to_string()));
                }
            }
            s = "";
        }

        if !s.is_empty() {
            return None;
        }

        Some(Pep440Version {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    /// True when the version carries a pre-release or dev segment
    /// (post-releases are final releases per PEP 440).
    pub fn is_prerelease(&self) -> bool {
        self.pre.is_some() || self.dev.is_some()
    }

    /// True when the version carries a local version label (`+...`).
    pub fn has_local(&self) -> bool {
        !self.local.is_empty()
    }

    /// Compare ignoring local version labels — the "public" comparison
    /// used when an `==`/`!=` specifier has no local label of its own.
    pub fn public_cmp(&self, other: &Self) -> Ordering {
        self.cmp_release(other)
            .then_with(|| self.pre_key().cmp(&other.pre_key()))
            .then_with(|| self.post.cmp(&other.post))
            .then_with(|| self.dev_key().cmp(&other.dev_key()))
    }

    fn cmp_release(&self, other: &Self) -> Ordering {
        self.epoch.cmp(&other.epoch).then_with(|| {
            let len = self.release.len().max(other.release.len());
            let seg = |rel: &[u64], i: usize| rel.get(i).copied().unwrap_or(0);
            (0..len)
                .map(|i| seg(&self.release, i).cmp(&seg(&other.release, i)))
                .find(|ord| *ord != Ordering::Equal)
                .unwrap_or(Ordering::Equal)
        })
    }

    fn pre_key(&self) -> PreKey {
        match self.pre {
            Some((phase, num)) => PreKey::Value(phase, num),
            // `1.0.dev1` sorts below `1.0a1`; a final/post-only version
            // sorts above every pre-release.
            None if self.post.is_none() && self.dev.is_some() => PreKey::MinSentinel,
            None => PreKey::MaxSentinel,
        }
    }

    fn dev_key(&self) -> DevKey {
        match self.dev {
            Some(num) => DevKey::Value(num),
            None => DevKey::MaxSentinel,
        }
    }
}

impl PartialEq for Pep440Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Pep440Version {}

impl PartialOrd for Pep440Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Pep440Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.public_cmp(other)
            .then_with(|| self.local.cmp(&other.local))
    }
}

fn leading_digits(s: &str) -> &str {
    let end = s
        .as_bytes()
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(s.len());
    &s[..end]
}

/// Match an optional `.`/`-`/`_` separator followed by one of `words`
/// (longest spelling first in the caller's table). The word must not be
/// followed by another letter, so `post` does not swallow the `p` of a
/// hypothetical `p1`. Returns the mapped value and the remaining input.
fn take_alpha_segment<'a, T: Copy>(s: &'a str, words: &[(&str, T)]) -> Option<(T, &'a str)> {
    let trimmed = s
        .strip_prefix(['.', '-', '_'])
        .filter(|rest| rest.starts_with(|c: char| c.is_ascii_alphabetic()))
        .unwrap_or(s);
    for (word, value) in words {
        if let Some(rest) = trimmed.strip_prefix(word)
            && !rest.starts_with(|c: char| c.is_ascii_alphabetic())
        {
            return Some((*value, rest));
        }
    }
    None
}

/// Parse an optional `[.-_]? N` after a segment word (implicit `0` when
/// absent, e.g. `1.2a` == `1.2a0`). Rejects a dangling separator with no
/// digits (`1.0.post.` is not a valid version).
fn take_optional_number(s: &str) -> Option<(u64, &str)> {
    let (stripped, had_sep) = match s.strip_prefix(['.', '-', '_']) {
        Some(rest) => (rest, true),
        None => (s, false),
    };
    let digits = leading_digits(stripped);
    if digits.is_empty() {
        if had_sep {
            return None;
        }
        return Some((0, s));
    }
    Some((digits.parse().ok()?, &stripped[digits.len()..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Pep440Version {
        Pep440Version::parse(s).unwrap_or_else(|| panic!("{s} should parse"))
    }

    fn assert_order(lower: &str, higher: &str) {
        assert_eq!(
            v(lower).cmp(&v(higher)),
            Ordering::Less,
            "{lower} < {higher}"
        );
        assert_eq!(
            v(higher).cmp(&v(lower)),
            Ordering::Greater,
            "{higher} > {lower}"
        );
    }

    #[test]
    fn post_release_sorts_above_base() {
        assert_order("1.0", "1.0.post1");
        assert_order("1.0.post1", "1.0.post2");
        assert_order("1.0.post10", "1.0.1");
    }

    #[test]
    fn epoch_dominates() {
        assert_order("2.0", "1!1.0");
        assert_order("1!2.0", "2!0.1");
    }

    #[test]
    fn numeric_prerelease_ordering() {
        assert_order("1.0a2", "1.0a10");
        assert_order("1.0rc2", "1.0rc10");
    }

    #[test]
    fn pep440_segment_chain() {
        assert_order("1.0.dev1", "1.0a1");
        assert_order("1.0a1", "1.0b1");
        assert_order("1.0b1", "1.0rc1");
        assert_order("1.0rc1", "1.0");
        assert_order("1.0", "1.0.post1.dev1");
        assert_order("1.0.post1.dev1", "1.0.post1");
    }

    #[test]
    fn dev_sorts_below_prereleases_of_same_release() {
        assert_order("1.0.dev99", "1.0a0");
        assert_order("1.0a1.dev1", "1.0a1");
        assert_order("0.9", "1.0.dev1");
    }

    #[test]
    fn zero_padded_releases_are_equal() {
        assert_eq!(v("1.4"), v("1.4.0"));
        assert_eq!(v("2024.01"), v("2024.1"));
        assert_ne!(v("1.2.3"), v("1.2.3.4"));
    }

    #[test]
    fn spelling_aliases_normalize() {
        assert_eq!(v("1.0rc1"), v("1.0c1"));
        assert_eq!(v("1.0rc1"), v("1.0.pre1"));
        assert_eq!(v("1.0rc1"), v("1.0-preview.1"));
        assert_eq!(v("1.0a1"), v("1.0alpha1"));
        assert_eq!(v("1.0b1"), v("1.0-beta_1"));
        assert_eq!(v("1.0.post1"), v("1.0rev1"));
        assert_eq!(v("1.0.post1"), v("1.0-r1"));
        assert_eq!(v("1.0.post1"), v("1.0-1"));
        assert_eq!(v("1.2a"), v("1.2a0"));
        assert_eq!(v("V1.0"), v("1.0"));
    }

    #[test]
    fn local_versions_sort_above_public_and_numeric_above_alpha() {
        assert_order("1.0", "1.0+abc");
        assert_order("1.0+abc", "1.0+abc.1");
        assert_order("1.0+ubuntu1", "1.0+5");
        assert_order("1.0+5", "1.0+6");
        assert_eq!(v("1.0+foo-1"), v("1.0+foo.1"));
    }

    #[test]
    fn public_cmp_ignores_local() {
        assert_eq!(v("1.0+local").public_cmp(&v("1.0")), Ordering::Equal);
        assert!(v("1.0+local").has_local());
        assert!(!v("1.0").has_local());
    }

    #[test]
    fn prerelease_detection() {
        assert!(v("1.0a1").is_prerelease());
        assert!(v("1.0.dev1").is_prerelease());
        assert!(v("1.0a1.post2").is_prerelease());
        assert!(!v("1.0.post1").is_prerelease());
        assert!(!v("1!1.0+local").is_prerelease());
    }

    #[test]
    fn invalid_strings_do_not_parse() {
        for bad in [
            "",
            "abc",
            "1.4.*",
            "1.0.x",
            "1.0..2",
            "1.0+",
            "1.0+a..b",
            "!1.0",
            "1.0.post.",
            "1.0-",
            "1.0 .1",
            "1.0garbage",
        ] {
            assert!(
                Pep440Version::parse(bad).is_none(),
                "{bad:?} should not parse"
            );
        }
    }

    #[test]
    fn whitespace_and_case_are_normalized() {
        assert_eq!(v(" 1.0.POST1 "), v("1.0.post1"));
        assert_eq!(v("1.0RC1"), v("1.0rc1"));
    }
}
