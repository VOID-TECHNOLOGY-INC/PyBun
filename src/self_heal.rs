use crate::resolver::{Requirement, ResolveError};
use crate::schema::{Diagnostic, FixCandidate, RiskLevel};
use serde_json::json;

/// Build the fix candidate(s) for a missing/undetected Python runtime.
///
/// We cannot safely guess which version a project needs, so the suggested
/// command is informational only (`auto_applicable: false`) — an agent or
/// human still has to pick a version before `pybun python install` runs.
pub fn fix_candidates_for_missing_python() -> Vec<FixCandidate> {
    vec![FixCandidate::new(
        "pybun python list --all",
        "List installable Python versions, then run `pybun python install <version>`",
        RiskLevel::Medium,
        false,
    )]
}

/// Build the fix candidate for stale PyPI metadata cache entries
/// (see Issue #202). Safe to run unattended: it only deletes cache
/// files that are already known to be stale.
pub fn fix_candidates_for_stale_pypi_cache() -> Vec<FixCandidate> {
    vec![FixCandidate::new(
        "pybun gc",
        "Remove stale PyPI metadata cache entries",
        RiskLevel::Low,
        true,
    )]
}

/// Build the fix candidate for a lockfile containing placeholder hashes
/// instead of verified sha256 digests. Re-resolving touches the lockfile
/// and may hit the network, so this is not auto-applied.
pub fn fix_candidates_for_lock_drift() -> Vec<FixCandidate> {
    vec![FixCandidate::new(
        "pybun install",
        "Re-resolve and re-lock dependencies against an index that provides sha256 digests",
        RiskLevel::Medium,
        false,
    )]
}

pub fn diagnostics_for_resolve_error(
    requirements: &[Requirement],
    err: &ResolveError,
) -> Vec<Diagnostic> {
    let root_reqs: Vec<String> = requirements.iter().map(|r| r.to_string()).collect();

    match err {
        ResolveError::Missing {
            name,
            constraint,
            requested_by,
            available_versions,
        } => {
            let mut diags = Vec::new();
            diags.push(
                Diagnostic::error(format!(
                    "Could not resolve dependencies: no version of {name} satisfies the constraint {constraint}"
                ))
                .with_code("E_RESOLVE_MISSING")
                .with_suggestion(
                    "Check the package name, constraint, and index contents, and re-run with a looser constraint if needed.",
                )
                .with_context(json!({
                    "name": name,
                    "constraint": constraint,
                    "requested_by": requested_by,
                    "available_versions": available_versions,
                    "root_requirements": root_reqs,
                })),
            );

            if available_versions.is_empty() {
                diags.push(
                    Diagnostic::hint(format!(
                        "{name} may not exist in the index (check for a typo or a different index)"
                    ))
                    .with_code("H_RESOLVE_MISSING_NOT_IN_INDEX"),
                );
            } else {
                // Keep the hint compact.
                let sample: Vec<String> = available_versions.iter().take(5).cloned().collect();
                diags.push(
                    Diagnostic::hint(format!("Available versions include: {}", sample.join(", ")))
                        .with_code("H_RESOLVE_AVAILABLE_VERSIONS")
                        .with_context(json!({ "sample": sample })),
                );
            }
            diags
        }
        ResolveError::Conflict {
            name,
            existing,
            requested,
            existing_chain,
            requested_chain,
        } => {
            let mut diags = Vec::new();
            diags.push(
                Diagnostic::error(format!(
                    "Dependency version conflict: {name} already has {existing} selected, but {requested} was requested via a different path"
                ))
                .with_code("E_RESOLVE_CONFLICT")
                .with_suggestion(format!(
                    "Check the conflicting requesters and align the constraints on {name} (same version/range), or adjust the version of an upstream dependency."
                ))
                .with_context(json!({
                    "name": name,
                    "existing": existing,
                    "requested": requested,
                    "existing_chain": existing_chain,
                    "requested_chain": requested_chain,
                    "root_requirements": root_reqs,
                })),
            );

            diags.push(
                Diagnostic::hint(
                    "Walk the conflict tree and resolve the places where the same package has different constraints.",
                )
                .with_code("H_RESOLVE_CONFLICT_TREE"),
            );
            diags
        }
        ResolveError::Io(msg) => {
            vec![
                Diagnostic::error(format!(
                    "An IO error occurred while fetching package metadata: {}",
                    msg
                ))
                .with_code("E_RESOLVE_IO")
                .with_suggestion(
                    "Check your internet connection and the index file's path/permissions.",
                )
                .with_context(json!({ "error": msg })),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_python_fix_is_not_auto_applicable() {
        let candidates = fix_candidates_for_missing_python();
        assert_eq!(candidates.len(), 1);
        assert!(!candidates[0].auto_applicable);
        assert_eq!(candidates[0].risk, RiskLevel::Medium);
        assert!(candidates[0].command.starts_with("pybun python"));
    }

    #[test]
    fn stale_pypi_cache_fix_is_low_risk_and_auto_applicable() {
        let candidates = fix_candidates_for_stale_pypi_cache();
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].auto_applicable);
        assert_eq!(candidates[0].risk, RiskLevel::Low);
        assert_eq!(candidates[0].command, "pybun gc");
    }

    #[test]
    fn lock_drift_fix_requires_manual_confirmation() {
        let candidates = fix_candidates_for_lock_drift();
        assert_eq!(candidates.len(), 1);
        assert!(!candidates[0].auto_applicable);
        assert_eq!(candidates[0].command, "pybun install");
    }

    /// Regression test for Issue #270: `diagnostics[].message` and
    /// `diagnostics[].suggestion` must be locale-neutral (English) since
    /// `code` is the stable machine-readable contract that agents/tooling
    /// key off of. These strings must never depend on OS/shell locale
    /// (LANG/LC_*) — they are compiled-in literals, so this also guards
    /// against regressions to non-English hardcoded text.
    fn assert_ascii_only(label: &str, text: &str) {
        assert!(
            text.is_ascii(),
            "{label} must be locale-neutral ASCII/English text, got: {text:?}"
        );
    }

    #[test]
    fn resolve_error_missing_diagnostics_are_locale_neutral() {
        let requirements = vec![Requirement::any("requests")];
        let err = ResolveError::Missing {
            name: "requests".to_string(),
            constraint: ">=2.0".to_string(),
            requested_by: None,
            available_versions: vec!["1.0.0".to_string()],
        };
        let diags = diagnostics_for_resolve_error(&requirements, &err);
        assert!(!diags.is_empty());
        for d in &diags {
            assert_ascii_only("message", &d.message);
            if let Some(suggestion) = &d.suggestion {
                assert_ascii_only("suggestion", suggestion);
            }
        }
    }

    #[test]
    fn resolve_error_missing_not_in_index_diagnostics_are_locale_neutral() {
        let requirements = vec![Requirement::any("requests")];
        let err = ResolveError::Missing {
            name: "requests".to_string(),
            constraint: ">=2.0".to_string(),
            requested_by: None,
            available_versions: vec![],
        };
        let diags = diagnostics_for_resolve_error(&requirements, &err);
        assert!(!diags.is_empty());
        for d in &diags {
            assert_ascii_only("message", &d.message);
            if let Some(suggestion) = &d.suggestion {
                assert_ascii_only("suggestion", suggestion);
            }
        }
    }

    #[test]
    fn resolve_error_conflict_diagnostics_are_locale_neutral() {
        let requirements = vec![Requirement::any("requests")];
        let err = ResolveError::Conflict {
            name: "requests".to_string(),
            existing: "1.0.0".to_string(),
            requested: "2.0.0".to_string(),
            existing_chain: vec!["root".to_string()],
            requested_chain: vec!["root".to_string(), "urllib3".to_string()],
        };
        let diags = diagnostics_for_resolve_error(&requirements, &err);
        assert!(!diags.is_empty());
        for d in &diags {
            assert_ascii_only("message", &d.message);
            if let Some(suggestion) = &d.suggestion {
                assert_ascii_only("suggestion", suggestion);
            }
        }
    }

    #[test]
    fn resolve_error_io_diagnostics_are_locale_neutral() {
        let requirements = vec![Requirement::any("requests")];
        let err = ResolveError::Io("permission denied".to_string());
        let diags = diagnostics_for_resolve_error(&requirements, &err);
        assert!(!diags.is_empty());
        for d in &diags {
            assert_ascii_only("message", &d.message);
            if let Some(suggestion) = &d.suggestion {
                assert_ascii_only("suggestion", suggestion);
            }
        }
    }
}
