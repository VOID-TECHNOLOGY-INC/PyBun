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
                    "依存関係を解決できませんでした: {name} は {constraint} を満たすバージョンが見つかりません"
                ))
                .with_code("E_RESOLVE_MISSING")
                .with_suggestion("パッケージ名・制約・インデックス内容を確認し、必要なら制約を緩めて再実行してください。")
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
                        "{name} がインデックスに存在しない可能性があります（タイプミス/インデックス違い）"
                    ))
                    .with_code("H_RESOLVE_MISSING_NOT_IN_INDEX"),
                );
            } else {
                // Keep the hint compact.
                let sample: Vec<String> = available_versions.iter().take(5).cloned().collect();
                diags.push(
                    Diagnostic::hint(format!("利用可能なバージョン例: {}", sample.join(", ")))
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
                    "依存関係のバージョン衝突: {name} は既に {existing} が選択されていますが、別経路で {requested} が要求されました"
                ))
                .with_code("E_RESOLVE_CONFLICT")
                .with_suggestion(format!("衝突している要求元を確認し、{name} の制約を揃える（同一バージョン/範囲へ）か、上位依存のバージョンを調整してください。"))
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
                Diagnostic::hint("衝突ツリーを辿って、同じパッケージに対して異なる制約が入っている箇所を解消してください。")
                    .with_code("H_RESOLVE_CONFLICT_TREE"),
            );
            diags
        }
        ResolveError::Io(msg) => {
            vec![
                Diagnostic::error(format!(
                    "パッケージ情報の取得中にIOエラーが発生しました: {}",
                    msg
                ))
                .with_code("E_RESOLVE_IO")
                .with_suggestion(
                    "インターネット接続やインデックスファイルのパス/権限を確認してください。",
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
}
