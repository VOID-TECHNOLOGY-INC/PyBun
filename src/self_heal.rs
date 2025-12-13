use crate::resolver::{Requirement, ResolveError};
use crate::schema::Diagnostic;
use serde_json::json;

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
    }
}
