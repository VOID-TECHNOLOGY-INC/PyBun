use super::*;
use crate::security_assessment::{
    CoverageUnit,
    qualification::{
        evidence::AffectedStatus,
        findings::{FindingAssessment, FindingCluster, FindingSeverity},
        service::{PackageAssessment, SecurityAssessment},
    },
};
use std::time::{Duration, Instant};

fn observed_high() -> SecurityAssessment {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/security_check_v2.json"
    ))
    .unwrap();
    let mut assessment: SecurityAssessment =
        serde_json::from_value(fixture["detail"]["assessment"].clone()).unwrap();
    assessment.packages.push(PackageAssessment {
        instance_id: "observed-instance".into(),
        installed: FindingAssessment {
            instance_id: "observed-instance".into(),
            source_id: "public".into(),
            auth_scope_id: "public".into(),
            scope_variant: "installed".into(),
            clusters: vec![FindingCluster {
                ids: vec!["OBSERVED-HIGH".into()],
                aliases: vec![],
                cluster_digest: "cluster".into(),
                affected: AffectedStatus::Yes,
                complete: true,
                severity: FindingSeverity::High,
                records: vec![],
                diagnostics: vec![],
            }],
            affected: AffectedStatus::Yes,
            complete: true,
            coverage: CoverageUnit::default(),
            diagnostics: vec![],
        },
        registry: None,
        candidates: vec![],
        metadata_recommendations: vec![],
        lowest_assessed_candidate: None,
        lowest_proven_candidate: None,
        pending_previous_candidates: vec![],
        unknown_remainder: false,
        diagnostics: vec![],
    });
    assessment
}

#[test]
fn queued_pure_finalization_expires_with_known_high_summary_before_pool_release() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocker = runtime.spawn_blocking(move || {
        started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    started_rx.recv().unwrap();
    runtime.block_on(async {
        let work = tokio::spawn(prepare_monitor_assessment(
            observed_high(),
            "app".into(),
            "policy".into(),
            Some(CheckSeverityThreshold::High),
            4096,
            Instant::now() + Duration::from_millis(40),
        ));
        tokio::time::sleep(Duration::from_millis(150)).await;
        let returned = work.is_finished();
        release_tx.send(()).unwrap();
        let result = work.await.unwrap();
        blocker.await.unwrap();
        assert!(
            returned,
            "queued semantic preparation extended the deadline"
        );
        let partial = result.unwrap_err();
        assert_eq!(partial.exit_code, 3);
        assert_eq!(partial.diagnostics[0].code, "E_SECURITY_DEADLINE");
        assert_eq!(partial.threshold_match_count, 1);
        assert_eq!(partial.threshold_matches[0].severity, FindingSeverity::High);
        assert_eq!(partial.threshold_matches[0].advisory_ids, ["OBSERVED-HIGH"]);
        assert!(partial.assessment.is_none());
        assert!(partial.assessment_id.is_none());
        assert_eq!(partial.omitted.unwrap().finding_clusters, 1);
    });
}

#[tokio::test]
async fn completed_pure_preparation_preserves_full_observation_and_semantic_ids() {
    let result = prepare_monitor_assessment(
        observed_high(),
        "app".into(),
        "policy".into(),
        Some(CheckSeverityThreshold::High),
        65536,
        Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(result.threshold_match_count, 1);
    assert!(result.assessment.is_some());
    assert!(result.assessment_id.is_some());
    assert!(result.observation_id.is_some());
}
