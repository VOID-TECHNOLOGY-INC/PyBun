#![cfg(unix)]
#[path = "security_monitor_store_support/mod.rs"]
mod common;
use pybun::security_assessment::{
    monitor::*,
    qualification::{findings::FindingSeverity, service::SecurityAssessment},
    *,
};
use serde_json::json;
fn setup() -> (tempfile::TempDir, MonitorStore, Registration, MonitorConfig) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("project")).unwrap();
    let config = common::config(&root.join("project"));
    let store = MonitorStore::create(StoreOptions::new(root.join("state"))).unwrap();
    let registration = store.register(config.clone()).unwrap();
    (temp, store, registration, config)
}
fn check(store: &MonitorStore, id: &str, assessment: &SecurityAssessment, now: u64) -> CheckResult {
    let ticket = store.prepare_check(id).unwrap();
    let context = CheckContext::online(ticket.registration().config.domain.clone(), now);
    store
        .commit_check(&ticket, assessment, context, None)
        .unwrap()
}
fn contains(result: &CheckResult, event: MonitorEventType) -> bool {
    result
        .newly_committed_events
        .iter()
        .any(|value| value.event_type == event)
}
#[test]
fn explicit_no_fix_to_published_fix_and_new_advisory_are_distinct_from_initial_baseline() {
    let (_temp, store, registration, config) = setup();
    let first = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], false)],
            Some("2"),
            100,
        ),
        100,
    );
    assert_eq!(first.newly_committed_events.len(), 1);
    assert!(!contains(&first, MonitorEventType::FixCandidateAvailable));
    let fixed = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            101,
        ),
        101,
    );
    assert!(contains(&fixed, MonitorEventType::FixCandidateAvailable));
    assert!(!contains(&fixed, MonitorEventType::NewAdvisory));
    let stable = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            102,
        ),
        102,
    );
    assert!(stable.newly_committed_events.is_empty());
    assert_eq!(
        first.current.findings[0].finding_id,
        stable.current.findings[0].finding_id
    );
    let added = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![
                common::advisory("A", &[], true),
                common::advisory("B", &[], true),
            ],
            Some("2"),
            103,
        ),
        103,
    );
    assert!(contains(&added, MonitorEventType::NewAdvisory));
    assert_eq!(added.current.findings.len(), 2);
}
#[test]
fn public_fix_survives_unrelated_private_partial_and_complete_removal_survives_provider_failure() {
    let (_temp, store, registration, config) = setup();
    check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], false)],
            Some("2"),
            100,
        ),
        100,
    );
    let mut partial = common::assessment(
        &config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        101,
    );
    let mut private = partial.inventory.packages[0].clone();
    private.instance_id = "private".into();
    private.name = "secret-internal".into();
    private.source = SourceIdentity::new("private", "tenant", SourceKind::Unknown).unwrap();
    private.source_mapping = None;
    private.coverage.status = CoverageStatus::Unsupported;
    partial.inventory.packages.push(private);
    partial.inventory.coverage.inventory_instances.status = CoverageStatus::Partial;
    partial.coverage.status = CoverageStatus::Partial;
    partial.unknown_remainder = true;
    let positive = check(&store, &registration.monitor_id, &partial, 101);
    assert!(contains(&positive, MonitorEventType::FixCandidateAvailable));
    assert!(!positive.current.complete);
    let mut removed = common::assessment(&config, "1", vec![], None, 102);
    removed.inventory.packages.clear();
    removed.packages.clear();
    removed.providers[0].instances.clear();
    removed.providers[0].coverage.status = CoverageStatus::Error;
    removed.coverage.status = CoverageStatus::Partial;
    let resolved = check(&store, &registration.monitor_id, &removed, 102);
    assert!(
        resolved
            .newly_committed_events
            .iter()
            .any(
                |event| event.event_type == MonitorEventType::FindingResolved
                    && event.reason.as_deref() == Some("package_removed")
            )
    );
    assert!(resolved.current.findings.is_empty());
}
#[test]
fn same_version_disappearance_never_resolves_but_fresh_fully_observed_upgrade_can() {
    let (_temp, store, registration, config) = setup();
    let baseline = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            100,
        ),
        100,
    );
    let mut lock_only = common::assessment(
        &config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        101,
    );
    lock_only.inventory.target.as_mut().unwrap().lock_digest = Some("changed-only-lock".into());
    assert!(
        check(&store, &registration.monitor_id, &lock_only, 101)
            .newly_committed_events
            .is_empty()
    );
    let missing = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", vec![], None, 102),
        102,
    );
    assert!(!contains(&missing, MonitorEventType::FindingResolved));
    assert!(!missing.current.complete);
    assert_eq!(missing.current.findings.len(), 1);
    assert!(missing.current.findings[0].active);
    let upgraded = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "2", vec![], None, 103),
        103,
    );
    assert!(contains(&upgraded, MonitorEventType::FindingResolved));
    assert_eq!(upgraded.current.epoch_id, baseline.current.epoch_id);
    assert!(upgraded.current.findings.is_empty());
}
#[test]
fn offline_empty_inventory_and_inventory_failure_preserve_baseline_and_coalesce_failure_episodes() {
    let (_temp, store, registration, config) = setup();
    check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            100,
        ),
        100,
    );
    let mut empty = common::assessment(&config, "1", vec![], None, 101);
    empty.inventory.packages.clear();
    empty.packages.clear();
    empty.providers[0].instances.clear();
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let first = store
        .commit_check(
            &ticket,
            &empty,
            CheckContext::offline(config.domain.clone(), 101),
            None,
        )
        .unwrap();
    assert!(!contains(&first, MonitorEventType::FindingResolved));
    assert!(contains(&first, MonitorEventType::CheckIncomplete));
    assert_eq!(first.current.findings.len(), 1);
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let second = store
        .commit_check(
            &ticket,
            &empty,
            CheckContext::offline(config.domain.clone(), 102),
            None,
        )
        .unwrap();
    assert!(second.newly_committed_events.is_empty());
    empty.inventory.coverage.inventory_instances.status = CoverageStatus::Error;
    let failed = check(&store, &registration.monitor_id, &empty, 103);
    assert!(!contains(&failed, MonitorEventType::FindingResolved));
    assert_eq!(failed.current.findings.len(), 1);
    let recovered = common::assessment(
        &config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        104,
    );
    check(&store, &registration.monitor_id, &recovered, 104);
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let recurring = store
        .commit_check(
            &ticket,
            &empty,
            CheckContext::offline(config.domain, 105),
            None,
        )
        .unwrap();
    assert!(contains(&recurring, MonitorEventType::CheckIncomplete));
}
#[test]
fn fresh_explicit_withdrawal_and_alias_contradiction_have_different_transitions() {
    let (_temp, store, registration, config) = setup();
    check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &["shared"], true)],
            Some("2"),
            100,
        ),
        100,
    );
    let mut withdrawn = common::advisory("B", &["shared"], true);
    withdrawn["withdrawn"] = json!("2026-02-01T00:00:00Z");
    let conflict = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &["shared"], true), withdrawn],
            Some("2"),
            101,
        ),
        101,
    );
    assert!(contains(
        &conflict,
        MonitorEventType::FindingEvidenceChanged
    ));
    assert!(!contains(&conflict, MonitorEventType::AdvisoryWithdrawn));
    assert!(conflict.current.findings[0].active);
    let mut withdrawn = common::advisory("A", &["shared"], true);
    withdrawn["withdrawn"] = json!("2026-02-01T00:00:00Z");
    let explicit = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", vec![withdrawn], None, 102),
        102,
    );
    assert!(contains(&explicit, MonitorEventType::AdvisoryWithdrawn));
    assert!(!contains(&explicit, MonitorEventType::FindingResolved));
}
#[test]
fn severity_uses_last_known_level_without_ranking_unknown_below_low() {
    let (_temp, store, registration, config) = setup();
    let high = common::advisory("A", &[], true);
    check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", vec![high.clone()], None, 100),
        100,
    );
    let mut unknown = high.clone();
    unknown["database_specific"] = json!({});
    unknown["severity"] =
        json!([{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]);
    let unknown_result = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", vec![unknown], None, 101),
        101,
    );
    assert_eq!(
        unknown_result.current.findings[0].severity,
        FindingSeverity::Unknown
    );
    assert!(!contains(
        &unknown_result,
        MonitorEventType::SeverityIncreased
    ));
    let mut critical = high;
    critical["database_specific"]["severity"] = json!("CRITICAL");
    let result = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", vec![critical], None, 102),
        102,
    );
    assert!(contains(&result, MonitorEventType::SeverityIncreased));
}

#[test]
fn alias_addition_merge_and_split_keep_lineage_without_new_or_resolved_incidents() {
    let (_temp, store, registration, config) = setup();
    let baseline = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![
                common::advisory("A", &["X"], true),
                common::advisory("B", &["Y"], true),
            ],
            Some("2"),
            100,
        ),
        100,
    );
    let ids: std::collections::BTreeSet<_> = baseline
        .current
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect();
    let addition = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![
                common::advisory("A", &["000", "X"], true),
                common::advisory("B", &["Y"], true),
            ],
            Some("2"),
            101,
        ),
        101,
    );
    assert_eq!(
        addition
            .current
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        ids
    );
    assert!(!contains(&addition, MonitorEventType::NewAdvisory));
    let merged = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![
                common::advisory("A", &["X", "Y"], true),
                common::advisory("B", &["Y"], true),
            ],
            Some("2"),
            102,
        ),
        102,
    );
    assert_eq!(merged.current.findings.len(), 1);
    assert!(contains(&merged, MonitorEventType::FindingEvidenceChanged));
    assert!(!contains(&merged, MonitorEventType::NewAdvisory));
    assert!(!contains(&merged, MonitorEventType::FindingResolved));
    let split = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![
                common::advisory("A", &["X"], true),
                common::advisory("B", &["Y"], true),
            ],
            Some("2"),
            103,
        ),
        103,
    );
    assert_eq!(
        split
            .current
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        ids
    );
    assert!(contains(&split, MonitorEventType::FindingEvidenceChanged));
    assert!(!contains(&split, MonitorEventType::NewAdvisory));
    assert!(!contains(&split, MonitorEventType::FindingResolved));
    let stable = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![
                common::advisory("A", &["X"], true),
                common::advisory("B", &["Y"], true),
            ],
            Some("2"),
            104,
        ),
        104,
    );
    assert!(stable.newly_committed_events.is_empty());
}

#[test]
fn one_original_lineage_split_gets_stable_linked_children_instead_of_new_incidents() {
    let (_temp, store, registration, config) = setup();
    let baseline = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![
                common::advisory("A", &["shared"], true),
                common::advisory("B", &["shared"], true),
            ],
            None,
            100,
        ),
        100,
    );
    assert_eq!(baseline.current.findings.len(), 1);
    let parent = baseline.current.findings[0].finding_id.clone();
    let split = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![
                common::advisory("A", &[], true),
                common::advisory("B", &[], true),
            ],
            None,
            101,
        ),
        101,
    );
    assert_eq!(split.current.findings.len(), 2);
    assert!(
        split
            .current
            .findings
            .iter()
            .any(|finding| finding.finding_id == parent)
    );
    assert!(
        split
            .current
            .findings
            .iter()
            .any(|finding| finding.related_lineages.contains(&parent))
    );
    assert!(!contains(&split, MonitorEventType::NewAdvisory));
    assert!(!contains(&split, MonitorEventType::FindingResolved));
    let ids: std::collections::BTreeSet<_> = split
        .current
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect();
    let stable = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![
                common::advisory("B", &[], true),
                common::advisory("A", &[], true),
            ],
            None,
            102,
        ),
        102,
    );
    assert_eq!(
        stable
            .current
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        ids
    );
    assert!(stable.newly_committed_events.is_empty());
}

#[test]
fn exact_prior_artifact_yank_requires_fresh_same_source_evidence_and_reappearance_is_new_fix() {
    use pybun::security_assessment::{
        CoverageStatus,
        http::{EvidenceFreshness, FreshnessKind},
    };
    let (_temp, store, registration, config) = setup();
    let records = vec![common::advisory("A", &[], true)];
    let baseline = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", records.clone(), Some("2"), 100),
        100,
    );
    let original = baseline.current.findings[0].candidate.clone().unwrap();
    let mut unknown = common::assessment(&config, "1", records.clone(), Some("2"), 101);
    let registry = unknown.packages[0].registry.as_mut().unwrap();
    registry.catalog.releases.clear();
    registry.catalog.coverage.status = CoverageStatus::Partial;
    registry.catalog.enumeration_digest.clear();
    let deferred = check(&store, &registration.monitor_id, &unknown, 101);
    assert!(!contains(&deferred, MonitorEventType::CandidateUnavailable));
    assert!(
        deferred.current.findings[0]
            .candidate
            .as_ref()
            .unwrap()
            .publication_available
    );
    let mut yanked = common::assessment(&config, "1", records.clone(), Some("2"), 102);
    for release in &mut yanked.packages[0]
        .registry
        .as_mut()
        .unwrap()
        .catalog
        .releases
    {
        for file in &mut release.files {
            file.yanked = Some(true);
        }
    }
    yanked.packages[0].registry.as_mut().unwrap().freshness = EvidenceFreshness {
        kind: FreshnessKind::StaleCache,
        age_seconds: 100,
    };
    let stale = check(&store, &registration.monitor_id, &yanked, 102);
    assert!(!contains(&stale, MonitorEventType::CandidateUnavailable));
    yanked.packages[0].registry.as_mut().unwrap().freshness = Default::default();
    let fresh = check(&store, &registration.monitor_id, &yanked, 102);
    assert!(contains(&fresh, MonitorEventType::CandidateUnavailable));
    let unavailable = fresh.current.findings[0].candidate.as_ref().unwrap();
    assert_eq!(unavailable.artifacts, original.artifacts);
    assert!(!unavailable.publication_available);
    assert!(!unavailable.qualified_remediation);
    assert!(fresh.current.findings[0].active);
    let repeated = check(&store, &registration.monitor_id, &yanked, 103);
    assert!(!contains(&repeated, MonitorEventType::CandidateUnavailable));
    let restored = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", records, Some("2"), 104),
        104,
    );
    assert!(contains(&restored, MonitorEventType::FixCandidateAvailable));
    assert!(
        restored.current.findings[0]
            .candidate
            .as_ref()
            .unwrap()
            .publication_available
    );
}

#[test]
fn runner_failure_preserves_baseline_and_continuation_without_fabricated_assessment() {
    use pybun::security_assessment::monitor::MonitorDiagnostic;
    let (_temp, store, registration, config) = setup();
    let first = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            100,
        ),
        100,
    );
    let before = store.prepare_check(&registration.monitor_id).unwrap();
    let failure = vec![MonitorDiagnostic {
        code: "E_SECURITY_DEADLINE".into(),
        scope: "target".into(),
    }];
    let failed = store
        .commit_failure(
            &before,
            &failure,
            CheckContext::online(config.domain.clone(), 101),
            None,
        )
        .unwrap();
    assert!(contains(&failed, MonitorEventType::CheckIncomplete));
    assert_eq!(
        failed.current.findings[0].finding_id,
        first.current.findings[0].finding_id
    );
    assert!(failed.current.findings[0].active);
    assert!(!failed.current.complete);
    let after = store.prepare_check(&registration.monitor_id).unwrap();
    assert_eq!(before.known_advisories(), after.known_advisories());
    let next = store
        .commit_failure(
            &after,
            &failure,
            CheckContext::online(config.domain, 102),
            None,
        )
        .unwrap();
    assert!(next.newly_committed_events.is_empty());
}

#[test]
fn configured_epoch_reset_is_not_repeated_by_offline_checks_before_baseline() {
    let (_temp, store, registration, config) = setup();
    check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            100,
        ),
        100,
    );
    store
        .configure(&registration.monitor_id, 1, config.clone())
        .unwrap();
    for now in [101, 102] {
        let ticket = store.prepare_check(&registration.monitor_id).unwrap();
        let observed = common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            now,
        );
        let result = store
            .commit_check(
                &ticket,
                &observed,
                CheckContext::offline(config.domain.clone(), now),
                None,
            )
            .unwrap();
        assert_eq!(
            result
                .newly_committed_events
                .iter()
                .filter(|event| event.event_type == MonitorEventType::ObservationReset)
                .count(),
            usize::from(now == 101)
        );
        assert!(!result.current.initialized);
    }
}

#[test]
fn cached_alias_merge_cannot_rewrite_authoritative_lineage_or_fabricate_later_split() {
    let (_temp, store, registration, config) = setup();
    let separate = vec![
        common::advisory("A", &["X"], true),
        common::advisory("B", &["Y"], true),
    ];
    let baseline = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", separate.clone(), None, 100),
        100,
    );
    let ids = baseline
        .current
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let cached = common::assessment(
        &config,
        "1",
        vec![
            common::advisory("A", &["X", "Y"], true),
            common::advisory("B", &["Y"], true),
        ],
        None,
        101,
    );
    let offline = store
        .commit_check(
            &ticket,
            &cached,
            CheckContext::offline(config.domain.clone(), 101),
            None,
        )
        .unwrap();
    assert_eq!(offline.current.findings.len(), 2);
    assert!(!contains(
        &offline,
        MonitorEventType::FindingEvidenceChanged
    ));
    let fresh = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", separate, None, 102),
        102,
    );
    assert_eq!(
        fresh
            .current
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        ids
    );
    assert!(!contains(&fresh, MonitorEventType::FindingEvidenceChanged));
    assert!(!contains(&fresh, MonitorEventType::NewAdvisory));
}

#[test]
fn merge_retains_fix_history_from_absorbed_lineage_without_duplicate_fix_event() {
    let (_temp, store, registration, config) = setup();
    let mut no_boundary = common::advisory("A", &["X"], false);
    no_boundary["affected"][0]
        .as_object_mut()
        .unwrap()
        .remove("ranges");
    no_boundary["affected"][0]["versions"] = serde_json::json!(["1"]);
    let initial = vec![no_boundary.clone(), common::advisory("B", &["Y"], true)];
    let first = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", initial, Some("2"), 100),
        100,
    );
    assert_eq!(
        first
            .current
            .findings
            .iter()
            .filter(|finding| finding.candidate.is_some())
            .count(),
        1
    );
    no_boundary["aliases"] = serde_json::json!(["X", "Y"]);
    let merged = vec![no_boundary, common::advisory("B", &["Y"], true)];
    let second = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", merged.clone(), Some("2"), 101),
        101,
    );
    assert_eq!(second.current.findings.len(), 1);
    assert!(second.current.findings[0].candidate.is_some());
    let stable = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", merged, Some("2"), 102),
        102,
    );
    assert!(!contains(&stable, MonitorEventType::FixCandidateAvailable));
}

#[test]
fn mixed_cached_alias_bridge_locates_fresh_records_without_changing_other_lineage() {
    use pybun::security_assessment::http::{EvidenceFreshness, FreshnessKind};
    let (_temp, store, registration, config) = setup();
    let original = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![
                common::advisory("A", &["X"], true),
                common::advisory("B", &["Y"], true),
            ],
            None,
            100,
        ),
        100,
    );
    let b_id = original
        .current
        .findings
        .iter()
        .find(|finding| finding.aliases.contains(&"B".to_string()))
        .unwrap()
        .finding_id
        .clone();
    let mut mixed = common::assessment(
        &config,
        "1",
        vec![
            common::advisory("A", &["X"], true),
            common::advisory("B", &["Y"], true),
            common::advisory("C", &["X", "Y"], true),
        ],
        None,
        101,
    );
    for instance in &mut mixed.providers[0].instances {
        for record in &mut instance.records {
            if record.id != "B" {
                record.freshness = EvidenceFreshness {
                    kind: FreshnessKind::StaleCache,
                    age_seconds: 100,
                };
            }
        }
    }
    let observed = check(&store, &registration.monitor_id, &mixed, 101);
    assert_eq!(observed.current.findings.len(), 2);
    assert!(!contains(
        &observed,
        MonitorEventType::FindingEvidenceChanged
    ));
    let b = observed
        .current
        .findings
        .iter()
        .find(|finding| finding.finding_id == b_id)
        .unwrap();
    assert!(
        b.evidence
            .iter()
            .any(|evidence| evidence.record_id == "B" && evidence.currently_fresh)
    );
    assert!(
        observed
            .current
            .findings
            .iter()
            .filter(|finding| finding.finding_id != b_id)
            .all(|finding| !finding
                .evidence
                .iter()
                .any(|evidence| evidence.record_id == "B" && evidence.currently_fresh))
    );
}

#[test]
fn partial_alias_components_cannot_overwrite_current_fresh_positive_of_same_lineage() {
    use pybun::security_assessment::{
        http::{EvidenceFreshness, FreshnessKind},
        qualification::evidence::AffectedStatus,
    };
    let (_temp, store, registration, config) = setup();
    let baseline = check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![
                common::advisory("A", &["X", "Y"], true),
                common::advisory("B", &["Y"], true),
            ],
            None,
            100,
        ),
        100,
    );
    assert_eq!(baseline.current.findings.len(), 1);
    let mut current = common::assessment(
        &config,
        "1",
        vec![
            common::advisory("A", &["X"], true),
            common::advisory("B", &["Y"], true),
        ],
        None,
        101,
    );
    for instance in &mut current.providers[0].instances {
        for record in &mut instance.records {
            if record.id == "B" {
                record.freshness = EvidenceFreshness {
                    kind: FreshnessKind::StaleCache,
                    age_seconds: 10,
                };
            }
        }
    }
    let result = check(&store, &registration.monitor_id, &current, 101);
    assert_eq!(result.current.findings.len(), 1);
    assert_eq!(
        result.current.findings[0].observed_affected,
        AffectedStatus::Yes
    );
    assert!(!result.current.findings[0].complete);
    assert!(!contains(&result, MonitorEventType::NewAdvisory));
    assert!(!contains(&result, MonitorEventType::FindingResolved));
}

fn verify_hash_augmentation(candidate_complete: bool) {
    use pybun::security_assessment::CoverageStatus;

    let (_temp, store, registration, config) = setup();
    let records = vec![common::advisory("A", &[], true)];
    let first = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", records.clone(), Some("2"), 100),
        100,
    );
    let artifact = first.current.findings[0]
        .candidate
        .as_ref()
        .unwrap()
        .artifacts[0]
        .clone();
    let mut augmented = common::assessment(&config, "1", records, Some("2"), 101);
    for release in &mut augmented.packages[0]
        .registry
        .as_mut()
        .unwrap()
        .catalog
        .releases
    {
        for file in &mut release.files {
            file.hashes.insert("sha512".into(), "a".repeat(128));
        }
    }
    if !candidate_complete {
        augmented.packages[0].candidates[0]
            .qualification
            .authoritative = false;
        augmented.packages[0].candidates[0]
            .qualification
            .coverage
            .status = CoverageStatus::Partial;
    }
    let updated = check(&store, &registration.monitor_id, &augmented, 101);
    assert!(!contains(&updated, MonitorEventType::CandidateChanged));
    assert!(!contains(&updated, MonitorEventType::CandidateUnavailable));
    assert_eq!(
        updated.current.findings[0]
            .candidate
            .as_ref()
            .unwrap()
            .artifacts[0]
            .artifact_id,
        artifact.artifact_id
    );
    assert!(
        updated.current.findings[0]
            .candidate
            .as_ref()
            .unwrap()
            .publication_available
    );
}

#[test]
fn extra_hash_metadata_does_not_change_fresh_candidate() {
    verify_hash_augmentation(true);
}
#[test]
fn extra_hash_metadata_does_not_make_retained_candidate_unavailable() {
    verify_hash_augmentation(false);
}

#[test]
fn fresh_exact_candidate_advisory_correction_removes_remediation_claim_without_unpublishing() {
    for versions_only in [false, true] {
        let (_temp, store, registration, config) = setup();
        check(
            &store,
            &registration.monitor_id,
            &common::assessment(
                &config,
                "1",
                vec![common::advisory("A", &[], true)],
                Some("2"),
                100,
            ),
            100,
        );
        let mut corrected = common::advisory("A", &[], false);
        if versions_only {
            corrected["affected"][0]
                .as_object_mut()
                .unwrap()
                .remove("ranges");
            corrected["affected"][0]["versions"] = serde_json::json!(["1"]);
        }
        let observed = common::assessment(&config, "1", vec![corrected], Some("2"), 101);
        let result = check(&store, &registration.monitor_id, &observed, 101);
        assert!(contains(&result, MonitorEventType::CandidateChanged));
        assert!(!contains(&result, MonitorEventType::CandidateUnavailable));
        let prior = result.current.findings[0].candidate.as_ref().unwrap();
        assert!(!prior.qualified_remediation);
        assert!(prior.publication_available);
        assert!(result.current.findings[0].active);
        let repeated = check(&store, &registration.monitor_id, &observed, 102);
        assert!(!contains(&repeated, MonitorEventType::CandidateChanged));
    }
}

#[test]
fn missing_configured_provider_cannot_publish_fix_even_when_input_qualified_for_smaller_provider_set()
 {
    let (_temp, store, registration, mut config) = setup();
    config.domain.authoritative_providers.push("backup".into());
    let changed = store
        .configure(&registration.monitor_id, 1, config.clone())
        .unwrap();
    let result = check(
        &store,
        &changed.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            100,
        ),
        100,
    );
    assert!(result.current.findings[0].active);
    assert!(result.current.findings[0].candidate.is_none());
    assert!(!result.current.complete);
}
#[test]
fn cached_first_severity_cannot_seed_authoritative_increase_history() {
    let (_temp, store, registration, config) = setup();
    check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", vec![], None, 100),
        100,
    );
    let mut low = common::advisory("B", &[], true);
    low["database_specific"]["severity"] = serde_json::json!("LOW");
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let offline = store
        .commit_check(
            &ticket,
            &common::assessment(&config, "1", vec![low], None, 101),
            CheckContext::offline(config.domain.clone(), 101),
            None,
        )
        .unwrap();
    assert!(offline.current.findings[0].last_known_severity.is_none());
    let mut critical = common::advisory("B", &[], true);
    critical["database_specific"]["severity"] = serde_json::json!("CRITICAL");
    let fresh = check(
        &store,
        &registration.monitor_id,
        &common::assessment(&config, "1", vec![critical], None, 102),
        102,
    );
    assert!(contains(&fresh, MonitorEventType::NewAdvisory));
    assert!(!contains(&fresh, MonitorEventType::SeverityIncreased));
}

#[test]
fn stale_empty_provider_query_cannot_resolve_after_upgrade() {
    let (_temp, store, registration, config) = setup();
    check(
        &store,
        &registration.monitor_id,
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            100,
        ),
        100,
    );
    let mut changed = common::assessment(&config, "2", vec![], None, 100000);
    changed.providers[0].observed_at = 100;
    let result = check(&store, &registration.monitor_id, &changed, 100000);
    assert!(result.current.findings[0].active);
    assert!(!contains(&result, MonitorEventType::FindingResolved));
    assert!(!result.current.complete);
}
