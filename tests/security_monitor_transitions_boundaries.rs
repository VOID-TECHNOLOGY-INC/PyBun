#![cfg(unix)]
#[path = "security_monitor_store_support/mod.rs"]
mod common;
use pybun::security_assessment::monitor::*;
fn setup() -> (tempfile::TempDir, MonitorStore, Registration) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("project")).unwrap();
    let store = MonitorStore::create(StoreOptions::new(root.join("state"))).unwrap();
    let registered = store
        .register(common::config(&root.join("project")))
        .unwrap();
    (temp, store, registered)
}
fn commit(
    store: &MonitorStore,
    registered: &Registration,
    records: Vec<serde_json::Value>,
    now: u64,
) -> CheckResult {
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let assessment =
        common::assessment(&ticket.registration().config, "1", records, Some("2"), now);
    store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(ticket.registration().config.domain.clone(), now),
            None,
        )
        .unwrap()
}
#[test]
fn prose_fetch_times_and_irrelevant_reference_changes_do_not_create_incidents() {
    let (_temp, store, registered) = setup();
    let original = common::advisory("A", &["CVE-A"], true);
    let first = commit(&store, &registered, vec![original.clone()], 100);
    let mut edited = original;
    edited["modified"] = serde_json::json!("2026-02-01T00:00:00Z");
    edited["summary"] = serde_json::json!("New prose");
    edited["details"] = serde_json::json!("Additional narrative");
    edited["references"] =
        serde_json::json!([{"type":"WEB","url":"https://example.invalid/updated"}]);
    let later = commit(&store, &registered, vec![edited], 101);
    assert!(later.newly_committed_events.is_empty());
    assert_eq!(
        later.current.findings[0].finding_id,
        first.current.findings[0].finding_id
    );
    assert_ne!(
        later.current.findings[0].evidence[0].payload_digest,
        first.current.findings[0].evidence[0].payload_digest
    );
}
#[test]
fn current_policy_and_actual_runtime_changes_reset_epoch_without_historical_resolution() {
    let (_temp, store, registered) = setup();
    commit(
        &store,
        &registered,
        vec![common::advisory("A", &[], true)],
        100,
    );
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let mut assessment = common::assessment(
        &registered.config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        101,
    );
    assessment
        .inventory
        .target
        .as_mut()
        .unwrap()
        .tag_profile
        .python_version = "3.14.0".into();
    let changed = store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(registered.config.domain.clone(), 101),
            None,
        )
        .unwrap();
    assert_ne!(changed.current.epoch_id, registered.epoch_id);
    assert_eq!(
        changed
            .newly_committed_events
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        vec![
            MonitorEventType::ObservationReset,
            MonitorEventType::BaselineObserved
        ]
    );
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let mut domain = ticket.registration().config.domain.clone();
    domain.source_policy_digest = "9".repeat(64);
    let again = store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(domain, 101),
            None,
        )
        .unwrap();
    assert_ne!(again.current.epoch_id, changed.current.epoch_id);
    assert!(again.newly_committed_events.iter().all(|event| matches!(
        event.event_type,
        MonitorEventType::ObservationReset | MonitorEventType::BaselineObserved
    )));
}
#[test]
fn configured_revision_rejects_old_ticket_without_publishing_under_new_policy() {
    let (_temp, store, registered) = setup();
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let next = store
        .configure(&registered.monitor_id, 1, registered.config.clone())
        .unwrap();
    let assessment = common::assessment(
        &registered.config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        100,
    );
    assert_eq!(
        store
            .commit_check(
                &ticket,
                &assessment,
                CheckContext::online(registered.config.domain, 100),
                None
            )
            .unwrap_err()
            .code,
        "E_MONITOR_STALE_CONFIG"
    );
    let pending = store
        .events(&registered.monitor_id, None)
        .unwrap_err()
        .replay
        .unwrap();
    assert_eq!(pending.current.epoch_id, next.epoch_id);
    assert!(pending.current.findings.is_empty());
}
#[test]
fn oversized_inventory_is_rejected_without_trimming_or_changing_checkpoint() {
    let (_temp, store, registered) = setup();
    let baseline = commit(
        &store,
        &registered,
        vec![common::advisory("A", &[], true)],
        100,
    );
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let mut huge = common::assessment(&registered.config, "1", vec![], None, 101);
    huge.inventory.packages = vec![huge.inventory.packages[0].clone(); 1001];
    assert_eq!(
        store
            .commit_check(
                &ticket,
                &huge,
                CheckContext::online(registered.config.domain, 101),
                None
            )
            .unwrap_err()
            .code,
        "E_MONITOR_ASSESSMENT"
    );
    let after = store.events(&registered.monitor_id, None).unwrap();
    assert_eq!(after.current, baseline.current);
    assert_eq!(after.events, baseline.replay.events);
}
#[test]
fn first_offline_observation_never_becomes_authoritative_baseline_or_fix() {
    let (_temp, store, registered) = setup();
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let assessment = common::assessment(
        &registered.config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        100,
    );
    let offline = store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::offline(registered.config.domain.clone(), 100),
            None,
        )
        .unwrap();
    assert!(!offline.current.initialized);
    assert!(
        offline
            .newly_committed_events
            .iter()
            .all(|event| event.event_type == MonitorEventType::CheckIncomplete)
    );
    let first = commit(
        &store,
        &registered,
        vec![common::advisory("A", &[], true)],
        101,
    );
    assert_eq!(
        first
            .newly_committed_events
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        vec![MonitorEventType::BaselineObserved]
    );
}
#[test]
fn wrong_source_registry_evidence_cannot_negate_exact_previous_artifact() {
    let (_temp, store, registered) = setup();
    commit(
        &store,
        &registered,
        vec![common::advisory("A", &[], true)],
        100,
    );
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let mut observed = common::assessment(
        &registered.config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        101,
    );
    let registry = observed.packages[0].registry.as_mut().unwrap();
    registry.source_auth_scope_id = "different-tenant".into();
    registry.catalog.releases.clear();
    let result = store
        .commit_check(
            &ticket,
            &observed,
            CheckContext::online(registered.config.domain, 101),
            None,
        )
        .unwrap();
    assert!(
        result.current.findings[0]
            .candidate
            .as_ref()
            .unwrap()
            .publication_available
    );
    assert!(
        !result
            .newly_committed_events
            .iter()
            .any(|event| event.event_type == MonitorEventType::CandidateUnavailable)
    );
}
