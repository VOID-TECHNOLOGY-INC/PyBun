//! A zero ceiling admits same-capture fresh facts and never ages them by one second.
#![cfg(unix)]
#[path = "security_monitor_store_support/mod.rs"]
mod common;
use pybun::security_assessment::monitor::*;

#[test]
fn zero_ttl_accepts_fresh_age_zero_but_never_older_fix_or_removal_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("project")).unwrap();
    let mut config = common::config(&root.join("project"));
    config.freshness_ttl_seconds = 0;
    let store = MonitorStore::create(StoreOptions::new(root.join("state"))).unwrap();
    let registration = store.register(config.clone()).unwrap();
    let commit = |assessment: &_, now| {
        let ticket = store.prepare_check(&registration.monitor_id).unwrap();
        store
            .commit_check(
                &ticket,
                assessment,
                CheckContext::online(ticket.registration().config.domain.clone(), now),
                None,
            )
            .unwrap()
    };
    let baseline = commit(
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], false)],
            Some("2"),
            100,
        ),
        100,
    );
    assert!(baseline.current.complete);
    assert!(baseline.current.findings[0].active);
    assert!(baseline.current.findings[0].candidate.is_none());
    let old_fix = commit(
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            100,
        ),
        101,
    );
    assert!(!old_fix.current.complete);
    assert!(old_fix.current.findings[0].active);
    assert!(old_fix.current.findings[0].candidate.is_none());
    assert!(
        !old_fix
            .newly_committed_events
            .iter()
            .any(|event| event.event_type == MonitorEventType::FixCandidateAvailable)
    );
    let fresh_fix = commit(
        &common::assessment(
            &config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            102,
        ),
        102,
    );
    assert!(
        fresh_fix
            .newly_committed_events
            .iter()
            .any(|event| event.event_type == MonitorEventType::FixCandidateAvailable)
    );
    let mut removed = common::assessment(&config, "1", vec![], None, 102);
    removed.inventory.packages.clear();
    removed.packages.clear();
    for provider in &mut removed.providers {
        provider.instances.clear();
    }
    let stale_removed = commit(&removed, 103);
    assert!(stale_removed.current.findings[0].active);
    assert!(
        !stale_removed
            .newly_committed_events
            .iter()
            .any(|event| event.event_type == MonitorEventType::FindingResolved)
    );
    removed.inventory.observed_at = 104;
    let offline_ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let offline = store
        .commit_check(
            &offline_ticket,
            &removed,
            CheckContext::offline(config.domain.clone(), 104),
            None,
        )
        .unwrap();
    assert!(offline.current.findings[0].active);
    assert!(
        !offline
            .newly_committed_events
            .iter()
            .any(|event| event.event_type == MonitorEventType::FindingResolved)
    );
    let fresh_removed = commit(&removed, 104);
    assert!(fresh_removed.current.findings.is_empty());
    assert!(
        fresh_removed
            .newly_committed_events
            .iter()
            .any(|event| event.event_type == MonitorEventType::FindingResolved)
    );
    assert_eq!(store.list().unwrap()[0].config.freshness_ttl_seconds, 0);
}
