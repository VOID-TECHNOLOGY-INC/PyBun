#![cfg(unix)]
#[path = "security_monitor_store_support/mod.rs"]
mod common;
use pybun::security_assessment::monitor::{
    CheckContext, EventReplayCursor, MonitorEventType, MonitorStore, StoreOptions,
};
#[test]
fn committed_baseline_and_replay_share_identical_ids_without_consuming_events() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("project")).unwrap();
    let config = common::config(&root.join("project"));
    let store = MonitorStore::create(StoreOptions::new(root.join("state"))).unwrap();
    let registration = store.register(config.clone()).unwrap();
    let origin = EventReplayCursor::origin(&registration);
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let assessment = common::assessment(
        &config,
        "1",
        vec![common::advisory("A", &["CVE-A"], true)],
        Some("2"),
        100,
    );
    let checked = store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(config.domain.clone(), 100),
            Some(&origin),
        )
        .unwrap();
    assert_eq!(checked.newly_committed_events.len(), 1);
    assert_eq!(
        checked.newly_committed_events[0].event_type,
        MonitorEventType::BaselineObserved
    );
    assert_eq!(checked.current.findings.len(), 1);
    let again = store
        .events(&registration.monitor_id, Some(&origin))
        .unwrap();
    assert_eq!(again.events, checked.replay.events);
    assert_eq!(
        store
            .events(&registration.monitor_id, Some(&origin))
            .unwrap()
            .events,
        again.events
    );
    let next = store
        .events(&registration.monitor_id, again.next_cursor.as_ref())
        .unwrap();
    assert!(next.events.is_empty());
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let unchanged = store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(config.domain, 101),
            None,
        )
        .unwrap();
    assert!(unchanged.newly_committed_events.is_empty());
    assert_eq!(
        unchanged.current.findings[0].finding_id,
        checked.current.findings[0].finding_id
    );
}

#[test]
fn config_only_registration_learns_runtime_at_first_explicit_check_without_extra_epoch() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("project")).unwrap();
    let mut config = common::config(&root.join("project"));
    config.domain.runtime = None;
    let store = MonitorStore::create(StoreOptions::new(root.join("state"))).unwrap();
    let registered = store.register(config.clone()).unwrap();
    assert!(registered.observed_runtime.is_none());
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let assessment = common::assessment(
        &config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        100,
    );
    let result = store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(config.domain, 100),
            None,
        )
        .unwrap();
    assert_eq!(result.current.epoch_id, registered.epoch_id);
    assert_eq!(result.current.config_revision, 1);
    assert_eq!(
        result
            .newly_committed_events
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        vec![MonitorEventType::BaselineObserved]
    );
    let learned = store.list().unwrap().pop().unwrap();
    assert!(learned.observed_runtime.is_some());
    assert!(learned.config.domain.runtime.is_none());
}

#[test]
fn configure_hides_old_scope_until_new_baseline_and_rejects_old_cursor_with_new_summary() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("private-project")).unwrap();
    std::fs::create_dir(root.join("public-project")).unwrap();
    let private = common::config(&root.join("private-project"));
    let public = common::config(&root.join("public-project"));
    let store = MonitorStore::create(StoreOptions::new(root.join("state"))).unwrap();
    let registration = store.register(private.clone()).unwrap();
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let old = store
        .commit_check(
            &ticket,
            &common::assessment(
                &private,
                "1",
                vec![common::advisory("PRIVATE-ID", &[], true)],
                Some("2"),
                100,
            ),
            CheckContext::online(private.domain, 100),
            None,
        )
        .unwrap();
    let old_cursor = old.replay.next_cursor.unwrap();
    let configured = store
        .configure(&registration.monitor_id, 1, public.clone())
        .unwrap();
    let pending = store.events(&registration.monitor_id, None).unwrap_err();
    assert_eq!(pending.code, "E_MONITOR_BASELINE_REQUIRED");
    let summary = pending.replay.unwrap();
    assert_eq!(summary.current.epoch_id, configured.epoch_id);
    assert!(!summary.current.initialized);
    assert!(summary.current.findings.is_empty());
    assert!(summary.events.is_empty());
    assert!(
        !serde_json::to_string(&summary)
            .unwrap()
            .contains("PRIVATE-ID")
    );
    let scoped = store
        .events(&registration.monitor_id, Some(&old_cursor))
        .unwrap_err();
    assert_eq!(scoped.code, "E_MONITOR_CURSOR_SCOPE");
    assert!(scoped.replay.unwrap().current.findings.is_empty());
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let fresh = store
        .commit_check(
            &ticket,
            &common::assessment(&public, "1", vec![], None, 101),
            CheckContext::online(public.domain, 101),
            None,
        )
        .unwrap();
    assert!(fresh.current.findings.is_empty());
    assert!(
        fresh
            .replay
            .events
            .iter()
            .all(|event| event.epoch_id == configured.epoch_id)
    );
}

#[test]
fn prepared_check_exposes_only_durable_known_record_ids_and_remaps_exact_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("project")).unwrap();
    let config = common::config(&root.join("project"));
    let store = MonitorStore::create(StoreOptions::new(root.join("state"))).unwrap();
    let registered = store.register(config.clone()).unwrap();
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    assert!(ticket.known_advisories().is_empty());
    let first = common::assessment(
        &config,
        "1",
        vec![common::advisory("A", &["alias"], true)],
        Some("2"),
        100,
    );
    store
        .commit_check(
            &ticket,
            &first,
            CheckContext::online(config.domain.clone(), 100),
            None,
        )
        .unwrap();
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let witnesses = ticket.known_advisories();
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0].record_id, "A");
    assert_eq!(witnesses[0].provider_id, "osv");
    let upgraded = common::assessment(
        &config,
        "1.5",
        vec![common::advisory("A", &["alias"], true)],
        Some("2"),
        101,
    );
    let remapped = ticket.assessment_options(&upgraded.inventory).unwrap();
    assert_eq!(remapped.previous_candidates.len(), 1);
    assert_eq!(
        remapped.previous_candidates[0].instance_id,
        upgraded.inventory.packages[0].instance_id
    );
    assert_eq!(remapped.previous_candidates[0].version, "2");
    assert_eq!(
        witnesses[0].package_key,
        pybun::security_assessment::monitor::logical_package_key(&upgraded.inventory.packages[0])
            .unwrap()
    );
}

#[test]
fn replay_retention_reports_gap_and_advances_only_to_last_returned_event() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("project")).unwrap();
    let config = common::config(&root.join("project"));
    let mut options = StoreOptions::new(root.join("state"));
    options.limits.retained_events = 105;
    options.limits.history_seconds = 10;
    let store = MonitorStore::create(options).unwrap();
    let registered = store.register(config.clone()).unwrap();
    let initial = vec![common::advisory("A", &[], false)];
    let first = store.prepare_check(&registered.monitor_id).unwrap();
    store
        .commit_check(
            &first,
            &common::assessment(&config, "1", initial.clone(), None, 100),
            CheckContext::online(config.domain.clone(), 100),
            None,
        )
        .unwrap();
    let mut all = initial;
    all.extend((0..150).map(|i| common::advisory(&format!("B{i:03}"), &[], false)));
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let added = store
        .commit_check(
            &ticket,
            &common::assessment(&config, "1", all.clone(), None, 101),
            CheckContext::online(config.domain.clone(), 101),
            None,
        )
        .unwrap();
    assert_eq!(added.newly_committed_count, 150);
    assert!(added.newly_committed_truncated);
    assert!(added.newly_committed_gap);
    let expired = store
        .events(
            &registered.monitor_id,
            Some(&EventReplayCursor::origin(&registered)),
        )
        .unwrap_err();
    assert_eq!(expired.code, "E_MONITOR_CURSOR_EXPIRED");
    let details = expired.replay.unwrap();
    assert_eq!(details.current.findings.len(), 151);
    assert_eq!(details.low_water_mark, 47);
    assert_eq!(details.high_water_mark, 151);
    assert!(details.next_cursor.is_none());
    let page = store.events(&registered.monitor_id, None).unwrap();
    assert_eq!(page.events.len(), 100);
    assert!(page.has_more);
    assert_eq!(page.events.last().unwrap().sequence, 146);
    let rest = store
        .events(&registered.monitor_id, page.next_cursor.as_ref())
        .unwrap();
    assert_eq!(rest.events.len(), 5);
    assert_eq!(rest.events[0].sequence, 147);
    assert!(!rest.has_more);
    let last = rest.next_cursor.unwrap();
    assert!(
        store
            .events(&registered.monitor_id, Some(&last))
            .unwrap()
            .events
            .is_empty()
    );
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let aged = store
        .commit_check(
            &ticket,
            &common::assessment(&config, "1", all, None, 200),
            CheckContext::online(config.domain, 200),
            None,
        )
        .unwrap();
    assert_eq!(aged.current.findings.len(), 151);
    assert!(aged.replay.events.is_empty());
    assert_eq!(aged.replay.high_water_mark, 151);
    assert!(aged.replay.next_cursor.is_none());
    let resume = store.events(&registered.monitor_id, Some(&last)).unwrap();
    assert!(resume.events.is_empty());
}

#[test]
fn committed_check_with_expired_replay_cursor_still_returns_bounded_new_event_receipt() {
    use pybun::security_assessment::monitor::CommitStatus;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("project")).unwrap();
    let config = common::config(&root.join("project"));
    let mut options = StoreOptions::new(root.join("state"));
    options.limits.retained_events = 1;
    let store = MonitorStore::create(options).unwrap();
    let registered = store.register(config.clone()).unwrap();
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    store
        .commit_check(
            &ticket,
            &common::assessment(
                &config,
                "1",
                vec![common::advisory("A", &[], false)],
                None,
                100,
            ),
            CheckContext::online(config.domain.clone(), 100),
            None,
        )
        .unwrap();
    let ticket = store.prepare_check(&registered.monitor_id).unwrap();
    let changed = common::assessment(
        &config,
        "1",
        vec![
            common::advisory("A", &[], false),
            common::advisory("B", &[], false),
        ],
        None,
        101,
    );
    let error = store
        .commit_check(
            &ticket,
            &changed,
            CheckContext::online(config.domain.clone(), 101),
            Some(&EventReplayCursor::origin(&registered)),
        )
        .unwrap_err();
    assert_eq!(error.code, "E_MONITOR_CURSOR_EXPIRED");
    assert_eq!(error.commit_status, CommitStatus::Committed);
    let receipt = error.receipt.unwrap();
    assert_eq!(receipt.newly_committed_count, 1);
    assert!(!receipt.newly_committed_gap);
    assert_eq!(receipt.newly_committed_events.len(), 1);
    assert_eq!(
        receipt.newly_committed_events,
        store.events(&registered.monitor_id, None).unwrap().events
    );
    let retry = store
        .commit_check(
            &ticket,
            &changed,
            CheckContext::online(config.domain, 101),
            Some(&EventReplayCursor::origin(&registered)),
        )
        .unwrap_err();
    assert_eq!(retry.receipt.unwrap(), receipt);
}
