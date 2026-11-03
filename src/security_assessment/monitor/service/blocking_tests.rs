use super::*;

#[cfg(unix)]
#[test]
fn selected_profile_store_deadline_expires_during_post_lookup_lock_contention() {
    // The registration/authorized lookup exists BEFORE contention begins.
    let (temp, mut store, expected, _) = ticket_fixture();
    store.options.deadline = Some(Instant::now() + Duration::from_secs(5));
    let held = store
        .root
        .lock(Instant::now() + Duration::from_secs(5))
        .unwrap();
    let deadline = Instant::now() + Duration::from_millis(40);
    let selected = narrow_store_deadline(Arc::new(store), deadline).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let operation = tokio::spawn(task(deadline, true, move || {
            remove_authorized_registration(&selected, &expected)
        }));
        tokio::time::sleep(Duration::from_millis(150)).await;
        let returned = operation.is_finished();
        drop(held);
        let result = operation.await.unwrap();
        assert!(
            returned,
            "selected profile deadline was widened to the global store deadline"
        );
        assert_eq!(result.unwrap_err().code, "E_MONITOR_DEADLINE");
        let remaining = MonitorStore::open(StoreOptions::new(
            temp.path().canonicalize().unwrap().join("state"),
        ))
        .unwrap()
        .list()
        .unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "expired selected-profile removal wrote after lock release"
        );
    });
}

#[cfg(unix)]
#[test]
fn selected_profile_store_deadline_never_extends_or_mutates_shared_handles() {
    let (_, mut store, _, _) = ticket_fixture();
    let original = Instant::now() + Duration::from_secs(1);
    store.options.deadline = Some(original);
    let selected =
        narrow_store_deadline(Arc::new(store), original + Duration::from_secs(1)).unwrap();
    assert_eq!(selected.options.deadline, Some(original));
    let alias = selected.clone();
    assert_eq!(
        narrow_store_deadline(selected, Instant::now())
            .err()
            .unwrap()
            .code,
        "E_MONITOR_STATE_BUSY"
    );
    assert_eq!(alias.options.deadline, Some(original));
}

#[cfg(unix)]
fn ticket_fixture() -> (tempfile::TempDir, MonitorStore, Registration, MonitorConfig) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let project = root.join("project");
    std::fs::create_dir(&project).unwrap();
    let config = MonitorConfig {
        profile_id: "app".into(),
        name: "test".into(),
        freshness_ttl_seconds: 30,
        include_prereleases: false,
        domain: ComparisonDomain {
            project_root: project.clone(),
            environment_root: project.join(".venv"),
            backend: InventoryBackend::Uv,
            target: crate::security_assessment::InventoryTarget::Installed,
            scope: Default::default(),
            runtime: None,
            source_policy_digest: "a".repeat(64),
            provider_config_digest: "b".repeat(64),
            index_config_digest: "c".repeat(64),
            observation_version: 1,
            authoritative_providers: vec!["osv".into()],
        },
    };
    let store = MonitorStore::create(StoreOptions::new(root.join("state"))).unwrap();
    let expected = store.register(config.clone()).unwrap();
    (temp, store, expected, config)
}

#[cfg(unix)]
fn interposed_private_scope(store: &MonitorStore, old: &Registration) -> Registration {
    let mut config = old.config.clone();
    config.profile_id = "private-b".into();
    config.domain.source_policy_digest = "d".repeat(64);
    let newer = store
        .configure(&old.monitor_id, old.config_revision, config)
        .unwrap();
    let ticket = store.prepare_check(&newer.monitor_id).unwrap();
    store
        .commit_failure(
            &ticket,
            &[MonitorDiagnostic {
                code: "E_PRIVATE_B".into(),
                scope: "PRIVATE_B".into(),
            }],
            CheckContext::online(newer.config.domain.clone(), 10),
            None,
        )
        .unwrap();
    newer
}

#[cfg(unix)]
#[test]
fn final_authority_race_events_never_reads_interposed_private_scope() {
    let (_temp, store, old, _) = ticket_fixture();
    let newer = interposed_private_scope(&store, &old);
    let result = read_authorized_events(&store, &old, None);
    assert!(
        result.is_err(),
        "old A authority read private B: {result:?}"
    );
    assert_eq!(result.unwrap_err().code, "E_MONITOR_STALE_CHECK");
    assert!(
        read_authorized_events(&store, &newer, None)
            .unwrap()
            .current
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.scope == "PRIVATE_B")
    );
}

#[cfg(unix)]
#[test]
fn final_authority_race_remove_cannot_delete_interposed_private_scope() {
    let (temp, store, old, _) = ticket_fixture();
    let newer = interposed_private_scope(&store, &old);
    let before = std::fs::read(temp.path().join("state/registry.json")).unwrap();
    let result = remove_authorized_registration(&store, &old);
    assert!(result.is_err(), "old A authority deleted B: {result:?}");
    assert_eq!(result.unwrap_err().code, "E_MONITOR_STALE_CHECK");
    assert_eq!(
        std::fs::read(temp.path().join("state/registry.json")).unwrap(),
        before
    );
    assert_eq!(store.list().unwrap()[0].epoch_id, newer.epoch_id);
}

#[cfg(unix)]
#[test]
fn final_authority_race_future_revision_cannot_reconfigure_interposed_private_scope() {
    let (temp, store, old, _) = ticket_fixture();
    let newer = interposed_private_scope(&store, &old);
    let before = std::fs::read(temp.path().join("state/registry.json")).unwrap();
    let result =
        configure_authorized_registration(&store, &old, newer.config_revision, old.config.clone());
    assert!(
        result.is_err(),
        "guessed future revision rolled B back to A: {result:?}"
    );
    assert_eq!(result.unwrap_err().code, "E_MONITOR_STALE_CONFIG");
    assert_eq!(
        std::fs::read(temp.path().join("state/registry.json")).unwrap(),
        before
    );
}

#[cfg(unix)]
#[test]
fn final_review_pre_ticket_configure_is_rejected_before_observation() {
    let (temp, store, expected, mut config) = ticket_fixture();
    config.domain.source_policy_digest = "d".repeat(64);
    config.include_prereleases = true;
    let configured = store
        .configure(&expected.monitor_id, expected.config_revision, config)
        .unwrap();
    let poisoned = temp
        .path()
        .join("state")
        .join(format!("{}.checkpoint.json", expected.monitor_id));
    std::fs::write(&poisoned, "untrusted-new-scope-checkpoint").unwrap();
    let before = std::fs::read(temp.path().join("state/registry.json")).unwrap();
    let result = prepare_authorized_ticket(&store, expected, None);
    assert!(
        result.is_err(),
        "an old authorized lookup adopted a newer configured ticket"
    );
    assert_eq!(result.unwrap_err().code, "E_MONITOR_STALE_CHECK");
    let unchanged = store.list().unwrap();
    assert_eq!(unchanged[0].epoch_id, configured.epoch_id);
    assert_eq!(unchanged[0].config_revision, configured.config_revision);
    assert_eq!(
        std::fs::read(poisoned).unwrap(),
        b"untrusted-new-scope-checkpoint"
    );
    assert_eq!(
        std::fs::read(temp.path().join("state/registry.json")).unwrap(),
        before
    );
}

#[cfg(unix)]
#[test]
fn final_review_returned_configure_scope_is_pinned_before_ticket_adoption() {
    let (_temp, store, initial, config) = ticket_fixture();
    let expected = store
        .configure(&initial.monitor_id, initial.config_revision, config.clone())
        .unwrap();
    let newer = store
        .configure(&expected.monitor_id, expected.config_revision, config)
        .unwrap();
    assert_eq!(
        store.prepare_check_expected(&expected).unwrap_err().code,
        "E_MONITOR_STALE_CHECK"
    );
    assert!(store.prepare_check_expected(&newer).is_ok());
}

#[cfg(unix)]
#[test]
fn final_review_fresher_same_scope_generation_does_not_require_reconfiguration() {
    let (_temp, store, expected, _config) = ticket_fixture();
    let initial = store.prepare_check(&expected.monitor_id).unwrap();
    store
        .commit_failure(
            &initial,
            &[MonitorDiagnostic {
                code: "E_TEST".into(),
                scope: "target".into(),
            }],
            CheckContext::online(expected.config.domain.clone(), 10),
            None,
        )
        .unwrap();
    let fresh = prepare_authorized_ticket(&store, expected, None).unwrap();
    assert!(fresh.generation > initial.generation);
}

#[test]
fn queued_mutation_expires_while_pool_is_saturated_and_never_writes_later() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("late-write");
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
        let target = marker.clone();
        let operation = tokio::spawn(task(
            Instant::now() + Duration::from_millis(40),
            true,
            move || {
                std::fs::write(target, "forbidden").unwrap();
                Ok(())
            },
        ));
        tokio::time::sleep(Duration::from_millis(150)).await;
        let returned = operation.is_finished();
        release_tx.send(()).unwrap();
        let result = operation.await.unwrap();
        blocker.await.unwrap();
        assert!(
            returned,
            "a queued mutation extended the authorized request deadline"
        );
        assert_eq!(
            result.unwrap_err().commit_status,
            CommitStatus::NotCommitted
        );
        assert!(
            !marker.exists(),
            "expired queued mutation wrote after its response"
        );
    });
}

#[test]
fn entered_atomic_operation_is_awaited_to_its_actual_terminal_outcome() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("entered-write");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    runtime.block_on(async {
        let operation = tokio::spawn(task(
            Instant::now() + Duration::from_millis(40),
            true,
            move || {
                std::fs::write(marker, "already-entered").unwrap();
                let _ = entered_tx.send(());
                release_rx.recv().unwrap();
                Err::<(), _>(MonitorError::new("E_MONITOR_STATE").indeterminate())
            },
        ));
        entered_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !operation.is_finished(),
            "an entered atomic effect was detached at timeout"
        );
        release_tx.send(()).unwrap();
        let result = operation.await.unwrap();
        assert_eq!(
            result.unwrap_err().commit_status,
            CommitStatus::Indeterminate
        );
    });
}
