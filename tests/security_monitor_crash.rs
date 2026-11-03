#![cfg(unix)]
#[path = "security_monitor_store_support/mod.rs"]
mod common;
use pybun::security_assessment::monitor::*;
use std::{
    io,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
fn setup() -> (tempfile::TempDir, StoreOptions, Registration) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("project")).unwrap();
    let options = StoreOptions::new(root.join("state"));
    let registered = MonitorStore::create(options.clone())
        .unwrap()
        .register(common::config(&root.join("project")))
        .unwrap();
    (temp, options, registered)
}
struct FailOnce {
    stage: CommitStage,
    failed: AtomicBool,
}
impl CommitObserver for FailOnce {
    fn observe(&self, target: CommitTarget, stage: CommitStage) -> io::Result<()> {
        if target == CommitTarget::Checkpoint
            && stage == self.stage
            && !self.failed.swap(true, Ordering::SeqCst)
        {
            Err(io::Error::other("injected checkpoint failure"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn replace_success_and_directory_fsync_failure_are_indeterminate_and_retry_keeps_ids() {
    for stage in [
        CommitStage::BeforeReplace,
        CommitStage::BeforeDirectorySync,
        CommitStage::BeforeResponse,
    ] {
        let (_temp, options, registration) = setup();
        let store = MonitorStore::open(options.clone())
            .unwrap()
            .with_observer(Arc::new(FailOnce {
                stage,
                failed: AtomicBool::new(false),
            }));
        let ticket = store.prepare_check(&registration.monitor_id).unwrap();
        let assessment = common::assessment(
            &registration.config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            100,
        );
        let failed = store
            .commit_check(
                &ticket,
                &assessment,
                CheckContext::online(registration.config.domain.clone(), 100),
                None,
            )
            .unwrap_err();
        assert_eq!(
            failed.commit_status,
            if stage == CommitStage::BeforeReplace {
                CommitStatus::NotCommitted
            } else {
                CommitStatus::Indeterminate
            }
        );
        let before = MonitorStore::open(options.clone())
            .unwrap()
            .events(&registration.monitor_id, None)
            .ok();
        let recovered = store
            .commit_check(
                &ticket,
                &assessment,
                CheckContext::online(registration.config.domain.clone(), 100),
                None,
            )
            .unwrap();
        assert_eq!(recovered.newly_committed_events.len(), 1);
        assert_eq!(recovered.newly_committed_events[0].sequence, 1);
        if let Some(before) = before {
            assert_eq!(before.events, recovered.replay.events);
        }
        assert_eq!(
            store
                .commit_check(
                    &ticket,
                    &assessment,
                    CheckContext::online(registration.config.domain.clone(), 100),
                    None
                )
                .unwrap()
                .replay
                .events,
            recovered.replay.events
        );
    }
}
#[test]
fn concurrent_prepared_checks_cannot_overwrite_same_generation() {
    let (_temp, options, registration) = setup();
    let store = MonitorStore::open(options.clone()).unwrap();
    let tickets = [
        store.prepare_check(&registration.monitor_id).unwrap(),
        store.prepare_check(&registration.monitor_id).unwrap(),
    ];
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let mut tasks = vec![];
        for ticket in tickets {
            let options = options.clone();
            let barrier = barrier.clone();
            tasks.push(scope.spawn(move || {
                let store = MonitorStore::open(options).unwrap();
                let config = ticket.registration().config.clone();
                let assessment = common::assessment(
                    &config,
                    "1",
                    vec![common::advisory("A", &[], true)],
                    Some("2"),
                    100,
                );
                barrier.wait();
                store.commit_check(
                    &ticket,
                    &assessment,
                    CheckContext::online(config.domain, 100),
                    None,
                )
            }));
        }
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .into_iter()
            .filter_map(Result::err)
            .next()
            .unwrap()
            .code,
        "E_MONITOR_STALE_CHECK"
    );
    assert_eq!(
        store
            .events(&registration.monitor_id, None)
            .unwrap()
            .events
            .len(),
        1
    );
}
#[test]
fn real_process_exit_before_and_after_replace_recovers_checkpoint_or_reset_without_new_fix() {
    for stage in ["before", "temp", "after"] {
        let (_temp, options, registration) = setup();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "monitor_crash_child", "--nocapture"])
            .env("PYBUN_MONITOR_TEST_ROOT", &options.root)
            .env("PYBUN_MONITOR_TEST_ID", &registration.monitor_id)
            .env("PYBUN_MONITOR_TEST_CRASH", stage)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77));
        let store = MonitorStore::open(options).unwrap();
        let ticket = store.prepare_check(&registration.monitor_id).unwrap();
        let assessment = common::assessment(
            &ticket.registration().config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            101,
        );
        let result = store
            .commit_check(
                &ticket,
                &assessment,
                CheckContext::online(ticket.registration().config.domain.clone(), 101),
                None,
            )
            .unwrap();
        let events = store.events(&registration.monitor_id, None).unwrap();
        assert!(!events.events.iter().any(|event| event.event_type
            == MonitorEventType::FixCandidateAvailable
            || event.event_type == MonitorEventType::NewAdvisory));
        if stage == "after" {
            assert_eq!(result.newly_committed_count, 0);
            assert_eq!(events.events.len(), 1);
        } else {
            assert_eq!(events.events.len(), 2);
            assert_eq!(
                events.events[0].event_type,
                MonitorEventType::ObservationReset
            );
            assert_eq!(
                events.events[0].reason.as_deref(),
                Some("initial_check_interrupted")
            );
        }
    }
}
#[test]
fn monitor_crash_child() {
    let Some(root) = std::env::var_os("PYBUN_MONITOR_TEST_ROOT") else {
        return;
    };
    struct Crash {
        stage: CommitStage,
    }
    impl CommitObserver for Crash {
        fn observe(&self, target: CommitTarget, stage: CommitStage) -> io::Result<()> {
            if target == CommitTarget::Checkpoint && stage == self.stage {
                std::process::exit(77);
            }
            Ok(())
        }
    }
    let mode = std::env::var("PYBUN_MONITOR_TEST_CRASH").unwrap();
    let store = MonitorStore::open(StoreOptions::new(root.into()))
        .unwrap()
        .with_observer(Arc::new(Crash {
            stage: match mode.as_str() {
                "before" => CommitStage::BeforeTempWrite,
                "temp" => CommitStage::AfterTempSync,
                _ => CommitStage::AfterReplace,
            },
        }));
    let id = std::env::var("PYBUN_MONITOR_TEST_ID").unwrap();
    let ticket = store.prepare_check(&id).unwrap();
    let assessment = common::assessment(
        &ticket.registration().config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        100,
    );
    store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(ticket.registration().config.domain.clone(), 100),
            None,
        )
        .unwrap();
    panic!("fault hook was not reached");
}

#[test]
fn corrupt_checkpoint_requires_explicit_recovery_and_unknown_schema_is_never_overwritten() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, options, registration) = setup();
    let store = MonitorStore::open(options.clone()).unwrap();
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let assessment = common::assessment(
        &registration.config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        100,
    );
    store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(registration.config.domain.clone(), 100),
            None,
        )
        .unwrap();
    let snapshot = options
        .root
        .join(format!("{}.checkpoint.json", registration.monitor_id));
    let original = std::fs::read(&snapshot).unwrap();
    std::fs::write(&snapshot, b"{corrupt").unwrap();
    assert_eq!(
        store
            .events(&registration.monitor_id, None)
            .unwrap_err()
            .code,
        "E_MONITOR_STATE_CORRUPT"
    );
    assert_eq!(std::fs::read(&snapshot).unwrap(), b"{corrupt");
    let recovered = store
        .recover_corrupt_snapshot(
            &registration.monitor_id,
            1,
            RecoveryAuthorization::explicit_operator_action(),
        )
        .unwrap();
    assert_ne!(recovered.epoch_id, registration.epoch_id);
    assert!(!snapshot.exists());
    assert!(
        std::fs::read_dir(&options.root)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains("quarantine"))
    );
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let result = store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(recovered.config.domain.clone(), 101),
            None,
        )
        .unwrap();
    assert_eq!(
        result.newly_committed_events[0].event_type,
        MonitorEventType::ObservationReset
    );
    assert!(
        !result
            .newly_committed_events
            .iter()
            .any(|event| event.event_type == MonitorEventType::FixCandidateAvailable)
    );
    let mut unsupported: serde_json::Value = serde_json::from_slice(&original).unwrap();
    unsupported["state_version"] = serde_json::json!(999);
    let bytes = serde_json::to_vec(&unsupported).unwrap();
    std::fs::write(&snapshot, &bytes).unwrap();
    std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        store
            .recover_corrupt_snapshot(
                &registration.monitor_id,
                recovered.config_revision,
                RecoveryAuthorization::explicit_operator_action()
            )
            .unwrap_err()
            .code,
        "E_MONITOR_STATE_VERSION"
    );
    assert_eq!(std::fs::read(&snapshot).unwrap(), bytes);
}

#[test]
fn registry_loss_is_not_implicit_continuity_and_corrupt_registry_requires_authorized_recovery() {
    let (_temp, options, registration) = setup();
    let store = MonitorStore::open(options.clone()).unwrap();
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let assessment = common::assessment(
        &registration.config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        100,
    );
    store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(registration.config.domain.clone(), 100),
            None,
        )
        .unwrap();
    std::fs::remove_file(options.root.join("registry.json")).unwrap();
    assert_eq!(store.list().unwrap_err().code, "E_MONITOR_REGISTRY_MISSING");
    assert_eq!(
        store
            .events(&registration.monitor_id, None)
            .unwrap_err()
            .code,
        "E_MONITOR_REGISTRY_MISSING"
    );
    assert!(!options.root.join("registry.json").exists());
    let fresh = store.register(registration.config.clone()).unwrap();
    assert_ne!(fresh.monitor_id, registration.monitor_id);
    assert_eq!(store.list().unwrap().len(), 1);
    std::fs::write(options.root.join("registry.json"), b"{corrupt").unwrap();
    assert_eq!(store.list().unwrap_err().code, "E_MONITOR_STATE_CORRUPT");
    store
        .recover_corrupt_registry(RecoveryAuthorization::explicit_operator_action())
        .unwrap();
    assert!(store.list().unwrap().is_empty());
    let again = store.register(registration.config).unwrap();
    assert_ne!(again.monitor_id, fresh.monitor_id);
}

#[test]
fn sigint_before_replace_and_broken_output_after_commit_do_not_lose_events() {
    use std::{
        io::{BufRead, BufReader},
        os::unix::process::ExitStatusExt,
        process::Stdio,
        time::{Duration, Instant},
    };
    for mode in ["sigint", "brokenpipe"] {
        let (_temp, options, registration) = setup();
        let ready = options.root.parent().unwrap().join("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "monitor_io_child", "--nocapture"])
            .env("PYBUN_MONITOR_TEST_ROOT", &options.root)
            .env("PYBUN_MONITOR_TEST_ID", &registration.monitor_id)
            .env("PYBUN_MONITOR_TEST_IO", mode)
            .env("PYBUN_MONITOR_TEST_READY", &ready)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        if mode == "sigint" {
            let until = Instant::now() + Duration::from_secs(5);
            while !ready.exists() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
            if !ready.exists() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not reach checkpoint hook");
            }
            assert!(
                Command::new("kill")
                    .args(["-INT", &child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGINT));
        } else {
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            while output.read_line(&mut line).unwrap() != 0 {
                if line.contains("MONITOR_COMMITTED") {
                    break;
                }
                line.clear();
            }
            assert!(line.contains("MONITOR_COMMITTED"));
            drop(output);
            assert_eq!(child.wait().unwrap().code(), Some(88));
        }
        let store = MonitorStore::open(options).unwrap();
        let before = store.events(&registration.monitor_id, None).ok();
        let ticket = store.prepare_check(&registration.monitor_id).unwrap();
        let assessment = common::assessment(
            &ticket.registration().config,
            "1",
            vec![common::advisory("A", &[], true)],
            Some("2"),
            101,
        );
        let result = store
            .commit_check(
                &ticket,
                &assessment,
                CheckContext::online(ticket.registration().config.domain.clone(), 101),
                None,
            )
            .unwrap();
        if mode == "brokenpipe" {
            assert_eq!(result.newly_committed_count, 0);
            assert_eq!(result.replay.events, before.unwrap().events);
        } else {
            assert_eq!(
                result.replay.events[0].event_type,
                MonitorEventType::ObservationReset
            );
        }
        assert!(
            !result
                .replay
                .events
                .iter()
                .any(|event| event.event_type == MonitorEventType::FixCandidateAvailable)
        );
    }
}
#[test]
fn monitor_io_child() {
    use std::io::Write;
    let Some(root) = std::env::var_os("PYBUN_MONITOR_TEST_ROOT") else {
        return;
    };
    let mode = std::env::var("PYBUN_MONITOR_TEST_IO").unwrap();
    struct Pause {
        ready: std::path::PathBuf,
    }
    impl CommitObserver for Pause {
        fn observe(&self, target: CommitTarget, stage: CommitStage) -> io::Result<()> {
            if target == CommitTarget::Checkpoint && stage == CommitStage::BeforeReplace {
                std::fs::write(&self.ready, b"ready")?;
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        }
    }
    let mut store = MonitorStore::open(StoreOptions::new(root.into())).unwrap();
    if mode == "sigint" {
        store = store.with_observer(Arc::new(Pause {
            ready: std::env::var_os("PYBUN_MONITOR_TEST_READY").unwrap().into(),
        }));
    }
    let id = std::env::var("PYBUN_MONITOR_TEST_ID").unwrap();
    let ticket = store.prepare_check(&id).unwrap();
    let assessment = common::assessment(
        &ticket.registration().config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        100,
    );
    store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(ticket.registration().config.domain.clone(), 100),
            None,
        )
        .unwrap();
    println!("MONITOR_COMMITTED");
    std::io::stdout().flush().unwrap();
    let error = std::io::stdout()
        .write_all(&vec![b'x'; 1024 * 1024])
        .unwrap_err();
    std::process::exit(if error.kind() == io::ErrorKind::BrokenPipe {
        88
    } else {
        89
    });
}

#[test]
fn two_os_processes_cannot_commit_same_snapshot_generation() {
    use std::time::{Duration, Instant};
    let (_temp, options, registration) = setup();
    let barrier = options.root.parent().unwrap().join("release");
    let mut children = vec![];
    for ordinal in 0..2 {
        let ready = options
            .root
            .parent()
            .unwrap()
            .join(format!("ready-{ordinal}"));
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "monitor_race_child", "--nocapture"])
            .env("PYBUN_MONITOR_TEST_ROOT", &options.root)
            .env("PYBUN_MONITOR_TEST_ID", &registration.monitor_id)
            .env("PYBUN_MONITOR_TEST_READY", &ready)
            .env("PYBUN_MONITOR_TEST_RELEASE", &barrier)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        children.push((child, ready));
    }
    let until = Instant::now() + Duration::from_secs(5);
    while !children.iter().all(|(_, ready)| ready.exists()) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    if !children.iter().all(|(_, ready)| ready.exists()) {
        for (child, _) in &mut children {
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!("process tickets were not prepared");
    }
    std::fs::write(barrier, b"release").unwrap();
    let mut exits = children
        .into_iter()
        .map(|(mut child, _)| child.wait().unwrap().code().unwrap())
        .collect::<Vec<_>>();
    exits.sort();
    assert_eq!(exits, vec![90, 91]);
    let store = MonitorStore::open(options).unwrap();
    assert_eq!(
        store
            .events(&registration.monitor_id, None)
            .unwrap()
            .events
            .len(),
        1
    );
}
#[test]
fn monitor_race_child() {
    use std::time::{Duration, Instant};
    let Some(root) = std::env::var_os("PYBUN_MONITOR_TEST_ROOT") else {
        return;
    };
    let store = MonitorStore::open(StoreOptions::new(root.into())).unwrap();
    let ticket = store
        .prepare_check(&std::env::var("PYBUN_MONITOR_TEST_ID").unwrap())
        .unwrap();
    let assessment = common::assessment(
        &ticket.registration().config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        100,
    );
    std::fs::write(
        std::env::var_os("PYBUN_MONITOR_TEST_READY").unwrap(),
        b"ready",
    )
    .unwrap();
    let release = std::path::PathBuf::from(std::env::var_os("PYBUN_MONITOR_TEST_RELEASE").unwrap());
    let until = Instant::now() + Duration::from_secs(5);
    while !release.exists() {
        if Instant::now() >= until {
            std::process::exit(99);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let result = store.commit_check(
        &ticket,
        &assessment,
        CheckContext::online(ticket.registration().config.domain.clone(), 100),
        None,
    );
    std::process::exit(match result {
        Ok(_) => 90,
        Err(error) if error.code == "E_MONITOR_STALE_CHECK" => 91,
        Err(_) => 92,
    });
}
#[test]
fn contended_process_lock_honors_deadline_and_cannot_commit_after_timeout() {
    use std::time::{Duration, Instant};
    let (_temp, options, registration) = setup();
    let store = MonitorStore::open(options.clone()).unwrap();
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let assessment = common::assessment(
        &registration.config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        100,
    );
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(options.root.join("state.lock"))
        .unwrap();
    fs2::FileExt::lock_exclusive(&held).unwrap();
    let started = Instant::now();
    let mut context = CheckContext::online(registration.config.domain, 100);
    context.deadline = started + Duration::from_millis(40);
    assert_eq!(
        store
            .commit_check(&ticket, &assessment, context, None)
            .unwrap_err()
            .code,
        "E_MONITOR_DEADLINE"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(held);
    assert!(
        !options
            .root
            .join(format!("{}.checkpoint.json", registration.monitor_id))
            .exists()
    );
    assert_eq!(
        store
            .prepare_check(&registration.monitor_id)
            .unwrap()
            .registration()
            .baseline_state,
        BaselineState::NotStarted
    );
}

#[test]
fn losing_initialized_snapshot_resets_continuity_without_new_fix_and_rejects_fifo_or_symlink() {
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        time::{Duration, Instant},
    };
    let (_temp, options, registration) = setup();
    let store = MonitorStore::open(options.clone()).unwrap();
    let ticket = store.prepare_check(&registration.monitor_id).unwrap();
    let assessment = common::assessment(
        &registration.config,
        "1",
        vec![common::advisory("A", &[], true)],
        Some("2"),
        100,
    );
    store
        .commit_check(
            &ticket,
            &assessment,
            CheckContext::online(registration.config.domain.clone(), 100),
            None,
        )
        .unwrap();
    let snapshot = options
        .root
        .join(format!("{}.checkpoint.json", registration.monitor_id));
    let saved = std::fs::read(&snapshot).unwrap();
    std::fs::remove_file(&snapshot).unwrap();
    let reset = store.prepare_check(&registration.monitor_id).unwrap();
    assert_ne!(reset.registration().epoch_id, registration.epoch_id);
    let result = store
        .commit_check(
            &reset,
            &assessment,
            CheckContext::online(registration.config.domain, 101),
            None,
        )
        .unwrap();
    assert_eq!(
        result.newly_committed_events[0].reason.as_deref(),
        Some("observation_missing")
    );
    assert_eq!(
        result.newly_committed_events[1].event_type,
        MonitorEventType::BaselineObserved
    );
    let external = options.root.parent().unwrap().join("unapproved.json");
    std::fs::write(&external, &saved).unwrap();
    std::fs::set_permissions(&external, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_file(&snapshot).unwrap();
    symlink(&external, &snapshot).unwrap();
    assert!(store.events(&registration.monitor_id, None).is_err());
    assert_eq!(std::fs::read(&external).unwrap(), saved);
    std::fs::remove_file(&snapshot).unwrap();
    assert!(
        Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&snapshot)
            .status()
            .unwrap()
            .success()
    );
    let began = Instant::now();
    assert!(store.events(&registration.monitor_id, None).is_err());
    assert!(began.elapsed() < Duration::from_secs(1));
}
