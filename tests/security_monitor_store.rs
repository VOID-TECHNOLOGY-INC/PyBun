#![cfg(unix)]
use pybun::security_assessment::{
    InventoryBackend, InventoryScope, InventoryTarget,
    monitor::{ComparisonDomain, MonitorConfig, MonitorStore, StoreOptions},
};
use std::{fs, path::Path};
fn config(project: &Path, name: &str) -> MonitorConfig {
    MonitorConfig {
        profile_id: "profile-main".into(),
        name: name.into(),
        freshness_ttl_seconds: 86400,
        include_prereleases: false,
        domain: ComparisonDomain {
            project_root: project.to_path_buf(),
            environment_root: project.join(".venv"),
            backend: InventoryBackend::Uv,
            target: InventoryTarget::Installed,
            scope: InventoryScope::default(),
            runtime: None,
            source_policy_digest: "c".repeat(64),
            provider_config_digest: "d".repeat(64),
            index_config_digest: "e".repeat(64),
            observation_version: 1,
            authoritative_providers: vec!["osv".into()],
        },
    }
}
#[test]
fn registration_is_explicit_random_and_name_reuse_never_restores_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::create_dir(root.join("project")).unwrap();
    let options = StoreOptions::new(root.join("state"));
    assert!(MonitorStore::open(options.clone()).is_err());
    let store = MonitorStore::create(options.clone()).unwrap();
    assert!(store.list().unwrap().is_empty());
    let first = store
        .register(config(&root.join("project"), "same"))
        .unwrap();
    let second = store
        .register(config(&root.join("project"), "same"))
        .unwrap();
    assert_ne!(first.monitor_id, second.monitor_id);
    assert_ne!(first.epoch_id, second.epoch_id);
    assert_eq!(first.config_revision, 1);
    assert!(store.remove(&first.monitor_id).unwrap());
    assert!(!store.remove(&first.monitor_id).unwrap());
    let readded = store
        .register(config(&root.join("project"), "same"))
        .unwrap();
    assert_ne!(readded.monitor_id, first.monitor_id);
    assert_eq!(store.list().unwrap().len(), 2);
    drop(store);
    assert_eq!(
        MonitorStore::open(options).unwrap().list().unwrap().len(),
        2
    );
}
#[test]
fn private_root_and_no_follow_profile_rejects_symlinks_and_repository_default() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let store = MonitorStore::create(StoreOptions::new(root.join("state"))).unwrap();
    assert_eq!(
        fs::metadata(root.join("state"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    symlink(root.join("state"), root.join("link")).unwrap();
    assert!(MonitorStore::open(StoreOptions::new(root.join("link"))).is_err());
    fs::create_dir(root.join("repo")).unwrap();
    fs::write(root.join("repo/.git"), "gitdir: elsewhere").unwrap();
    assert!(MonitorStore::create(StoreOptions::new(root.join("repo/state"))).is_err());
    drop(store);
}

#[test]
fn state_root_replacement_is_not_reported_as_committed_to_the_approved_path() {
    use pybun::security_assessment::monitor::{
        CommitObserver, CommitStage, CommitStatus, CommitTarget,
    };
    use std::{
        os::unix::fs::DirBuilderExt,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    struct Swap {
        root: std::path::PathBuf,
        moved: std::path::PathBuf,
        stage: CommitStage,
        swapped: AtomicBool,
    }
    impl CommitObserver for Swap {
        fn observe(&self, target: CommitTarget, stage: CommitStage) -> std::io::Result<()> {
            if target == CommitTarget::Registry
                && stage == self.stage
                && !self.swapped.swap(true, Ordering::SeqCst)
            {
                fs::rename(&self.root, &self.moved)?;
                std::fs::DirBuilder::new().mode(0o700).create(&self.root)?;
            }
            Ok(())
        }
    }
    for (stage, status) in [
        (CommitStage::BeforeReplace, CommitStatus::NotCommitted),
        (CommitStage::AfterReplace, CommitStatus::Indeterminate),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::create_dir(root.join("project")).unwrap();
        let store = MonitorStore::create(StoreOptions::new(root.join("state"))).unwrap();
        store
            .register(config(&root.join("project"), "original"))
            .unwrap();
        let store = store.with_observer(Arc::new(Swap {
            root: root.join("state"),
            moved: root.join("moved"),
            stage,
            swapped: AtomicBool::new(false),
        }));
        let error = store
            .register(config(&root.join("project"), "next"))
            .unwrap_err();
        assert_eq!(error.commit_status, status);
        assert!(!root.join("state/registry.json").exists());
    }
}

#[test]
fn an_expired_absolute_deadline_cannot_create_state_or_later_register() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let mut options = StoreOptions::new(root.join("state"));
    options.deadline = Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
    assert!(MonitorStore::create(options).is_err());
    assert!(!root.join("state").exists());
}

#[test]
fn registration_requires_stable_opaque_operator_profile_binding() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::create_dir(root.join("project")).unwrap();
    let store = MonitorStore::create(StoreOptions::new(root.join("state"))).unwrap();
    let mut selected = config(&root.join("project"), "name");
    selected.profile_id = "operator-profile".into();
    let registered = store.register(selected.clone()).unwrap();
    assert_eq!(registered.config.profile_id, "operator-profile");
    for invalid in ["", "profile name", "profile\nname"] {
        selected.profile_id = invalid.into();
        assert_eq!(
            store.register(selected.clone()).unwrap_err().code,
            "E_MONITOR_CONFIG"
        );
    }
}

#[test]
fn narrowed_monitor_limit_rejects_new_registration_without_hiding_existing_entries() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::create_dir(root.join("project")).unwrap();
    let options = StoreOptions::new(root.join("state"));
    let store = MonitorStore::create(options.clone()).unwrap();
    let a = store.register(config(&root.join("project"), "a")).unwrap();
    store.register(config(&root.join("project"), "b")).unwrap();
    let mut narrowed = options;
    narrowed.limits.max_monitors = 1;
    let limited = MonitorStore::open(narrowed).unwrap();
    assert_eq!(limited.list().unwrap().len(), 2);
    assert_eq!(
        limited
            .register(config(&root.join("project"), "c"))
            .unwrap_err()
            .code,
        "E_MONITOR_LIMIT"
    );
    assert!(limited.remove(&a.monitor_id).unwrap());
    assert_eq!(limited.list().unwrap().len(), 1);
}

#[test]
fn root_handle_clones_opened_directory_identity_instead_of_reopening_replaced_path() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("state");
    let store = MonitorStore::create(StoreOptions::new(path.clone())).unwrap();
    let original = fs::metadata(&path).unwrap();
    fs::rename(&path, root.join("moved")).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    let held = store.root_handle().unwrap().metadata().unwrap();
    assert_eq!((held.dev(), held.ino()), (original.dev(), original.ino()));
    assert_ne!(held.ino(), fs::metadata(path).unwrap().ino());
}
