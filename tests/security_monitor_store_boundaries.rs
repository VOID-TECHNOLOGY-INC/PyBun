#![cfg(unix)]
#[path = "security_monitor_store_support/mod.rs"]
mod common;
use pybun::security_assessment::monitor::*;
#[test]
fn invalid_operator_configuration_is_secret_safe_and_cannot_create_registration() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("project")).unwrap();
    let base = common::config(&root.join("project"));
    let state = root.join("state");
    let store = MonitorStore::create(StoreOptions::new(state.clone())).unwrap();
    let mut cases = vec![];
    let mut changed = base.clone();
    changed.name = " ".into();
    cases.push(changed);
    let mut changed = base.clone();
    changed.profile_id = "x".repeat(129);
    cases.push(changed);
    let mut changed = base.clone();
    changed.domain.project_root = "relative/project".into();
    cases.push(changed);
    let mut changed = base.clone();
    changed.domain.environment_root = root.join("project/../secret");
    cases.push(changed);
    let mut changed = base.clone();
    changed.domain.observation_version = 999;
    cases.push(changed);
    let mut changed = base.clone();
    changed.domain.source_policy_digest = "https://user:PRIVATE-CREDENTIAL@host.invalid".into();
    cases.push(changed);
    let mut changed = base.clone();
    changed.domain.authoritative_providers.clear();
    cases.push(changed);
    let mut changed = base.clone();
    changed.domain.authoritative_providers = vec!["credential:PRIVATE-CREDENTIAL".into()];
    cases.push(changed);
    let mut changed = base.clone();
    changed.domain.scope.extras = vec!["control\nvalue".into()];
    cases.push(changed);
    let mut changed = base.clone();
    changed.domain.scope.groups = vec!["".into()];
    cases.push(changed);
    let mut changed = base.clone();
    changed.domain.scope.members = vec!["member".into(); 1001];
    cases.push(changed);
    let mut changed = base.clone();
    changed.domain.runtime = Some(RuntimeIdentity {
        interpreter_digest: "bad".into(),
        tag_profile_digest: "b".repeat(64),
        platform_identity_digest: "c".repeat(64),
    });
    cases.push(changed);
    for config in cases {
        let error = store.register(config).unwrap_err();
        assert_eq!(error.code, "E_MONITOR_CONFIG");
        assert!(!error.to_string().contains("PRIVATE-CREDENTIAL"));
    }
    assert!(store.list().unwrap().is_empty());
    assert!(!state.join("registry.json").exists());
    let mut unsorted = base.clone();
    unsorted.domain.authoritative_providers = vec!["z".into(), "osv".into(), "z".into()];
    unsorted.domain.scope.extras = vec!["b".into(), "a".into(), "b".into()];
    let normalized = store.register(unsorted).unwrap();
    assert_eq!(
        normalized.config.domain.authoritative_providers,
        vec!["osv", "z"]
    );
    assert_eq!(normalized.config.domain.scope.extras, vec!["a", "b"]);
    assert_eq!(
        normalized.config.domain.digest(),
        store.list().unwrap()[0].config.domain.digest()
    );
    let mut same_capture_only = base;
    same_capture_only.freshness_ttl_seconds = 0;
    assert_eq!(
        store
            .register(same_capture_only)
            .unwrap()
            .config
            .freshness_ttl_seconds,
        0
    );
}
#[test]
fn caller_limits_only_narrow_and_invalid_caps_do_not_create_state() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let limits = [
        MonitorLimits {
            max_monitors: 0,
            ..Default::default()
        },
        MonitorLimits {
            max_monitors: 101,
            ..Default::default()
        },
        MonitorLimits {
            max_inventory_instances: 1001,
            ..Default::default()
        },
        MonitorLimits {
            retained_events: 1001,
            ..Default::default()
        },
        MonitorLimits {
            history_seconds: 90 * 86400 + 1,
            ..Default::default()
        },
        MonitorLimits {
            max_checkpoint_bytes: 64 * 1024 * 1024 + 1,
            ..Default::default()
        },
    ];
    for (i, limit) in limits.into_iter().enumerate() {
        let state = root.join(format!("state-{i}"));
        let mut options = StoreOptions::new(state.clone());
        options.limits = limit;
        assert_eq!(
            MonitorStore::create(options).err().unwrap().code,
            "E_MONITOR_LIMIT"
        );
        assert!(!state.exists());
    }
    assert!(StoreOptions::user_default().unwrap().root.is_absolute());
}

#[test]
fn held_parent_constructor_confines_creation_and_supports_existing_root_without_reopening_it() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let parent = base.join("parent");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&parent)
        .unwrap();
    let held = std::fs::File::open(&parent).unwrap();
    let options = StoreOptions::new(parent.join("nested/state"));
    let store = MonitorStore::create_from_parent(options.clone(), &parent, &held).unwrap();
    let root_handle = store.root_handle().unwrap();
    assert_eq!(
        root_handle.metadata().unwrap().ino(),
        std::fs::metadata(&options.root).unwrap().ino()
    );
    assert!(
        MonitorStore::create_from_parent(options.clone(), &options.root, &root_handle)
            .unwrap()
            .list()
            .unwrap()
            .is_empty()
    );
    let invalid = StoreOptions::new(base.join("outside/state"));
    assert!(MonitorStore::create_from_parent(invalid, &parent, &held).is_err());
    assert!(!base.join("outside").exists());
    let outside = base.join("replacement");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&outside)
        .unwrap();
    std::fs::rename(&parent, base.join("moved")).unwrap();
    symlink(&outside, &parent).unwrap();
    assert!(
        MonitorStore::create_from_parent(StoreOptions::new(parent.join("other")), &parent, &held)
            .is_err()
    );
    assert!(!outside.join("other").exists());
}

#[test]
fn read_only_open_and_list_do_not_require_write_access_to_state_lock() {
    use std::os::unix::fs::PermissionsExt;
    struct Restore(std::path::PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    std::fs::create_dir(base.join("project")).unwrap();
    let path = base.join("state");
    let options = StoreOptions::new(path.clone());
    let store = MonitorStore::create(options.clone()).unwrap();
    let registered = store
        .register(common::config(&base.join("project")))
        .unwrap();
    drop(store);
    let original = std::fs::read(path.join("registry.json")).unwrap();
    std::fs::set_permissions(
        path.join("state.lock"),
        std::fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    std::fs::set_permissions(
        path.join("registry.json"),
        std::fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    let _restore = Restore(path.clone());
    let read = MonitorStore::open(options).unwrap();
    assert_eq!(read.list().unwrap(), vec![registered.clone()]);
    assert_eq!(
        read.events(&registered.monitor_id, None).unwrap_err().code,
        "E_MONITOR_BASELINE_REQUIRED"
    );
    assert_eq!(std::fs::read(path.join("registry.json")).unwrap(), original);
    assert!(
        !path
            .join(format!("{}.checkpoint.json", registered.monitor_id))
            .exists()
    );
}
