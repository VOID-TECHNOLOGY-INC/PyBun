#![cfg(unix)]
use pybun::security_assessment::{
    check::{CheckMode, CheckUpdatesRequest},
    config::{MonitorStateAccess, SecurityAuthority},
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    time::{Duration, Instant},
};
use tempfile::TempDir;
fn fixture() -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(dir.path().join("app/.venv")).unwrap();
    fs::write(
        dir.path().join("app/pyproject.toml"),
        "[project]\nname='app'\nversion='1'\n",
    )
    .unwrap();
    fs::write(dir.path().join("python"), "#!/bin/sh\ntouch helper-ran\n").unwrap();
    fs::set_permissions(dir.path().join("python"), fs::Permissions::from_mode(0o755)).unwrap();
    (
        dir,
        r#"[security_assessment]
config_version=1
default_profile="app"
monitor_state_root="monitors/state"
[[security_assessment.profiles]]
id="app"
project_root="app"
environment="app/.venv"
backend="uv"
trusted_python="python"
source_policy_id="explicit"
provider_ids=["osv"]
allowed_modes=["online", "offline"]
[[security_assessment.providers]]
id="osv"
url="https://api.osv.dev/v1/querybatch"
auth_scope_id="public"
[security_assessment.source_policies.explicit]
"#
        .into(),
    )
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
#[test]
fn monitor_roots_are_explicit_and_absent_read_has_no_creation_side_effect() {
    let (dir, text) = fixture();
    let denied = SecurityAuthority::from_toml(
        &text.replace("monitor_state_root=\"monitors/state\"\n", ""),
        dir.path(),
    )
    .unwrap();
    assert!(denied.monitor_state_grant().is_err());
    let authority = SecurityAuthority::from_toml(&text, dir.path()).unwrap();
    let grant = authority.monitor_state_grant().unwrap();
    let read = grant
        .authorize(MonitorStateAccess::Read, deadline())
        .unwrap();
    assert!(!read.exists());
    assert!(!read.creation_allowed());
    assert!(!dir.path().join("monitors").exists());
    assert_eq!(
        read.root(),
        dir.path().canonicalize().unwrap().join("monitors/state")
    );
    let write = grant
        .authorize(MonitorStateAccess::WriteCreate, deadline())
        .unwrap();
    assert!(write.creation_allowed());
    assert!(!dir.path().join("monitors").exists());
    assert!(!dir.path().join("helper-ran").exists());
}
#[test]
fn a_created_root_is_pinned_to_the_actual_creation_handle() {
    let (dir, text) = fixture();
    let authority = SecurityAuthority::from_toml(&text, dir.path()).unwrap();
    let grant = authority.monitor_state_grant().unwrap();
    let approved = grant
        .authorize(MonitorStateAccess::WriteCreate, deadline())
        .unwrap();
    fs::create_dir(dir.path().join("monitors")).unwrap();
    fs::set_permissions(
        dir.path().join("monitors"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::create_dir(approved.root()).unwrap();
    fs::set_permissions(approved.root(), fs::Permissions::from_mode(0o700)).unwrap();
    let created = fs::File::open(approved.root()).unwrap();
    grant.pin_created_root(&created, deadline()).unwrap();
    assert!(
        grant
            .authorize(MonitorStateAccess::Read, deadline())
            .unwrap()
            .exists()
    );
    fs::rename(approved.root(), dir.path().join("old-root")).unwrap();
    fs::create_dir(approved.root()).unwrap();
    fs::set_permissions(approved.root(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(grant.pin_created_root(&created, deadline()).is_err());
    assert!(
        grant
            .authorize(MonitorStateAccess::Read, deadline())
            .is_err()
    );
}
#[test]
fn root_symlink_parent_swap_and_permission_revocation_deny_before_store_access() {
    for action in ["symlink", "parent", "permissions"] {
        let (dir, text) = fixture();
        fs::create_dir(dir.path().join("monitors")).unwrap();
        fs::set_permissions(
            dir.path().join("monitors"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let authority = SecurityAuthority::from_toml(&text, dir.path()).unwrap();
        let grant = authority.monitor_state_grant().unwrap();
        match action {
            "symlink" => {
                symlink(dir.path().join("app"), dir.path().join("monitors/state")).unwrap();
            }
            "parent" => {
                fs::rename(dir.path().join("monitors"), dir.path().join("old-parent")).unwrap();
                fs::create_dir(dir.path().join("monitors")).unwrap();
                fs::set_permissions(
                    dir.path().join("monitors"),
                    fs::Permissions::from_mode(0o700),
                )
                .unwrap();
            }
            _ => fs::set_permissions(
                dir.path().join("monitors"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap(),
        }
        assert!(
            grant
                .authorize(MonitorStateAccess::WriteCreate, deadline())
                .is_err(),
            "{action}"
        );
        assert!(!dir.path().join("monitors/state/registry.json").exists());
        assert!(!dir.path().join("helper-ran").exists());
    }
}
#[test]
fn declared_descriptor_is_pure_stable_and_distinct_from_request_policy() {
    let (dir, text) = fixture();
    let authority = SecurityAuthority::from_toml(&text, dir.path()).unwrap();
    let declared = authority.monitor_profile(None).unwrap();
    let online = authority
        .prepare(&CheckUpdatesRequest::default(), None)
        .unwrap()
        .authorize()
        .unwrap();
    let request = CheckUpdatesRequest {
        mode: CheckMode::Offline,
        max_cache_age_seconds: Some(60),
        ..Default::default()
    };
    let offline = authority
        .prepare(&request, None)
        .unwrap()
        .authorize()
        .unwrap();
    assert_ne!(online.policy_digest(), offline.policy_digest());
    assert_eq!(
        declared.profile_binding,
        authority.monitor_profile(None).unwrap().profile_binding
    );
    fs::write(
        dir.path().join("app/pyproject.toml"),
        "[project]\nname='app'\nversion='2'\n",
    )
    .unwrap();
    fs::remove_dir_all(dir.path().join("app/.venv")).unwrap();
    let frozen = authority.monitor_profile(None).unwrap();
    assert_eq!(declared.profile_binding, frozen.profile_binding);
    assert!(frozen.authorize(deadline()).is_err());
    assert!(!dir.path().join("monitors").exists());
}
#[test]
fn monitor_state_does_not_need_a_default_profile_and_deadlines_cannot_create_state() {
    let (dir, text) = fixture();
    let authority =
        SecurityAuthority::from_toml(&text.replace("default_profile=\"app\"\n", ""), dir.path())
            .unwrap();
    assert!(authority.monitor_profile(None).is_err());
    let grant = authority.monitor_state_grant().unwrap();
    assert!(grant.limits().total_timeout_ms > 0);
    assert!(grant.max_output_bytes() >= 4096);
    assert!(
        grant
            .authorize(
                MonitorStateAccess::WriteCreate,
                Instant::now() - Duration::from_millis(1)
            )
            .is_err()
    );
    assert!(!dir.path().join("monitors").exists());
}
#[test]
fn monitor_descriptor_source_provider_and_bounds_changes_are_declared_identity_changes() {
    let (dir, text) = fixture();
    let first = SecurityAuthority::from_toml(&text, dir.path())
        .unwrap()
        .monitor_profile(None)
        .unwrap();
    for changed in [
        text.replace("auth_scope_id=\"public\"", "auth_scope_id=\"different\""),
        text.replace("backend=\"uv\"", "max_cache_age_seconds=60\nbackend=\"uv\""),
        text.replace("backend=\"uv\"", "include_prereleases=true\nbackend=\"uv\""),
    ] {
        let next = SecurityAuthority::from_toml(&changed, dir.path())
            .unwrap()
            .monitor_profile(None)
            .unwrap();
        assert_ne!(first.profile_binding, next.profile_binding);
    }
    assert_eq!(
        first.project_root,
        dir.path().join("app").canonicalize().unwrap()
    );
    assert_eq!(first.observation_version, 1);
}

#[test]
fn a_parent_first_seen_after_startup_is_pinned_before_later_creation() {
    let (dir, text) = fixture();
    let authority = SecurityAuthority::from_toml(&text, dir.path()).unwrap();
    let grant = authority.monitor_state_grant().unwrap();
    fs::create_dir(dir.path().join("monitors")).unwrap();
    fs::set_permissions(
        dir.path().join("monitors"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(
        !grant
            .authorize(MonitorStateAccess::Read, deadline())
            .unwrap()
            .exists()
    );
    fs::rename(dir.path().join("monitors"), dir.path().join("prior-parent")).unwrap();
    fs::create_dir(dir.path().join("monitors")).unwrap();
    fs::set_permissions(
        dir.path().join("monitors"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(
        grant
            .authorize(MonitorStateAccess::WriteCreate, deadline())
            .is_err()
    );
    assert!(!dir.path().join("monitors/state").exists());
}

#[test]
fn replacement_before_first_creation_pin_cannot_be_adopted_on_retry() {
    let (dir, text) = fixture();
    let authority = SecurityAuthority::from_toml(&text, dir.path()).unwrap();
    let grant = authority.monitor_state_grant().unwrap();
    let root = grant
        .authorize(MonitorStateAccess::WriteCreate, deadline())
        .unwrap();
    fs::create_dir(dir.path().join("monitors")).unwrap();
    fs::set_permissions(
        dir.path().join("monitors"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::create_dir(root.root()).unwrap();
    fs::set_permissions(root.root(), fs::Permissions::from_mode(0o700)).unwrap();
    let created = fs::File::open(root.root()).unwrap();
    fs::rename(root.root(), dir.path().join("created-root")).unwrap();
    fs::create_dir(root.root()).unwrap();
    fs::set_permissions(root.root(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(grant.pin_created_root(&created, deadline()).is_err());
    assert!(
        grant
            .authorize(MonitorStateAccess::Read, deadline())
            .is_err(),
        "a rejected replacement must not become the next grant"
    );
    assert!(!root.root().join("registry.json").exists());
}

#[test]
fn creation_authority_retains_the_verified_parent_directory_handle() {
    use std::os::unix::fs::MetadataExt;
    let (dir, text) = fixture();
    let authority = SecurityAuthority::from_toml(&text, dir.path()).unwrap();
    let grant = authority.monitor_state_grant().unwrap();
    let parent = grant.creation_parent(deadline()).unwrap();
    let approved = fs::metadata(dir.path()).unwrap();
    let held = parent.parent_handle().metadata().unwrap();
    assert_eq!((held.dev(), held.ino()), (approved.dev(), approved.ino()));
    assert_eq!(parent.parent_path(), dir.path().canonicalize().unwrap());
    assert_eq!(
        parent.root(),
        dir.path().canonicalize().unwrap().join("monitors/state")
    );
    assert!(!dir.path().join("monitors").exists());
}
#[test]
fn swapped_private_creation_ancestor_is_denied_before_any_outside_write() {
    let (dir, text) = fixture();
    fs::create_dir(dir.path().join("monitors")).unwrap();
    fs::set_permissions(
        dir.path().join("monitors"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let authority = SecurityAuthority::from_toml(&text, dir.path()).unwrap();
    let grant = authority.monitor_state_grant().unwrap();
    let outside = TempDir::new().unwrap();
    fs::rename(
        dir.path().join("monitors"),
        dir.path().join("approved-parent"),
    )
    .unwrap();
    symlink(outside.path(), dir.path().join("monitors")).unwrap();
    assert!(grant.creation_parent(deadline()).is_err());
    assert!(!outside.path().join("state").exists());
}
#[test]
fn creation_authority_uses_the_nearest_verified_existing_prefix() {
    use std::os::unix::fs::MetadataExt;
    let (dir, text) = fixture();
    let authority = SecurityAuthority::from_toml(&text, dir.path()).unwrap();
    let grant = authority.monitor_state_grant().unwrap();
    fs::create_dir(dir.path().join("monitors")).unwrap();
    fs::set_permissions(
        dir.path().join("monitors"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let parent = grant.creation_parent(deadline()).unwrap();
    let expected = fs::metadata(dir.path().join("monitors")).unwrap();
    let held = parent.parent_handle().metadata().unwrap();
    assert_eq!((held.dev(), held.ino()), (expected.dev(), expected.ino()));
    assert_eq!(
        parent.parent_path(),
        dir.path().join("monitors").canonicalize().unwrap()
    );
    assert!(!dir.path().join("monitors/state").exists());
}
