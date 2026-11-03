//! The request budget includes queuing current authority revalidation.
#![cfg(unix)]
use pybun::security_assessment::{
    check::{CheckUpdatesRequest, authorize_and_run},
    config::SecurityAuthority,
};
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
use tempfile::TempDir;

#[test]
fn queued_authorization_expires_before_target_or_cache_revalidation() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("app")).unwrap();
    fs::create_dir(root.path().join("app/.venv")).unwrap();
    fs::write(
        root.path().join("app/pyproject.toml"),
        "[project]\nname='app'\nversion='1'\n",
    )
    .unwrap();
    fs::write(root.path().join("python"), "#!/bin/sh\nexit 99\n").unwrap();
    fs::set_permissions(
        root.path().join("python"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let text = r#"
[security_assessment]
config_version=1
default_profile="app"
[[security_assessment.profiles]]
id="app"
project_root="app"
environment="app/.venv"
backend="uv"
trusted_python="python"
source_policy_id="explicit"
provider_ids=["osv"]
registry_source_ids=[]
[[security_assessment.providers]]
id="osv"
url="https://example.invalid/v1/querybatch"
auth_scope_id="public"
[security_assessment.source_policies.explicit]
sources=[]
rules=[]
disclosure=[]
[security_assessment.limits]
total_timeout_ms=40
"#;
    let authority = SecurityAuthority::from_toml(text, root.path()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocker = runtime.spawn_blocking(move || {
        started_tx.send(()).unwrap();
        let _ = release_rx.recv();
    });
    started_rx.recv().unwrap();
    runtime.block_on(async {
        let prepared = authority
            .prepare(&CheckUpdatesRequest::default(), None)
            .unwrap();
        // If expired queued work still revalidates, these revoked bindings fail
        // with an authority error instead of respecting the absolute deadline.
        fs::remove_file(root.path().join("python")).unwrap();
        fs::remove_file(root.path().join("app/pyproject.toml")).unwrap();
        let check = tokio::spawn(authorize_and_run(prepared, 20));
        tokio::time::sleep(Duration::from_millis(150)).await;
        let returned = check.is_finished();
        release_tx.send(()).unwrap();
        let result = check.await.unwrap();
        blocker.await.unwrap();
        assert!(returned, "authority queue extended the request budget");
        assert_eq!(result.exit_code, 3);
        assert_eq!(result.diagnostics[0].code, "E_SECURITY_DEADLINE");
        assert!(result.assessment.is_none());
    });
}
