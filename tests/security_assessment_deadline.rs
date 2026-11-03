//! A saturated blocking pool must not extend the shared observation deadline.
#![cfg(unix)]

use pybun::security_assessment::{
    InventoryRequest,
    http::{HttpSession, ProviderConfig, ProviderEndpoint},
    qualification::service::{AssessmentOptions, assess_project},
};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command, time::Duration};
use tempfile::TempDir;

#[test]
fn expired_queued_inventory_never_starts_its_helper() {
    let project = TempDir::new().unwrap();
    fs::write(
        project.path().join("pyproject.toml"),
        "[project]\nname='deadline'\nversion='1'\n",
    )
    .unwrap();
    let python = std::env::var_os("PYBUN_SECURITY_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let output = Command::new(&python)
        .args(["-I", "-S", "-B", "-c", "import sys; print(sys.executable)"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let python = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    assert!(
        Command::new(&python)
            .args(["-I", "-B", "-m", "venv", "--without-pip"])
            .arg(project.path().join(".venv"))
            .status()
            .unwrap()
            .success()
    );
    let marker = project.path().join("HELPER_STARTED");
    let helper = project.path().join("trusted-helper");
    // The explicitly trusted fixture records execution before invoking CPython.
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\nprintf executed > '{}'\nexec '{}' \"$@\"\n",
            marker.display(),
            python.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let mut request = InventoryRequest::installed(project.path(), &helper);
    request.limits.total_timeout_ms = 40;
    request.limits.http_timeout_ms = 40;
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
    runtime.block_on(async move {
        let session = HttpSession::new(request.limits.clone(), 10).unwrap();
        let providers = vec![
            ProviderEndpoint::new(ProviderConfig {
                id: "osv".into(),
                url: "https://example.invalid/v1/querybatch".into(),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: false,
            })
            .unwrap(),
        ];
        let check = tokio::spawn(async move {
            assess_project(
                &session,
                &request,
                &providers,
                &[],
                &AssessmentOptions::default(),
                None,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        let returned_while_queued = check.is_finished();
        release_tx.send(()).unwrap();
        let result = check.await.unwrap();
        blocker.await.unwrap();
        assert!(
            !marker.exists(),
            "expired queued inventory executed its helper"
        );
        assert!(
            returned_while_queued,
            "queue wait extended the shared deadline"
        );
        assert_eq!(result.unwrap_err().code, "E_SECURITY_DEADLINE");
    });
}
