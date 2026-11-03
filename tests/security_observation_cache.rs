#![cfg(unix)]
use pybun::security_assessment::http::JsonEvidence;
use pybun::security_assessment::qualification::cache::ObservationCache;
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
use tempfile::TempDir;
fn private_root() -> TempDir {
    let root = tempfile::Builder::new()
        .prefix("pybun-security-cache-")
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn evidence() -> JsonEvidence {
    JsonEvidence {
        freshness: Default::default(),
        value: json!({"id":"A","name":"demo"}),
        payload_digest: "a".repeat(64),
        fetched_at: 10,
    }
}
#[test]
fn cache_is_bounded_private_partitioned_and_detects_corruption() {
    let root = private_root();
    let cache = ObservationCache::open(root.path(), 1024).unwrap();
    let key = "1".repeat(64);
    assert!(cache.read(&key, 20).unwrap().is_none());
    cache.write(&key, &evidence()).unwrap();
    let restored = cache.read(&key, 20).unwrap().unwrap();
    assert_eq!(restored.value, evidence().value);
    assert_eq!(restored.fetched_at, 10);
    assert!(cache.read(&"2".repeat(64), 20).unwrap().is_none());
    assert!(cache.read(&key, 9).is_err());
    let path = root.path().join(format!("v1-{key}.json"));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::write(&path, b"not-json").unwrap();
    assert!(cache.read(&key, 20).is_err());
    assert!(cache.read("../outside", 20).is_err());
    assert!(cache.write("../outside", &evidence()).is_err());
    let oversized = JsonEvidence {
        value: json!({"x":"x".repeat(1025)}),
        ..evidence()
    };
    assert!(cache.write(&key, &oversized).is_err());
}
#[test]
fn cache_does_not_follow_files_or_write_to_a_replaced_root() {
    let root = private_root();
    let outside = private_root();
    let cache = ObservationCache::open(root.path(), 1024).unwrap();
    let key = "1".repeat(64);
    let victim = outside.path().join("victim");
    fs::write(&victim, "untouched").unwrap();
    symlink(&victim, root.path().join(format!("v1-{key}.json"))).unwrap();
    assert!(cache.read(&key, 20).is_err());
    cache.write(&key, &evidence()).unwrap();
    assert_eq!(fs::read_to_string(&victim).unwrap(), "untouched");
    let original = root.path().to_path_buf();
    let moved = original.with_extension("moved");
    fs::rename(&original, &moved).unwrap();
    symlink(outside.path(), &original).unwrap();
    cache.write(&"2".repeat(64), &evidence()).unwrap();
    assert!(
        !outside
            .path()
            .join(format!("v1-{}.json", "2".repeat(64)))
            .exists()
    );
    assert!(moved.join(format!("v1-{}.json", "2".repeat(64))).exists());
    fs::remove_file(&original).unwrap();
    fs::rename(&moved, &original).unwrap();
}
#[test]
fn cache_rejects_public_directories_and_future_schema_without_rewriting() {
    let root = private_root();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(ObservationCache::open(root.path(), 1024).is_err());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let cache = ObservationCache::open(root.path(), 1024).unwrap();
    let key = "1".repeat(64);
    cache.write(&key, &evidence()).unwrap();
    let path = root.path().join(format!("v1-{key}.json"));
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["cache_version"] = json!(2);
    fs::write(&path, value.to_string()).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(cache.read(&key, 20).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
}

fn approved(
    server: &httpmock::MockServer,
) -> (
    pybun::security_assessment::http::ProviderEndpoint,
    pybun::security_assessment::AuthorizedQuery,
) {
    use pybun::security_assessment::*;
    let policy = SourcePolicy {
        sources: vec![SourceIdentity::new("public", "public", SourceKind::PublicRegistry).unwrap()],
        rules: vec![SourceRule {
            name: "demo".into(),
            distribution: None,
            source_id: "public".into(),
            upstream_name: Some("demo".into()),
            ecosystem: Some("PyPI".into()),
            assumption: Some("explicit source equivalence".into()),
        }],
        disclosure: vec![DisclosureGrant {
            provider_id: "osv".into(),
            source_id: "public".into(),
            packages: vec!["demo".into()],
        }],
    };
    let mapped = policy
        .map_package("demo", "demo.dist-info", SourceKind::Unknown)
        .unwrap();
    let proof = policy.authorized_query("osv", "demo", &mapped).unwrap();
    let endpoint = pybun::security_assessment::http::ProviderEndpoint::new(
        pybun::security_assessment::http::ProviderConfig {
            id: "osv".into(),
            url: server.url("/v1/querybatch"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        },
    )
    .unwrap();
    (endpoint, proof)
}
#[tokio::test]
async fn offline_and_fallback_observations_have_age_and_never_become_fresh() {
    use pybun::security_assessment::{
        ObservationLimits,
        http::{FreshnessKind, HttpSession, ObservationMode},
    };
    let server = httpmock::MockServer::start();
    let secret = "credential-outside-env";
    let mut fresh = server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.json_body(json!({"name":"demo","echo":secret}));
    });
    let (endpoint, proof) = approved(&server);
    let endpoint = endpoint.with_bearer_token(secret).unwrap();
    let root = private_root();
    let session = HttpSession::new(ObservationLimits::default(), 20)
        .unwrap()
        .with_cache(
            ObservationCache::open(root.path(), 1024).unwrap(),
            ObservationMode::Online,
        )
        .unwrap();
    let observed = session
        .request_json(
            &endpoint,
            reqwest::Method::POST,
            endpoint.url().clone(),
            None,
            &proof,
        )
        .await
        .unwrap();
    assert_eq!(observed.freshness.kind, FreshnessKind::Fresh);
    fresh.assert_calls(1);
    for entry in fs::read_dir(root.path()).unwrap() {
        assert!(
            !fs::read_to_string(entry.unwrap().path())
                .unwrap()
                .contains(secret)
        );
    }
    let offline = HttpSession::new(ObservationLimits::default(), 30)
        .unwrap()
        .with_cache(
            ObservationCache::open(root.path(), 1024).unwrap(),
            ObservationMode::Offline,
        )
        .unwrap();
    let cached = offline
        .request_json(
            &endpoint,
            reqwest::Method::POST,
            endpoint.url().clone(),
            None,
            &proof,
        )
        .await
        .unwrap();
    assert_eq!(cached.freshness.kind, FreshnessKind::OfflineCache);
    assert_eq!(cached.freshness.age_seconds, 10);
    assert_eq!(cached.fetched_at, 20);
    assert_eq!(offline.request_count(), 0);
    fresh.assert_calls(1);
    let mut changed = endpoint.config().clone();
    changed.auth_scope_id = "other-tenant".into();
    let changed = pybun::security_assessment::http::ProviderEndpoint::new(changed).unwrap();
    assert!(
        offline
            .request_json(
                &changed,
                reqwest::Method::POST,
                changed.url().clone(),
                None,
                &proof
            )
            .await
            .is_err()
    );
    assert_eq!(offline.request_count(), 0);
    fresh.delete();
    server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.status(503);
    });
    let fallback = HttpSession::new(
        ObservationLimits {
            max_attempts: 1,
            ..Default::default()
        },
        40,
    )
    .unwrap()
    .with_cache(
        ObservationCache::open(root.path(), 1024).unwrap(),
        ObservationMode::OnlineWithCacheFallback,
    )
    .unwrap();
    let stale = fallback
        .request_json(
            &endpoint,
            reqwest::Method::POST,
            endpoint.url().clone(),
            None,
            &proof,
        )
        .await
        .unwrap();
    assert_eq!(stale.freshness.kind, FreshnessKind::StaleCache);
    assert_eq!(stale.freshness.age_seconds, 20);
    assert!(!fallback.cache_diagnostics().is_empty());
}
#[tokio::test]
async fn cache_write_failure_preserves_fresh_http_evidence_with_a_diagnostic() {
    use pybun::security_assessment::{
        ObservationLimits,
        http::{FreshnessKind, HttpSession, ObservationMode},
    };
    let server = httpmock::MockServer::start();
    server.mock(|when, then| {
        when.any_request();
        then.json_body(json!({"id":"A"}));
    });
    let (endpoint, proof) = approved(&server);
    let root = private_root();
    let key = endpoint.observation_key(&proof, "POST", endpoint.url(), &None);
    fs::create_dir(root.path().join(format!("v1-{key}.json"))).unwrap();
    let session = HttpSession::new(ObservationLimits::default(), 20)
        .unwrap()
        .with_cache(
            ObservationCache::open(root.path(), 1024).unwrap(),
            ObservationMode::Online,
        )
        .unwrap();
    let observed = session
        .request_json(
            &endpoint,
            reqwest::Method::POST,
            endpoint.url().clone(),
            None,
            &proof,
        )
        .await
        .unwrap();
    assert_eq!(observed.freshness.kind, FreshnessKind::Fresh);
    assert_eq!(observed.value["id"], "A");
    assert!(!session.cache_diagnostics().is_empty());
}

#[tokio::test]
async fn fallback_does_not_read_cache_after_the_shared_deadline_expires() {
    use pybun::security_assessment::{
        ObservationLimits,
        http::{HttpSession, ObservationMode},
    };
    let server = httpmock::MockServer::start();
    let (endpoint, proof) = approved(&server);
    let root = private_root();
    let key = endpoint.observation_key(&proof, "POST", endpoint.url(), &None);
    ObservationCache::open(root.path(), 1024)
        .unwrap()
        .write(&key, &evidence())
        .unwrap();
    let delayed = server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.status(503)
            .delay(std::time::Duration::from_millis(100));
    });
    let session = HttpSession::new(
        ObservationLimits {
            total_timeout_ms: 50,
            max_attempts: 1,
            ..Default::default()
        },
        20,
    )
    .unwrap()
    .with_cache(
        ObservationCache::open(root.path(), 1024).unwrap(),
        ObservationMode::OnlineWithCacheFallback,
    )
    .unwrap();
    assert!(
        session
            .request_json(
                &endpoint,
                reqwest::Method::POST,
                endpoint.url().clone(),
                None,
                &proof
            )
            .await
            .is_err()
    );
    delayed.assert_calls(1);
}

#[tokio::test]
async fn offline_cache_is_redacted_again_for_rotated_endpoint_credentials() {
    use pybun::security_assessment::{
        ObservationLimits,
        http::{HttpSession, ObservationMode},
    };
    let server = httpmock::MockServer::start();
    let forbidden = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    let (endpoint, proof) = approved(&server);
    let root = private_root();
    let key = endpoint.observation_key(&proof, "POST", endpoint.url(), &None);
    let saved = JsonEvidence {
        value: json!({"name":"rotated-credential","details":"rotated-credential"}),
        ..evidence()
    };
    ObservationCache::open(root.path(), 1024)
        .unwrap()
        .write(&key, &saved)
        .unwrap();
    let rotated = endpoint.with_bearer_token("rotated-credential").unwrap();
    let session = HttpSession::new(ObservationLimits::default(), 20)
        .unwrap()
        .with_cache(
            ObservationCache::open(root.path(), 1024).unwrap(),
            ObservationMode::Offline,
        )
        .unwrap();
    let observed = session
        .request_json(
            &rotated,
            reqwest::Method::POST,
            rotated.url().clone(),
            None,
            &proof,
        )
        .await
        .unwrap();
    assert!(
        !serde_json::to_string(&observed)
            .unwrap()
            .contains("rotated-credential")
    );
    forbidden.assert_calls(0);
}
