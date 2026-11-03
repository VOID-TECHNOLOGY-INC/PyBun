//! Previously observed IDs are locators, never source or HTTP authority.
use httpmock::prelude::*;
use pybun::security_assessment::{
    http::{HttpSession, ProviderConfig, ProviderEndpoint},
    osv::{KnownAdvisoryId, query_authoritative_advisories_with_history},
    *,
};
use serde_json::json;

fn inputs(server: &MockServer) -> (ProviderEndpoint, SourcePolicy, PackageInstance) {
    let policy = SourcePolicy {
        sources: vec![SourceIdentity::new("public", "public", SourceKind::PublicRegistry).unwrap()],
        rules: vec![SourceRule {
            name: "demo".into(),
            distribution: None,
            source_id: "public".into(),
            upstream_name: Some("demo".into()),
            ecosystem: Some("PyPI".into()),
            assumption: Some("Explicit operator mapping".into()),
        }],
        disclosure: vec![DisclosureGrant {
            provider_id: "osv".into(),
            source_id: "public".into(),
            packages: vec!["demo".into()],
        }],
    };
    let mapped = policy
        .map_package("demo", "demo-1.dist-info", SourceKind::Unknown)
        .unwrap();
    let package = PackageInstance {
        instance_id: "current-instance".into(),
        name: "demo".into(),
        version: "1".into(),
        source: mapped.source,
        source_mapping: mapped.mapping,
        scope_variant: "installed".into(),
        distribution_path: "demo-1.dist-info".into(),
        metadata_digest: "metadata".into(),
        direct_url_digest: None,
        origin_identity: None,
        requires_dist: vec![],
        coverage: CoverageUnit::default(),
    };
    let endpoint = ProviderEndpoint::new(ProviderConfig {
        id: "osv".into(),
        url: server.url("/v1/querybatch"),
        auth_scope_id: "public".into(),
        allow_insecure_loopback: true,
    })
    .unwrap();
    (endpoint, policy, package)
}
fn known() -> KnownAdvisoryId {
    KnownAdvisoryId {
        instance_id: "current-instance".into(),
        provider_id: "osv".into(),
        record_id: "OLD".into(),
    }
}

#[tokio::test]
async fn query_omission_still_refreshes_an_explicit_withdrawal() {
    let server = MockServer::start();
    let batch = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let detail = server.mock(|when, then| {
        when.method(GET).path("/v1/vulns/OLD");
        then.json_body(json!({"id":"OLD","modified":"2026-01-02T00:00:00Z","withdrawn":"2026-01-02T00:00:00Z"}));
    });
    let (endpoint, policy, package) = inputs(&server);
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let observations = query_authoritative_advisories_with_history(
        &session,
        &[&endpoint],
        &[package],
        &policy,
        &[known()],
    )
    .await;
    let item = &observations[0].instances[0];
    assert_eq!(item.records.len(), 1);
    assert_eq!(item.records[0].coverage.status, CoverageStatus::Complete);
    assert!(item.records[0].payload.get("withdrawn").is_some());
    assert_eq!(observations[0].coverage.status, CoverageStatus::Complete);
    batch.assert_calls(1);
    detail.assert_calls(1);
}

#[tokio::test]
async fn known_id_also_returned_by_query_is_not_a_pagination_duplicate() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST);
        then.json_body(json!({"results":[{"vulns":[{"id":"OLD"}]}]}));
    });
    let detail = server.mock(|when, then| {
        when.method(GET).path("/v1/vulns/OLD");
        then.json_body(json!({"id":"OLD","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"versions":["1"]}]}));
    });
    let (endpoint, policy, package) = inputs(&server);
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let observations = query_authoritative_advisories_with_history(
        &session,
        &[&endpoint],
        &[package],
        &policy,
        &[known(), known()],
    )
    .await;
    assert_eq!(observations[0].coverage.status, CoverageStatus::Complete);
    assert_eq!(observations[0].instances[0].records.len(), 1);
    detail.assert_calls(1);
}

#[tokio::test]
async fn saved_ids_do_not_restore_revoked_disclosure_authority() {
    let server = MockServer::start();
    let network = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    let (endpoint, mut policy, package) = inputs(&server);
    policy.disclosure.clear();
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let observations = query_authoritative_advisories_with_history(
        &session,
        &[&endpoint],
        &[package],
        &policy,
        &[known()],
    )
    .await;
    assert_ne!(observations[0].coverage.status, CoverageStatus::Complete);
    assert!(observations[0].instances[0].records.is_empty());
    network.assert_calls(0);
}

#[tokio::test]
async fn missing_known_detail_is_incomplete_and_never_fabricated_as_withdrawn() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST);
        then.json_body(json!({"results":[{}]}));
    });
    let detail = server.mock(|when, then| {
        when.method(GET).path("/v1/vulns/OLD");
        then.status(404);
    });
    let (endpoint, policy, package) = inputs(&server);
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let observations = query_authoritative_advisories_with_history(
        &session,
        &[&endpoint],
        &[package],
        &policy,
        &[known()],
    )
    .await;
    assert_ne!(observations[0].coverage.status, CoverageStatus::Complete);
    assert!(observations[0].instances[0].records.is_empty());
    detail.assert_calls(1);
}

#[tokio::test]
async fn historical_hydration_uses_the_same_request_budget() {
    let server = MockServer::start();
    let batch = server.mock(|when, then| {
        when.method(POST);
        then.json_body(json!({"results":[{}]}));
    });
    let detail = server.mock(|when, then| {
        when.method(GET);
        then.status(500);
    });
    let (endpoint, policy, package) = inputs(&server);
    let session = HttpSession::new(
        ObservationLimits {
            max_requests: 1,
            ..ObservationLimits::default()
        },
        20,
    )
    .unwrap();
    let observations = query_authoritative_advisories_with_history(
        &session,
        &[&endpoint],
        &[package],
        &policy,
        &[known()],
    )
    .await;
    assert_ne!(observations[0].coverage.status, CoverageStatus::Complete);
    assert!(observations[0].instances[0].records.is_empty());
    batch.assert_calls(1);
    detail.assert_calls(0);
}
