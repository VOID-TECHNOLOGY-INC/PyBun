use httpmock::prelude::*;
use pybun::security_assessment::http::{HttpSession, ProviderConfig};
use pybun::security_assessment::qualification::registry_source::{
    RegistrySource, RegistrySourceConfig, observe_registry,
};
use pybun::security_assessment::*;
use serde_json::json;

fn policy() -> SourcePolicy {
    SourcePolicy {
        sources: vec![
            SourceIdentity::new("mirror-a", "tenant-a", SourceKind::PrivateRegistry).unwrap(),
        ],
        rules: vec![SourceRule {
            name: "internal-demo".into(),
            distribution: None,
            source_id: "mirror-a".into(),
            upstream_name: Some("public-demo".into()),
            ecosystem: Some("PyPI".into()),
            assumption: Some("Operator maps this mirror artifact to the public upstream.".into()),
        }],
        disclosure: vec![DisclosureGrant {
            provider_id: "mirror".into(),
            source_id: "mirror-a".into(),
            packages: vec!["internal-demo".into()],
        }],
    }
}

fn package(policy: &SourcePolicy) -> PackageInstance {
    let mapped = policy
        .map_package(
            "internal-demo",
            "internal_demo-1.dist-info",
            SourceKind::Unknown,
        )
        .unwrap();
    PackageInstance {
        instance_id: "instance".into(),
        name: "internal-demo".into(),
        version: "1".into(),
        source: mapped.source,
        source_mapping: mapped.mapping,
        scope_variant: "installed".into(),
        distribution_path: "internal_demo-1.dist-info".into(),
        metadata_digest: "metadata".into(),
        direct_url_digest: None,
        origin_identity: None,
        requires_dist: vec![],
        coverage: CoverageUnit::default(),
    }
}

fn source(server: &MockServer, source_id: &str) -> RegistrySource {
    RegistrySource::new(RegistrySourceConfig {
        source_id: source_id.into(),
        provider: ProviderConfig {
            id: "mirror".into(),
            url: server.url("/simple/"),
            auth_scope_id: "registry-tenant-a".into(),
            allow_insecure_loopback: true,
        },
    })
    .unwrap()
}

fn target() -> TargetTagProfile {
    TargetTagProfile {
        profile_version: 1,
        generator: "fixture".into(),
        generator_version: "1".into(),
        digest: "tags".into(),
        tags: vec!["py3-none-any".into()],
        implementation: "cpython".into(),
        python_version: "3.13.0".into(),
        os: "linux".into(),
        architecture: "x86_64".into(),
        libc: Some("glibc-2.34".into()),
        deployment: None,
    }
}

#[tokio::test]
async fn registry_uses_installed_distribution_instead_of_advisory_upstream_name() {
    let server = MockServer::start();
    let expected = server.mock(|when, then| {
        when.method(GET).path("/simple/internal-demo/");
        then.json_body(json!({"meta":{"api-version":"1.4"},"name":"internal-demo","versions":["2.0"],"files":[{"filename":"internal_demo-2.0-py3-none-any.whl","url":"../files/internal_demo-2.0-py3-none-any.whl","hashes":{},"size":123,"yanked":false}]}));
    });
    let forbidden = server.mock(|when, then| {
        when.path("/simple/public-demo/");
        then.status(500);
    });
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let remaining_before = session.remaining_evidence_bytes();
    let observed = observe_registry(
        &session,
        &source(&server, "mirror-a"),
        &package(&policy()),
        &target(),
        &policy(),
    )
    .await
    .unwrap();
    assert_eq!(observed.distribution, "internal-demo");
    assert_eq!(observed.source_id, "mirror-a");
    assert_eq!(observed.source_auth_scope_id, "tenant-a");
    assert_eq!(observed.provider_auth_scope_id, "registry-tenant-a");
    assert_eq!(observed.catalog.releases.len(), 1);
    assert!(
        session.remaining_evidence_bytes() < remaining_before,
        "registry evidence must use the shared run budget"
    );
    expected.assert_calls(1);
    forbidden.assert_calls(0);
}

#[tokio::test]
async fn registry_permissions_and_source_binding_are_rechecked_before_http() {
    let server = MockServer::start();
    let forbidden = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    let observed = package(&policy());
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let mut revoked = policy();
    revoked.disclosure.clear();
    assert!(
        observe_registry(
            &session,
            &source(&server, "mirror-a"),
            &observed,
            &target(),
            &revoked
        )
        .await
        .is_err()
    );
    assert!(
        observe_registry(
            &session,
            &source(&server, "mirror-b"),
            &observed,
            &target(),
            &policy()
        )
        .await
        .is_err()
    );
    let mut changed = policy();
    changed.rules[0].source_id = "other-source".into();
    changed.sources.push(
        SourceIdentity::new("other-source", "other-scope", SourceKind::PrivateRegistry).unwrap(),
    );
    assert!(
        observe_registry(
            &session,
            &source(&server, "mirror-a"),
            &observed,
            &target(),
            &changed
        )
        .await
        .is_err()
    );
    forbidden.assert_calls(0);
}

#[tokio::test]
async fn registry_catalogs_share_the_retained_evidence_budget() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/simple/internal-demo/");
        then.json_body(json!({"meta":{"api-version":"1.4"},"name":"internal-demo","versions":["2.0"],"files":[{"filename":"internal_demo-2.0-py3-none-any.whl","url":"../files/internal_demo-2.0-py3-none-any.whl","hashes":{},"size":123,"yanked":false}]}));
    });
    let source = source(&server, "mirror-a");
    let package = package(&policy());
    let sample_session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let sample = observe_registry(&sample_session, &source, &package, &target(), &policy())
        .await
        .unwrap();
    let size = serde_json::to_vec(&sample).unwrap().len();
    let session = HttpSession::new(
        ObservationLimits {
            max_retained_evidence_bytes: size + size / 2,
            ..Default::default()
        },
        20,
    )
    .unwrap();
    observe_registry(&session, &source, &package, &target(), &policy())
        .await
        .unwrap();
    let remaining = session.remaining_evidence_bytes();
    let error = observe_registry(&session, &source, &package, &target(), &policy())
        .await
        .unwrap_err();
    assert_eq!(error.code, "E_SECURITY_EVIDENCE_LIMIT");
    assert_eq!(
        session.remaining_evidence_bytes(),
        remaining,
        "failed reservation must not change the budget"
    );
}
