use httpmock::prelude::*;
use pybun::security_assessment::http::{HttpSession, ProviderConfig, ProviderEndpoint};
use pybun::security_assessment::osv::observe_advisories;
use pybun::security_assessment::*;
use serde_json::json;

#[tokio::test]
async fn provider_echoes_cannot_leak_ephemeral_bearer_credentials() {
    for secret in [
        format!("credential-{}", uuid::Uuid::new_v4()),
        "12345678".into(),
        "true".into(),
        "secr3t".into(),
    ] {
        let server = MockServer::start();
        server.mock(|when,then| {
        when.method(POST).path("/v1/querybatch");
        let scalar=serde_json::from_str::<serde_json::Value>(&secret).unwrap_or(json!(null));
        then.json_body(json!({"message":format!("prefix{secret}suffix"),"type":secret,"name":secret,format!("prefix{secret}suffix"):scalar}));
    });
        let provider = endpoint(&server).with_bearer_token(&secret).unwrap();
        let current = policy();
        let mapped = current
            .map_package("demo", "demo-1.0.dist-info", SourceKind::Unknown)
            .unwrap();
        let proof = current.authorized_query("osv", "demo", &mapped).unwrap();
        let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
        let observed = session
            .request_json(
                &provider,
                reqwest::Method::POST,
                provider.url().clone(),
                None,
                &proof,
            )
            .await
            .unwrap();
        assert!(!serde_json::to_string(&observed).unwrap().contains(&secret));
    }
}

#[tokio::test]
async fn combined_current_and_candidate_work_is_chunked_without_relaxing_inventory_limits() {
    let server = MockServer::start();
    let queries:Vec<_>=(0..1001).map(|index|json!({"package":{"name":"demo","ecosystem":"PyPI"},"version":format!("1.{index}")})).collect();
    let first = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/querybatch")
            .json_body(json!({"queries":&queries[..1000]}));
        then.json_body(json!({"results":vec![json!({});1000]}));
    });
    let second = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/querybatch")
            .json_body(json!({"queries":&queries[1000..]}));
        then.json_body(json!({"results":[{}]}));
    });
    let mut input = inventory(&policy());
    let package = input.packages[0].clone();
    input.packages = (0..1001)
        .map(|index| {
            let mut item = package.clone();
            item.instance_id = format!("query-{index}");
            item.version = format!("1.{index}");
            item
        })
        .collect();
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let denied = observe_advisories(&session, &endpoint(&server), &input, &policy()).await;
    assert_ne!(denied.coverage.status, CoverageStatus::Complete);
    first.assert_calls(0);
    second.assert_calls(0);
    let observed = pybun::security_assessment::osv::query_advisories(
        &session,
        &endpoint(&server),
        &input.packages,
        &policy(),
    )
    .await;
    assert_eq!(
        observed.coverage.status,
        CoverageStatus::Complete,
        "{observed:?}"
    );
    assert_eq!(observed.instances.len(), 1001);
    first.assert_calls(1);
    second.assert_calls(1);
}

#[tokio::test]
async fn bounded_provider_work_preserves_the_callers_package_priority() {
    let server = MockServer::start();
    let batch = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let mut current = policy();
    let rule = current.rules[0].clone();
    current.sources.clear();
    current.rules.clear();
    current.disclosure.clear();
    let mut input = inventory(&policy());
    input.packages.push(input.packages[0].clone());
    for (index, (id, distribution)) in [("tenant-z", "z.dist-info"), ("tenant-a", "a.dist-info")]
        .into_iter()
        .enumerate()
    {
        current
            .sources
            .push(SourceIdentity::new(id, id, SourceKind::PrivateRegistry).unwrap());
        let mut entry = rule.clone();
        entry.source_id = id.into();
        entry.distribution = Some(distribution.into());
        current.rules.push(entry);
        current.disclosure.push(DisclosureGrant {
            provider_id: "osv".into(),
            source_id: id.into(),
            packages: vec!["demo".into()],
        });
        let mapped = current
            .map_package("demo", distribution, SourceKind::Unknown)
            .unwrap();
        input.packages[index].source = mapped.source;
        input.packages[index].source_mapping = mapped.mapping;
        input.packages[index].distribution_path = distribution.into();
        input.packages[index].instance_id = id.into();
    }
    let session = HttpSession::new(
        ObservationLimits {
            max_pages: 1,
            ..Default::default()
        },
        20,
    )
    .unwrap();
    let observed = observe_advisories(&session, &endpoint(&server), &input, &current).await;
    assert_eq!(
        observed.instances[0].coverage.status,
        CoverageStatus::Complete,
        "the caller's circular start must survive grouping"
    );
    assert_eq!(
        observed.instances[1].coverage.status,
        CoverageStatus::Partial
    );
    batch.assert_calls(1);
}

#[tokio::test]
async fn ecosystem_wildcard_advisories_remain_complete_scoped_evidence() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{"vulns":[{"id":"ECOSYSTEM-EOL"}]}]}));
    });
    server.mock(|when, then| {
        when.method(GET).path("/v1/vulns/ECOSYSTEM-EOL");
        then.json_body(json!({"id":"ECOSYSTEM-EOL","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"*","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}));
    });
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let observed = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert_eq!(observed.coverage.status, CoverageStatus::Complete);
    assert_eq!(
        observed.instances[0].records[0].coverage.status,
        CoverageStatus::Complete
    );
}

#[tokio::test]
async fn retained_evidence_budget_is_shared_across_candidate_queries() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{"vulns":[{"id":"EXAMPLE-1"}]}]}));
    });
    server.mock(|when, then| {
        when.method(GET).path("/v1/vulns/EXAMPLE-1");
        then.json_body(json!({"id":"EXAMPLE-1","modified":"2026-01-01T00:00:00Z","details":"x".repeat(900),"affected":[{"package":{"name":"demo","ecosystem":"PyPI"}}]}));
    });
    let session = HttpSession::new(
        ObservationLimits {
            max_response_bytes: 1800,
            max_retained_evidence_bytes: 5000,
            ..Default::default()
        },
        20,
    )
    .unwrap();
    let first = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert_eq!(first.instances[0].records.len(), 1);
    let second = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert!(second.instances[0].records.is_empty());
    assert_ne!(second.coverage.status, CoverageStatus::Complete);
    assert!(
        second
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_EVIDENCE_LIMIT")
    );
}

#[tokio::test]
async fn shared_advisory_payload_cannot_multiply_the_run_evidence_budget() {
    let server = MockServer::start();
    let batch = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(
            json!({"results":[{"vulns":[{"id":"EXAMPLE-1"}]},{"vulns":[{"id":"EXAMPLE-1"}]}]}),
        );
    });
    let detail = server.mock(|when, then| {
        when.method(GET).path("/v1/vulns/EXAMPLE-1");
        then.json_body(json!({"id":"EXAMPLE-1","modified":"2026-01-01T00:00:00Z","details":"x".repeat(900),"affected":[{"package":{"name":"demo","ecosystem":"PyPI"}}]}));
    });
    let mut input = inventory(&policy());
    let mut second = input.packages[0].clone();
    second.instance_id = "second-instance".into();
    second.version = "1.1".into();
    input.packages.push(second);
    let limits = ObservationLimits {
        max_response_bytes: 1800,
        max_retained_evidence_bytes: 5000,
        ..Default::default()
    };
    let session = HttpSession::new(limits, 20).unwrap();
    let observed = observe_advisories(&session, &endpoint(&server), &input, &policy()).await;
    assert_eq!(observed.instances[0].records.len(), 1);
    assert!(observed.instances[1].records.is_empty());
    assert_eq!(
        observed.instances[0].coverage.status,
        CoverageStatus::Complete
    );
    assert_eq!(
        observed.instances[1].coverage.status,
        CoverageStatus::Partial
    );
    assert!(
        observed
            .diagnostics
            .iter()
            .any(|error| error.code == "E_SECURITY_EVIDENCE_LIMIT")
    );
    batch.assert_calls(1);
    detail.assert_calls(1);
}

#[tokio::test]
async fn failed_inventory_is_never_a_complete_empty_advisory_scan() {
    let server = MockServer::start();
    let forbidden = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    for status in [CoverageStatus::Unsupported, CoverageStatus::Error] {
        let mut input = inventory(&policy());
        input.coverage.inventory_instances.status = status;
        input.packages.clear();
        input.target = None;
        let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
        let observed = observe_advisories(&session, &endpoint(&server), &input, &policy()).await;
        assert_eq!(observed.coverage.status, status);
        assert_eq!(observed.advisory_records.status, status);
        assert!(!observed.diagnostics.is_empty());
    }
    forbidden.assert_calls(0);
}

#[tokio::test]
async fn partial_inventory_preserves_complete_known_instance_evidence() {
    let server = MockServer::start();
    let batch = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let mut input = inventory(&policy());
    input.coverage.inventory_instances.status = CoverageStatus::Partial;
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let observed = observe_advisories(&session, &endpoint(&server), &input, &policy()).await;
    assert_eq!(observed.coverage.status, CoverageStatus::Partial);
    assert_eq!(observed.advisory_records.status, CoverageStatus::Partial);
    assert_eq!(
        observed.instances[0].coverage.status,
        CoverageStatus::Complete
    );
    batch.assert_calls(1);
}

#[tokio::test]
async fn provider_page_budget_is_shared_across_observations_in_one_run() {
    let server = MockServer::start();
    let batch = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let limits = ObservationLimits {
        max_pages: 1,
        ..Default::default()
    };
    let session = HttpSession::new(limits, 20).unwrap();
    let first = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert_eq!(first.coverage.status, CoverageStatus::Complete);
    let second = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert_ne!(second.coverage.status, CoverageStatus::Complete);
    batch.assert_calls(1);
}

fn endpoint(server: &MockServer) -> ProviderEndpoint {
    ProviderEndpoint::new(ProviderConfig {
        id: "osv".into(),
        url: server.url("/v1/querybatch"),
        auth_scope_id: "public".into(),
        allow_insecure_loopback: true,
    })
    .unwrap()
}

fn policy() -> SourcePolicy {
    SourcePolicy {
        sources: vec![
            SourceIdentity::new("public-pypi", "public", SourceKind::PublicRegistry).unwrap(),
        ],
        rules: vec![SourceRule {
            name: "demo".into(),
            distribution: None,
            source_id: "public-pypi".into(),
            upstream_name: Some("demo".into()),
            ecosystem: Some("PyPI".into()),
            assumption: Some("Operator explicitly maps this distribution to public PyPI.".into()),
        }],
        disclosure: vec![DisclosureGrant {
            provider_id: "osv".into(),
            source_id: "public-pypi".into(),
            packages: vec!["demo".into()],
        }],
    }
}

fn inventory(policy: &SourcePolicy) -> InventoryObservation {
    let source = policy
        .map_package("demo", "demo-1.0.dist-info", SourceKind::Unknown)
        .unwrap();
    InventoryObservation {
        observation_version: 1,
        inventory_id: "inventory".into(),
        observation_id: "observation".into(),
        observed_at: 10,
        target: Some(ObservedTarget {
            marker_environment: Default::default(),
            interpreter_digest: "fixture-digest".into(),
            interpreter_identity_evidence: "canonical_path".into(),
            project_root: "/fixture".into(),
            environment_root: "/fixture/.venv".into(),
            interpreter: "/fixture/.venv/bin/python".into(),
            inspector: "/trusted/python".into(),
            kind: InventoryTarget::Installed,
            backend: InventoryBackend::Uv,
            scope: InventoryScope::default(),
            tag_profile: TargetTagProfile {
                profile_version: 1,
                generator: "fixture".into(),
                generator_version: "1".into(),
                digest: "tag-profile".into(),
                tags: vec!["py3-none-any".into()],
                implementation: "cpython".into(),
                python_version: "3.13.0".into(),
                os: "linux".into(),
                architecture: "x86_64".into(),
                libc: Some("glibc-2.34".into()),
                deployment: None,
            },
            environment_fingerprint: "environment".into(),
            project_digest: None,
            lock_digest: None,
        }),
        packages: vec![PackageInstance {
            instance_id: "instance".into(),
            name: "demo".into(),
            version: "1.0".into(),
            source: source.source,
            source_mapping: source.mapping,
            scope_variant: "installed".into(),
            distribution_path: "demo-1.0.dist-info".into(),
            metadata_digest: "metadata".into(),
            direct_url_digest: None,
            origin_identity: None,
            requires_dist: vec![],
            coverage: CoverageUnit::default(),
        }],
        direct_constraints: vec![],
        coverage: ObservationCoverage::default(),
        diagnostics: vec![],
    }
}

#[tokio::test]
async fn observations_hydrate_id_only_results_and_preserve_full_records() {
    let server = MockServer::start();
    let batch = server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch").json_body(
            json!({"queries":[{"package":{"name":"demo","ecosystem":"PyPI"},"version":"1.0"}]}),
        );
        then.json_body(
            json!({"results":[{"vulns":[{"id":"EXAMPLE-1","modified":"2026-01-01T00:00:00Z"}]}]}),
        );
    });
    let payload = json!({"schema_version":"1.7.0","id":"EXAMPLE-1","modified":"2026-01-01T00:00:00Z","aliases":["CVE-EXAMPLE"],"affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}],"references":[{"type":"WEB","url":"https://never-follow.invalid/reference"}]});
    let detail = server.mock(|when, then| {
        when.method(GET).path("/v1/vulns/EXAMPLE-1");
        then.json_body(payload.clone());
    });
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let observed = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert_eq!(
        observed.coverage.status,
        CoverageStatus::Complete,
        "{observed:?}"
    );
    assert_eq!(observed.instances[0].records[0].payload, payload);
    assert_eq!(observed.instances[0].records[0].fetched_at, 20);
    assert_eq!(observed.instances[0].records[0].payload_digest.len(), 64);
    batch.assert_calls(1);
    detail.assert_calls(1);
}

#[tokio::test]
async fn revoked_disclosure_or_unknown_mapping_never_issues_a_request() {
    let server = MockServer::start();
    let forbidden = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let mut revoked = policy();
    revoked.disclosure.clear();
    let result = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &revoked,
    )
    .await;
    assert_ne!(result.coverage.status, CoverageStatus::Complete);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_DISCLOSURE_DENIED")
    );
    let unknown = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &SourcePolicy::default(),
    )
    .await;
    assert_ne!(unknown.coverage.status, CoverageStatus::Complete);
    forbidden.assert_calls(0);
}

#[tokio::test]
async fn cross_origin_redirect_and_response_limits_are_fail_closed() {
    let server = MockServer::start();
    let other = MockServer::start();
    let forbidden = other.mock(|when, then| {
        when.any_request();
        then.json_body(json!({"results":[]}));
    });
    server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.status(307).header("location", other.url("/collect"));
    });
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let observed = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert!(
        observed
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_PROVIDER_REDIRECT"),
        "{observed:?}"
    );
    forbidden.assert_calls(0);
    let large = MockServer::start();
    large.mock(|when, then| {
        when.any_request();
        then.body("x".repeat(1025));
    });
    let limits = ObservationLimits {
        max_response_bytes: 1024,
        ..Default::default()
    };
    let bounded = HttpSession::new(limits, 20).unwrap();
    let observed = observe_advisories(
        &bounded,
        &endpoint(&large),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert!(
        observed
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_RESPONSE_LIMIT"),
        "{observed:?}"
    );
}

#[tokio::test]
async fn pagination_loops_and_missing_details_keep_explicit_incomplete_coverage() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.any_request().path("/v1/querybatch");
        then.json_body(
            json!({"results":[{"vulns":[{"id":"EXAMPLE-1"}],"next_page_token":"same"}]}),
        );
    });
    server.mock(|when, then| {
        when.path("/v1/vulns/EXAMPLE-1");
        then.status(404);
    });
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let observed = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert_ne!(observed.coverage.status, CoverageStatus::Complete);
    assert!(
        observed
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_PROVIDER_PAGE"),
        "{observed:?}"
    );
    assert!(
        observed
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_PROVIDER_HTTP"),
        "{observed:?}"
    );
}

#[test]
fn endpoints_reject_credentials_and_unapproved_plain_http() {
    for url in [
        "https://user:secret@example.com/v1/querybatch",
        "https://example.com/v1/querybatch?token=secret",
        "http://example.com/v1/querybatch",
    ] {
        assert!(
            ProviderEndpoint::new(ProviderConfig {
                id: "osv".into(),
                url: url.into(),
                auth_scope_id: "tenant".into(),
                allow_insecure_loopback: false
            })
            .is_err()
        );
    }
}

#[tokio::test]
async fn request_deadline_budget_and_unsupported_encoding_are_explicit() {
    let server = MockServer::start();
    let unavailable = server.mock(|when, then| {
        when.any_request();
        then.status(503);
    });
    let session = HttpSession::new(
        ObservationLimits {
            max_requests: 1,
            ..Default::default()
        },
        20,
    )
    .unwrap();
    let observed = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert!(
        observed
            .diagnostics
            .iter()
            .any(|error| error.code == "E_SECURITY_REQUEST_LIMIT"),
        "{observed:?}"
    );
    assert_eq!(session.request_count(), 1);
    unavailable.assert_calls(1);

    let slow = MockServer::start();
    slow.mock(|when, then| {
        when.any_request();
        then.delay(std::time::Duration::from_secs(1))
            .json_body(json!({"results":[{}]}));
    });
    let session = HttpSession::new(
        ObservationLimits {
            total_timeout_ms: 40,
            http_timeout_ms: 10,
            ..Default::default()
        },
        20,
    )
    .unwrap();
    let observed =
        observe_advisories(&session, &endpoint(&slow), &inventory(&policy()), &policy()).await;
    assert_ne!(observed.coverage.status, CoverageStatus::Complete);
    assert!(
        observed.diagnostics.iter().any(|error| matches!(
            error.code.as_str(),
            "E_SECURITY_PROVIDER_HTTP" | "E_SECURITY_DEADLINE"
        )),
        "{observed:?}"
    );
    assert!(session.request_count() <= 2);

    let encoded = MockServer::start();
    encoded.mock(|when, then| {
        when.any_request();
        then.header("content-encoding", "gzip")
            .body("compressed bytes");
    });
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let observed = observe_advisories(
        &session,
        &endpoint(&encoded),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert!(
        observed
            .diagnostics
            .iter()
            .any(|error| error.code == "E_SECURITY_PROVIDER_ENCODING")
    );
}

#[test]
fn derived_urls_and_transport_identities_do_not_expand_with_credentials() {
    let server = MockServer::start();
    let provider = endpoint(&server);
    let source = policy();
    let mapped = source
        .map_package("demo", "demo-1.0.dist-info", SourceKind::Unknown)
        .unwrap();
    let proof = source.authorized_query("osv", "demo", &mapped).unwrap();
    let key = provider.observation_key(&proof, "POST", provider.url(), &None);
    let rotated = provider
        .clone()
        .with_bearer_token("secret-rotation")
        .unwrap();
    assert_eq!(
        key,
        rotated.observation_key(&proof, "POST", rotated.url(), &None)
    );
    let other_scope = ProviderEndpoint::new(ProviderConfig {
        auth_scope_id: "other-tenant".into(),
        id: "osv".into(),
        url: provider.url().to_string(),
        allow_insecure_loopback: true,
    })
    .unwrap();
    assert_ne!(
        key,
        other_scope.observation_key(&proof, "POST", other_scope.url(), &None)
    );
    assert!(!format!("{rotated:?}").contains("secret-rotation"));
    assert!(!provider.permits(&server.url("/outside").parse().unwrap()));
    assert!(!provider.permits(&"https://not-approved.invalid/v1/vulns/ID".parse().unwrap()));
    assert!(provider.detail_url("../../outside").is_err());
}

#[tokio::test]
async fn full_evidence_is_redacted_and_wrong_package_or_future_schema_is_incomplete() {
    for (name, schema) in [("different", "1.7.0"), ("demo", "9.0.0")] {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.path("/v1/querybatch");
            then.json_body(json!({"results":[{"vulns":[{"id":"EXAMPLE-1"}]}]}));
        });
        server.mock(|when,then| {when.path("/v1/vulns/EXAMPLE-1");then.json_body(json!({"schema_version":schema,"id":"EXAMPLE-1","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":name,"ecosystem":"PyPI"}}],"references":[{"url":"https://user:password@example.com/?token=secret-value"}]}));});
        let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
        let observed = observe_advisories(
            &session,
            &endpoint(&server),
            &inventory(&policy()),
            &policy(),
        )
        .await;
        assert_ne!(
            observed.coverage.status,
            CoverageStatus::Complete,
            "{observed:?}"
        );
        assert_eq!(
            observed.instances[0].records.len(),
            1,
            "invalid evidence is retained explicitly"
        );
        let serialized = serde_json::to_string(&observed).unwrap();
        assert!(!serialized.contains("user:password"));
        assert!(!serialized.contains("secret-value"));
    }
}

#[tokio::test]
async fn candidate_progress_distinguishes_detail_attempts_from_budget_misses() {
    for status in [200, 500] {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.path("/v1/querybatch");
            then.json_body(json!({"results":[{"vulns":[{"id":"A"}]},{"vulns":[{"id":"B"}]},{}]}));
        });
        server.mock(|when,then| {when.path("/v1/vulns/A");then.status(status).json_body(json!({"id":"A","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"versions":["1.0"]}]}));});
        let policy = policy();
        let mut input = inventory(&policy);
        input.packages = (0..3)
            .map(|i| {
                let mut package = input.packages[0].clone();
                package.instance_id = format!("instance-{i}");
                package
            })
            .collect();
        let session = HttpSession::new(
            ObservationLimits {
                max_requests: 2,
                max_attempts: 1,
                ..Default::default()
            },
            20,
        )
        .unwrap();
        let observed = observe_advisories(&session, &endpoint(&server), &input, &policy).await;
        assert!(
            observed.instances[0].work_attempted,
            "a real failed detail attempt still visits the candidate"
        );
        assert!(
            !observed.instances[1].work_attempted,
            "a shared request-budget miss is not observed work"
        );
        assert!(
            observed.instances[2].work_attempted,
            "a complete empty query needs no detail request"
        );
    }
}

#[tokio::test]
async fn empty_advisory_queries_still_reserve_retained_instance_evidence() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.respond_with(|request| {
            let value: serde_json::Value = serde_json::from_slice(request.body_ref()).unwrap();
            let count = value["queries"].as_array().unwrap().len();
            httpmock::HttpMockResponse::builder()
                .status(200)
                .body(json!({"results":vec![json!({});count]}).to_string())
                .build()
        });
    });
    let policy = policy();
    let mut input = inventory(&policy);
    input.packages = (0..50)
        .map(|index| {
            let mut package = input.packages[0].clone();
            package.instance_id = format!("instance-{index}");
            package
        })
        .collect();
    let session = HttpSession::new(
        ObservationLimits {
            max_retained_evidence_bytes: 8000,
            ..Default::default()
        },
        20,
    )
    .unwrap();
    let result = observe_advisories(&session, &endpoint(&server), &input, &policy).await;
    assert_ne!(
        result.coverage.status,
        CoverageStatus::Complete,
        "an empty record set does not make per-instance provenance free"
    );
    assert!(result.instances.len() < 50);
    assert!(serde_json::to_vec(&result.instances).unwrap().len() <= 8000);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|error| error.code == "E_SECURITY_EVIDENCE_LIMIT")
    );
}

#[tokio::test]
async fn successful_pagination_preserves_the_exact_noncredential_page_token() {
    let server = MockServer::start();
    let token = "opaque-page-two";
    let first = server.mock(|when, then| {
        when.path("/v1/querybatch").json_body(
            json!({"queries":[{"package":{"name":"demo","ecosystem":"PyPI"},"version":"1.0"}]}),
        );
        then.json_body(json!({"results":[{"vulns":[{"id":"A"}],"next_page_token":token}]}));
    });
    let second=server.mock(|when,then|{when.path("/v1/querybatch").json_body(json!({"queries":[{"package":{"name":"demo","ecosystem":"PyPI"},"version":"1.0","page_token":token}]}));then.json_body(json!({"results":[{"vulns":[{"id":"B"}]}]}));});
    for id in ["A", "B"] {
        server.mock(|when,then|{when.path(format!("/v1/vulns/{id}"));then.json_body(json!({"id":id,"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"versions":["1.0"]}]}));});
    }
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let result = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert_eq!(
        result.coverage.status,
        CoverageStatus::Complete,
        "{result:?}"
    );
    assert_eq!(result.instances[0].records.len(), 2);
    first.assert_calls(1);
    second.assert_calls(1);
}

#[tokio::test]
async fn redaction_of_a_functional_cursor_is_incomplete_instead_of_a_different_request() {
    let server = MockServer::start();
    let secret = "credential-in-page-token";
    let first = server.mock(|when, then| {
        when.path("/v1/querybatch").json_body(
            json!({"queries":[{"package":{"name":"demo","ecosystem":"PyPI"},"version":"1.0"}]}),
        );
        then.json_body(json!({"results":[{"next_page_token":secret}]}));
    });
    let corrupted=server.mock(|when,then|{when.path("/v1/querybatch").json_body(json!({"queries":[{"package":{"name":"demo","ecosystem":"PyPI"},"version":"1.0","page_token":"<redacted>"}]}));then.json_body(json!({"results":[{}]}));});
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let endpoint = endpoint(&server).with_bearer_token(secret).unwrap();
    let result = observe_advisories(&session, &endpoint, &inventory(&policy()), &policy()).await;
    assert_eq!(result.coverage.status, CoverageStatus::Partial);
    first.assert_calls(1);
    corrupted.assert_calls(0);
}

#[tokio::test]
async fn individually_attempted_pagination_is_progress_even_without_advisory_records() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.respond_with(|request| {
            let value: serde_json::Value = serde_json::from_slice(request.body_ref()).unwrap();
            let page = value["queries"][0]["page_token"]
                .as_str()
                .and_then(|token| token.parse::<usize>().ok())
                .unwrap_or(0);
            httpmock::HttpMockResponse::builder()
                .status(200)
                .body(json!({"results":[{"next_page_token":(page+1).to_string()}]}).to_string())
                .build()
        });
    });
    let session = HttpSession::new(
        ObservationLimits {
            max_pages: 2,
            ..Default::default()
        },
        20,
    )
    .unwrap();
    let result = observe_advisories(
        &session,
        &endpoint(&server),
        &inventory(&policy()),
        &policy(),
    )
    .await;
    assert_eq!(result.coverage.status, CoverageStatus::Partial);
    assert!(result.instances[0].records.is_empty());
    assert!(
        result.instances[0].work_attempted,
        "an individually visited candidate must not pin continuation before later candidates"
    );
}
