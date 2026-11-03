use httpmock::prelude::*;
use pybun::security_assessment::http::{HttpSession, ProviderConfig, ProviderEndpoint};
use pybun::security_assessment::qualification::{
    candidate::CandidateKind,
    registry_source::{RegistrySource, RegistrySourceConfig},
    service::{AssessmentOptions, assess_inventory},
};
use pybun::security_assessment::*;
use serde_json::json;
fn policy() -> SourcePolicy {
    let mut policy = SourcePolicy {
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
    };
    policy.disclosure.push(DisclosureGrant {
        provider_id: "registry".into(),
        source_id: "public-pypi".into(),
        packages: vec!["demo".into()],
    });
    policy
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
async fn known_withdrawal_reaches_the_shared_assessment_after_query_omission() {
    use pybun::security_assessment::osv::KnownAdvisoryId;
    use pybun::security_assessment::qualification::service::assess_inventory_with_history;
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/simple/demo/");
        then.json_body(
            json!({"meta":{"api-version":"1.4"},"name":"demo","versions":[],"files":[]}),
        );
    });
    server.mock(|when, then| {
        when.method(POST).path("/v1/querybatch");
        then.json_body(json!({"results":[{}]}));
    });
    let detail = server.mock(|when, then| {
        when.method(GET).path("/v1/vulns/OLD");
        then.json_body(json!({"id":"OLD","modified":"2026-01-02T00:00:00Z","withdrawn":"2026-01-02T00:00:00Z"}));
    });
    let provider = ProviderEndpoint::new(ProviderConfig {
        id: "osv".into(),
        url: server.url("/v1/querybatch"),
        auth_scope_id: "public".into(),
        allow_insecure_loopback: true,
    })
    .unwrap();
    let source = RegistrySource::new(RegistrySourceConfig {
        source_id: "public-pypi".into(),
        provider: ProviderConfig {
            id: "registry".into(),
            url: server.url("/simple/"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        },
    })
    .unwrap();
    let policy = policy();
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let result = assess_inventory_with_history(
        &session,
        &inventory(&policy),
        &policy,
        &[provider],
        &[source],
        &AssessmentOptions::default(),
        &[KnownAdvisoryId {
            instance_id: "instance".into(),
            provider_id: "osv".into(),
            record_id: "OLD".into(),
        }],
    )
    .await
    .unwrap();
    let record = &result.providers[0].instances[0].records[0];
    assert_eq!(record.id, "OLD");
    assert_eq!(record.coverage.status, CoverageStatus::Complete);
    assert!(record.payload.get("withdrawn").is_some());
    detail.assert_calls(1);
}

#[tokio::test]
async fn shared_service_retains_blocked_candidates_and_queries_current_and_candidates_together() {
    let server = MockServer::start();
    let index=server.mock(|when,then|{when.method(GET).path("/simple/demo/");then.json_body(json!({"meta":{"api-version":"1.4"},"name":"demo","versions":["2","3rc1"],"files":[{"filename":"demo-2-py3-none-any.whl","url":"demo-2.whl","hashes":{},"size":100},{"filename":"demo-3rc1-py3-none-any.whl","url":"demo-3rc1.whl","hashes":{},"size":100}]}));});
    let batch=server.mock(|when,then|{when.method(POST).path("/v1/querybatch").json_body(json!({"queries":[{"package":{"name":"demo","ecosystem":"PyPI"},"version":"1.0"},{"package":{"name":"demo","ecosystem":"PyPI"},"version":"2"}]}));then.json_body(json!({"results":[{"vulns":[{"id":"A"}]},{}]}));});
    server.mock(|when,then|{when.path("/v1/vulns/A");then.json_body(json!({"id":"A","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]}]}));});
    let policy = policy();
    let mut inventory = inventory(&policy);
    inventory.direct_constraints.push(ConstraintEvidence {
        requirement: "demo<2".into(),
        origin: "pyproject.toml".into(),
        digest: "digest".into(),
    });
    // A captured real marker environment is required even for unconditional
    // declarations; this fixture supplies all standard keys explicitly.
    inventory.target.as_mut().unwrap().marker_environment=serde_json::from_value(json!({"implementation_name":"cpython","implementation_version":"3.13.0","os_name":"posix","platform_machine":"x86_64","platform_python_implementation":"CPython","platform_release":"1","platform_system":"Linux","platform_version":"1","python_full_version":"3.13.0","python_version":"3.13","sys_platform":"linux"})).unwrap();
    let providers = vec![
        ProviderEndpoint::new(ProviderConfig {
            id: "osv".into(),
            url: server.url("/v1/querybatch"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        })
        .unwrap(),
    ];
    let sources = vec![
        RegistrySource::new(RegistrySourceConfig {
            source_id: "public-pypi".into(),
            provider: ProviderConfig {
                id: "registry".into(),
                url: server.url("/simple/"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            },
        })
        .unwrap(),
    ];
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let result = assess_inventory(
        &session,
        &inventory,
        &policy,
        &providers,
        &sources,
        &AssessmentOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(result.packages.len(), 1);
    let package = &result.packages[0];
    assert_eq!(
        package.candidates.len(),
        1,
        "prereleases excluded by default"
    );
    let candidate = &package.candidates[0];
    assert_eq!(
        candidate.qualification.candidate_kind,
        Some(CandidateKind::PublishedRemediationCandidate)
    );
    assert_eq!(candidate.constraints.constraint_status,pybun::security_assessment::qualification::constraints::ConstraintStatus::BlockedByKnownConstraint);
    assert!(package.metadata_recommendations.is_empty());
    assert_eq!(package.lowest_proven_candidate.as_deref(), Some("2"));
    index.assert_calls(1);
    batch.assert_calls(1);
    // Reusing a token in a changed policy domain is rejected before any HTTP.
    let mut revoked = policy.clone();
    revoked.disclosure.clear();
    let options = AssessmentOptions {
        continuation: Some(result.continuation),
        ..Default::default()
    };
    assert!(
        assess_inventory(
            &session, &inventory, &revoked, &providers, &sources, &options
        )
        .await
        .is_err()
    );
    index.assert_calls(1);
    batch.assert_calls(1);
}

#[tokio::test]
async fn empty_release_set_does_not_hide_failed_installed_advisory_coverage() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.path("/simple/demo/");
        then.json_body(
            json!({"meta":{"api-version":"1.4"},"name":"demo","versions":[],"files":[]}),
        );
    });
    server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.status(500);
    });
    let policy = policy();
    let inventory = inventory(&policy);
    let providers = vec![
        ProviderEndpoint::new(ProviderConfig {
            id: "osv".into(),
            url: server.url("/v1/querybatch"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        })
        .unwrap(),
    ];
    let sources = vec![
        RegistrySource::new(RegistrySourceConfig {
            source_id: "public-pypi".into(),
            provider: ProviderConfig {
                id: "registry".into(),
                url: server.url("/simple/"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            },
        })
        .unwrap(),
    ];
    let session = HttpSession::new(
        ObservationLimits {
            max_attempts: 1,
            ..Default::default()
        },
        20,
    )
    .unwrap();
    let result = assess_inventory(
        &session,
        &inventory,
        &policy,
        &providers,
        &sources,
        &AssessmentOptions::default(),
    )
    .await
    .unwrap();
    assert!(result.unknown_remainder);
    assert!(
        result.packages[0].unknown_remainder,
        "per-package advisory failure is not complete just because no candidates exist"
    );
}

#[tokio::test]
async fn expired_empty_assessment_cannot_report_complete_without_http() {
    let server = MockServer::start();
    let forbidden = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    let policy = policy();
    let mut inventory = inventory(&policy);
    inventory.packages.clear();
    let providers = vec![
        ProviderEndpoint::new(ProviderConfig {
            id: "osv".into(),
            url: server.url("/v1/querybatch"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        })
        .unwrap(),
    ];
    let session = HttpSession::new(
        ObservationLimits {
            total_timeout_ms: 1,
            ..Default::default()
        },
        20,
    )
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    assert!(
        assess_inventory(
            &session,
            &inventory,
            &policy,
            &providers,
            &[],
            &AssessmentOptions::default()
        )
        .await
        .is_err()
    );
    forbidden.assert_calls(0);
}

#[tokio::test]
async fn request_budget_cannot_permanently_starve_middle_versions() {
    verify_version_progress(
        ObservationLimits {
            max_requests: 5,
            max_attempts: 1,
            ..Default::default()
        },
        false,
        1,
    )
    .await;
}
#[tokio::test]
async fn retained_result_budget_cannot_permanently_starve_middle_versions() {
    verify_version_progress(
        ObservationLimits {
            max_retained_evidence_bytes: 120_000,
            max_attempts: 1,
            ..Default::default()
        },
        true,
        1,
    )
    .await;
}
#[tokio::test]
async fn retained_result_budget_keeps_circular_priority_across_packages() {
    verify_version_progress(
        ObservationLimits {
            max_retained_evidence_bytes: 240_000,
            max_attempts: 1,
            ..Default::default()
        },
        true,
        2,
    )
    .await;
}
async fn verify_version_progress(
    limits: ObservationLimits,
    retained_budget: bool,
    instance_count: usize,
) {
    use std::collections::BTreeSet;
    let server = MockServer::start();
    let versions: Vec<_> = (2..=41).map(|v| v.to_string()).collect();
    let files:Vec<_>=versions.iter().map(|v|json!({"filename":format!("demo-{v}-py3-none-any.whl"),"url":format!("demo-{v}.whl"),"hashes":{},"size":100})).collect();
    server.mock(|when, then| {
        when.path("/simple/demo/");
        then.json_body(
            json!({"meta":{"api-version":"1.4"},"name":"demo","versions":versions,"files":files}),
        );
    });
    server.mock(|when,then|{when.path("/v1/querybatch");then.respond_with(|request|{
        let body:serde_json::Value=serde_json::from_slice(request.body_ref()).unwrap();
        if body["queries"].as_array().unwrap().iter().filter(|query| query["version"]=="1.0").count()==2 {
            assert_eq!(body["queries"][0]["version"],"1.0");
            assert_eq!(body["queries"][2]["version"],"1.0", "the first query pass must visit both installed instances before a second candidate for either");
            assert_ne!(body["queries"][1]["version"],"1.0");
            assert_ne!(body["queries"][3]["version"],"1.0");
        }
        let results:Vec<_>=body["queries"].as_array().unwrap().iter().map(|query|{
            let version=query["version"].as_str().unwrap();
            json!({"vulns":[{"id":if version=="1.0" {"CURRENT".into()}else{format!("CHECK-{version}")}}]})
        }).collect();
        httpmock::HttpMockResponse::builder().status(200).body(json!({"results":results}).to_string()).build()
    });});
    server.mock(|when,then|{when.path_includes("/v1/vulns/");then.respond_with(|request|{
        let id=request.uri().path().rsplit('/').next().unwrap().to_owned();
        let events=if id=="CURRENT" {json!([{"introduced":"0"},{"fixed":"2"}])}else{json!([{"introduced":id.strip_prefix("CHECK-").unwrap()}])};
        httpmock::HttpMockResponse::builder().status(200).body(json!({"id":id,"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":events}]}]}).to_string()).build()
    });});
    let policy = policy();
    let mut inventory = inventory(&policy);
    inventory.packages = (0..instance_count)
        .map(|index| {
            let mut package = inventory.packages[0].clone();
            package.instance_id = format!("instance-{index}");
            package
        })
        .collect();
    let providers = vec![
        ProviderEndpoint::new(ProviderConfig {
            id: "osv".into(),
            url: server.url("/v1/querybatch"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        })
        .unwrap(),
    ];
    let sources = vec![
        RegistrySource::new(RegistrySourceConfig {
            source_id: "public-pypi".into(),
            provider: ProviderConfig {
                id: "registry".into(),
                url: server.url("/simple/"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            },
        })
        .unwrap(),
    ];
    let mut options = AssessmentOptions::default();
    let mut seen = BTreeSet::new();
    for _ in 0..20 {
        let session = HttpSession::new(limits.clone(), 20).unwrap();
        let result = assess_inventory(
            &session, &inventory, &policy, &providers, &sources, &options,
        )
        .await
        .unwrap();
        let output_count = result
            .packages
            .iter()
            .map(|package| package.candidates.len())
            .sum::<usize>();
        if retained_budget {
            assert!(output_count > 0, "budget must allow some output");
            assert!(
                output_count < 20 * instance_count,
                "output budget must be the active limit"
            );
        }
        for package in &result.packages {
            for candidate in &package.candidates {
                if candidate.qualification.coverage.status == CoverageStatus::Complete {
                    seen.insert((
                        package.instance_id.clone(),
                        candidate.qualification.version.clone(),
                    ));
                }
            }
        }
        options.continuation = Some(result.continuation);
    }
    assert_eq!(
        seen.len(),
        40 * instance_count,
        "only advancing scheduled work repeats a few chunk heads forever: {seen:?}"
    );
    if retained_budget {
        // Previously reported candidates that cannot fit this response remain
        // pending; successful HTTP alone must not count as returned evidence.
        options.previous_candidates = versions
            .iter()
            .take(20)
            .map(
                |version| pybun::security_assessment::qualification::schedule::ExactCandidate {
                    instance_id: "instance-0".into(),
                    version: version.clone(),
                },
            )
            .collect();
        let session = HttpSession::new(limits, 20).unwrap();
        let result = assess_inventory(
            &session, &inventory, &policy, &providers, &sources, &options,
        )
        .await
        .unwrap();
        let package = result
            .packages
            .iter()
            .find(|package| package.instance_id == "instance-0")
            .unwrap();
        assert!(!package.pending_previous_candidates.is_empty());
        assert!(package.unknown_remainder);
        for previous in &options.previous_candidates {
            let returned = package
                .candidates
                .iter()
                .any(|candidate| candidate.qualification.version == previous.version);
            assert_eq!(
                package
                    .pending_previous_candidates
                    .contains(&previous.version),
                !returned
            );
        }
    }
}

#[tokio::test]
async fn e2e_security_assessment_observes_real_environment_without_imports_or_project_writes() {
    use pybun::security_assessment::qualification::service::assess_project;
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        process::Command,
    };
    fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let metadata = fs::symlink_metadata(path).unwrap();
            if metadata.file_type().is_symlink() {
                files.insert(
                    path.strip_prefix(root).unwrap().into(),
                    fs::read_link(path)
                        .unwrap()
                        .to_string_lossy()
                        .as_bytes()
                        .to_vec(),
                );
            } else if metadata.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    visit(root, &entry.unwrap().path(), files);
                }
            } else {
                files.insert(
                    path.strip_prefix(root).unwrap().into(),
                    fs::read(path).unwrap(),
                );
            }
        }
        let mut files = BTreeMap::new();
        visit(root, root, &mut files);
        files
    }
    let project = tempfile::TempDir::new().unwrap();
    fs::write(
        project.path().join("pyproject.toml"),
        "[project]\nname='test-project'\nversion='1'\ndependencies=['demo<2']\n",
    )
    .unwrap();
    let executable =
        std::env::var_os("PYBUN_SECURITY_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let output=Command::new(executable).args(["-I","-S","-B","-c","import sys,json;print(json.dumps([sys.executable,str(sys.version_info.major)+'.'+str(sys.version_info.minor)]))"]).output().unwrap();
    assert!(output.status.success());
    let interpreter: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
    let trusted = PathBuf::from(&interpreter[0]);
    assert!(
        Command::new(&trusted)
            .args(["-I", "-B", "-m", "venv", "--without-pip"])
            .arg(project.path().join(".venv"))
            .status()
            .unwrap()
            .success()
    );
    let site = if cfg!(windows) {
        project.path().join(".venv/Lib/site-packages")
    } else {
        project
            .path()
            .join(format!(".venv/lib/python{}/site-packages", interpreter[1]))
    };
    let metadata = site.join("demo-1.0.dist-info");
    fs::create_dir_all(&metadata).unwrap();
    fs::write(
        metadata.join("METADATA"),
        "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
    )
    .unwrap();
    let marker = project.path().join("STARTUP_EXECUTED");
    fs::write(
        site.join("sitecustomize.py"),
        format!(
            "open({:?},'w').write('executed')\nraise RuntimeError('startup executed')\n",
            marker
        ),
    )
    .unwrap();
    let server = MockServer::start();
    let archive = server.mock(|when, then| {
        when.path_includes("/archives/");
        then.status(500);
    });
    server.mock(|when,then|{when.path("/simple/demo/");then.json_body(json!({"meta":{"api-version":"1.4"},"name":"demo","versions":["2"],"files":[{"filename":"demo-2-py3-none-any.whl","url":server.url("/archives/demo-2.whl"),"hashes":{},"size":100}]}));});
    server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.json_body(json!({"results":[{"vulns":[{"id":"A"}]},{}]}));
    });
    server.mock(|when,then|{when.path("/v1/vulns/A");then.body(serde_json::to_string_pretty(&json!({"id":"A","modified":"2026-01-01T00:00:00Z","references":[{"url":"https://user:password@references.invalid/?token=credential"}],"affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]}]})).unwrap());});
    let mut request = InventoryRequest::installed(project.path(), &trusted);
    request.source_policy = policy();
    let providers = vec![
        ProviderEndpoint::new(ProviderConfig {
            id: "osv".into(),
            url: server.url("/v1/querybatch"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        })
        .unwrap(),
    ];
    let sources = vec![
        RegistrySource::new(RegistrySourceConfig {
            source_id: "public-pypi".into(),
            provider: ProviderConfig {
                id: "registry".into(),
                url: server.url("/simple/"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            },
        })
        .unwrap(),
    ];
    let before = snapshot(project.path());
    let session = HttpSession::new(request.limits.clone(), 20).unwrap();
    let result = assess_project(
        &session,
        &request,
        &providers,
        &sources,
        &AssessmentOptions::default(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(result.inventory.packages.len(), 1, "{result:?}");
    assert_eq!(result.evidence_coverage.inventory_instances.requested, 1);
    assert_eq!(result.evidence_coverage.advisory_records.complete, 1);
    assert_eq!(result.evidence_coverage.finding_clusters.complete, 1);
    assert_eq!(result.evidence_coverage.candidate_checks.complete, 1);

    assert_eq!(
        result.packages[0].installed.affected,
        pybun::security_assessment::qualification::evidence::AffectedStatus::Yes
    );
    assert_eq!(
        result.packages[0].candidates[0]
            .qualification
            .candidate_kind,
        Some(CandidateKind::PublishedRemediationCandidate)
    );
    assert!(
        !result.packages[0].candidates[0]
            .constraints
            .blockers
            .is_empty()
    );
    assert_eq!(before, snapshot(project.path()));
    assert!(!marker.exists());
    archive.assert_calls(0);
}

#[tokio::test]
async fn unrelated_private_instance_does_not_suppress_a_complete_public_patch() {
    let server = MockServer::start();
    server.mock(|when,then|{when.path("/simple/demo/");then.json_body(json!({"meta":{"api-version":"1.4"},"name":"demo","versions":["2"],"files":[{"filename":"demo-2-py3-none-any.whl","url":"demo-2.whl","hashes":{},"size":100}]}));});
    server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.json_body(json!({"results":[{"vulns":[{"id":"A"}]},{}]}));
    });
    server.mock(|when,then|{when.path("/v1/vulns/A");then.json_body(json!({"id":"A","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]}]}));});
    let policy = policy();
    let mut inventory = inventory(&policy);
    let mut private = inventory.packages[0].clone();
    private.instance_id = "z-private".into();
    private.name = "private-demo".into();
    private.source = SourceIdentity::new("private", "tenant", SourceKind::PrivateRegistry).unwrap();
    private.source_mapping = None;
    inventory.packages.push(private);
    let providers = vec![
        ProviderEndpoint::new(ProviderConfig {
            id: "osv".into(),
            url: server.url("/v1/querybatch"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        })
        .unwrap(),
    ];
    let sources = vec![
        RegistrySource::new(RegistrySourceConfig {
            source_id: "public-pypi".into(),
            provider: ProviderConfig {
                id: "registry".into(),
                url: server.url("/simple/"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            },
        })
        .unwrap(),
    ];
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let result = assess_inventory(
        &session,
        &inventory,
        &policy,
        &providers,
        &sources,
        &AssessmentOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(result.coverage.status, CoverageStatus::Partial);
    let public = result
        .packages
        .iter()
        .find(|package| package.instance_id == "instance")
        .unwrap();
    assert_eq!(
        public.candidates[0].qualification.candidate_kind,
        Some(CandidateKind::PublishedRemediationCandidate)
    );
    assert!(public.installed.complete);
}

#[tokio::test]
async fn asymmetric_providers_complete_one_candidate_bundle_before_spending_on_later_versions() {
    for (budget, a_records, paginate_later) in [(7, 1, false), (8, 2, false), (7, 1, true)] {
        let server = MockServer::start();
        server.mock(|when,then|{when.path("/simple/demo/");then.json_body(json!({"meta":{"api-version":"1.4"},"name":"demo","versions":["2","3"],"files":[{"filename":"demo-2-py3-none-any.whl","url":"demo-2.whl","hashes":{},"size":100},{"filename":"demo-3-py3-none-any.whl","url":"demo-3.whl","hashes":{},"size":100}]}));});
        for prefix in ["a", "b"] {
            server.mock(|when, then| {
                when.path(format!("/{prefix}/querybatch"));
                then.respond_with(move |request| {
                    let body: serde_json::Value =
                        serde_json::from_slice(request.body_ref()).unwrap();
                    let results: Vec<_> = body["queries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|query| {
                            let version = query["version"].as_str().unwrap();
                            let ids = if version == "1.0" {
                                vec![json!({"id":"CURRENT"})]
                            } else {
                                (0..if prefix == "a" { a_records } else { 1 })
                                    .map(|index| json!({"id":format!("CHECK-{version}-{index}")}))
                                    .collect()
                            };
                            {
                                let mut response = json!({"vulns":ids});
                                if paginate_later && prefix == "a" && version == "3" {
                                    if query.get("page_token").is_none() {
                                        response["next_page_token"] = json!("second");
                                    } else {
                                        response["vulns"] = json!([]);
                                    }
                                }
                                response
                            }
                        })
                        .collect();
                    httpmock::HttpMockResponse::builder()
                        .status(200)
                        .body(json!({"results":results}).to_string())
                        .build()
                });
            });
            server.mock(|when,then|{when.path_includes(format!("/{prefix}/vulns/"));let then=if prefix=="b"{then.delay(std::time::Duration::from_millis(60))}else{then};then.respond_with(|request|{
                let id=request.uri().path().rsplit('/').next().unwrap().to_owned();let affected=if id=="CURRENT"{json!({"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]})}else{json!({"package":{"name":"demo","ecosystem":"PyPI"},"versions":["0"]})};
                httpmock::HttpMockResponse::builder().status(200).body(json!({"id":id,"modified":"2026-01-01T00:00:00Z","affected":[affected]}).to_string()).build()
            });});
        }
        let mut policy = policy();
        policy.disclosure.push(DisclosureGrant {
            provider_id: "second".into(),
            source_id: "public-pypi".into(),
            packages: vec!["demo".into()],
        });
        let inventory = inventory(&policy);
        let providers = vec![
            ProviderEndpoint::new(ProviderConfig {
                id: "osv".into(),
                url: server.url("/a/querybatch"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            })
            .unwrap(),
            ProviderEndpoint::new(ProviderConfig {
                id: "second".into(),
                url: server.url("/b/querybatch"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            })
            .unwrap(),
        ];
        let sources = vec![
            RegistrySource::new(RegistrySourceConfig {
                source_id: "public-pypi".into(),
                provider: ProviderConfig {
                    id: "registry".into(),
                    url: server.url("/simple/"),
                    auth_scope_id: "public".into(),
                    allow_insecure_loopback: true,
                },
            })
            .unwrap(),
        ];
        let mut options = AssessmentOptions::default();
        for expected in ["2", "3"] {
            let session = HttpSession::new(
                ObservationLimits {
                    max_requests: if paginate_later && expected == "3" {
                        budget + 1
                    } else {
                        budget
                    },
                    max_attempts: 1,
                    ..Default::default()
                },
                20,
            )
            .unwrap();
            let result = assess_inventory(
                &session, &inventory, &policy, &providers, &sources, &options,
            )
            .await
            .unwrap();
            let complete: Vec<_> = result.packages[0]
                .candidates
                .iter()
                .filter(|candidate| candidate.qualification.authoritative)
                .collect();
            assert_eq!(
                complete.len(),
                1,
                "budget suffices for exactly one complete all-provider bundle: {result:?}"
            );
            assert_eq!(complete[0].qualification.version, expected);
            assert_eq!(
                complete[0].qualification.candidate_kind,
                Some(CandidateKind::PublishedRemediationCandidate)
            );
            assert_eq!(
                result.coverage.status,
                CoverageStatus::Partial,
                "later budget misses stay explicit"
            );
            options.continuation = Some(result.continuation);
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn stale_lower_exclusion_cannot_prove_the_minimum_for_a_fresh_higher_candidate() {
    use pybun::security_assessment::http::{FreshnessKind, JsonEvidence, ObservationMode};
    use pybun::security_assessment::qualification::cache::ObservationCache;
    let server = MockServer::start();
    server.mock(|when,then|{when.path("/simple/demo/");then.json_body(json!({"meta":{"api-version":"1.4"},"name":"demo","versions":["2","3"],"files":[{"filename":"demo-2-py3-none-any.whl","url":"demo-2.whl","hashes":{},"size":100},{"filename":"demo-3-py3-none-any.whl","url":"demo-3.whl","hashes":{},"size":100}]}));});
    server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.json_body(
            json!({"results":[{"vulns":[{"id":"CURRENT"}]},{"vulns":[{"id":"LOWER"}]},{}]}),
        );
    });
    server.mock(|when,then|{when.path("/v1/vulns/CURRENT");then.json_body(json!({"id":"CURRENT","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]}]}));});
    server.mock(|when, then| {
        when.path("/v1/vulns/LOWER");
        then.status(503);
    });
    let policy = policy();
    let inventory = inventory(&policy);
    let endpoint = ProviderEndpoint::new(ProviderConfig {
        id: "osv".into(),
        url: server.url("/v1/querybatch"),
        auth_scope_id: "public".into(),
        allow_insecure_loopback: true,
    })
    .unwrap();
    let mapped = policy
        .map_package("demo", "demo-1.0.dist-info", SourceKind::Unknown)
        .unwrap();
    let proof = policy.authorized_query("osv", "demo", &mapped).unwrap();
    let root = tempfile::TempDir::new().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let cache = ObservationCache::open(&root.path().canonicalize().unwrap(), 1024).unwrap();
    let payload = json!({"id":"LOWER","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"versions":["2"]}]});
    let key =
        endpoint.observation_key(&proof, "GET", &endpoint.detail_url("LOWER").unwrap(), &None);
    cache
        .write(
            &key,
            &JsonEvidence {
                payload_digest: semantic_digest(&payload),
                value: payload,
                fetched_at: 10,
                freshness: Default::default(),
            },
        )
        .unwrap();
    let providers = vec![endpoint];
    let sources = vec![
        RegistrySource::new(RegistrySourceConfig {
            source_id: "public-pypi".into(),
            provider: ProviderConfig {
                id: "registry".into(),
                url: server.url("/simple/"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            },
        })
        .unwrap(),
    ];
    let session = HttpSession::new(
        ObservationLimits {
            max_attempts: 1,
            ..Default::default()
        },
        20,
    )
    .unwrap()
    .with_cache(cache, ObservationMode::OnlineWithCacheFallback)
    .unwrap();
    let result = assess_inventory(
        &session,
        &inventory,
        &policy,
        &providers,
        &sources,
        &AssessmentOptions::default(),
    )
    .await
    .unwrap();
    let package = &result.packages[0];
    assert_eq!(package.lowest_assessed_candidate.as_deref(), Some("3"));
    assert!(package.lowest_proven_candidate.is_none());
    assert_eq!(
        package.candidates[0].qualification.freshness.kind,
        FreshnessKind::StaleCache
    );
    assert!(!package.candidates[0].qualification.authoritative);
    assert_eq!(
        package.candidates[1].qualification.candidate_kind,
        Some(CandidateKind::PublishedRemediationCandidate)
    );
    assert!(package.candidates[1].qualification.authoritative);
}

#[tokio::test]
async fn advisories_discovered_at_either_candidate_are_rechecked_for_all_candidates() {
    for revealed_at in [2, 3] {
        let server = MockServer::start();
        server.mock(|when,then|{when.path("/simple/demo/");then.json_body(json!({"meta":{"api-version":"1.4"},"name":"demo","versions":["2","3"],"files":[{"filename":"demo-2-py3-none-any.whl","url":"demo-2.whl","hashes":{},"size":100},{"filename":"demo-3-py3-none-any.whl","url":"demo-3.whl","hashes":{},"size":100}]}));});
        server.mock(|when, then| {
            when.path("/v1/querybatch");
            let mut results = vec![json!({"vulns":[{"id":"A"}]}), json!({}), json!({})];
            results[(revealed_at - 1) as usize] = json!({"vulns":[{"id":"B"}]});
            then.json_body(json!({"results":results}));
        });
        for id in ["A", "B"] {
            server.mock(|when,then|{when.path(format!("/v1/vulns/{id}"));let events=if id=="A"{json!([{"introduced":"0"},{"fixed":"2"}])}else{json!([{"introduced":"2"}])};then.json_body(json!({"id":id,"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":events}]}]}));});
        }
        let policy = policy();
        let inventory = inventory(&policy);
        let providers = vec![
            ProviderEndpoint::new(ProviderConfig {
                id: "osv".into(),
                url: server.url("/v1/querybatch"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            })
            .unwrap(),
        ];
        let sources = vec![
            RegistrySource::new(RegistrySourceConfig {
                source_id: "public-pypi".into(),
                provider: ProviderConfig {
                    id: "registry".into(),
                    url: server.url("/simple/"),
                    auth_scope_id: "public".into(),
                    allow_insecure_loopback: true,
                },
            })
            .unwrap(),
        ];
        let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
        let result = assess_inventory(
            &session,
            &inventory,
            &policy,
            &providers,
            &sources,
            &AssessmentOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.packages[0].candidates.len(), 2);
        for candidate in &result.packages[0].candidates {
            assert_eq!(
                candidate.qualification.affected,
                pybun::security_assessment::qualification::evidence::AffectedStatus::Yes,
                "B's full range applies even if this version's query omits B"
            );
            assert!(candidate.qualification.candidate_kind.is_none());
        }
        assert!(result.packages[0].lowest_assessed_candidate.is_none());
    }
}

#[tokio::test]
async fn fresh_fixed_positive_does_not_require_every_current_query_to_complete() {
    let server = MockServer::start();
    server.mock(|when,then|{when.path("/simple/demo/");then.json_body(json!({"meta":{"api-version":"1.4"},"name":"demo","versions":["2"],"files":[{"filename":"demo-2-py3-none-any.whl","url":"demo-2.whl","hashes":{},"size":100}]}));});
    server.mock(|when, then| {
        when.path("/a/querybatch");
        then.json_body(json!({"results":[{"vulns":[{"id":"A"}]},{}]}));
    });
    server.mock(|when, then| {
        when.path("/b/querybatch");
        then.json_body(json!({"results":[null,{}]}));
    });
    server.mock(|when,then|{when.path("/a/vulns/A");then.json_body(json!({"id":"A","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]}]}));});
    let mut policy = policy();
    policy.disclosure.push(DisclosureGrant {
        provider_id: "second".into(),
        source_id: "public-pypi".into(),
        packages: vec!["demo".into()],
    });
    let inventory = inventory(&policy);
    let providers = vec![
        ProviderEndpoint::new(ProviderConfig {
            id: "osv".into(),
            url: server.url("/a/querybatch"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        })
        .unwrap(),
        ProviderEndpoint::new(ProviderConfig {
            id: "second".into(),
            url: server.url("/b/querybatch"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        })
        .unwrap(),
    ];
    let sources = vec![
        RegistrySource::new(RegistrySourceConfig {
            source_id: "public-pypi".into(),
            provider: ProviderConfig {
                id: "registry".into(),
                url: server.url("/simple/"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            },
        })
        .unwrap(),
    ];
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let result = assess_inventory(
        &session,
        &inventory,
        &policy,
        &providers,
        &sources,
        &AssessmentOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(result.coverage.status, CoverageStatus::Partial);
    assert!(!result.packages[0].installed.complete);
    let candidate = &result.packages[0].candidates[0];
    assert!(!candidate.qualification.current_authoritative);
    assert!(candidate.qualification.authoritative);
    assert_eq!(
        candidate.qualification.candidate_kind,
        Some(CandidateKind::PublishedRemediationCandidate)
    );
}

#[tokio::test]
async fn current_heavy_advisories_do_not_starve_a_complete_candidate_bundle() {
    let server = MockServer::start();
    server.mock(|when,then| {
        when.path("/simple/demo/");
        then.json_body(json!({"meta":{"api-version":"1.4"},"name":"demo","versions":["2"],"files":[{"filename":"demo-2-py3-none-any.whl","url":"demo-2.whl","hashes":{},"size":100}]}));
    });
    server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.respond_with(|request| {
            let body: serde_json::Value = serde_json::from_slice(request.body_ref()).unwrap();
            let results: Vec<_> = body["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|query| {
                    let ids: Vec<_> = if query["version"] == "1.0" {
                        (0..30)
                            .map(|index| json!({"id":format!("A{index:02}")}))
                            .collect()
                    } else {
                        vec![json!({"id":"B"})]
                    };
                    json!({"vulns":ids})
                })
                .collect();
            httpmock::HttpMockResponse::builder()
                .status(200)
                .body(json!({"results":results}).to_string())
                .build()
        });
    });
    server.mock(|when,then| {
        when.path_includes("/v1/vulns/");
        then.respond_with(|request| {
            let id=request.uri().path().rsplit('/').next().unwrap().to_owned();
            let affected=if id=="B" {json!({"package":{"name":"demo","ecosystem":"PyPI"},"versions":["0"]})}else{json!({"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]})};
            httpmock::HttpMockResponse::builder().status(200).body(json!({"id":id,"modified":"2026-01-01T00:00:00Z","affected":[affected]}).to_string()).build()
        });
    });
    let policy = policy();
    let inventory = inventory(&policy);
    let providers = vec![
        ProviderEndpoint::new(ProviderConfig {
            id: "osv".into(),
            url: server.url("/v1/querybatch"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        })
        .unwrap(),
    ];
    let sources = vec![
        RegistrySource::new(RegistrySourceConfig {
            source_id: "public-pypi".into(),
            provider: ProviderConfig {
                id: "registry".into(),
                url: server.url("/simple/"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            },
        })
        .unwrap(),
    ];
    let session = HttpSession::new(
        ObservationLimits {
            max_requests: 5,
            max_attempts: 1,
            ..Default::default()
        },
        20,
    )
    .unwrap();
    let result = assess_inventory(
        &session,
        &inventory,
        &policy,
        &providers,
        &sources,
        &AssessmentOptions::default(),
    )
    .await
    .unwrap();
    assert!(!result.packages[0].installed.complete);
    assert!(result.unknown_remainder);
    let candidate = &result.packages[0].candidates[0].qualification;
    assert!(
        candidate.authoritative,
        "candidate bundle must complete before unrelated current-record hydration exhausts the budget: {candidate:?}"
    );
    assert_eq!(
        candidate.candidate_kind,
        Some(CandidateKind::PublishedRemediationCandidate)
    );
    assert!(session.request_count() <= 5);
}

struct AdmissionFixture {
    _server: MockServer,
    inventory: InventoryObservation,
    policy: SourcePolicy,
    providers: Vec<ProviderEndpoint>,
    sources: Vec<RegistrySource>,
}
fn admission_fixture(count: usize, versions: Vec<String>, first_name: &str) -> AdmissionFixture {
    let server = MockServer::start();
    server.mock(|when,then| {
        when.path_includes("/simple-");
        then.respond_with(move |request| {
            let uri=request.uri();
            let name=uri.path().trim_end_matches('/').rsplit('/').next().unwrap();
            let versions=if name=="empty" {Vec::new()} else {versions.clone()};
            let files:Vec<_>=versions.iter().map(|version|json!({"filename":format!("{name}-{version}-py3-none-any.whl"),"url":format!("{name}-{version}.whl"),"hashes":{},"size":100})).collect();
            httpmock::HttpMockResponse::builder().status(200).body(json!({"meta":{"api-version":"1.4"},"name":name,"versions":versions,"files":files}).to_string()).build()
        });
    });
    server.mock(|when,then| {
        when.path("/v1/querybatch");
        then.respond_with(|request| {
            let body:serde_json::Value=serde_json::from_slice(request.body_ref()).unwrap();
            let results:Vec<_>=body["queries"].as_array().unwrap().iter().map(|query| {
                let name=query["package"]["name"].as_str().unwrap();
                let version=query["version"].as_str().unwrap();
                if name=="empty" {return json!({});}
                json!({"vulns":[{"id":if version=="1.0" {format!("CUR-{name}")}else{format!("NEG-{name}-{version}")}}]})
            }).collect();
            httpmock::HttpMockResponse::builder().status(200).body(json!({"results":results}).to_string()).build()
        });
    });
    server.mock(|when,then| {
        when.path_includes("/v1/vulns/");
        then.respond_with(|request| {
            let id=request.uri().path().rsplit('/').next().unwrap().to_owned();
            let name=id.split('-').nth(1).unwrap();
            let affected=if id.starts_with("CUR-") {json!({"package":{"name":name,"ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]})}else{json!({"package":{"name":name,"ecosystem":"PyPI"},"versions":["0"]})};
            let padding=if name=="heavy" {"x".repeat(100_000)}else{String::new()};
            httpmock::HttpMockResponse::builder().status(200).body(json!({"id":id,"summary":padding,"modified":"2026-01-01T00:00:00Z","affected":[affected]}).to_string()).build()
        });
    });
    let mut inventory = inventory(&policy());
    let template = inventory.packages[0].clone();
    let mut policy = SourcePolicy::default();
    let mut sources = vec![];
    for index in 0..count {
        let name = if index == 0 { first_name } else { "demo" };
        let source_id = format!("source-{index}");
        policy
            .sources
            .push(SourceIdentity::new(&source_id, "public", SourceKind::PublicRegistry).unwrap());
        policy.rules.push(SourceRule {
            name: name.into(),
            distribution: Some(format!("{name}-{index}.dist-info")),
            source_id: source_id.clone(),
            upstream_name: Some(name.into()),
            ecosystem: Some("PyPI".into()),
            assumption: Some("Explicit fixture registry association".into()),
        });
        for provider in ["osv".to_string(), format!("registry-{index}")] {
            policy.disclosure.push(DisclosureGrant {
                provider_id: provider,
                source_id: source_id.clone(),
                packages: vec![name.into()],
            });
        }
        sources.push(
            RegistrySource::new(RegistrySourceConfig {
                source_id,
                provider: ProviderConfig {
                    id: format!("registry-{index}"),
                    url: server.url(format!("/simple-{index}/").as_str()),
                    auth_scope_id: "public".into(),
                    allow_insecure_loopback: true,
                },
            })
            .unwrap(),
        );
    }
    inventory.packages = (0..count)
        .map(|index| {
            let mut package = template.clone();
            let name = if index == 0 { first_name } else { "demo" };
            package.instance_id = format!("instance-{index:03}");
            package.name = name.into();
            package.distribution_path = format!("{name}-{index}.dist-info");
            let source = policy
                .map_package(name, &package.distribution_path, SourceKind::Unknown)
                .unwrap();
            package.source = source.source;
            package.source_mapping = source.mapping;
            package
        })
        .collect();
    let providers = vec![
        ProviderEndpoint::new(ProviderConfig {
            id: "osv".into(),
            url: server.url("/v1/querybatch"),
            auth_scope_id: "public".into(),
            allow_insecure_loopback: true,
        })
        .unwrap(),
    ];
    AdmissionFixture {
        _server: server,
        inventory,
        policy,
        providers,
        sources,
    }
}

#[tokio::test]
async fn adaptive_admission_allows_advisories_after_one_hundred_registry_sources() {
    use std::collections::BTreeSet;
    let fixture = admission_fixture(100, vec!["2".into()], "demo");
    let mut options = AssessmentOptions::default();
    let mut seen = BTreeSet::new();
    for _ in 0..16 {
        let session = HttpSession::new(
            ObservationLimits {
                max_requests: 100,
                max_attempts: 1,
                ..Default::default()
            },
            20,
        )
        .unwrap();
        let result = assess_inventory(
            &session,
            &fixture.inventory,
            &fixture.policy,
            &fixture.providers,
            &fixture.sources,
            &options,
        )
        .await
        .unwrap();
        assert_eq!(result.packages.len(), 100);
        for package in &result.packages {
            if package.candidates.iter().any(|candidate| {
                candidate.qualification.candidate_kind
                    == Some(CandidateKind::PublishedRemediationCandidate)
            }) {
                seen.insert(package.instance_id.clone());
            }
        }
        options.continuation = Some(result.continuation);
        if seen.len() == 100 {
            break;
        }
    }
    assert_eq!(
        seen.len(),
        100,
        "metadata admission must leave room for complete advisory frames"
    );
}

#[tokio::test]
async fn adaptive_admission_narrows_eager_headers_and_records_until_one_frame_fits() {
    use std::collections::BTreeSet;
    let fixture = admission_fixture(1, (2..=41).map(|v| v.to_string()).collect(), "demo");
    let mut options = AssessmentOptions::default();
    let mut seen = BTreeSet::new();
    for _ in 0..80 {
        let session = HttpSession::new(
            ObservationLimits {
                max_retained_evidence_bytes: 50_000,
                max_attempts: 1,
                ..Default::default()
            },
            20,
        )
        .unwrap();
        let result = assess_inventory(
            &session,
            &fixture.inventory,
            &fixture.policy,
            &fixture.providers,
            &fixture.sources,
            &options,
        )
        .await
        .unwrap();
        for candidate in &result.packages[0].candidates {
            if candidate.qualification.authoritative
                && candidate.qualification.coverage.status == CoverageStatus::Complete
            {
                seen.insert(candidate.qualification.version.clone());
            }
        }
        options.continuation = Some(result.continuation);
        if seen.len() == 40 {
            break;
        }
    }
    assert_eq!(
        seen.len(),
        40,
        "a fitting one-candidate frame must eventually visit every version"
    );
}

#[tokio::test]
async fn adaptive_admission_rotates_intrinsically_unfit_package_without_starving_fit_package() {
    use std::collections::BTreeSet;
    let fixture = admission_fixture(2, (2..=41).map(|v| v.to_string()).collect(), "heavy");
    let mut options = AssessmentOptions::default();
    let mut seen = BTreeSet::new();
    for _ in 0..40 {
        let session = HttpSession::new(
            ObservationLimits {
                max_retained_evidence_bytes: 50_000,
                max_attempts: 1,
                ..Default::default()
            },
            20,
        )
        .unwrap();
        let result = assess_inventory(
            &session,
            &fixture.inventory,
            &fixture.policy,
            &fixture.providers,
            &fixture.sources,
            &options,
        )
        .await
        .unwrap();
        for candidate in &result.packages[1].candidates {
            if candidate.qualification.candidate_kind
                == Some(CandidateKind::PublishedRemediationCandidate)
            {
                seen.insert(candidate.qualification.version.clone());
            }
        }
        assert!(result.packages[0].unknown_remainder);
        options.continuation = Some(result.continuation);
        if seen.len() == 3 {
            break;
        }
    }
    assert_eq!(
        seen.len(),
        3,
        "an intrinsically unfit package cannot monopolize every run"
    );
}

#[tokio::test]
async fn adaptive_admission_focuses_candidate_failure_after_complete_empty_package() {
    let fixture = admission_fixture(2, vec!["2".into()], "empty");
    let mut options = AssessmentOptions::default();
    let mut complete = false;
    for _ in 0..16 {
        let session = HttpSession::new(
            ObservationLimits {
                max_requests: 5,
                max_attempts: 1,
                ..Default::default()
            },
            20,
        )
        .unwrap();
        let result = assess_inventory(
            &session,
            &fixture.inventory,
            &fixture.policy,
            &fixture.providers,
            &fixture.sources,
            &options,
        )
        .await
        .unwrap();
        complete |= result.packages[1].candidates.iter().any(|candidate| {
            candidate.qualification.candidate_kind
                == Some(CandidateKind::PublishedRemediationCandidate)
        });
        options.continuation = Some(result.continuation);
        if complete {
            break;
        }
    }
    assert!(
        complete,
        "an empty complete package must not hide resource failure in the first planned candidate package"
    );
}

fn admission_cursor_json(
    cursor: &pybun::security_assessment::qualification::schedule::AssessmentContinuation,
) -> serde_json::Value {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(cursor.as_str()).unwrap()).unwrap()
}
fn admission_cursor_width(
    cursor: &pybun::security_assessment::qualification::schedule::AssessmentContinuation,
    width: usize,
) -> pybun::security_assessment::qualification::schedule::AssessmentContinuation {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut value = admission_cursor_json(cursor);
    value["admission_width"] = width.into();
    pybun::security_assessment::qualification::schedule::AssessmentContinuation::parse(
        &URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap()),
    )
    .unwrap()
}

#[tokio::test]
async fn adaptive_admission_preserves_all_deferred_state_and_exact_previous_revalidation() {
    let fixture = admission_fixture(2, (2..=41).map(|v| v.to_string()).collect(), "demo");
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let first = assess_inventory(
        &session,
        &fixture.inventory,
        &fixture.policy,
        &fixture.providers,
        &fixture.sources,
        &AssessmentOptions::default(),
    )
    .await
    .unwrap();
    let old = admission_cursor_json(&first.continuation);
    let mut options = AssessmentOptions {
        continuation: Some(admission_cursor_width(&first.continuation, 1)),
        previous_candidates: vec![
            pybun::security_assessment::qualification::schedule::ExactCandidate {
                instance_id: "instance-001".into(),
                version: "99".into(),
            },
        ],
        ..Default::default()
    };
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let second = assess_inventory(
        &session,
        &fixture.inventory,
        &fixture.policy,
        &fixture.providers,
        &fixture.sources,
        &options,
    )
    .await
    .unwrap();
    assert_eq!(
        admission_cursor_json(&second.continuation)["packages"][1],
        old["packages"][1]
    );
    assert!(second.packages[1].registry.is_none());
    assert!(!second.packages[1].installed.complete);
    assert_eq!(second.packages[1].pending_previous_candidates, vec!["99"]);
    assert_eq!(
        second.evidence_coverage.advisory_records.status,
        CoverageStatus::Partial
    );
    assert!(
        second
            .evidence_coverage
            .advisory_records
            .reasons
            .iter()
            .any(|reason| reason == "E_SECURITY_ADMISSION_DEFERRED")
    );
    assert!(
        !second
            .invalidated_instances
            .contains(&"instance-001".into())
    );
    options.continuation = Some(second.continuation);
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let third = assess_inventory(
        &session,
        &fixture.inventory,
        &fixture.policy,
        &fixture.providers,
        &fixture.sources,
        &options,
    )
    .await
    .unwrap();
    assert_eq!(third.packages[1].candidates[0].qualification.version, "99");
    assert!(third.packages[1].candidates[0].revalidation);
    assert!(third.invalidated_instances.contains(&"instance-001".into()));
    assert_eq!(
        admission_cursor_json(&third.continuation)["packages"][1]["discovery_offset"],
        old["packages"][1]["discovery_offset"]
    );
}

#[tokio::test]
async fn unavailable_registry_enumeration_preserves_discovery_offset_until_supported_metadata_returns()
 {
    let fixture = admission_fixture(1, (2..=41).map(|v| v.to_string()).collect(), "demo");
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let first = assess_inventory(
        &session,
        &fixture.inventory,
        &fixture.policy,
        &fixture.providers,
        &fixture.sources,
        &AssessmentOptions::default(),
    )
    .await
    .unwrap();
    let old = admission_cursor_json(&first.continuation);
    fixture._server.reset();
    fixture._server.mock(|when, then| {
        when.path_includes("/simple-");
        then.json_body(
            json!({"meta":{"api-version":"2.0"},"name":"demo","versions":[],"files":[]}),
        );
    });
    fixture._server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.respond_with(|request| {
            let body: serde_json::Value = serde_json::from_slice(request.body_ref()).unwrap();
            httpmock::HttpMockResponse::builder()
                .status(200)
                .body(
                    json!({"results":vec![json!({});body["queries"].as_array().unwrap().len()]})
                        .to_string(),
                )
                .build()
        });
    });
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let second = assess_inventory(
        &session,
        &fixture.inventory,
        &fixture.policy,
        &fixture.providers,
        &fixture.sources,
        &AssessmentOptions {
            continuation: Some(first.continuation),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        second.packages[0]
            .registry
            .as_ref()
            .unwrap()
            .catalog
            .enumeration_digest
            .is_empty()
    );
    let retained = admission_cursor_json(&second.continuation);
    assert_eq!(
        retained["packages"][0]["discovery_offset"],
        old["packages"][0]["discovery_offset"]
    );
    assert_eq!(
        retained["packages"][0]["enumeration_digest"],
        old["packages"][0]["enumeration_digest"]
    );
    assert!(second.unknown_remainder);
    fixture._server.reset();
    fixture._server.mock(|when,then|{when.path_includes("/simple-");let versions:Vec<_>=(2..=41).map(|v|v.to_string()).collect();let files:Vec<_>=versions.iter().map(|v|json!({"filename":format!("demo-{v}-py3-none-any.whl"),"url":format!("demo-{v}.whl"),"hashes":{},"size":100})).collect();then.json_body(json!({"meta":{"api-version":"1.4"},"name":"demo","versions":versions,"files":files}));});
    fixture._server.mock(|when, then| {
        when.path("/v1/querybatch");
        then.respond_with(|request| {
            let body: serde_json::Value = serde_json::from_slice(request.body_ref()).unwrap();
            httpmock::HttpMockResponse::builder()
                .status(200)
                .body(
                    json!({"results":vec![json!({});body["queries"].as_array().unwrap().len()]})
                        .to_string(),
                )
                .build()
        });
    });
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let resumed = assess_inventory(
        &session,
        &fixture.inventory,
        &fixture.policy,
        &fixture.providers,
        &fixture.sources,
        &AssessmentOptions {
            continuation: Some(second.continuation),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        resumed.packages[0].candidates[0].qualification.version,
        "22"
    );
}

#[tokio::test]
async fn previous_prerelease_remains_visible_without_entering_default_minimum_selection() {
    let fixture = admission_fixture(1, vec!["3rc1".into()], "demo");
    let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
    let result = assess_inventory(
        &session,
        &fixture.inventory,
        &fixture.policy,
        &fixture.providers,
        &fixture.sources,
        &AssessmentOptions {
            previous_candidates: vec![
                pybun::security_assessment::qualification::schedule::ExactCandidate {
                    instance_id: "instance-000".into(),
                    version: "3rc1".into(),
                },
            ],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let package = &result.packages[0];
    assert_eq!(package.candidates.len(), 1);
    assert!(package.candidates[0].revalidation);
    assert_eq!(
        package.candidates[0].qualification.candidate_kind,
        Some(CandidateKind::PublishedRemediationCandidate)
    );
    assert!(package.lowest_assessed_candidate.is_none());
    assert!(package.lowest_proven_candidate.is_none());
    assert!(package.metadata_recommendations.is_empty());
}
