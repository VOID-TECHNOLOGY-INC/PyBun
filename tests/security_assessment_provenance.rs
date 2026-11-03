//! Shared-service regressions joining real installed inventory and frozen uv provenance.
#![cfg(unix)]

use httpmock::prelude::*;
use pybun::security_assessment::{
    CoverageStatus, DisclosureGrant, InventoryRequest, SourceIdentity, SourceKind, SourceRule,
    http::{HttpSession, ProviderConfig, ProviderEndpoint},
    qualification::{
        candidate::CandidateKind,
        provenance::{ApprovedRegistryBinding, ParentActivation, ProvenanceRequest},
        registry_source::{RegistrySource, RegistrySourceConfig},
        service::{AssessmentOptions, SecurityAssessment, assess_project},
    },
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

// Same static offline graph as security_candidate_provenance: no package archive is needed.
const LOCK: &str = r#"version=1
revision=3
requires-python=">=3.11"
[[package]]
name="example"
version="1"
source={virtual="."}
dependencies=[{name="requests"}]
[package.metadata]
requires-dist=[{name="requests",specifier=">=2"}]
[[package]]
name="requests"
version="2.32.5"
source={registry="https://pypi.org/simple"}
dependencies=[{name="urllib3"}]
[[package]]
name="urllib3"
version="2.5.0"
source={registry="https://pypi.org/simple"}
"#;

struct Fixture {
    project: TempDir,
    cache: TempDir,
    server: MockServer,
    inventory: InventoryRequest,
    graph: ProvenanceRequest,
    bindings: Vec<ApprovedRegistryBinding>,
    providers: Vec<ProviderEndpoint>,
    sources: Vec<RegistrySource>,
}

fn fixture(unknown_lower_version: bool) -> Fixture {
    let project = TempDir::new().unwrap();
    let cache = TempDir::new().unwrap();
    fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(project.path().join("pyproject.toml"), "[project]\nname='example'\nversion='1'\nrequires-python='>=3.11'\ndependencies=['requests>=2']\n").unwrap();
    fs::write(project.path().join("uv.lock"), LOCK).unwrap();
    let name = std::env::var_os("PYBUN_SECURITY_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let output = Command::new(name)
        .args(["-I", "-S", "-B", "-c", "import sys,json;print(json.dumps([sys.executable,str(sys.version_info.major)+'.'+str(sys.version_info.minor)]))"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let values: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
    let python = PathBuf::from(&values[0]);
    assert!(
        Command::new(&python)
            .args(["-I", "-B", "-m", "venv", "--without-pip"])
            .arg(project.path().join(".venv"))
            .status()
            .unwrap()
            .success()
    );
    let site = project
        .path()
        .join(format!(".venv/lib/python{}/site-packages", values[1]));
    for (name, version, requires) in [
        ("requests", "2.32.5", "Requires-Dist: urllib3>=1.21.1,<3\n"),
        ("urllib3", "2.5.0", ""),
    ] {
        let directory = site.join(format!("{name}-{version}.dist-info"));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("METADATA"),
            format!("Name: {name}\nVersion: {version}\n{requires}"),
        )
        .unwrap();
    }
    fs::write(
        site.join("sitecustomize.py"),
        format!(
            "open({:?},'w').write('executed')\nraise RuntimeError('startup executed')\n",
            project.path().join("STARTUP_EXECUTED")
        ),
    )
    .unwrap();

    let server = MockServer::start();
    server.mock(|when, then| {
        when.path("/simple/requests/");
        then.json_body(
            json!({"meta":{"api-version":"1.4"},"name":"requests","versions":[],"files":[]}),
        );
    });
    server.mock(|when, then| {
        when.path("/simple/urllib3/");
        let versions = if unknown_lower_version { json!(["unparseable-version", "2.6.0"]) } else { json!(["2.6.0"]) };
        then.json_body(json!({"meta":{"api-version":"1.4"},"name":"urllib3","versions":versions,"files":[{"filename":"urllib3-2.6.0-py3-none-any.whl","url":"/archives/urllib3-2.6.0.whl","hashes":{},"size":100}]}));
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
                    if query["package"]["name"] == "urllib3" && query["version"] == "2.5.0" {
                        json!({"vulns":[{"id":"FIX-URLLIB3"}]})
                    } else {
                        json!({})
                    }
                })
                .collect();
            httpmock::HttpMockResponse::builder()
                .status(200)
                .body(json!({"results":results}).to_string())
                .build()
        });
    });
    server.mock(|when, then| {
        when.path("/v1/vulns/FIX-URLLIB3");
        then.json_body(json!({"id":"FIX-URLLIB3","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"urllib3","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.6.0"}]}]}]}));
    });
    let mut inventory = InventoryRequest::installed(project.path(), &python);
    inventory
        .source_policy
        .sources
        .push(SourceIdentity::new("public", "public-auth", SourceKind::PublicRegistry).unwrap());
    for name in ["requests", "urllib3"] {
        inventory.source_policy.rules.push(SourceRule {
            name: name.into(),
            distribution: None,
            source_id: "public".into(),
            upstream_name: Some(name.into()),
            ecosystem: Some("PyPI".into()),
            assumption: Some(
                "Operator maps these installed fixture artifacts to public upstreams.".into(),
            ),
        });
    }
    for provider_id in ["osv", "registry"] {
        inventory.source_policy.disclosure.push(DisclosureGrant {
            provider_id: provider_id.into(),
            source_id: "public".into(),
            packages: vec!["requests".into(), "urllib3".into()],
        });
    }
    let graph = ProvenanceRequest {
        trusted_uv: pybun::env::find_uv_executable()
            .expect("install the supported uv test dependency"),
        approved_cache_root: cache.path().canonicalize().unwrap(),
        authorized_roots: vec![project.path().canonicalize().unwrap()],
        limits: inventory.limits.clone(),
    };
    let bindings = vec![ApprovedRegistryBinding {
        source_id: "public".into(),
        auth_scope_id: "public-auth".into(),
        registry_url: "https://pypi.org/simple".into(),
    }];
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
            source_id: "public".into(),
            provider: ProviderConfig {
                id: "registry".into(),
                url: server.url("/simple/"),
                auth_scope_id: "public".into(),
                allow_insecure_loopback: true,
            },
        })
        .unwrap(),
    ];
    Fixture {
        project,
        cache,
        server,
        inventory,
        graph,
        bindings,
        providers,
        sources,
    }
}

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

async fn assess(fixture: &Fixture, session: &HttpSession, graph: bool) -> SecurityAssessment {
    assess_project(
        session,
        &fixture.inventory,
        &fixture.providers,
        &fixture.sources,
        &AssessmentOptions::default(),
        graph.then_some((&fixture.graph, fixture.bindings.as_slice())),
    )
    .await
    .unwrap()
}

fn assert_patch(result: &SecurityAssessment) {
    let package = result
        .packages
        .iter()
        .find(|package| {
            result.inventory.packages.iter().any(|instance| {
                instance.name == "urllib3" && instance.instance_id == package.instance_id
            })
        })
        .unwrap();
    assert_eq!(package.candidates.len(), 1, "{result:?}");
    assert!(
        package.candidates[0].qualification.authoritative,
        "{result:?}"
    );
    assert_eq!(
        package.candidates[0].qualification.candidate_kind,
        Some(CandidateKind::PublishedRemediationCandidate)
    );
}

#[tokio::test]
async fn shared_assessment_joins_real_frozen_parent_graph_without_project_writes() {
    let fixture = fixture(false);
    let archive = fixture.server.mock(|when, then| {
        when.path_includes("/archives/");
        then.status(500);
    });
    let before = snapshot(fixture.project.path());
    let session = HttpSession::new(fixture.inventory.limits.clone(), 20).unwrap();
    let result = assess(&fixture, &session, true).await;
    assert_patch(&result);
    let graph = result.provenance.as_ref().unwrap();
    assert_eq!(graph.coverage.status, CoverageStatus::Complete, "{graph:?}");
    let child = result
        .inventory
        .packages
        .iter()
        .find(|package| package.name == "urllib3")
        .unwrap();
    let evidence = graph
        .instances
        .iter()
        .find(|instance| instance.instance_id == child.instance_id)
        .unwrap();
    assert_eq!(evidence.parents.len(), 1);
    assert_eq!(evidence.parents[0].parent_name, "requests");
    assert_eq!(evidence.parents[0].activation, ParentActivation::Proven);
    assert_eq!(
        evidence.parents[0].requirements[0].requirement,
        "urllib3>=1.21.1,<3"
    );
    assert_eq!(before, snapshot(fixture.project.path()));
    assert_eq!(fs::read_dir(fixture.cache.path()).unwrap().count(), 0);
    archive.assert_calls(0);
}

#[tokio::test]
async fn partial_graph_does_not_erase_a_fresh_patch_candidate() {
    let fixture = fixture(false);
    let project_path = fixture.project.path().join("pyproject.toml");
    let project = fs::read_to_string(&project_path).unwrap();
    fs::write(
        project_path,
        format!("{project}\n[tool.uv.sources]\nurllib3={{path='../unapproved'}}\n"),
    )
    .unwrap();
    let before = snapshot(fixture.project.path());
    let session = HttpSession::new(fixture.inventory.limits.clone(), 20).unwrap();
    let result = assess(&fixture, &session, true).await;
    assert_patch(&result);
    assert_eq!(result.coverage.status, CoverageStatus::Partial);
    assert!(
        result
            .coverage
            .reasons
            .iter()
            .any(|reason| reason == "E_SECURITY_GRAPH_PARTIAL")
    );
    let graph = result.provenance.as_ref().unwrap();
    assert_eq!(graph.coverage.status, CoverageStatus::Partial);
    assert!(
        graph
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "E_SECURITY_GRAPH_LAYOUT_UNSUPPORTED")
    );
    assert_eq!(before, snapshot(fixture.project.path()));
    assert_eq!(fs::read_dir(fixture.cache.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn optional_graph_shares_the_retained_evidence_budget_with_candidate_assessment() {
    let mut fixture = fixture(false);
    let baseline = HttpSession::new(fixture.inventory.limits.clone(), 20).unwrap();
    let result = assess(&fixture, &baseline, false).await;
    assert_patch(&result);
    let used =
        fixture.inventory.limits.max_retained_evidence_bytes - baseline.remaining_evidence_bytes();
    fixture.inventory.limits.max_retained_evidence_bytes = used + 100;
    fixture.graph.limits = fixture.inventory.limits.clone();
    let before = snapshot(fixture.project.path());
    let bounded = HttpSession::new(fixture.inventory.limits.clone(), 20).unwrap();
    let result = assess(&fixture, &bounded, true).await;
    assert_patch(&result);
    assert_eq!(result.coverage.status, CoverageStatus::Partial);
    assert!(
        result.provenance.is_none(),
        "graph evidence exceeded remaining capacity: {result:?}"
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "E_SECURITY_EVIDENCE_LIMIT")
    );
    assert_eq!(before, snapshot(fixture.project.path()));
    assert_eq!(fs::read_dir(fixture.cache.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn unknown_declared_release_keeps_the_patch_but_prevents_a_proven_minimum() {
    let fixture = fixture(true);
    let session = HttpSession::new(fixture.inventory.limits.clone(), 20).unwrap();
    let result = assess(&fixture, &session, false).await;
    assert_patch(&result);
    let package = result
        .packages
        .iter()
        .find(|package| {
            package
                .registry
                .as_ref()
                .is_some_and(|registry| registry.distribution == "urllib3")
        })
        .unwrap();
    assert_eq!(
        package.registry.as_ref().unwrap().catalog.unknown_versions,
        1
    );
    assert_eq!(package.lowest_assessed_candidate.as_deref(), Some("2.6.0"));
    assert!(package.lowest_proven_candidate.is_none());
    assert!(package.unknown_remainder);
    assert_eq!(result.coverage.status, CoverageStatus::Partial);
}

#[test]
fn queued_graph_expires_without_losing_the_fresh_assessment() {
    use std::time::Duration;
    let mut fixture = fixture(false);
    fixture.inventory.limits.total_timeout_ms = 1000;
    fixture.inventory.limits.http_timeout_ms = 1000;
    fixture.graph.limits = fixture.inventory.limits.clone();
    let before = snapshot(fixture.project.path());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let session = HttpSession::new(fixture.inventory.limits.clone(), 20).unwrap();
        let mut check = Box::pin(assess(&fixture, &session, true));
        // Queue inventory first, then occupy its only blocking worker before
        // the async continuation can enqueue optional graph observation.
        assert!(futures::poll!(check.as_mut()).is_pending());
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = release_rx.recv();
        });
        let completed = tokio::time::timeout(Duration::from_millis(1500), check.as_mut()).await;
        release_tx.send(()).unwrap();
        let returned_while_queued = completed.is_ok();
        let result = match completed {
            Ok(result) => result,
            Err(_) => check.await,
        };
        blocker.await.unwrap();
        assert!(
            returned_while_queued,
            "graph queue extended the shared deadline"
        );
        assert_patch(&result);
        assert!(result.provenance.is_none());
        assert_eq!(result.coverage.status, CoverageStatus::Partial);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "E_SECURITY_DEADLINE")
        );
    });
    assert_eq!(before, snapshot(fixture.project.path()));
    assert_eq!(fs::read_dir(fixture.cache.path()).unwrap().count(), 0);
}
