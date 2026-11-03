#![allow(dead_code)]
use pybun::security_assessment::{
    monitor::{ComparisonDomain, MonitorConfig},
    qualification::{
        candidate::{CandidateProviderEvidence, qualify_candidate},
        constraints::evaluate_constraints,
        findings::assess_findings,
        registry::parse_registry_catalog,
        registry_source::RegistryObservation,
        schedule::{AssessmentDomain, DiscoveryInput, plan_candidates},
        service::{AssessedCandidate, PackageAssessment, SecurityAssessment},
    },
    *,
};
use serde_json::{Value, json};
use std::path::Path;

pub fn profile() -> TargetTagProfile {
    TargetTagProfile {
        profile_version: 1,
        generator: "fixture".into(),
        generator_version: "1".into(),
        digest: "b".repeat(64),
        tags: vec!["py3-none-any".into()],
        implementation: "cpython".into(),
        python_version: "3.13.0".into(),
        os: "linux".into(),
        architecture: "x86_64".into(),
        libc: None,
        deployment: None,
    }
}
pub fn config(project: &Path) -> MonitorConfig {
    MonitorConfig {
        profile_id: "profile-main".into(),
        name: "fixture".into(),
        freshness_ttl_seconds: 86400,
        include_prereleases: false,
        domain: ComparisonDomain {
            project_root: project.to_path_buf(),
            environment_root: project.join(".venv"),
            backend: InventoryBackend::Uv,
            target: InventoryTarget::Installed,
            scope: InventoryScope::default(),
            runtime: None,
            source_policy_digest: "c".repeat(64),
            provider_config_digest: "d".repeat(64),
            index_config_digest: "e".repeat(64),
            observation_version: 1,
            authoritative_providers: vec!["osv".into()],
        },
    }
}
pub fn advisory(id: &str, aliases: &[&str], fixed: bool) -> Value {
    let events = if fixed {
        json!([{"introduced":"0"},{"fixed":"2"}])
    } else {
        json!([{"introduced":"0"}])
    };
    json!({"id":id,"aliases":aliases,"modified":"2026-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":events}]}]})
}
pub fn assessment(
    config: &MonitorConfig,
    version: &str,
    records: Vec<Value>,
    candidate_version: Option<&str>,
    now: u64,
) -> SecurityAssessment {
    let target = ObservedTarget {
        project_root: config.domain.project_root.clone(),
        environment_root: config.domain.environment_root.clone(),
        interpreter: config.domain.environment_root.join("bin/python"),
        inspector: config.domain.environment_root.join("bin/python"),
        interpreter_digest: "a".repeat(64),
        interpreter_identity_evidence: "fixture".into(),
        marker_environment: Default::default(),
        kind: config.domain.target,
        backend: config.domain.backend,
        scope: config.domain.scope.clone(),
        tag_profile: profile(),
        environment_fingerprint: version.into(),
        project_digest: Some("project".into()),
        lock_digest: Some("lock".into()),
    };
    let package = PackageInstance {
        instance_id: format!("instance-{}", semantic_digest(&version)),
        name: "demo".into(),
        version: version.into(),
        source: SourceIdentity::new("public-pypi", "public", SourceKind::PublicRegistry).unwrap(),
        source_mapping: Some(SourceMapping {
            ecosystem: "PyPI".into(),
            upstream_name: "demo".into(),
            assumption: "Explicit fixture association".into(),
        }),
        scope_variant: "scope".into(),
        distribution_path: format!("demo-{version}.dist-info"),
        metadata_digest: "metadata".into(),
        direct_url_digest: None,
        origin_identity: None,
        requires_dist: vec![],
        coverage: CoverageUnit::default(),
    };
    let inventory = InventoryObservation {
        observation_version: 1,
        inventory_id: semantic_digest(&version),
        observation_id: "observation".into(),
        observed_at: now,
        target: Some(target.clone()),
        packages: vec![package.clone()],
        direct_constraints: vec![],
        coverage: ObservationCoverage::default(),
        diagnostics: vec![],
    };
    let current = osv::InstanceAdvisories {
        freshness: Default::default(),
        work_attempted: true,
        instance_id: package.instance_id.clone(),
        version: version.into(),
        source_id: package.source.id.clone(),
        auth_scope_id: package.source.auth_scope_id.clone(),
        upstream_name: Some("demo".into()),
        ecosystem: Some("PyPI".into()),
        mapping_assumption: package
            .source_mapping
            .as_ref()
            .map(|mapping| mapping.assumption.clone()),
        records: records
            .into_iter()
            .map(|payload| osv::AdvisoryRecord {
                freshness: Default::default(),
                id: payload["id"].as_str().unwrap().into(),
                payload_digest: semantic_digest(&payload),
                payload,
                fetched_at: now,
                coverage: CoverageUnit::default(),
            })
            .collect(),
        coverage: CoverageUnit::default(),
    };
    let mut candidate = current.clone();
    candidate.instance_id = "candidate".into();
    candidate.version = candidate_version.unwrap_or("2").into();
    let provider = osv::AdvisoryObservation {
        observation_version: 1,
        provider_id: "osv".into(),
        observed_at: now,
        instances: if candidate_version.is_some() {
            vec![current.clone(), candidate.clone()]
        } else {
            vec![current.clone()]
        },
        coverage: CoverageUnit::default(),
        advisory_records: CoverageUnit::default(),
        diagnostics: vec![],
    };
    let installed = assess_findings(&package, &["osv".into()], std::slice::from_ref(&provider));
    let registry=candidate_version.map(|version| {let value=json!({"meta":{"api-version":"1.4"},"name":"demo","versions":[version],"files":[{"filename":format!("demo-{version}-py3-none-any.whl"),"url":format!("demo-{version}.whl"),"hashes":{"sha256":"f".repeat(64)},"size":100}]});RegistryObservation {freshness:Default::default(),source_id:package.source.id.clone(),source_auth_scope_id:package.source.auth_scope_id.clone(),provider_id:"registry".into(),provider_auth_scope_id:"public".into(),distribution:"demo".into(),fetched_at:now,payload_digest:semantic_digest(&value),catalog:parse_registry_catalog("demo",&value,&target.tag_profile)}});
    let candidates = candidate_version
        .map(|version| {
            vec![AssessedCandidate {
                qualification: qualify_candidate(
                    &package,
                    version,
                    registry.as_ref(),
                    &["osv".into()],
                    &[CandidateProviderEvidence {
                        provider_id: "osv",
                        related: &[],
                        candidate_instance_id: "candidate",
                        current: Some(&current),
                        candidate: Some(&candidate),
                    }],
                ),
                constraints: evaluate_constraints(&inventory, &package, version),
                discovery: true,
                revalidation: false,
            }]
        })
        .unwrap_or_default();
    let continuation = plan_candidates(
        &AssessmentDomain {
            inventory_digest: inventory.inventory_id.clone(),
            scope_digest: "scope".into(),
            provider_digest: "provider".into(),
            policy_digest: "policy".into(),
            tag_profile_digest: target.tag_profile.digest.clone(),
            evidence_revision: 1,
        },
        &[DiscoveryInput {
            instance_id: package.instance_id.clone(),
            enumeration_digest: "enumeration".into(),
            versions: candidate_version
                .map(|value| vec![value.into()])
                .unwrap_or_default(),
        }],
        &[],
        &ObservationLimits::default(),
        None,
    )
    .unwrap()
    .continuation;
    SecurityAssessment {
        evidence_coverage: ObservationCoverage::default(),
        provenance: None,
        assessment_version: 1,
        inventory,
        providers: vec![provider],
        packages: vec![PackageAssessment {
            installed,
            instance_id: package.instance_id,
            registry,
            candidates,
            metadata_recommendations: vec![],
            lowest_assessed_candidate: None,
            lowest_proven_candidate: None,
            pending_previous_candidates: vec![],
            unknown_remainder: false,
            diagnostics: vec![],
        }],
        continuation,
        invalidated_instances: vec![],
        unknown_remainder: false,
        coverage: CoverageUnit::default(),
        diagnostics: vec![],
    }
}
