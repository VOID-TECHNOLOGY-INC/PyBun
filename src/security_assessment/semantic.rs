//! Explicit semantic facts, separated from capture clocks and raw evidence IDs.
use super::{CoverageUnit, ObservationDiagnostic, qualification::service::SecurityAssessment};
use pep440_rs::Version;
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Serialize)]
struct SemanticAssessmentV1<'a> {
    projection_version: u32,
    policy_digest: &'a str,
    target: Option<Value>,
    inventory: Vec<Value>,
    direct_constraints: Vec<Value>,
    providers: Vec<Value>,
    packages: Vec<Value>,
    provenance: Option<Value>,
    coverage: Value,
    evidence_coverage: Value,
    diagnostics: Vec<Value>,
    inventory_diagnostics: Vec<Value>,
    unknown_remainder: bool,
}

pub fn assessment_id(assessment: &SecurityAssessment, policy_digest: &str) -> String {
    let target = assessment.inventory.target.as_ref().map(|target| json!({
        "project_root":target.project_root,"environment_root":target.environment_root,
        "interpreter_digest":target.interpreter_digest,"kind":target.kind,"backend":target.backend,
        "scope":{"members":ordered(target.scope.members.iter().map(|v|json!(v))),"groups":ordered(target.scope.groups.iter().map(|v|json!(v))),"extras":ordered(target.scope.extras.iter().map(|v|json!(v)))},
        "markers":target.marker_environment,
        "tags":{"profile_version":target.tag_profile.profile_version,"implementation":target.tag_profile.implementation,"python_version":version(&target.tag_profile.python_version),"os":target.tag_profile.os,"architecture":target.tag_profile.architecture,"libc":target.tag_profile.libc,"deployment":target.tag_profile.deployment,"tags":ordered(target.tag_profile.tags.iter().map(|v|json!(v)))},
    }));
    let inventory = ordered(assessment.inventory.packages.iter().map(|package| json!({
        "instance_id":package.instance_id,"name":package.name,"version":version(&package.version),
        "source":package.source,"mapping":package.source_mapping,"scope_variant":package.scope_variant,
        "requirements":constraints(&package.requires_dist),"coverage":coverage(&package.coverage),
    })));
    let providers = ordered(assessment.providers.iter().map(|provider| json!({
        "provider_id":provider.provider_id,"coverage":coverage(&provider.coverage),"advisory_records":coverage(&provider.advisory_records),"diagnostics":codes(&provider.diagnostics),
        "instances":ordered(provider.instances.iter().map(|instance|json!({
            "instance_id":instance.instance_id,"version":version(&instance.version),"source_id":instance.source_id,"auth_scope_id":instance.auth_scope_id,"upstream_name":instance.upstream_name,"ecosystem":instance.ecosystem,"mapping_assumption":instance.mapping_assumption,
            "freshness":instance.freshness.kind,"coverage":coverage(&instance.coverage),
            "records":ordered(instance.records.iter().map(|record|json!({"id":record.id,"freshness":record.freshness.kind,"coverage":coverage(&record.coverage),"facts":advisory_facts(&record.payload)}))),
        }))),
    })));
    let packages = ordered(assessment.packages.iter().map(|package| json!({
        "instance_id":package.instance_id,"affected":package.installed.affected,"complete":package.installed.complete,"coverage":coverage(&package.installed.coverage),
        "clusters":ordered(package.installed.clusters.iter().map(|cluster|json!({"ids":ordered(cluster.ids.iter().map(|v|json!(v))),"aliases":ordered(cluster.aliases.iter().map(|v|json!(v))),"digest":cluster.cluster_digest,"affected":cluster.affected,"complete":cluster.complete,"severity":cluster.severity}))),
        "registry":package.registry.as_ref().map(|registry|json!({
            "source_id":registry.source_id,"source_auth_scope_id":registry.source_auth_scope_id,"provider_id":registry.provider_id,"provider_auth_scope_id":registry.provider_auth_scope_id,"distribution":registry.distribution,"freshness":registry.freshness.kind,
            "coverage":coverage(&registry.catalog.coverage),"unknown_files":registry.catalog.unknown_files,"unknown_versions":registry.catalog.unknown_versions,
            "releases":ordered(registry.catalog.releases.iter().map(|release|json!({"version":version(&release.version),"availability":release.availability,"coverage":coverage(&release.coverage),"files":ordered(release.files.iter().map(|file|json!({"filename":file.filename,"hashes":file.hashes,"requires_python":file.requires_python,"requires_python_declared":file.requires_python_declared,"requires_python_satisfied":file.requires_python_satisfied,"yanked":file.yanked,"source_distribution":file.source_distribution,"matched_tags":ordered(file.matched_tags.iter().map(|v|json!(v))),"coverage":coverage(&file.coverage)})))}))),
        })),
        "candidates":ordered(package.candidates.iter().map(|candidate|{
            let q=&candidate.qualification;
            json!({"version":version(&q.version),"freshness":q.freshness.kind,"authoritative":q.authoritative,"current_authoritative":q.current_authoritative,"current_affected":q.current_affected,"affected":q.affected,"fix_evidence":q.fix_evidence,"candidate_kind":q.candidate_kind,"availability":q.availability,
            "fixed_boundaries":boundaries(&q.fixed_boundaries),"published_remediation_basis":boundaries(&q.published_remediation_basis),"coverage":coverage(&q.coverage),"resolution_status":q.resolution_status,"verification_status":q.verification_status,
            "providers":ordered(q.providers.iter().map(|provider|json!({"provider_id":provider.provider_id,"complete":provider.complete,"current":ordered(provider.current.iter().map(evaluation)),"candidate":ordered(provider.candidate.iter().map(evaluation))}))),
            "constraints":{"constraint_status":candidate.constraints.constraint_status,"known_direct_status":candidate.constraints.known_direct_status,"is_direct_dependency":candidate.constraints.is_direct_dependency,"full_constraint_completeness":candidate.constraints.full_constraint_completeness,"coverage":coverage(&candidate.constraints.coverage),"blockers":ordered(candidate.constraints.blockers.iter().map(|blocker|json!({"candidate_version":version(&blocker.candidate_version),"requirement":blocker.requirement,"origin":blocker.origin}))),"evaluated":ordered(candidate.constraints.evaluated.iter().map(|fact|json!({"requirement":fact.requirement,"origin":fact.origin,"applies":fact.applies,"satisfied":fact.satisfied,"reason":fact.reason}))),"diagnostics":codes(&candidate.constraints.diagnostics)}})
        })),
        "metadata_recommendations":ordered(package.metadata_recommendations.iter().map(|v|json!(version(v)))),"lowest_assessed_candidate":package.lowest_assessed_candidate.as_deref().map(version),"lowest_proven_candidate":package.lowest_proven_candidate.as_deref().map(version),"pending_previous_candidates":ordered(package.pending_previous_candidates.iter().map(|v|json!(version(v)))),"unknown_remainder":package.unknown_remainder,"diagnostics":codes(&package.diagnostics),
    })));
    let provenance=assessment.provenance.as_ref().map(|graph|json!({
        "coverage":coverage(&graph.coverage),"diagnostics":codes(&graph.diagnostics),
        "instances":ordered(graph.instances.iter().map(|instance|json!({"instance_id":instance.instance_id,"coverage":coverage(&instance.coverage),"parents":ordered(instance.parents.iter().map(|parent|json!({"parent_instance_id":parent.parent_instance_id,"name":parent.parent_name,"version":version(&parent.parent_version),"source_id":parent.source_id,"requirements":constraints(&parent.requirements),"edge_marker":parent.edge_marker,"activation":parent.activation,"coverage":coverage(&parent.coverage)})))}))),
    }));
    super::semantic_digest(&SemanticAssessmentV1 {
        projection_version: 1,
        policy_digest,
        target,
        inventory,
        direct_constraints: constraints(&assessment.inventory.direct_constraints),
        providers,
        packages,
        provenance,
        coverage: coverage(&assessment.coverage),
        evidence_coverage: json!({"inventory_instances":coverage(&assessment.evidence_coverage.inventory_instances),"advisory_records":coverage(&assessment.evidence_coverage.advisory_records),"finding_clusters":coverage(&assessment.evidence_coverage.finding_clusters),"candidate_checks":coverage(&assessment.evidence_coverage.candidate_checks)}),
        diagnostics: codes(&assessment.diagnostics),
        inventory_diagnostics: codes(&assessment.inventory.diagnostics),
        unknown_remainder: assessment.unknown_remainder,
    })
}

pub fn observation_id(assessment: &SecurityAssessment) -> String {
    super::semantic_digest(&(1, &assessment.inventory.observation_id, assessment.inventory.observed_at,
        ordered(assessment.providers.iter().map(|provider|json!({"provider_id":provider.provider_id,"observed_at":provider.observed_at,"records":ordered(provider.instances.iter().flat_map(|instance|instance.records.iter().map(|record|json!({"instance_id":instance.instance_id,"id":record.id,"payload_digest":record.payload_digest,"fetched_at":record.fetched_at,"freshness":record.freshness}))))}))),
        ordered(assessment.packages.iter().filter_map(|package|package.registry.as_ref().map(|registry|json!({"instance_id":package.instance_id,"payload_digest":registry.payload_digest,"fetched_at":registry.fetched_at,"freshness":registry.freshness})))),
        assessment.provenance.as_ref().and_then(|graph|graph.lock_digest.as_ref()),
    ))
}
fn version(value: &str) -> String {
    value
        .parse::<Version>()
        .map(|version| {
            let release = version.release();
            let end = release.iter().rposition(|n| *n != 0).map_or(1, |i| i + 1);
            version
                .clone()
                .with_release(release[..end].to_vec())
                .to_string()
        })
        .unwrap_or_else(|_| value.into())
}
fn ordered(values: impl IntoIterator<Item = Value>) -> Vec<Value> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_by_cached_key(Value::to_string);
    values.dedup();
    values
}
fn codes(values: &[ObservationDiagnostic]) -> Vec<Value> {
    ordered(
        values
            .iter()
            .map(|value| json!({"code":value.code,"instance_id":value.instance_id})),
    )
}

fn coverage(value: &CoverageUnit) -> Value {
    let mut value = value.clone();
    value.reasons.sort();
    value.reasons.dedup();
    json!(value)
}
fn constraints(values: &[super::ConstraintEvidence]) -> Vec<Value> {
    ordered(
        values
            .iter()
            .map(|value| json!({"requirement":value.requirement,"origin":value.origin})),
    )
}
fn boundaries(values: &[super::qualification::evidence::FixedBoundaryEvidence]) -> Vec<Value> {
    ordered(values.iter().map(|value|json!({"provider_id":value.provider_id,"record_id":value.record_id,"introduced":introduced(&value.introduced),"fixed":version(&value.fixed)})))
}
fn introduced(value: &str) -> Value {
    if value == "0" {
        json!({"unbounded":true})
    } else {
        json!(version(value))
    }
}
fn evaluation(value: &super::qualification::evidence::AdvisoryEvaluation) -> Value {
    json!({"provider_id":value.provider_id,"record_id":value.record_id,"affected":value.affected,"complete":value.complete,"withdrawn":value.withdrawn.is_some(),"aliases":ordered(value.aliases.iter().map(|v|json!(v))),"fixed_boundaries":boundaries(&value.fixed_boundaries),"diagnostics":ordered(value.diagnostics.iter().map(|v|json!(v.code)))})
}
fn advisory_facts(payload: &Value) -> Value {
    json!({"id":payload.get("id"),"aliases":ordered(payload.get("aliases").and_then(Value::as_array).into_iter().flatten().cloned()),"withdrawn":payload.get("withdrawn").map(|value|if value.as_str().is_some_and(|text|time::OffsetDateTime::parse(text,&time::format_description::well_known::Rfc3339).is_ok()){json!(true)}else{json!({"invalid":value})}),"severity":severity_values(payload.get("severity")),"database_severity":database_severity(payload),
    "affected":ordered(payload.get("affected").and_then(Value::as_array).into_iter().flatten().map(|affected|json!({"package":affected.get("package"),"severity":severity_values(affected.get("severity")),"versions":ordered(affected.get("versions").and_then(Value::as_array).into_iter().flatten().map(|v|v.as_str().map_or_else(||v.clone(),|v|json!(version(v))))),"ranges":ordered(affected.get("ranges").and_then(Value::as_array).into_iter().flatten().map(|range|json!({"type":range.get("type"),"repo":range.get("repo"),"events":ordered(range.get("events").and_then(Value::as_array).into_iter().flatten().map(|event|{let mut fact=serde_json::Map::new();if let Some(event)=event.as_object(){for (key,value) in event {fact.insert(key.clone(),value.as_str().map_or_else(||value.clone(),|value|if key=="introduced"{introduced(value)}else{json!(version(value))}));}}else{fact.insert("invalid".into(),event.clone());}Value::Object(fact)}))})))})))})
}

fn severity_values(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Array(values)) => json!(ordered(values.iter().cloned())),
        Some(value) => value.clone(),
        None => Value::Null,
    }
}
fn database_severity(payload: &Value) -> Value {
    let declared = super::qualification::findings::provider_declared_severity(payload);
    if declared.rank().is_some() {
        json!(declared)
    } else {
        payload
            .pointer("/database_specific/severity")
            .cloned()
            .unwrap_or(Value::Null)
    }
}
