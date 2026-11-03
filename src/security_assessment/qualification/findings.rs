//! Per-instance advisory identity clustering. Traversal and aliases convey no
//! transport authority; payloads remain in their original provider observation.
use super::evidence::{AdvisoryEvaluation, AffectedStatus, evaluate_advisory};
use crate::security_assessment::{
    CoverageStatus, CoverageUnit, PackageInstance,
    osv::{AdvisoryObservation, InstanceAdvisories},
    semantic_digest,
    source::normalize_name,
};
use pep440_rs::Version;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingRecordEvidence {
    pub provider_id: String,
    pub record_id: String,
    pub payload_digest: String,
    pub fetched_at: u64,
    pub evaluation: AdvisoryEvaluation,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingCluster {
    pub ids: Vec<String>,
    pub aliases: Vec<String>,
    pub cluster_digest: String,
    pub affected: AffectedStatus,
    pub complete: bool,
    pub severity: FindingSeverity,
    pub records: Vec<FindingRecordEvidence>,
    pub diagnostics: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingAssessment {
    pub instance_id: String,
    pub source_id: String,
    pub auth_scope_id: String,
    pub scope_variant: String,
    pub clusters: Vec<FindingCluster>,
    pub affected: AffectedStatus,
    pub complete: bool,
    pub coverage: CoverageUnit,
    pub diagnostics: Vec<String>,
}

/// A same-run query explicitly bound by the caller to its installed parent.
/// This binding conveys no authority to query a provider or another source.
#[derive(Debug, Clone, Copy)]
pub struct RelatedAdvisories<'a> {
    pub provider_id: &'a str,
    pub parent_instance_id: &'a str,
    pub instance: &'a InstanceAdvisories,
}

pub fn assess_findings(
    package: &PackageInstance,
    required_providers: &[String],
    observations: &[AdvisoryObservation],
) -> FindingAssessment {
    assess_findings_with_related(package, required_providers, observations, &[])
}

pub fn assess_findings_with_related(
    package: &PackageInstance,
    required_providers: &[String],
    observations: &[AdvisoryObservation],
    related: &[RelatedAdvisories<'_>],
) -> FindingAssessment {
    let mut diagnostics = BTreeSet::new();
    let required: BTreeSet<_> = required_providers.iter().map(String::as_str).collect();
    if required.is_empty()
        || required.len() != required_providers.len()
        || required
            .iter()
            .any(|id| !crate::security_assessment::source::opaque_id(id))
    {
        diagnostics.insert("E_SECURITY_FINDING_PROVIDERS".to_owned());
    }
    if package.coverage.status != CoverageStatus::Complete {
        diagnostics.insert("E_SECURITY_FINDING_INVENTORY_PARTIAL".into());
    }
    let mut records = Vec::new();
    let mut complete_providers = 0;
    for provider in &required {
        let matching: Vec<_> = observations
            .iter()
            .filter(|observation| observation.provider_id == *provider)
            .collect();
        let mut pool = Vec::new();
        let mut complete = matching.len() == 1;
        if !complete {
            diagnostics.insert("E_SECURITY_FINDING_PROVIDER_MISSING_OR_DUPLICATE".into());
        }
        for observation in matching {
            // Global coverage may include unrelated instances or later candidate
            // work. Only this exact instance's coverage governs this assessment.
            complete &= observation.observation_version == 1;
            let instances: Vec<_> = observation
                .instances
                .iter()
                .filter(|instance| instance.instance_id == package.instance_id)
                .collect();
            complete &= instances.len() == 1;
            for instance in instances {
                if !context_matches(package, instance)
                    || instance
                        .version
                        .parse::<Version>()
                        .ok()
                        .zip(package.version.parse::<Version>().ok())
                        .is_none_or(|(a, b)| a != b)
                {
                    complete = false;
                    diagnostics.insert("E_SECURITY_FINDING_CONTEXT_MISMATCH".into());
                    continue;
                }
                if !instance.freshness.is_authoritative() {
                    complete = false;
                    diagnostics.insert("E_SECURITY_FINDING_NOT_FRESH".into());
                }
                complete &=
                    instance.work_attempted && instance.coverage.status == CoverageStatus::Complete;
                for record in &instance.records {
                    pool.push((record, instance.freshness.is_authoritative(), false));
                }
            }
        }
        for query in related
            .iter()
            .filter(|query| query.provider_id == *provider)
        {
            if query.parent_instance_id != package.instance_id
                || !context_matches(package, query.instance)
                || query.instance.version.parse::<Version>().is_err()
            {
                continue;
            }
            for record in &query.instance.records {
                pool.push((record, query.instance.freshness.is_authoritative(), true));
            }
        }
        // The pool borrows original payloads. Prefer fresh evidence for identical
        // raw proofs and evaluate each (provider, ID, raw digest) only once.
        pool.sort_by_key(|(record, query_fresh, _)| {
            (
                &record.id,
                &record.payload_digest,
                !(*query_fresh && record.freshness.is_authoritative()),
                record.fetched_at,
            )
        });
        pool.dedup_by(|a, b| a.0.id == b.0.id && a.0.payload_digest == b.0.payload_digest);
        for (record, query_fresh, is_related) in pool {
            let mut evaluation = evaluate_advisory(package, &package.version, provider, record);
            // The digest proves raw HTTP bytes, whereas payload is parsed
            // and redacted. These are deliberately different domains.
            let malformed = !valid_identifier(&record.id)
                || record.payload_digest.len() != 64
                || !record
                    .payload_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit());
            let malformed_aliases = evaluation
                .aliases
                .iter()
                .any(|alias| !valid_identifier(alias));
            if malformed || malformed_aliases {
                evaluation.complete = false;
                diagnostics.insert("E_SECURITY_FINDING_RECORD_MALFORMED".into());
            }
            if malformed {
                evaluation.affected = AffectedStatus::Unknown;
                evaluation.fixed_boundaries.clear();
            }
            evaluation.aliases.retain(|alias| valid_identifier(alias));

            let authoritative = query_fresh && record.freshness.is_authoritative();
            if is_related
                && !authoritative
                && evaluation.complete
                && evaluation.affected == AffectedStatus::No
                && evaluation.withdrawn.is_none()
            {
                continue;
            }
            if !authoritative {
                complete = false;
                diagnostics.insert("E_SECURITY_FINDING_NOT_FRESH".into());
            }
            complete &= evaluation.complete;
            records.push(FindingRecordEvidence {
                provider_id: (*provider).into(),
                record_id: record.id.clone(),
                payload_digest: record.payload_digest.clone(),
                fetched_at: record.fetched_at,
                evaluation,
            });
        }
        if complete {
            complete_providers += 1;
        } else {
            diagnostics.insert("E_SECURITY_FINDING_PROVIDER_INCOMPLETE".into());
        }
    }
    records.sort_by_cached_key(|record| {
        (
            record.provider_id.clone(),
            record.record_id.clone(),
            record.payload_digest.clone(),
            record.fetched_at,
            semantic_digest(&record.evaluation),
        )
    });
    let mut parent: Vec<_> = (0..records.len()).collect();
    let mut identifiers: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        for identifier in std::iter::once(record.record_id.as_str())
            .chain(record.evaluation.aliases.iter().map(String::as_str))
            .filter(|id| valid_identifier(id))
        {
            if let Some(other) = identifiers.insert(identifier, index) {
                let a = root(&parent, index);
                let b = root(&parent, other);
                parent[a] = b;
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<FindingRecordEvidence>> = BTreeMap::new();
    for (index, record) in records.into_iter().enumerate() {
        groups.entry(root(&parent, index)).or_default().push(record);
    }
    let mut clusters = Vec::new();
    for records in groups.into_values() {
        let ids: BTreeSet<_> = records
            .iter()
            .map(|record| record.record_id.clone())
            .collect();
        let aliases: BTreeSet<_> = records
            .iter()
            .flat_map(|record| record.evaluation.aliases.iter().cloned())
            .filter(|alias| !ids.contains(alias))
            .collect();
        let mut reasons = Vec::new();
        let withdrawn = records
            .iter()
            .any(|record| record.evaluation.withdrawn.is_some());
        let active = records
            .iter()
            .any(|record| record.evaluation.withdrawn.is_none());
        if withdrawn && active {
            reasons.push("E_SECURITY_FINDING_WITHDRAWAL_CONTRADICTION".into());
        }
        let duplicate = records.windows(2).any(|pair| {
            pair[0].provider_id == pair[1].provider_id && pair[0].record_id == pair[1].record_id
        });
        if duplicate {
            reasons.push("E_SECURITY_FINDING_DUPLICATE_RECORD".into());
        }
        let complete =
            records.iter().all(|record| record.evaluation.complete) && reasons.is_empty();
        let affected = union(
            records.iter().map(|record| record.evaluation.affected),
            complete,
        );
        let ids: Vec<_> = ids.into_iter().collect();
        let aliases: Vec<_> = aliases.into_iter().collect();
        // Raw proof hashes, prose, timestamps and event positions belong to
        // evidence provenance. Compare only actionable evaluation semantics.
        let mut semantic_records: Vec<_> = records
            .iter()
            .map(|record| {
                let evaluation = &record.evaluation;
                let boundaries: BTreeSet<_> = evaluation
                    .fixed_boundaries
                    .iter()
                    .map(|boundary| {
                        (
                            boundary.introduced == "0",
                            semantic_version(&boundary.introduced),
                            semantic_version(&boundary.fixed),
                        )
                    })
                    .collect();
                let codes: BTreeSet<_> = evaluation
                    .diagnostics
                    .iter()
                    .map(|diagnostic| &diagnostic.code)
                    .collect();
                (
                    &record.provider_id,
                    &record.record_id,
                    &evaluation.aliases,
                    evaluation.affected,
                    evaluation.complete,
                    evaluation.withdrawn.is_some(),
                    boundaries,
                    codes,
                )
            })
            .collect();
        semantic_records.sort_by_cached_key(semantic_digest);
        let digest = semantic_digest(&(
            &package.instance_id,
            &package.source,
            &package.source_mapping,
            &package.scope_variant,
            &ids,
            &aliases,
            &semantic_records,
            &reasons,
        ));
        clusters.push(FindingCluster {
            ids,
            aliases,
            cluster_digest: digest,
            affected,
            complete,
            severity: FindingSeverity::Unknown,
            records,
            diagnostics: reasons,
        });
    }
    clusters.sort_by(|a, b| {
        a.ids
            .cmp(&b.ids)
            .then(a.cluster_digest.cmp(&b.cluster_digest))
    });
    diagnostics.extend(
        clusters
            .iter()
            .flat_map(|cluster| cluster.diagnostics.iter().cloned()),
    );
    let complete = diagnostics.is_empty() && clusters.iter().all(|cluster| cluster.complete);
    let affected = union(clusters.iter().map(|cluster| cluster.affected), complete);
    FindingAssessment {
        instance_id: package.instance_id.clone(),
        source_id: package.source.id.clone(),
        auth_scope_id: package.source.auth_scope_id.clone(),
        scope_variant: package.scope_variant.clone(),
        clusters,
        affected,
        complete,
        coverage: CoverageUnit {
            status: if complete {
                CoverageStatus::Complete
            } else {
                CoverageStatus::Partial
            },
            requested: required.len(),
            complete: complete_providers,
            partial: required.len() - complete_providers,
            reasons: diagnostics.iter().cloned().collect(),
            ..Default::default()
        },
        diagnostics: diagnostics.into_iter().collect(),
    }
}
pub(crate) fn context_matches(package: &PackageInstance, instance: &InstanceAdvisories) -> bool {
    instance.source_id == package.source.id
        && instance.auth_scope_id == package.source.auth_scope_id
        && package.source_mapping.as_ref().is_some_and(|mapping| {
            instance.ecosystem.as_deref() == Some(mapping.ecosystem.as_str())
                && instance.mapping_assumption.as_deref() == Some(mapping.assumption.as_str())
                && instance
                    .upstream_name
                    .as_deref()
                    .and_then(|name| normalize_name(name).ok())
                    .zip(normalize_name(&mapping.upstream_name).ok())
                    .is_some_and(|(observed, expected)| observed == expected)
        })
}

fn semantic_version(value: &str) -> Option<String> {
    let version = value.parse::<Version>().ok()?;
    let release = version.release();
    let end = release
        .iter()
        .rposition(|part| *part != 0)
        .map_or(1, |index| index + 1);
    let parts = release[..end].to_vec();
    Some(version.with_release(parts).to_string())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.chars().all(|c| !c.is_control() && !c.is_whitespace())
}
fn root(parent: &[usize], mut index: usize) -> usize {
    while parent[index] != index {
        index = parent[index];
    }
    index
}
fn union(values: impl Iterator<Item = AffectedStatus>, complete: bool) -> AffectedStatus {
    let mut unknown = !complete;
    for value in values {
        match value {
            AffectedStatus::Yes => return AffectedStatus::Yes,
            AffectedStatus::Unknown => unknown = true,
            AffectedStatus::No => {}
        }
    }
    if unknown {
        AffectedStatus::Unknown
    } else {
        AffectedStatus::No
    }
}
