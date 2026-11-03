//! Credential-free semantic projection of the companion engine's evidence.
use super::{model::*, state::*};
use crate::security_assessment::{
    http::EvidenceFreshness,
    qualification::{
        candidate::{CandidateKind, CandidateQualification, FixEvidence},
        evidence::AffectedStatus,
        findings::context_matches,
        registry::{PublishedFile, ReleaseAvailability},
        registry_source::RegistryObservation,
        service::SecurityAssessment,
    },
    *,
};
use pep440_rs::Version;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct Projected<'a> {
    pub packages: BTreeMap<String, PackageFacts<'a>>,
    pub inventory_complete: bool,
    pub online: bool,
    pub baseline_possible: bool,
    pub complete: bool,
    pub failures: BTreeSet<String>,
    pub diagnostics: Vec<MonitorDiagnostic>,
    pub continuation: Option<String>,
}
pub(crate) struct PackageFacts<'a> {
    pub source: SourceIdentity,
    pub versions: BTreeSet<String>,
    pub findings: Vec<ObservedFinding>,
    pub presence_fresh: bool,
    pub advisory_complete: bool,
    pub unaffected: bool,
    pub disqualified_candidates: BTreeSet<String>,
    pub registries: Vec<(&'a RegistryObservation, bool)>,
}
pub(crate) struct ObservedFinding {
    pub value: MonitorFinding,
    pub positive: bool,
    pub negative: bool,
    pub withdrawn: bool,
    pub conflict: bool,
    pub identity_authoritative: bool,
    pub fresh_aliases: BTreeSet<String>,
}

pub fn logical_package_key(package: &PackageInstance) -> MonitorResult<String> {
    let name = normalize_name(&package.name).map_err(|_| input_error())?;
    if !crate::security_assessment::source::opaque_id(&package.source.id)
        || !crate::security_assessment::source::opaque_id(&package.source.auth_scope_id)
        || !crate::security_assessment::source::opaque_id(&package.scope_variant)
    {
        return Err(input_error());
    }
    Ok(semantic_digest(&(
        name,
        &package.source,
        package
            .source_mapping
            .as_ref()
            .map(|mapping| (&mapping.ecosystem, &mapping.upstream_name)),
        &package.scope_variant,
        &package.origin_identity,
    )))
}
pub(crate) fn canonical_version(value: &str) -> MonitorResult<String> {
    let version = value.parse::<Version>().map_err(|_| input_error())?;
    let release = version.release();
    let end = release
        .iter()
        .rposition(|part| *part != 0)
        .map_or(1, |index| index + 1);
    let parts = release[..end].to_vec();
    Ok(version.with_release(parts).to_string())
}
pub(crate) fn project<'a>(
    assessment: &'a SecurityAssessment,
    config: &MonitorConfig,
    context: &CheckContext,
    limits: &MonitorLimits,
) -> MonitorResult<Projected<'a>> {
    if assessment.assessment_version != 1
        || assessment.inventory.observation_version != 1
        || assessment.inventory.packages.len() > limits.max_inventory_instances
    {
        return Err(input_error());
    }
    if assessment.providers.iter().any(|provider| {
        !context
            .domain
            .authoritative_providers
            .contains(&provider.provider_id)
    }) {
        return Err(input_error());
    }
    if let Some(target) = &assessment.inventory.target {
        let mut actual = context.domain.clone();
        actual.project_root = target.project_root.clone();
        actual.environment_root = target.environment_root.clone();
        actual.backend = target.backend;
        actual.target = target.kind;
        actual.scope = target.scope.clone();
        actual.runtime = context
            .domain
            .runtime
            .as_ref()
            .map(|_| RuntimeIdentity::from_target(target));
        actual.validate()?;
        if actual != context.domain {
            return Err(MonitorError::new("E_MONITOR_DOMAIN"));
        }
    }
    let ttl = config.freshness_ttl_seconds;
    let online = context.mode == ObservationMode::Online;
    let inventory_fresh = online
        && fresh(
            context.inventory_freshness,
            assessment.inventory.observed_at,
            context.now,
            ttl,
        );
    let valid_inventory = !matches!(
        assessment.inventory.coverage.inventory_instances.status,
        CoverageStatus::Error | CoverageStatus::Unsupported
    ) && assessment.inventory.target.is_some();
    let mut result = Projected {
        packages: BTreeMap::new(),
        inventory_complete: inventory_fresh
            && valid_inventory
            && assessment.inventory.coverage.inventory_instances.status == CoverageStatus::Complete,
        online,
        baseline_possible: inventory_fresh && valid_inventory,
        complete: online
            && inventory_fresh
            && assessment.coverage.status == CoverageStatus::Complete,
        failures: BTreeSet::new(),
        diagnostics: vec![],
        continuation: Some(assessment.continuation.as_str().into()),
    };
    if !online {
        failure(
            &mut result,
            "target",
            "E_MONITOR_OFFLINE",
            "inventory_instances",
        );
    } else if !inventory_fresh || !valid_inventory {
        failure(
            &mut result,
            "target",
            "E_MONITOR_INVENTORY_INCOMPLETE",
            "inventory_instances",
        );
    }
    if assessment.inventory.coverage.inventory_instances.status != CoverageStatus::Complete {
        failure(
            &mut result,
            "target",
            "E_MONITOR_INVENTORY_INCOMPLETE",
            "inventory_instances",
        );
    }
    let mut seen = BTreeSet::new();
    for package in &assessment.inventory.packages {
        if !seen.insert(&package.instance_id) {
            return Err(input_error());
        }
        let key = logical_package_key(package)?;
        let version = canonical_version(&package.version)?;
        let rows: Vec<_> = assessment
            .packages
            .iter()
            .filter(|row| row.instance_id == package.instance_id)
            .collect();
        if rows.len() > 1 {
            return Err(input_error());
        }
        let row = rows.first().copied();
        if row.is_some_and(|row| {
            row.installed.instance_id != package.instance_id
                || row.installed.source_id != package.source.id
                || row.installed.auth_scope_id != package.source.auth_scope_id
                || row.installed.scope_variant != package.scope_variant
        }) {
            return Err(input_error());
        }
        let present = inventory_fresh
            && valid_inventory
            && package.coverage.status == CoverageStatus::Complete;
        let providers_complete = present
            && context.domain.authoritative_providers.iter().all(|id| {
                let providers: Vec<_> = assessment
                    .providers
                    .iter()
                    .filter(|provider| provider.provider_id == *id)
                    .collect();
                providers.len() == 1 && time_fresh(providers[0].observed_at, context.now, ttl) && {
                    let instances: Vec<_> = providers[0]
                        .instances
                        .iter()
                        .filter(|instance| {
                            instance.instance_id == package.instance_id
                                && context_matches(package, instance)
                        })
                        .collect();
                    instances.len() == 1
                        && instances[0].coverage.status == CoverageStatus::Complete
                        && instances[0].freshness.is_authoritative()
                        && instances[0].records.iter().all(|record| {
                            record.coverage.status == CoverageStatus::Complete
                                && fresh(record.freshness, record.fetched_at, context.now, ttl)
                        })
                }
            });
        let mut observed = vec![];
        if let Some(row) = row {
            for cluster in &row.installed.clusters {
                let ids: BTreeSet<_> = cluster
                    .ids
                    .iter()
                    .chain(&cluster.aliases)
                    .filter(|id| valid_identifier(id))
                    .cloned()
                    .collect();
                if ids.is_empty() {
                    continue;
                }
                let conflict = cluster
                    .diagnostics
                    .iter()
                    .any(|code| code.contains("WITHDRAWAL") || code.contains("CONTRADICTION"));
                let mut positive = false;
                let mut withdrawn = false;
                let mut all_records = !cluster.records.is_empty();
                let mut evidence = vec![];
                let mut fresh_aliases = BTreeSet::new();
                let mut meanings = vec![];
                for reference in &cluster.records {
                    let record_fresh = present
                        && raw_fresh(
                            assessment,
                            package,
                            &reference.provider_id,
                            (
                                &reference.record_id,
                                &reference.payload_digest,
                                Some(reference.fetched_at),
                            ),
                            context,
                            ttl,
                        );
                    let evaluation = &reference.evaluation;
                    if record_fresh && evaluation.complete {
                        fresh_aliases.insert(reference.record_id.clone());
                        fresh_aliases.extend(evaluation.aliases.iter().cloned());
                    }
                    positive |= record_fresh
                        && evaluation.complete
                        && evaluation.affected == AffectedStatus::Yes;
                    withdrawn |=
                        record_fresh && evaluation.complete && evaluation.withdrawn.is_some();
                    all_records &= record_fresh && evaluation.complete;
                    evidence.push(MonitorEvidence {
                        provider_id: reference.provider_id.clone(),
                        record_id: reference.record_id.clone(),
                        payload_digest: reference.payload_digest.clone(),
                        fetched_at: reference.fetched_at,
                        evaluated_version: version.clone(),
                        affected: evaluation.affected,
                        complete: evaluation.complete,
                        withdrawn: evaluation.withdrawn.is_some(),
                        currently_fresh: record_fresh,
                        was_authoritative: record_fresh && evaluation.complete,
                        severity: reference.severity,
                    });
                    let payload = assessment
                        .providers
                        .iter()
                        .filter(|provider| provider.provider_id == reference.provider_id)
                        .flat_map(|provider| &provider.instances)
                        .filter(|instance| context_matches(package, instance))
                        .flat_map(|instance| &instance.records)
                        .find(|record| {
                            record.id == reference.record_id
                                && record.payload_digest == reference.payload_digest
                        })
                        .map(|record| &record.payload);
                    meanings.push(semantic_digest(&(
                        &reference.provider_id,
                        &reference.record_id,
                        evaluation.affected,
                        evaluation.complete,
                        evaluation.withdrawn.is_some(),
                        reference.severity,
                        payload.map(|payload| advisory_meaning(payload, package)),
                    )));
                }
                meanings.sort();
                meanings.dedup();
                evidence.sort_by(|a, b| {
                    (&a.provider_id, &a.record_id, &a.payload_digest).cmp(&(
                        &b.provider_id,
                        &b.record_id,
                        &b.payload_digest,
                    ))
                });
                let candidate = row
                    .candidates
                    .iter()
                    .filter_map(|candidate| {
                        let q = &candidate.qualification;
                        let runtime = context.domain.runtime.as_ref()?;
                        if !present {
                            return None;
                        }
                        if !config.include_prereleases
                            && q.version
                                .parse::<Version>()
                                .is_ok_and(|version| version.any_prerelease())
                        {
                            return None;
                        }
                        if !required_candidate_coverage(assessment, package, q, context, ttl)
                            || q.candidate_kind
                                != Some(CandidateKind::PublishedRemediationCandidate)
                            || q.fix_evidence != FixEvidence::KnownBoundary
                            || !q.authoritative
                            || q.coverage.status != CoverageStatus::Complete
                            || !q.freshness.is_authoritative()
                            || !online
                        {
                            return None;
                        }
                        if !q.published_remediation_basis.iter().any(|boundary| {
                            ids.contains(&boundary.record_id)
                                && raw_fresh(
                                    assessment,
                                    package,
                                    &boundary.provider_id,
                                    (&boundary.record_id, &boundary.payload_digest, None),
                                    context,
                                    ttl,
                                )
                        }) {
                            return None;
                        }
                        if !q.providers.iter().all(|provider| {
                            provider.complete
                                && provider.candidate.iter().all(|record| {
                                    record.complete
                                        && raw_fresh(
                                            assessment,
                                            package,
                                            &provider.provider_id,
                                            (&record.record_id, &record.payload_digest, None),
                                            context,
                                            ttl,
                                        )
                                })
                        }) {
                            return None;
                        }
                        let registry = row.registry.as_ref()?;
                        if !registry_fresh(registry, package, context, ttl) {
                            return None;
                        }
                        let release = registry.catalog.releases.iter().find(|release| {
                            canonical_version(&release.version).ok()
                                == canonical_version(&q.version).ok()
                        })?;
                        if release.availability != ReleaseAvailability::BinaryWheelAvailable {
                            return None;
                        }
                        let mut artifacts: Vec<_> = release
                            .files
                            .iter()
                            .filter(|file| {
                                file.coverage.status == CoverageStatus::Complete
                                    && file.yanked == Some(false)
                                    && !file.source_distribution
                                    && !file.matched_tags.is_empty()
                                    && file.requires_python_satisfied == Some(true)
                            })
                            .map(|file| {
                                artifact(
                                    file,
                                    &package.source,
                                    &q.version,
                                    &runtime.tag_profile_digest,
                                )
                            })
                            .collect();
                        artifacts.sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));
                        artifacts.dedup_by(|a, b| a.artifact_id == b.artifact_id);
                        if artifacts.is_empty() {
                            return None;
                        }
                        Some(MonitorCandidate {
                            source_id: package.source.id.clone(),
                            auth_scope_id: package.source.auth_scope_id.clone(),
                            version: canonical_version(&q.version).ok()?,
                            artifacts,
                            qualified_remediation: true,
                            publication_available: true,
                            constraint_status: candidate.constraints.constraint_status,
                            last_confirmed_at: context.now,
                        })
                    })
                    .min_by(|a, b| {
                        a.version
                            .parse::<Version>()
                            .ok()
                            .cmp(&b.version.parse::<Version>().ok())
                    });
                let aliases: Vec<_> = ids.into_iter().collect();
                let semantic = semantic_digest(&(&aliases, &meanings, cluster.severity));
                observed.push(ObservedFinding {
                    identity_authoritative: all_records && !conflict,
                    fresh_aliases,
                    positive: positive && !conflict,
                    negative: providers_complete
                        && all_records
                        && cluster.affected == AffectedStatus::No
                        && !conflict,
                    withdrawn: withdrawn && !conflict,
                    conflict,
                    value: MonitorFinding {
                        finding_id: String::new(),
                        package_key: key.clone(),
                        package_name: normalize_name(&package.name).map_err(|_| input_error())?,
                        source: package.source.clone(),
                        scope_variant: package.scope_variant.clone(),
                        aliases,
                        vulnerable_versions: vec![version.clone()],
                        active: positive && !conflict,
                        observed_affected: cluster.affected,
                        complete: providers_complete && all_records && !conflict,
                        severity: if all_records {
                            cluster.severity
                        } else {
                            Default::default()
                        },
                        last_known_severity: (all_records && cluster.severity.rank().is_some())
                            .then_some(cluster.severity),
                        candidate,
                        evidence,
                        related_lineages: vec![],
                        semantic_digest: semantic,
                    },
                });
            }
        }
        if row.is_none_or(|row| !row.installed.complete) || !providers_complete {
            failure(
                &mut result,
                &package.source.id,
                "E_MONITOR_ADVISORY_INCOMPLETE",
                "advisory_records",
            );
        }
        if row.is_some_and(|row| row.unknown_remainder) {
            failure(
                &mut result,
                &package.source.id,
                "E_MONITOR_ASSESSMENT_INCOMPLETE",
                "candidate_checks",
            );
        }
        let unaffected = providers_complete
            && row.is_some_and(|row| {
                row.installed.complete && row.installed.affected == AffectedStatus::No
            });
        let disqualified_candidates = candidate_corrections(assessment, row, package, context, ttl);
        if let Some(existing) = result.packages.get_mut(&key) {
            existing
                .disqualified_candidates
                .extend(disqualified_candidates);
            existing.versions.insert(version);
            existing.findings.extend(observed);
            existing.presence_fresh &= present;
            existing.advisory_complete &= providers_complete;
            existing.unaffected &= unaffected;
            if let Some(registry) = row.and_then(|row| row.registry.as_ref()) {
                existing
                    .registries
                    .push((registry, registry_fresh(registry, package, context, ttl)));
            }
        } else {
            result.packages.insert(
                key,
                PackageFacts {
                    source: package.source.clone(),
                    disqualified_candidates,
                    versions: BTreeSet::from([version]),
                    findings: observed,
                    presence_fresh: present,
                    advisory_complete: providers_complete,
                    unaffected,
                    registries: row
                        .and_then(|row| row.registry.as_ref())
                        .map(|registry| (registry, registry_fresh(registry, package, context, ttl)))
                        .into_iter()
                        .collect(),
                },
            );
        }
    }
    if assessment.unknown_remainder || assessment.coverage.status != CoverageStatus::Complete {
        failure(
            &mut result,
            "target",
            "E_MONITOR_ASSESSMENT_INCOMPLETE",
            "candidate_checks",
        );
    }
    for package in result.packages.values_mut() {
        package.findings = merge_findings(std::mem::take(&mut package.findings));
    }
    Ok(result)
}
fn merge_findings(findings: Vec<ObservedFinding>) -> Vec<ObservedFinding> {
    let mut parent: Vec<_> = (0..findings.len()).collect();
    let mut owners = BTreeMap::new();
    fn root(parent: &[usize], mut index: usize) -> usize {
        while parent[index] != index {
            index = parent[index];
        }
        index
    }
    for (index, finding) in findings.iter().enumerate() {
        for alias in &finding.value.aliases {
            if let Some(other) = owners.insert(alias, index) {
                let a = root(&parent, index);
                let b = root(&parent, other);
                parent[a] = b;
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<ObservedFinding>> = BTreeMap::new();
    for (index, finding) in findings.into_iter().enumerate() {
        groups
            .entry(root(&parent, index))
            .or_default()
            .push(finding);
    }
    groups
        .into_values()
        .map(|group| {
            let mut value = group[0].value.clone();
            let positive = group.iter().any(|finding| finding.positive);
            let withdrawn = group.iter().any(|finding| finding.withdrawn);
            let conflict = group.iter().any(|finding| finding.conflict) || (positive && withdrawn);
            value.aliases = group
                .iter()
                .flat_map(|finding| finding.value.aliases.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            value.vulnerable_versions = group
                .iter()
                .filter(|finding| finding.positive)
                .flat_map(|finding| finding.value.vulnerable_versions.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            value.evidence = group
                .iter()
                .flat_map(|finding| finding.value.evidence.iter().cloned())
                .collect();
            value.evidence.sort_by_key(|item| {
                (
                    item.provider_id.clone(),
                    item.record_id.clone(),
                    item.payload_digest.clone(),
                    item.evaluated_version.clone(),
                )
            });
            value.evidence.dedup();
            value.candidate = group
                .iter()
                .filter_map(|finding| finding.value.candidate.clone())
                .min_by(|a, b| {
                    a.version
                        .parse::<Version>()
                        .ok()
                        .cmp(&b.version.parse::<Version>().ok())
                });
            value.severity = if group
                .iter()
                .any(|finding| finding.value.severity.rank().is_none())
            {
                crate::security_assessment::qualification::findings::FindingSeverity::Unknown
            } else {
                group
                    .iter()
                    .map(|finding| finding.value.severity)
                    .max_by_key(|level| level.rank())
                    .unwrap_or_default()
            };
            value.last_known_severity = value.severity.rank().map(|_| value.severity);
            value.complete = group.iter().all(|finding| finding.value.complete) && !conflict;
            value.active = positive && !conflict;
            value.observed_affected = if conflict {
                AffectedStatus::Unknown
            } else if group
                .iter()
                .any(|finding| finding.value.observed_affected == AffectedStatus::Yes)
            {
                AffectedStatus::Yes
            } else if group
                .iter()
                .any(|finding| finding.value.observed_affected == AffectedStatus::Unknown)
            {
                AffectedStatus::Unknown
            } else {
                AffectedStatus::No
            };
            value.semantic_digest = semantic_digest(
                &group
                    .iter()
                    .map(|finding| finding.value.semantic_digest.clone())
                    .collect::<BTreeSet<_>>(),
            );
            ObservedFinding {
                fresh_aliases: group
                    .iter()
                    .flat_map(|finding| finding.fresh_aliases.iter().cloned())
                    .collect(),
                identity_authoritative: group.iter().all(|finding| finding.identity_authoritative)
                    && !conflict,
                value,
                positive: positive && !conflict,
                negative: group.iter().all(|finding| finding.negative) && !conflict,
                withdrawn: withdrawn && !conflict,
                conflict,
            }
        })
        .collect()
}
fn required_candidate_coverage(
    assessment: &SecurityAssessment,
    package: &PackageInstance,
    q: &CandidateQualification,
    context: &CheckContext,
    ttl: u64,
) -> bool {
    q.providers.len() == context.domain.authoritative_providers.len()
        && q.providers
            .iter()
            .map(|provider| &provider.provider_id)
            .collect::<BTreeSet<_>>()
            .len()
            == q.providers.len()
        && context.domain.authoritative_providers.iter().all(|id| {
            q.providers
                .iter()
                .any(|provider| &provider.provider_id == id)
                && candidate_query_complete(assessment, package, &q.version, id, context, ttl)
        })
}
fn candidate_query_complete(
    assessment: &SecurityAssessment,
    package: &PackageInstance,
    version: &str,
    provider_id: &str,
    context: &CheckContext,
    ttl: u64,
) -> bool {
    let providers: Vec<_> = assessment
        .providers
        .iter()
        .filter(|provider| provider.provider_id == provider_id)
        .collect();
    providers.len() == 1
        && time_fresh(providers[0].observed_at, context.now, ttl)
        && providers[0].instances.iter().any(|instance| {
            context_matches(package, instance)
                && canonical_version(&instance.version).ok() == canonical_version(version).ok()
                && instance.coverage.status == CoverageStatus::Complete
                && fresh(
                    instance.freshness,
                    providers[0].observed_at,
                    context.now,
                    ttl,
                )
                && instance.records.iter().all(|record| {
                    record.coverage.status == CoverageStatus::Complete
                        && fresh(record.freshness, record.fetched_at, context.now, ttl)
                })
        })
}
fn candidate_corrections(
    assessment: &SecurityAssessment,
    row: Option<&crate::security_assessment::qualification::service::PackageAssessment>,
    package: &PackageInstance,
    context: &CheckContext,
    ttl: u64,
) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    if context.mode != ObservationMode::Online {
        return result;
    }
    for candidate in row.into_iter().flat_map(|row| &row.candidates) {
        let q = &candidate.qualification;
        let positive = q
            .providers
            .iter()
            .flat_map(|provider| {
                provider
                    .candidate
                    .iter()
                    .map(move |record| (&provider.provider_id, record))
            })
            .any(|(provider, record)| {
                record.complete
                    && record.affected == AffectedStatus::Yes
                    && raw_fresh(
                        assessment,
                        package,
                        provider,
                        (&record.record_id, &record.payload_digest, None),
                        context,
                        ttl,
                    )
            });
        let complete = q.authoritative
            && required_candidate_coverage(assessment, package, q, context, ttl)
            && context.domain.authoritative_providers.iter().all(|id| {
                candidate_query_complete(assessment, package, &package.version, id, context, ttl)
            })
            && q.current_authoritative
            && q.coverage.status == CoverageStatus::Complete
            && q.freshness.is_authoritative()
            && q.freshness.age_seconds <= ttl
            && q.providers.iter().all(|provider| {
                provider.complete
                    && provider
                        .candidate
                        .iter()
                        .chain(&provider.current)
                        .all(|record| {
                            record.complete
                                && raw_fresh(
                                    assessment,
                                    package,
                                    &provider.provider_id,
                                    (&record.record_id, &record.payload_digest, None),
                                    context,
                                    ttl,
                                )
                        })
            });
        if (positive || complete && q.fix_evidence == FixEvidence::Unavailable)
            && let Ok(version) = canonical_version(&q.version)
        {
            result.insert(version);
        }
    }
    result
}
fn failure(result: &mut Projected<'_>, scope: &str, code: &str, coverage: &str) {
    result.complete = false;
    result
        .failures
        .insert(semantic_digest(&(scope, code, coverage)));
    let item = MonitorDiagnostic {
        code: code.into(),
        scope: scope.into(),
    };
    if !result.diagnostics.contains(&item) {
        result.diagnostics.push(item);
    }
}
pub(crate) fn fresh(value: EvidenceFreshness, fetched: u64, now: u64, ttl: u64) -> bool {
    value.is_authoritative() && value.age_seconds <= ttl && time_fresh(fetched, now, ttl)
}
fn time_fresh(fetched: u64, now: u64, ttl: u64) -> bool {
    fetched <= now && now - fetched <= ttl
}
fn raw_fresh(
    assessment: &SecurityAssessment,
    package: &PackageInstance,
    provider: &str,
    proof: (&str, &str, Option<u64>),
    context: &CheckContext,
    ttl: u64,
) -> bool {
    let (id, digest, fetched) = proof;
    context.mode == ObservationMode::Online
        && assessment
            .providers
            .iter()
            .filter(|entry| entry.provider_id == provider)
            .flat_map(|provider| &provider.instances)
            .filter(|instance| {
                context_matches(package, instance) && instance.freshness.is_authoritative()
            })
            .flat_map(|instance| &instance.records)
            .any(|record| {
                record.id == id
                    && record.payload_digest == digest
                    && fetched.is_none_or(|value| value == record.fetched_at)
                    && record.coverage.status == CoverageStatus::Complete
                    && fresh(record.freshness, record.fetched_at, context.now, ttl)
            })
}
pub(crate) fn registry_fresh(
    registry: &RegistryObservation,
    package: &PackageInstance,
    context: &CheckContext,
    ttl: u64,
) -> bool {
    context.mode == ObservationMode::Online
        && registry.source_id == package.source.id
        && registry.source_auth_scope_id == package.source.auth_scope_id
        && normalize_name(&registry.distribution).ok() == normalize_name(&package.name).ok()
        && fresh(registry.freshness, registry.fetched_at, context.now, ttl)
}
pub(crate) fn artifact(
    file: &PublishedFile,
    source: &SourceIdentity,
    version: &str,
    target: &str,
) -> ArtifactIdentity {
    let hashes = file.hashes.clone();
    let url_identity = if hashes.is_empty() {
        file.url.as_ref().map(semantic_digest)
    } else {
        None
    };
    let artifact_id = semantic_digest(&(
        &source.id,
        &source.auth_scope_id,
        canonical_version(version).ok(),
        &file.filename,
        &hashes,
        &url_identity,
        target,
    ));
    ArtifactIdentity {
        artifact_id,
        filename: file.filename.clone(),
        hashes,
        url_identity,
        target_tag_digest: target.into(),
    }
}
fn advisory_meaning(payload: &Value, package: &PackageInstance) -> Value {
    let Some(mapping) = &package.source_mapping else {
        return Value::Null;
    };
    let mut entries = vec![];
    for entry in payload
        .get("affected")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = entry.pointer("/package/name").and_then(Value::as_str);
        if entry.pointer("/package/ecosystem").and_then(Value::as_str) != Some(&mapping.ecosystem)
            || !name.is_some_and(|name| {
                name == "*"
                    || normalize_name(name).ok() == normalize_name(&mapping.upstream_name).ok()
            })
        {
            continue;
        }
        let versions: BTreeSet<_> = entry
            .get("versions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|value| canonical_version(value).unwrap_or_else(|_| semantic_digest(&value)))
            .collect();
        let mut ranges = vec![];
        for range in entry
            .get("ranges")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let mut events = vec![];
            for event in range
                .get("events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                for key in ["introduced", "fixed", "last_affected", "limit"] {
                    if let Some(value) = event.get(key).and_then(Value::as_str) {
                        events.push(json!([
                            key,
                            key == "introduced" && value == "0",
                            canonical_version(value).unwrap_or_else(|_| semantic_digest(&value))
                        ]));
                    }
                }
            }
            events.sort_by_cached_key(semantic_digest);
            ranges.push(json!([range.get("type"), events]));
        }
        ranges.sort_by_cached_key(semantic_digest);
        entries.push(json!([versions, ranges]));
    }
    entries.sort_by_cached_key(semantic_digest);
    json!(entries)
}
fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.chars().all(|c| !c.is_control() && !c.is_whitespace())
}
fn input_error() -> MonitorError {
    MonitorError::new("E_MONITOR_ASSESSMENT")
}
