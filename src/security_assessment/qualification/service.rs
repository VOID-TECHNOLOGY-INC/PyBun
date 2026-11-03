//! Shared bounded assessment over an observed inventory. Transport clients must
//! authorize the target and supply current operator-owned policy before entry.
use super::{
    candidate::{CandidateProviderEvidence, CandidateQualification, qualify_candidate},
    constraints::{ConstraintEvaluation, ConstraintStatus, evaluate_constraints},
    evidence::AffectedStatus,
    findings::{FindingAssessment, RelatedAdvisories, assess_findings_with_related},
    provenance::{
        ApprovedRegistryBinding, ProvenanceObservation, ProvenanceRequest, observe_provenance,
    },
    registry::{RegistryCatalog, ReleaseAvailability},
    registry_source::{RegistryObservation, RegistrySource, observe_registry},
    schedule::{
        AssessmentContinuation, AssessmentDomain, DiscoveryInput, ExactCandidate,
        plan_candidates_admitted,
    },
};
use crate::security_assessment::{
    http::{HttpSession, ProviderEndpoint},
    osv::{AdvisoryObservation, query_assessment_advisories},
    *,
};
use pep440_rs::Version;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default)]
pub struct AssessmentOptions {
    pub include_prereleases: bool,
    pub continuation: Option<AssessmentContinuation>,
    pub previous_candidates: Vec<ExactCandidate>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessedCandidate {
    pub qualification: CandidateQualification,
    pub constraints: ConstraintEvaluation,
    pub discovery: bool,
    pub revalidation: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageAssessment {
    pub installed: FindingAssessment,
    pub instance_id: String,
    pub registry: Option<RegistryObservation>,
    pub candidates: Vec<AssessedCandidate>,
    pub metadata_recommendations: Vec<String>,
    pub lowest_assessed_candidate: Option<String>,
    pub lowest_proven_candidate: Option<String>,
    /// A budget miss is distinct from a freshly checked negative result.
    pub pending_previous_candidates: Vec<String>,
    pub unknown_remainder: bool,
    pub diagnostics: Vec<ObservationDiagnostic>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAssessment {
    pub evidence_coverage: ObservationCoverage,
    pub provenance: Option<ProvenanceObservation>,
    pub assessment_version: u32,
    pub inventory: InventoryObservation,
    pub providers: Vec<AdvisoryObservation>,
    pub packages: Vec<PackageAssessment>,
    pub continuation: AssessmentContinuation,
    pub invalidated_instances: Vec<String>,
    pub unknown_remainder: bool,
    pub coverage: CoverageUnit,
    pub diagnostics: Vec<ObservationDiagnostic>,
}

/// Observe the target using its trusted fixed helper, then use the same run
/// deadline and resource budget for optional frozen graph and remote metadata.
/// CLI/MCP authorization must precede this function and cache-handle creation.
pub async fn assess_project(
    session: &HttpSession,
    request: &InventoryRequest,
    providers: &[ProviderEndpoint],
    sources: &[RegistrySource],
    options: &AssessmentOptions,
    provenance: Option<(&ProvenanceRequest, &[ApprovedRegistryBinding])>,
) -> Result<SecurityAssessment, ObservationDiagnostic> {
    request.source_policy.validate()?;
    validate_bindings(providers, sources)?;
    if provenance.is_some_and(|(request, _)| request.limits != *session.limits()) {
        return Err(input_error());
    }

    let inventory = observe_project_inventory(session, request).await?;
    let mut assessment = assess_inventory(
        session,
        &inventory,
        &request.source_policy,
        providers,
        sources,
        options,
    )
    .await?;
    attach_project_provenance(session, request, &mut assessment, provenance).await?;
    Ok(assessment)
}

/// Run the fixed inventory helper once within the existing observation budget.
pub(crate) async fn observe_project_inventory(
    session: &HttpSession,
    request: &InventoryRequest,
) -> Result<InventoryObservation, ObservationDiagnostic> {
    request.source_policy.validate()?;
    if request.limits != *session.limits() {
        return Err(input_error());
    }
    let started = std::time::Instant::now();
    let deadline = started + session.remaining()?;
    let mut bounded = request.clone();
    let observed_at = session.observed_at();
    let inventory_task = tokio::task::spawn_blocking(move || {
        // A queued blocking task must not start a helper after the shared
        // deadline, even when its awaiting caller has already timed out.
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or_else(assessment_deadline_error)?
            .as_millis() as u64;
        if remaining == 0 {
            return Err(assessment_deadline_error());
        }
        bounded.limits.total_timeout_ms = remaining;
        Ok(observe_inventory(&bounded, observed_at))
    });
    let inventory = tokio::time::timeout_at(deadline.into(), inventory_task)
        .await
        .map_err(|_| assessment_deadline_error())?
        .map_err(|_| input_error())??;
    if inventory.target.is_none() {
        return Err(inventory
            .diagnostics
            .first()
            .cloned()
            .unwrap_or_else(input_error));
    }
    session.remaining()?;
    Ok(inventory)
}

/// Attach optional frozen graph evidence without repeating the inventory scan.
pub(crate) async fn attach_project_provenance(
    session: &HttpSession,
    request: &InventoryRequest,
    assessment: &mut SecurityAssessment,
    provenance: Option<(&ProvenanceRequest, &[ApprovedRegistryBinding])>,
) -> Result<(), ObservationDiagnostic> {
    if provenance.is_some_and(|(request, _)| request.limits != *session.limits()) {
        return Err(input_error());
    }
    let deadline = std::time::Instant::now() + session.remaining().unwrap_or_default();
    let mut graph_diagnostics = vec![];
    let graph = match (provenance, session.remaining()) {
        (Some((graph_request, bindings)), Ok(_)) => {
            let graph_request = graph_request.clone();
            let bindings = bindings.to_vec();
            let inventory = assessment.inventory.clone();
            let policy = request.source_policy.clone();
            let graph_task = tokio::task::spawn_blocking(move || {
                if std::time::Instant::now() >= deadline {
                    return Err(assessment_deadline_error());
                }
                Ok(observe_provenance(
                    &graph_request,
                    &inventory,
                    &policy,
                    &bindings,
                    deadline,
                ))
            });
            let observed = tokio::time::timeout_at(deadline.into(), graph_task)
                .await
                .map_err(|_| assessment_deadline_error())
                .and_then(|joined| joined.map_err(|_| input_error()))
                .and_then(|observed| observed);
            match observed {
                Ok(observation) => {
                    let bytes = serde_json::to_vec(&observation)
                        .map_err(|_| input_error())?
                        .len();
                    if let Err(error) = session.reserve_evidence(bytes) {
                        graph_diagnostics.push(error);
                        None
                    } else {
                        Some(observation)
                    }
                }
                Err(error) => {
                    graph_diagnostics.push(error);
                    None
                }
            }
        }
        (Some(_), Err(error)) => {
            graph_diagnostics.push(error);
            None
        }
        (None, _) => None,
    };
    if let Err(error) = session.remaining() {
        graph_diagnostics.push(error);
    }
    let graph_partial = graph
        .as_ref()
        .is_some_and(|graph| graph.coverage.status != CoverageStatus::Complete);
    if graph_partial || !graph_diagnostics.is_empty() {
        assessment.unknown_remainder = true;
        assessment.coverage.status = CoverageStatus::Partial;
        assessment
            .coverage
            .reasons
            .push("E_SECURITY_GRAPH_PARTIAL".into());
    }
    assessment.diagnostics.extend(graph_diagnostics);
    assessment.provenance = graph;
    Ok(())
}

/// Validate a saved cursor before metadata effects. False means its decoded
/// domain changed; malformed cursors and same-domain position errors are not
/// silently converted into a restart.
pub(crate) fn continuation_matches_inventory(
    inventory: &InventoryObservation,
    policy: &SourcePolicy,
    providers: &[ProviderEndpoint],
    sources: &[RegistrySource],
    options: &AssessmentOptions,
) -> Result<bool, ObservationDiagnostic> {
    let Some(cursor) = &options.continuation else {
        return Ok(true);
    };
    cursor.matches_domain(&assessment_domain(
        inventory,
        policy,
        providers,
        sources,
        options.include_prereleases,
    )?)
}

fn assessment_domain(
    inventory: &InventoryObservation,
    policy: &SourcePolicy,
    providers: &[ProviderEndpoint],
    sources: &[RegistrySource],
    include_prereleases: bool,
) -> Result<AssessmentDomain, ObservationDiagnostic> {
    let target = inventory.target.as_ref().ok_or_else(input_error)?;
    let mut packages: Vec<_> = inventory.packages.iter().collect();
    packages.sort_by_key(|package| &package.instance_id);
    let mut ordered_providers: Vec<_> = providers.iter().collect();
    ordered_providers.sort_by_key(|provider| provider.id());
    let mut ordered_sources: Vec<_> = sources.iter().collect();
    ordered_sources.sort_by_key(|source| source.source_id());
    Ok(AssessmentDomain {
        inventory_digest: semantic_digest(&(&inventory.inventory_id, &packages)),
        scope_digest: semantic_digest(&(
            &target.project_root,
            &target.environment_root,
            &target.scope,
            &inventory.direct_constraints,
        )),
        provider_digest: semantic_digest(&(
            ordered_providers
                .iter()
                .map(|provider| provider.config())
                .collect::<Vec<_>>(),
            ordered_sources
                .iter()
                .map(|source| (source.source_id(), source.provider().config()))
                .collect::<Vec<_>>(),
        )),
        policy_digest: semantic_digest(&(policy, include_prereleases)),
        tag_profile_digest: semantic_digest(&target.tag_profile),
        evidence_revision: 1,
    })
}

pub async fn assess_inventory(
    session: &HttpSession,
    inventory: &InventoryObservation,
    policy: &SourcePolicy,
    providers: &[ProviderEndpoint],
    sources: &[RegistrySource],
    options: &AssessmentOptions,
) -> Result<SecurityAssessment, ObservationDiagnostic> {
    assess_inventory_with_history(session, inventory, policy, providers, sources, options, &[])
        .await
}

/// Revalidate approved historical record IDs alongside current query results.
pub async fn assess_inventory_with_history(
    session: &HttpSession,
    inventory: &InventoryObservation,
    policy: &SourcePolicy,
    providers: &[ProviderEndpoint],
    sources: &[RegistrySource],
    options: &AssessmentOptions,
    history: &[crate::security_assessment::osv::KnownAdvisoryId],
) -> Result<SecurityAssessment, ObservationDiagnostic> {
    session.remaining()?;
    policy.validate()?;
    validate_bindings(providers, sources)?;
    let target = inventory.target.as_ref().ok_or_else(input_error)?;
    if inventory.packages.len() > session.limits().max_inventory_instances
        || matches!(
            inventory.coverage.inventory_instances.status,
            CoverageStatus::Error | CoverageStatus::Unsupported
        )
    {
        return Err(input_error());
    }
    let mut ordered_providers: Vec<_> = providers.iter().collect();
    ordered_providers.sort_by_key(|provider| provider.id());
    let mut ordered_sources: Vec<_> = sources.iter().collect();
    ordered_sources.sort_by_key(|source| source.source_id());
    let mut packages: Vec<_> = inventory.packages.iter().collect();
    packages.sort_by_key(|package| &package.instance_id);
    let ids: Vec<_> = packages
        .iter()
        .map(|package| package.instance_id.clone())
        .collect();
    if ids.windows(2).any(|pair| pair[0] == pair[1])
        || ids.iter().any(|id| !super::super::source::opaque_id(id))
    {
        return Err(input_error());
    }
    let domain = assessment_domain(
        inventory,
        policy,
        providers,
        sources,
        options.include_prereleases,
    )?;
    let metadata_order =
        AssessmentContinuation::metadata_order(&domain, &ids, options.continuation.as_ref())?;
    if let Some(cursor) = &options.continuation {
        cursor.validate_previous(&domain, &options.previous_candidates)?;
    }
    let admission_width = options
        .continuation
        .as_ref()
        .map(AssessmentContinuation::admission_width)
        .transpose()?
        .unwrap_or(ObservationLimits::default().max_candidate_checks);
    let admitted_order: Vec<_> = metadata_order
        .iter()
        .take(admission_width)
        .cloned()
        .collect();
    let deferred: Vec<_> = metadata_order
        .iter()
        .skip(admission_width)
        .cloned()
        .collect();
    // Reject invalid previous identities and malformed cursors before metadata,
    // even when their release sets are not yet known.
    for previous in &options.previous_candidates {
        if !ids.contains(&previous.instance_id)
            || previous.version.len() > 200
            || previous.version.parse::<Version>().is_err()
        {
            return Err(input_error());
        }
    }
    if options.previous_candidates.len()
        > session.limits().max_inventory_instances.saturating_mul(20)
    {
        return Err(input_error());
    }
    session.reserve_evidence(
        serde_json::to_vec(inventory)
            .map_err(|_| input_error())?
            .len(),
    )?;
    let by_id: BTreeMap<_, _> = packages
        .iter()
        .map(|package| (package.instance_id.as_str(), *package))
        .collect();
    let mut registries = BTreeMap::new();
    let mut errors: BTreeMap<String, Vec<ObservationDiagnostic>> = BTreeMap::new();
    let mut last_metadata = None;
    for id in &admitted_order {
        let package = by_id[id.as_str()];
        let Some(source) = ordered_sources
            .iter()
            .find(|source| source.source_id() == package.source.id)
        else {
            errors
                .entry(id.clone())
                .or_default()
                .push(ObservationDiagnostic::new(
                    "E_SECURITY_REGISTRY_SOURCE",
                    "No approved registry binding is configured for this source.",
                ));
            continue;
        };
        let before = session.request_count();
        let observed =
            observe_registry(session, source, package, &target.tag_profile, policy).await;
        if session.request_count() > before {
            last_metadata = Some(id.clone());
        }
        match observed {
            Ok(observed) => {
                registries.insert(id.clone(), observed);
            }
            Err(error) => errors.entry(id.clone()).or_default().push(error),
        }
    }
    let discovery: Vec<_> = packages
        .iter()
        .map(|package| {
            let catalog = registries
                .get(&package.instance_id)
                .filter(|observation| enumeration_available(observation))
                .map(|observation| &observation.catalog);
            DiscoveryInput {
                instance_id: package.instance_id.clone(),
                enumeration_digest: catalog.map_or_else(
                    || "unobserved".into(),
                    |catalog| catalog.enumeration_digest.clone(),
                ),
                versions: catalog.map_or_else(Vec::new, |catalog| {
                    catalog
                        .releases
                        .iter()
                        .filter(|release| {
                            in_policy(
                                &release.version,
                                &package.version,
                                options.include_prereleases,
                            )
                        })
                        .map(|release| release.version.clone())
                        .collect()
                }),
            }
        })
        .collect();
    let mut planning_limits = session.limits().clone();
    planning_limits.max_candidates_per_package = planning_limits
        .max_candidates_per_package
        .min(admission_width);
    planning_limits.max_candidate_checks = planning_limits
        .max_candidate_checks
        .min(admission_width.saturating_mul(admitted_order.len().max(1)));
    let mut plan = plan_candidates_admitted(
        &domain,
        &discovery,
        &options.previous_candidates,
        &planning_limits,
        options.continuation.as_ref(),
        &admitted_order,
    )?;
    // One batch stream amortizes current + candidate hydration and preserves
    // circular priority when the shared HTTP/deadline budget runs out.
    let mut query_order = vec![];
    let mut first_versions = BTreeMap::new();
    for id in &admitted_order {
        let package = by_id[id.as_str()];
        query_order.push((package, None));
        if let Some(work) = plan.work.iter().find(|work| work.instance_id == *id) {
            query_order.push((package, Some(work)));
            first_versions.insert(work.instance_id.as_str(), work.version.as_str());
        }
    }
    for work in &plan.work {
        if first_versions.get(work.instance_id.as_str()) == Some(&work.version.as_str()) {
            continue;
        }
        query_order.push((by_id[work.instance_id.as_str()], Some(work)));
    }
    let mut candidate_ids = BTreeMap::new();
    let queries: Vec<_> = query_order
        .into_iter()
        .map(|(package, work)| {
            let mut query: PackageInstance = package.clone();
            if let Some(work) = work {
                query.instance_id = format!(
                    "candidate-{}",
                    semantic_digest(&(&work.instance_id, &work.version))
                );
                query.version = work.version.clone();
                candidate_ids.insert(
                    (work.instance_id.clone(), work.version.clone()),
                    query.instance_id.clone(),
                );
            }
            query
        })
        .collect();
    let observations = query_assessment_advisories(
        session,
        &ordered_providers,
        &queries,
        &admitted_order,
        policy,
        history,
    )
    .await;
    let observed_work: Vec<_> = plan
        .work
        .iter()
        .filter(|work| {
            let id = &candidate_ids[&(work.instance_id.clone(), work.version.clone())];
            observations.iter().all(|provider| {
                provider
                    .instances
                    .iter()
                    .find(|item| item.instance_id == *id)
                    .is_some_and(|item| item.work_attempted)
            })
        })
        .map(|work| ExactCandidate {
            instance_id: work.instance_id.clone(),
            version: work.version.clone(),
        })
        .collect();
    // Capture this before moving registry observations into package frames.
    let missing_metadata: Vec<_> = ids
        .iter()
        .filter(|id| {
            registries
                .get(*id)
                .is_none_or(|registry| !enumeration_available(registry))
        })
        .cloned()
        .collect();
    let required: Vec<_> = ordered_providers
        .iter()
        .map(|provider| provider.id().to_owned())
        .collect();
    let query_parents: BTreeMap<_, _> = candidate_ids
        .iter()
        .map(|((parent, _), query_id)| (query_id.as_str(), parent.as_str()))
        .collect();
    let mut related_by_parent: BTreeMap<&str, Vec<RelatedAdvisories<'_>>> = BTreeMap::new();
    for provider in &observations {
        for instance in &provider.instances {
            if let Some(parent) = query_parents.get(instance.instance_id.as_str()) {
                related_by_parent
                    .entry(parent)
                    .or_default()
                    .push(RelatedAdvisories {
                        provider_id: &provider.provider_id,
                        parent_instance_id: parent,
                        instance,
                    });
            }
        }
    }
    struct PackageFrame {
        installed: FindingAssessment,
        registry: Option<RegistryObservation>,
        candidates: Vec<AssessedCandidate>,
        diagnostics: Vec<ObservationDiagnostic>,
        retained: bool,
    }
    let mut frames = BTreeMap::new();
    // Frame retention follows the same circular priority as metadata work.
    for id in &admitted_order {
        let package = by_id[id.as_str()];
        let registry = registries.remove(&package.instance_id);
        let related = related_by_parent
            .get(package.instance_id.as_str())
            .map_or(&[][..], Vec::as_slice);
        let mut installed =
            assess_findings_with_related(package, &required, &observations, related);
        let mut diagnostics = errors.remove(&package.instance_id).unwrap_or_default();
        let mut installed_retained = true;
        if let Err(error) = session.reserve_evidence(
            serde_json::to_vec(&installed)
                .map_err(|_| input_error())?
                .len(),
        ) {
            installed_retained = false;
            installed.clusters.clear();
            installed.complete = false;
            installed.coverage.status = CoverageStatus::Partial;
            installed.diagnostics.push(error.code.clone());
            diagnostics.push(error);
        }
        frames.insert(
            id.clone(),
            PackageFrame {
                installed,
                registry,
                candidates: vec![],
                diagnostics,
                retained: installed_retained,
            },
        );
    }
    let mut retained = BTreeSet::new();
    let mut retention_blocked = BTreeSet::new();
    // Preserve the planner's global round-robin order rather than allowing the
    // first sorted package to consume the retained-output budget alone.
    for work in &plan.work {
        if retention_blocked.contains(work.instance_id.as_str()) {
            continue;
        }
        let package = by_id[work.instance_id.as_str()];
        let frame = frames.get_mut(&work.instance_id).ok_or_else(input_error)?;
        let related = related_by_parent
            .get(work.instance_id.as_str())
            .map_or(&[][..], Vec::as_slice);
        let candidate_id = &candidate_ids[&(work.instance_id.clone(), work.version.clone())];
        let evidence: Vec<_> = observations
            .iter()
            .map(|observation| CandidateProviderEvidence {
                provider_id: &observation.provider_id,
                related,
                candidate_instance_id: candidate_id,
                current: observation
                    .instances
                    .iter()
                    .find(|item| item.instance_id == package.instance_id),
                candidate: observation
                    .instances
                    .iter()
                    .find(|item| item.instance_id == *candidate_id),
            })
            .collect();
        let qualification = qualify_candidate(
            package,
            &work.version,
            frame.registry.as_ref(),
            &required,
            &evidence,
        );
        let assessed = AssessedCandidate {
            qualification,
            constraints: evaluate_constraints(inventory, package, &work.version),
            discovery: work.discovery,
            revalidation: work.revalidation,
        };
        let bytes = serde_json::to_vec(&assessed)
            .map_err(|_| input_error())?
            .len();
        if let Err(error) = session
            .remaining()
            .and_then(|_| session.reserve_evidence(bytes))
        {
            frame.diagnostics.push(error);
            retention_blocked.insert(work.instance_id.as_str());
            continue;
        }
        retained.insert((work.instance_id.as_str(), work.version.as_str()));
        frame.candidates.push(assessed);
    }
    let observed: BTreeSet<_> = observed_work
        .iter()
        .map(|work| (work.instance_id.as_str(), work.version.as_str()))
        .collect();
    let mut unobserved_prefix = BTreeSet::new();
    let committed: Vec<_> = plan
        .work
        .iter()
        .filter_map(|work| {
            if unobserved_prefix.contains(work.instance_id.as_str()) {
                return None;
            }
            let key = (work.instance_id.as_str(), work.version.as_str());
            if !retained.contains(&key) || !observed.contains(&key) {
                unobserved_prefix.insert(work.instance_id.as_str());
                return None;
            }
            Some(ExactCandidate {
                instance_id: work.instance_id.clone(),
                version: work.version.clone(),
            })
        })
        .collect();
    let failure_head = admitted_order
        .iter()
        .find(|id| plan.work.iter().any(|work| work.instance_id == **id))
        .or_else(|| admitted_order.first());
    let head_succeeded = failure_head
        .and_then(|id| frames.get(id))
        .is_some_and(|frame| {
            frame.retained
                && if plan
                    .work
                    .iter()
                    .any(|work| work.instance_id == frame.installed.instance_id)
                {
                    frame.candidates.iter().any(|candidate| {
                        candidate.qualification.authoritative
                            && candidate.qualification.coverage.status == CoverageStatus::Complete
                            && (candidate.qualification.current_authoritative
                                || candidate.qualification.current_affected == AffectedStatus::Yes)
                    })
                } else {
                    frame.installed.complete
                        && frame.registry.as_ref().is_some_and(enumeration_available)
                }
        });
    plan.continuation = plan.commit_observed_candidates(&domain, &committed)?;
    let mut admission_focused = false;
    if !head_succeeded && let Some(head) = failure_head {
        if let Some(frame) = frames.get_mut(head) {
            frame.diagnostics.push(ObservationDiagnostic::new(
                if admission_width == 1 { "E_SECURITY_ADMISSION_UNFIT" } else { "E_SECURITY_ADMISSION_BACKOFF" },
                "The admitted frame could not complete within this run; unresolved work remains eligible for retry.",
            ));
        }
        if admission_width == 1 {
            if let Some(cursor) = plan.defer_unfit_head(&domain)? {
                plan.continuation = cursor;
            } else {
                plan.continuation = plan
                    .continuation
                    .advance_after_metadata(&domain, &ids, head)?;
            }
        } else {
            plan.continuation = plan.continuation.focus_instance(&domain, &ids, head)?;
        }
        admission_focused = true;
    }

    if let Some(previous) = &options.continuation {
        plan.continuation = plan.continuation.retain_unobserved_metadata(
            previous,
            &domain,
            &ids,
            &missing_metadata,
        )?;
        plan.continuation = plan
            .continuation
            .retain_deferred(previous, &domain, &ids, &deferred)?;
    }
    plan.invalidated_instances
        .retain(|id| !deferred.contains(id));
    plan.continuation = plan.continuation.with_admission_width(if head_succeeded {
        admission_width
    } else {
        (admission_width / 2).max(1)
    })?;
    // Candidate progress owns priority when any observed/retained prefix moved;
    // metadata-only progress must not reset it back to the first package.
    if committed.is_empty()
        && !admission_focused
        && let Some(last) = last_metadata
    {
        plan.continuation = plan
            .continuation
            .advance_after_metadata(&domain, &ids, &last)?;
    }
    let mut results = vec![];
    let mut unknown = plan.unknown_remainder
        || inventory.coverage.inventory_instances.status != CoverageStatus::Complete;
    for package in packages {
        let PackageFrame {
            installed,
            registry,
            mut candidates,
            diagnostics,
            retained: _,
        } = frames.remove(&package.instance_id).unwrap_or_else(|| PackageFrame {
            installed: assess_findings_with_related(package, &required, &[], &[]), registry: None, candidates: vec![], retained: false,
            diagnostics: vec![ObservationDiagnostic::new("E_SECURITY_ADMISSION_DEFERRED", "This package was deferred by bounded admission; its observations and prior candidates remain unresolved.")],
        });
        candidates.sort_by(|a, b| {
            a.qualification
                .version
                .parse::<Version>()
                .ok()
                .cmp(&b.qualification.version.parse::<Version>().ok())
        });
        let qualified: Vec<_> = candidates
            .iter()
            .filter(|candidate| {
                candidate.qualification.candidate_kind.is_some()
                    && in_policy(
                        &candidate.qualification.version,
                        &package.version,
                        options.include_prereleases,
                    )
            })
            .collect();
        let lowest = qualified
            .first()
            .map(|candidate| candidate.qualification.version.clone());
        let proven = lowest
            .as_ref()
            .filter(|lowest| {
                registry.as_ref().is_some_and(|registry| {
                    minimum_proven(
                        &registry.catalog,
                        &candidates,
                        &package.version,
                        lowest,
                        options.include_prereleases,
                    )
                })
            })
            .cloned();
        let recommendations = qualified
            .iter()
            .filter(|candidate| {
                candidate.constraints.constraint_status == ConstraintStatus::PassesKnownConstraints
            })
            .map(|candidate| candidate.qualification.version.clone())
            .collect();
        let pending = options
            .previous_candidates
            .iter()
            .filter(|previous| {
                previous.instance_id == package.instance_id
                    && !candidates.iter().any(|candidate| {
                        same_version(&previous.version, &candidate.qualification.version)
                    })
            })
            .map(|previous| previous.version.clone())
            .collect::<Vec<_>>();
        let item_unknown = !installed.complete
            || installed.coverage.status != CoverageStatus::Complete
            || registry.as_ref().is_none_or(|registry| {
                registry.catalog.coverage.status != CoverageStatus::Complete
                    || !registry.freshness.is_authoritative()
            })
            || !diagnostics.is_empty()
            || !pending.is_empty()
            || candidates.iter().any(|candidate| {
                candidate.qualification.coverage.status != CoverageStatus::Complete
            })
            || discovery
                .iter()
                .find(|input| input.instance_id == package.instance_id)
                .is_some_and(|input| {
                    input.versions.iter().any(|version| {
                        !candidates.iter().any(|candidate| {
                            same_version(version, &candidate.qualification.version)
                        })
                    })
                });
        unknown |= item_unknown;
        results.push(PackageAssessment {
            installed,
            instance_id: package.instance_id.clone(),
            registry,
            candidates,
            metadata_recommendations: recommendations,
            lowest_assessed_candidate: lowest,
            lowest_proven_candidate: proven,
            pending_previous_candidates: pending,
            unknown_remainder: item_unknown,
            diagnostics,
        });
    }
    unknown |= observations
        .iter()
        .any(|observation| observation.coverage.status != CoverageStatus::Complete);
    let mut assessment_diagnostics = session.cache_diagnostics();
    if let Err(error) = session.remaining() {
        assessment_diagnostics.push(error);
    }
    unknown |= !assessment_diagnostics.is_empty();
    let completed = results
        .iter()
        .filter(|item| !item.unknown_remainder)
        .count();
    let mut evidence_coverage = ObservationCoverage {
        inventory_instances: inventory.coverage.inventory_instances.clone(),
        ..Default::default()
    };
    for provider in &observations {
        let unit = &mut evidence_coverage.advisory_records;
        let added = &provider.advisory_records;
        unit.requested += added.requested;
        unit.complete += added.complete;
        unit.partial += added.partial;
        unit.unsupported += added.unsupported;
        unit.errors += added.errors;
        if added.status != CoverageStatus::Complete
            || provider
                .instances
                .iter()
                .any(|instance| !instance.freshness.is_authoritative())
        {
            unit.status = CoverageStatus::Partial;
            unit.reasons.push("E_SECURITY_ADVISORIES_INCOMPLETE".into());
        }
    }
    if !deferred.is_empty() {
        evidence_coverage.advisory_records.status = CoverageStatus::Partial;
        evidence_coverage
            .advisory_records
            .reasons
            .push("E_SECURITY_ADMISSION_DEFERRED".into());
    }
    for item in &results {
        let unit = &mut evidence_coverage.finding_clusters;
        unit.requested += item.installed.clusters.len();
        unit.complete += item
            .installed
            .clusters
            .iter()
            .filter(|cluster| cluster.complete)
            .count();
        if !item.installed.complete {
            unit.status = CoverageStatus::Partial;
            unit.reasons.push("E_SECURITY_FINDINGS_INCOMPLETE".into());
        }
    }
    evidence_coverage.finding_clusters.partial =
        evidence_coverage.finding_clusters.requested - evidence_coverage.finding_clusters.complete;
    let candidate_complete = results
        .iter()
        .flat_map(|item| &item.candidates)
        .filter(|candidate| {
            candidate.qualification.authoritative
                && candidate.qualification.coverage.status == CoverageStatus::Complete
        })
        .count();
    evidence_coverage.candidate_checks = CoverageUnit {
        requested: plan.work.len(),
        complete: candidate_complete,
        partial: plan.work.len() - candidate_complete,
        status: if candidate_complete == plan.work.len() && !plan.unknown_remainder {
            CoverageStatus::Complete
        } else {
            CoverageStatus::Partial
        },
        reasons: if candidate_complete == plan.work.len() && !plan.unknown_remainder {
            vec![]
        } else {
            vec!["E_SECURITY_CANDIDATES_INCOMPLETE".into()]
        },
        ..Default::default()
    };
    evidence_coverage.advisory_records.reasons.sort();
    evidence_coverage.advisory_records.reasons.dedup();
    evidence_coverage.finding_clusters.reasons.sort();
    evidence_coverage.finding_clusters.reasons.dedup();
    Ok(SecurityAssessment {
        evidence_coverage,
        assessment_version: 1,
        provenance: None,
        diagnostics: assessment_diagnostics,
        inventory: inventory.clone(),
        providers: observations,
        packages: results,
        continuation: plan.continuation,
        invalidated_instances: plan.invalidated_instances,
        unknown_remainder: unknown,
        coverage: CoverageUnit {
            status: if unknown {
                CoverageStatus::Partial
            } else {
                CoverageStatus::Complete
            },
            requested: ids.len(),
            complete: completed,
            partial: ids.len() - completed,
            reasons: if unknown {
                vec!["E_SECURITY_ASSESSMENT_PARTIAL".into()]
            } else {
                vec![]
            },
            ..Default::default()
        },
    })
}
fn enumeration_available(registry: &RegistryObservation) -> bool {
    !registry.catalog.enumeration_digest.trim().is_empty()
        && !matches!(
            registry.catalog.coverage.status,
            CoverageStatus::Unsupported | CoverageStatus::Error
        )
}

fn same_version(a: &str, b: &str) -> bool {
    a.parse::<Version>()
        .ok()
        .is_some_and(|a| b.parse::<Version>().ok() == Some(a))
}
fn in_policy(version: &str, current: &str, include_prereleases: bool) -> bool {
    version
        .parse::<Version>()
        .ok()
        .zip(current.parse::<Version>().ok())
        .is_some_and(|(version, current)| {
            version > current && (include_prereleases || (!version.any_prerelease()))
        })
}
fn minimum_proven(
    catalog: &RegistryCatalog,
    candidates: &[AssessedCandidate],
    current: &str,
    lowest: &str,
    include_prereleases: bool,
) -> bool {
    if catalog.coverage.status != CoverageStatus::Complete {
        return false;
    }
    let Ok(lowest) = lowest.parse::<Version>() else {
        return false;
    };
    catalog
        .releases
        .iter()
        .filter(|release| {
            in_policy(&release.version, current, include_prereleases)
                && release
                    .version
                    .parse::<Version>()
                    .is_ok_and(|version| version < lowest)
        })
        .all(|release| {
            matches!(
                release.availability,
                ReleaseAvailability::SourceBuildRequired
                    | ReleaseAvailability::Yanked
                    | ReleaseAvailability::NoCompatibleWheel
            ) || candidates.iter().any(|candidate| {
                same_version(&candidate.qualification.version, &release.version)
                    && candidate.qualification.affected == AffectedStatus::Yes
                    && candidate.qualification.authoritative
                    && candidate.qualification.coverage.status == CoverageStatus::Complete
            })
        })
}
fn validate_bindings(
    providers: &[ProviderEndpoint],
    sources: &[RegistrySource],
) -> Result<(), ObservationDiagnostic> {
    let mut provider_ids = std::collections::BTreeSet::new();
    let mut source_ids = std::collections::BTreeSet::new();
    if providers.is_empty()
        || providers
            .iter()
            .any(|provider| !provider_ids.insert(provider.id()))
        || sources
            .iter()
            .any(|source| !source_ids.insert(source.source_id()))
    {
        return Err(input_error());
    }
    Ok(())
}

fn assessment_deadline_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_DEADLINE",
        "The shared assessment deadline was exhausted before metadata observation completed.",
    )
}

fn input_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_ASSESSMENT_INPUT",
        "Assessment requires a bounded observed inventory and unambiguous current provider/source bindings.",
    )
}
