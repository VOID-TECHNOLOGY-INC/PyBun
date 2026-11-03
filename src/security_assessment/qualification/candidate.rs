//! Combine explicit current and candidate advisory evidence. This pure reducer
//! accepts observations, never grants authority to fetch them or apply an update.
use super::{
    evidence::{AdvisoryEvaluation, AffectedStatus, FixedBoundaryEvidence, evaluate_advisory},
    findings::{RelatedAdvisories, context_matches},
    registry::ReleaseAvailability,
    registry_source::RegistryObservation,
};
use crate::security_assessment::{
    CoverageStatus, CoverageUnit, PackageInstance, http::EvidenceFreshness, osv::InstanceAdvisories,
};
use pep440_rs::Version;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FixEvidence {
    KnownBoundary,
    Unavailable,
    Unsupported,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    PublishedRemediationCandidate,
    NonAffectedUpgradeObserved,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateAvailability {
    PublishedCandidate,
    NotObserved,
    Unknown,
    SourceBuildRequired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    NotChecked,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    NotRun,
}

pub struct CandidateProviderEvidence<'a> {
    pub provider_id: &'a str,
    pub related: &'a [RelatedAdvisories<'a>],
    pub candidate_instance_id: &'a str,
    pub current: Option<&'a InstanceAdvisories>,
    pub candidate: Option<&'a InstanceAdvisories>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCandidateEvaluation {
    pub provider_id: String,
    pub current: Vec<AdvisoryEvaluation>,
    /// Includes current-query records evaluated again at the candidate. Query
    /// absence alone cannot erase known reintroduction or contradictory facts.
    pub candidate: Vec<AdvisoryEvaluation>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateQualification {
    pub freshness: EvidenceFreshness,
    pub authoritative: bool,
    pub current_authoritative: bool,
    pub version: String,
    pub current_affected: AffectedStatus,
    pub affected: AffectedStatus,
    pub fix_evidence: FixEvidence,
    pub candidate_kind: Option<CandidateKind>,
    pub availability: CandidateAvailability,
    pub fixed_boundaries: Vec<FixedBoundaryEvidence>,
    pub published_remediation_basis: Vec<FixedBoundaryEvidence>,
    pub providers: Vec<ProviderCandidateEvaluation>,
    pub coverage: CoverageUnit,
    pub resolution_status: ResolutionStatus,
    pub verification_status: VerificationStatus,
}

pub fn qualify_candidate(
    package: &PackageInstance,
    version: &str,
    registry: Option<&RegistryObservation>,
    required_providers: &[String],
    observations: &[CandidateProviderEvidence<'_>],
) -> CandidateQualification {
    let parsed = version.parse::<Version>().ok();
    let current_version = package.version.parse::<Version>().ok();
    let upgrade = parsed
        .as_ref()
        .zip(current_version.as_ref())
        .is_some_and(|(a, b)| a > b);
    let mut complete = parsed.is_some()
        && current_version.is_some()
        && package.coverage.status == CoverageStatus::Complete
        && !required_providers.is_empty();
    let mut current_complete = complete;
    let mut freshness = EvidenceFreshness::default();
    let mut current_freshness = EvidenceFreshness::default();
    let mut revisions_complete = true;
    let mut fresh_current_positive = false;
    let mut fresh_boundaries = vec![];
    let mut current_yes = false;
    let mut candidate_yes = false;
    let mut providers = vec![];
    let mut boundaries = vec![];
    let mut required = BTreeSet::new();
    for id in required_providers {
        if !required.insert(id) || !crate::security_assessment::source::opaque_id(id) {
            complete = false;
            current_complete = false;
            continue;
        }
        let mut matches = observations
            .iter()
            .filter(|observation| observation.provider_id == id);
        let observation = matches.next();
        let unique = matches.next().is_none();
        let current = observation
            .and_then(|observation| observation.current)
            .filter(|value| {
                unique
                    && value.instance_id == package.instance_id
                    && identity_matches(package, &package.version, value)
            });
        let candidate = observation
            .and_then(|observation| observation.candidate)
            .filter(|value| {
                unique
                    && observation.is_some_and(|observation| {
                        value.instance_id == observation.candidate_instance_id
                    })
                    && identity_matches(package, version, value)
            });
        if let Some(current) = current {
            current_freshness.merge(current.freshness);
        }
        if let Some(candidate) = candidate {
            freshness.merge(candidate.freshness);
        }
        let mut entry = ProviderCandidateEvaluation {
            provider_id: id.clone(),
            current: vec![],
            candidate: vec![],
            complete: false,
        };
        let current_ok =
            current.is_some_and(|value| value.coverage.status == CoverageStatus::Complete);
        let candidate_ok =
            candidate.is_some_and(|value| value.coverage.status == CoverageStatus::Complete);
        // The complete same-scope record set is known only after every query
        // finishes. Re-evaluate it for both versions, including discoveries at
        // later candidates; an omitted query ID cannot erase a known range.
        let mut pool: Vec<_> = current
            .into_iter()
            .flat_map(|value| &value.records)
            .map(|record| {
                (
                    record,
                    current.map(|value| value.freshness).unwrap_or_default(),
                    true,
                    false,
                )
            })
            .collect();
        pool.extend(
            candidate
                .into_iter()
                .flat_map(|value| &value.records)
                .map(|record| {
                    (
                        record,
                        candidate.map(|value| value.freshness).unwrap_or_default(),
                        false,
                        true,
                    )
                }),
        );
        if let Some(observation) = observation {
            for related in observation.related.iter().filter(|related| {
                related.provider_id == id
                    && related.parent_instance_id == package.instance_id
                    && context_matches(package, related.instance)
                    && related.instance.version.parse::<Version>().is_ok()
            }) {
                pool.extend(
                    related
                        .instance
                        .records
                        .iter()
                        .map(|record| (record, related.instance.freshness, false, false)),
                );
            }
        }
        pool.sort_by_key(|(record, query_freshness, _, _)| {
            (
                &record.id,
                &record.payload_digest,
                !record.freshness.is_authoritative(),
                !query_freshness.is_authoritative(),
            )
        });
        pool.dedup_by(|a, b| {
            if a.0.id == b.0.id && a.0.payload_digest == b.0.payload_digest {
                b.2 |= a.2;
                b.3 |= a.3;
                true
            } else {
                false
            }
        });
        for (record, query_freshness, required_current, required_candidate) in pool {
            let current_evaluation = evaluate_advisory(package, &package.version, id, record);
            let candidate_evaluation = evaluate_advisory(package, version, id, record);
            let fresh = record.freshness.is_authoritative() && query_freshness.is_authoritative();
            if required_current
                || fresh
                || !current_evaluation.complete
                || current_evaluation.affected != AffectedStatus::No
                || current_evaluation.withdrawn.is_some()
            {
                current_freshness.merge(record.freshness);
                current_freshness.merge(query_freshness);
                current_yes |= current_evaluation.affected == AffectedStatus::Yes;
                if current_evaluation.complete && current_evaluation.affected == AffectedStatus::Yes
                {
                    boundaries.extend(current_evaluation.fixed_boundaries.iter().cloned());
                    if record.freshness.is_authoritative() {
                        fresh_current_positive = true;
                        fresh_boundaries.extend(
                            current_evaluation
                                .fixed_boundaries
                                .iter()
                                .filter(|boundary| {
                                    boundary
                                        .fixed
                                        .parse::<Version>()
                                        .ok()
                                        .zip(parsed.as_ref())
                                        .is_some_and(|(fixed, candidate)| candidate >= &fixed)
                                })
                                .cloned(),
                        );
                    }
                }
                entry.current.push(current_evaluation);
            }
            // Cached negative records from other versions are not evidence
            // required to establish this candidate's fresh query result.
            if required_candidate
                || fresh
                || !candidate_evaluation.complete
                || candidate_evaluation.affected != AffectedStatus::No
            {
                freshness.merge(record.freshness);
                freshness.merge(query_freshness);
                entry.candidate.push(candidate_evaluation);
            }
        }
        candidate_yes |= entry
            .candidate
            .iter()
            .any(|value| value.affected == AffectedStatus::Yes);
        let mut known_basis: BTreeMap<&str, &AdvisoryEvaluation> = BTreeMap::new();
        let mut changed_contributor = false;
        for record in &entry.current {
            for name in std::iter::once(record.record_id.as_str())
                .chain(record.aliases.iter().map(String::as_str))
            {
                if let Some(old) = known_basis.insert(name, record) {
                    changed_contributor |= !same_current_basis(old, record);
                }
            }
        }
        revisions_complete &= !changed_contributor;
        let current_evaluated = current_ok && entry.current.iter().all(|value| value.complete);
        entry.complete = candidate_ok
            && !changed_contributor
            && entry.candidate.iter().all(|value| value.complete);
        current_complete &= current_evaluated;
        complete &= entry.complete;
        providers.push(entry);
    }
    let mut withdrawal_states: BTreeMap<&str, u8> = BTreeMap::new();
    for record in providers.iter().flat_map(|provider| &provider.current) {
        let state = if record.withdrawn.is_some() { 2 } else { 1 };
        for id in std::iter::once(record.record_id.as_str())
            .chain(record.aliases.iter().map(String::as_str))
        {
            *withdrawal_states.entry(id).or_default() |= state;
        }
    }
    let withdrawal_conflict = withdrawal_states.values().any(|state| *state == 3);
    current_complete &= !withdrawal_conflict && revisions_complete;
    complete &= !withdrawal_conflict;
    providers.sort_by(|a, b| a.provider_id.cmp(&b.provider_id));
    boundaries.sort_by(compare_boundaries);
    fresh_boundaries.sort_by(compare_boundaries);
    let current_affected = status(current_yes, current_complete);
    let affected = status(candidate_yes, complete);
    let publication = registry.filter(|observed| {
        observed.source_id == package.source.id
            && observed.source_auth_scope_id == package.source.auth_scope_id
            && crate::security_assessment::normalize_name(&observed.distribution).ok()
                == crate::security_assessment::normalize_name(&package.name).ok()
            && observed.distribution == observed.catalog.distribution
    });
    if let Some(publication) = publication {
        freshness.merge(publication.freshness);
    }
    let current_authoritative = current_complete && current_freshness.is_authoritative();
    let availability =
        publication
            .and_then(|observed| {
                observed.catalog.releases.iter().find(|value| {
                    value.version.parse::<Version>().ok() == parsed && parsed.is_some()
                })
            })
            .map_or_else(
                || {
                    if parsed.is_some()
                        && publication.is_some_and(|observed| {
                            observed.freshness.is_authoritative()
                                && observed.catalog.coverage.status == CoverageStatus::Complete
                        })
                    {
                        ReleaseAvailability::NoCompatibleWheel
                    } else {
                        ReleaseAvailability::Unknown
                    }
                },
                |value| value.availability,
            );
    let authoritative = complete
        && freshness.is_authoritative()
        && publication.is_some()
        && availability != ReleaseAvailability::Unknown;
    let fix_evidence = if !boundaries.is_empty() && !withdrawal_conflict && revisions_complete {
        FixEvidence::KnownBoundary
    } else if providers
        .iter()
        .flat_map(|provider| &provider.current)
        .flat_map(|record| &record.diagnostics)
        .any(|diagnostic| diagnostic.code == "E_SECURITY_ADVISORY_RANGE_UNSUPPORTED")
    {
        FixEvidence::Unsupported
    } else {
        FixEvidence::Unavailable
    };
    let candidate_kind = if authoritative
        && upgrade
        && current_affected == AffectedStatus::Yes
        && fresh_current_positive
        && affected == AffectedStatus::No
        && availability == ReleaseAvailability::BinaryWheelAvailable
    {
        Some(if !fresh_boundaries.is_empty() {
            CandidateKind::PublishedRemediationCandidate
        } else {
            CandidateKind::NonAffectedUpgradeObserved
        })
    } else {
        None
    };
    let availability = match availability {
        ReleaseAvailability::BinaryWheelAvailable => CandidateAvailability::PublishedCandidate,
        ReleaseAvailability::SourceBuildRequired => CandidateAvailability::SourceBuildRequired,
        ReleaseAvailability::Yanked | ReleaseAvailability::NoCompatibleWheel => {
            CandidateAvailability::NotObserved
        }
        ReleaseAvailability::Unknown => CandidateAvailability::Unknown,
    };
    let published_remediation_basis =
        if candidate_kind == Some(CandidateKind::PublishedRemediationCandidate) {
            fresh_boundaries
        } else {
            vec![]
        };
    let provider_complete = providers.iter().filter(|value| value.complete).count();
    CandidateQualification {
        freshness,
        authoritative,
        current_authoritative,
        version: parsed.map_or_else(|| "[invalid_version]".into(), |value| value.to_string()),
        current_affected,
        affected,
        fix_evidence,
        candidate_kind,
        availability,
        fixed_boundaries: boundaries,
        published_remediation_basis,
        providers,
        coverage: CoverageUnit {
            status: if authoritative {
                CoverageStatus::Complete
            } else {
                CoverageStatus::Partial
            },
            requested: required_providers.len(),
            complete: provider_complete,
            partial: required_providers.len().saturating_sub(provider_complete),
            reasons: if authoritative {
                vec![]
            } else {
                vec!["E_SECURITY_CANDIDATE_INCOMPLETE".into()]
            },
            ..Default::default()
        },
        resolution_status: ResolutionStatus::NotChecked,
        verification_status: VerificationStatus::NotRun,
    }
}
fn compare_boundaries(a: &FixedBoundaryEvidence, b: &FixedBoundaryEvidence) -> std::cmp::Ordering {
    (
        &a.provider_id,
        &a.record_id,
        &a.payload_digest,
        a.affected_index,
        a.range_index,
        a.fixed_event_index,
    )
        .cmp(&(
            &b.provider_id,
            &b.record_id,
            &b.payload_digest,
            b.affected_index,
            b.range_index,
            b.fixed_event_index,
        ))
}

fn same_current_basis(a: &AdvisoryEvaluation, b: &AdvisoryEvaluation) -> bool {
    let boundaries = |value: &AdvisoryEvaluation| {
        value
            .fixed_boundaries
            .iter()
            .filter_map(|boundary| {
                Some((
                    boundary.introduced == "0",
                    boundary.introduced.parse::<Version>().ok()?,
                    boundary.fixed.parse::<Version>().ok()?,
                ))
            })
            .collect::<BTreeSet<_>>()
    };
    a.complete
        && b.complete
        && a.affected == b.affected
        && a.withdrawn.is_some() == b.withdrawn.is_some()
        && boundaries(a) == boundaries(b)
}

fn status(yes: bool, complete: bool) -> AffectedStatus {
    if yes {
        AffectedStatus::Yes
    } else if complete {
        AffectedStatus::No
    } else {
        AffectedStatus::Unknown
    }
}
fn identity_matches(package: &PackageInstance, version: &str, value: &InstanceAdvisories) -> bool {
    package.source.id == value.source_id
        && package.source.auth_scope_id == value.auth_scope_id
        && version
            .parse::<Version>()
            .ok()
            .is_some_and(|version| value.version.parse::<Version>().ok() == Some(version))
        && package.source_mapping.as_ref().is_some_and(|mapping| {
            value.upstream_name.as_ref() == Some(&mapping.upstream_name)
                && value.ecosystem.as_ref() == Some(&mapping.ecosystem)
                && value.mapping_assumption.as_ref() == Some(&mapping.assumption)
        })
}
