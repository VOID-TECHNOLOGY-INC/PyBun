use super::{model::*, projection::Projected, state::*};
use crate::security_assessment::qualification::evidence::AffectedStatus;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::BTreeSet;

pub(crate) fn begin(
    registration: &Registration,
    previous: Option<&Snapshot>,
    check_id: &str,
    now: u64,
) -> MonitorResult<Snapshot> {
    let mut snapshot =
        if let Some(previous) = previous.filter(|value| value.epoch_id == registration.epoch_id) {
            previous.clone()
        } else {
            Snapshot {
                comparison_domain: registration.config.domain.clone(),
                monitor_id: registration.monitor_id.clone(),
                epoch_id: registration.epoch_id.clone(),
                config_revision: registration.config_revision,
                generation: previous.map_or(0, |value| value.generation),
                sequence: previous.map_or(0, |value| value.sequence),
                epoch_first_sequence: previous.map_or(1, |value| value.sequence.saturating_add(1)),
                reset_recorded: false,
                initialized: false,
                observed_at: now,
                complete: false,
                lineages: vec![],
                lineage_counter: 0,
                events: previous.map_or_else(Vec::new, |value| value.events.clone()),
                failure_episodes: BTreeSet::new(),
                diagnostics: vec![],
                continuation: None,
                last_check: CheckCommit {
                    check_id: check_id.into(),
                    first_sequence: 1,
                    event_count: 0,
                },
            }
        };
    snapshot.generation = snapshot
        .generation
        .checked_add(1)
        .ok_or_else(|| MonitorError::new("E_MONITOR_LIMIT"))?;
    snapshot.last_check = CheckCommit {
        check_id: check_id.into(),
        first_sequence: snapshot
            .sequence
            .checked_add(1)
            .ok_or_else(|| MonitorError::new("E_MONITOR_LIMIT"))?,
        event_count: 0,
    };
    snapshot.observed_at = now;
    if !snapshot.reset_recorded
        && (previous.is_some_and(|old| old.epoch_id != registration.epoch_id)
            || registration.reset_reason.is_some())
    {
        event(
            &mut snapshot,
            MonitorEventType::ObservationReset,
            None,
            registration.reset_reason.clone(),
            None,
            vec![],
        )?;
        snapshot.reset_recorded = true;
    }
    Ok(snapshot)
}
pub(crate) fn apply(snapshot: &mut Snapshot, projection: &Projected<'_>) -> MonitorResult<()> {
    let baseline = !snapshot.initialized && projection.baseline_possible;
    let previously_initialized = snapshot.initialized;
    let mut seen = BTreeSet::new();
    for package in projection.packages.values() {
        let alignments = super::lineage::align(snapshot, &package.findings)?;
        for (observed, alignment) in package.findings.iter().zip(alignments) {
            let aliases: BTreeSet<_> = observed.value.aliases.iter().cloned().collect();
            let found = alignment.index;
            if let Some(index) = found {
                let repeated = !seen.insert(index);
                let old = snapshot.lineages[index].finding.clone();
                if repeated
                    && !observed.identity_authoritative
                    && old.observed_affected == AffectedStatus::Yes
                    && old.evidence.iter().any(|item| {
                        item.currently_fresh
                            && item.was_authoritative
                            && item.affected == AffectedStatus::Yes
                    })
                {
                    let value = &mut snapshot.lineages[index].finding;
                    value.complete = false;
                    value.severity = Default::default();
                    for evidence in &observed.value.evidence {
                        if !value.evidence.contains(evidence) {
                            value.evidence.push(evidence.clone());
                        }
                    }
                    continue;
                }
                let mut value = observed.value.clone();
                value.finding_id = old.finding_id.clone();
                value.related_lineages = old.related_lineages.clone();
                value.evidence = merge_evidence(
                    &old.evidence,
                    &value.evidence,
                    package,
                    projection.inventory_complete,
                );
                value.last_known_severity = value.last_known_severity.or(old.last_known_severity);
                if let (Some(previous), Some(current)) = (&old.candidate, &mut value.candidate)
                    && previous.source_id == current.source_id
                    && previous.auth_scope_id == current.auth_scope_id
                    && previous.version == current.version
                {
                    for artifact in &mut current.artifacts {
                        if let Some(prior) = previous
                            .artifacts
                            .iter()
                            .find(|prior| artifact_agrees(prior, artifact) == Some(true))
                        {
                            *artifact = prior.clone();
                        }
                    }
                }
                let mut changes = vec![];
                if let Some(reason) = alignment.correction {
                    value.active = old.active || observed.positive;
                    value.observed_affected = AffectedStatus::Unknown;
                    value.complete = false;
                    value.vulnerable_versions = old.vulnerable_versions.clone();
                    value.candidate = old.candidate.clone();
                    value.last_known_severity = old.last_known_severity;
                    changes.push((
                        MonitorEventType::FindingEvidenceChanged,
                        Some(reason.into()),
                        None,
                    ));
                } else if observed.conflict {
                    value.active = old.active;
                    value.observed_affected = AffectedStatus::Unknown;
                    value.complete = false;
                    value.vulnerable_versions = old.vulnerable_versions.clone();
                    value.candidate = old.candidate.clone();
                    value.last_known_severity = old.last_known_severity;
                    if old.semantic_digest != value.semantic_digest
                        || old.observed_affected != AffectedStatus::Unknown
                    {
                        changes.push((
                            MonitorEventType::FindingEvidenceChanged,
                            Some("contradictory_evidence".into()),
                            None,
                        ));
                    }
                } else if old.active
                    && observed.withdrawn
                    && package.advisory_complete
                    && withdrawal_proven(
                        &old,
                        &observed.value,
                        package,
                        projection.inventory_complete,
                    )
                {
                    value.active = false;
                    value.observed_affected = AffectedStatus::No;
                    value.candidate = old.candidate.clone();
                    if let Some(candidate) = &mut value.candidate {
                        candidate.qualified_remediation = false;
                    }
                    changes.push((
                        MonitorEventType::AdvisoryWithdrawn,
                        Some("explicit_withdrawn".into()),
                        None,
                    ));
                } else if old.active
                    && observed.negative
                    && projection.inventory_complete
                    && package.advisory_complete
                    && old
                        .vulnerable_versions
                        .iter()
                        .all(|version| !package.versions.contains(version))
                {
                    value.active = false;
                    value.observed_affected = AffectedStatus::No;
                    value.candidate = old.candidate.clone();
                    if let Some(candidate) = &mut value.candidate {
                        candidate.qualified_remediation = false;
                    }
                    changes.push((
                        MonitorEventType::FindingResolved,
                        Some("version_upgraded".into()),
                        None,
                    ));
                } else if observed.positive {
                    value.active = true;
                    if !projection.inventory_complete {
                        value
                            .vulnerable_versions
                            .extend(old.vulnerable_versions.iter().cloned());
                        value.vulnerable_versions.sort();
                        value.vulnerable_versions.dedup();
                    }
                    if !old.active && previously_initialized && !baseline {
                        changes.push((MonitorEventType::NewAdvisory, None, None));
                    }
                    if let (Some(old), Some(current)) = (
                        old.last_known_severity.and_then(|level| level.rank()),
                        value.severity.rank(),
                    ) && current > old
                    {
                        changes.push((MonitorEventType::SeverityIncreased, None, None));
                    }
                    match (&old.candidate, &value.candidate) {
                        (None, Some(candidate)) if previously_initialized && !baseline => changes
                            .push((
                                MonitorEventType::FixCandidateAvailable,
                                None,
                                Some(candidate.version.clone()),
                            )),
                        (Some(previous), Some(candidate)) if !previous.qualified_remediation => {
                            changes.push((
                                MonitorEventType::FixCandidateAvailable,
                                Some("candidate_reappeared".into()),
                                Some(candidate.version.clone()),
                            ))
                        }
                        (Some(previous), Some(candidate))
                            if candidate_meaning(previous) != candidate_meaning(candidate) =>
                        {
                            changes.push((
                                MonitorEventType::CandidateChanged,
                                None,
                                Some(candidate.version.clone()),
                            ))
                        }
                        (Some(previous), None) => value.candidate = Some(previous.clone()),
                        _ => {}
                    }
                    if old.active
                        && observed.identity_authoritative
                        && old.semantic_digest != value.semantic_digest
                        && changes.is_empty()
                    {
                        changes.push((MonitorEventType::FindingEvidenceChanged, None, None));
                    }
                } else {
                    value.active = old.active;
                    value.vulnerable_versions = old.vulnerable_versions.clone();
                    value.candidate = old.candidate.clone();
                    value.last_known_severity = old.last_known_severity;
                    if old.active {
                        value.observed_affected = AffectedStatus::Unknown;
                        value.complete = false;
                    }
                    if observed.negative
                        && old.active
                        && old.semantic_digest != value.semantic_digest
                    {
                        changes.push((
                            MonitorEventType::FindingEvidenceChanged,
                            Some("same_version_evidence_correction".into()),
                            None,
                        ));
                    }
                }
                if observed.identity_authoritative {
                    snapshot.lineages[index]
                        .known_aliases
                        .extend(aliases.clone());
                    snapshot.lineages[index].current_aliases = aliases;
                } else {
                    value.aliases = old.aliases.clone();
                    if !observed.conflict {
                        value.semantic_digest = old.semantic_digest.clone();
                    }
                }
                snapshot.lineages[index].finding = value.clone();
                if projection.online && !baseline {
                    for (kind, reason, candidate) in changes {
                        event(snapshot, kind, Some(&value), reason, candidate, vec![])?;
                    }
                }
            } else if observed.value.observed_affected != AffectedStatus::No {
                let mut value = observed.value.clone();
                value.finding_id = random_id();
                snapshot.lineage_counter = snapshot
                    .lineage_counter
                    .checked_add(1)
                    .ok_or_else(|| MonitorError::new("E_MONITOR_LIMIT"))?;
                let index = snapshot.lineages.len();
                seen.insert(index);
                snapshot.lineages.push(LineageState {
                    ordinal: snapshot.lineage_counter,
                    anchor: value.aliases[0].clone(),
                    known_aliases: aliases.clone(),
                    current_aliases: aliases,
                    parents: vec![],
                    merged_into: None,
                    finding: value.clone(),
                });
                if previously_initialized && !baseline && observed.positive {
                    event(
                        snapshot,
                        MonitorEventType::NewAdvisory,
                        Some(&value),
                        None,
                        None,
                        vec![],
                    )?;
                    if let Some(candidate) = &value.candidate {
                        event(
                            snapshot,
                            MonitorEventType::FixCandidateAvailable,
                            Some(&value),
                            None,
                            Some(candidate.version.clone()),
                            vec![],
                        )?;
                    }
                }
            }
        }
    }
    for index in 0..snapshot.lineages.len() {
        if seen.contains(&index) || snapshot.lineages[index].merged_into.is_some() {
            continue;
        }
        let old = snapshot.lineages[index].finding.clone();
        let package = projection.packages.get(&old.package_key);
        let mut value = old.clone();
        let mut change = None;
        if projection.inventory_complete && package.is_none() {
            value.active = false;
            value.observed_affected = AffectedStatus::No;
            value.complete = true;
            if old.active {
                change = Some((MonitorEventType::FindingResolved, "package_removed"));
            }
            if let Some(candidate) = &mut value.candidate {
                candidate.qualified_remediation = false;
            }
        } else if let Some(package) = package {
            value.complete = false;
            value.observed_affected = AffectedStatus::Unknown;
            if old.active
                && projection.inventory_complete
                && package.advisory_complete
                && package.unaffected
            {
                if old
                    .vulnerable_versions
                    .iter()
                    .all(|version| !package.versions.contains(version))
                {
                    value.active = false;
                    value.observed_affected = AffectedStatus::No;
                    value.complete = true;
                    change = Some((MonitorEventType::FindingResolved, "version_upgraded"));
                    if let Some(candidate) = &mut value.candidate {
                        candidate.qualified_remediation = false;
                    }
                } else {
                    let meaning = crate::security_assessment::semantic_digest(&(
                        "same_version_absence",
                        &old.aliases,
                    ));
                    if value.semantic_digest != meaning {
                        value.semantic_digest = meaning;
                        change = Some((
                            MonitorEventType::FindingEvidenceChanged,
                            "same_version_evidence_correction",
                        ));
                    }
                }
            }
        }
        for evidence in &mut value.evidence {
            evidence.currently_fresh = false;
        }
        snapshot.lineages[index].finding = value.clone();
        if projection.online
            && !baseline
            && let Some((kind, reason)) = change
        {
            event(
                snapshot,
                kind,
                Some(&value),
                Some(reason.into()),
                None,
                vec![],
            )?;
        }
    }
    if projection.online {
        for index in 0..snapshot.lineages.len() {
            let node = &snapshot.lineages[index];
            if node.merged_into.is_some() || !node.finding.active {
                continue;
            }
            let Some(candidate) = node
                .finding
                .candidate
                .as_ref()
                .filter(|candidate| candidate.qualified_remediation)
            else {
                continue;
            };
            if !projection
                .packages
                .get(&node.finding.package_key)
                .is_some_and(|package| package.disqualified_candidates.contains(&candidate.version))
            {
                continue;
            }
            let mut value = node.finding.clone();
            let candidate = value.candidate.as_mut().expect("candidate checked above");
            candidate.qualified_remediation = false;
            let version = candidate.version.clone();
            snapshot.lineages[index].finding = value.clone();
            if !baseline {
                event(
                    snapshot,
                    MonitorEventType::CandidateChanged,
                    Some(&value),
                    Some("advisory_remediation_corrected".into()),
                    Some(version),
                    vec![],
                )?;
            }
        }
    }
    // Publication disappearance is a separate axis from advisory completeness.
    // Only exact prior artifacts and fresh same-source registry facts can negate it.
    if projection.online {
        for index in 0..snapshot.lineages.len() {
            let node = &snapshot.lineages[index];
            if node.merged_into.is_some() || !node.finding.active {
                continue;
            }
            let Some(candidate) = node
                .finding
                .candidate
                .as_ref()
                .filter(|candidate| candidate.publication_available)
            else {
                continue;
            };
            let Some(package) = projection
                .packages
                .get(&node.finding.package_key)
                .filter(|package| package.presence_fresh)
            else {
                continue;
            };
            if !unavailable(candidate, package) {
                continue;
            }
            let mut value = node.finding.clone();
            let candidate = value.candidate.as_mut().expect("candidate checked above");
            candidate.publication_available = false;
            candidate.qualified_remediation = false;
            let version = candidate.version.clone();
            snapshot.lineages[index].finding = value.clone();
            if !baseline {
                event(
                    snapshot,
                    MonitorEventType::CandidateUnavailable,
                    Some(&value),
                    Some("exact_artifact_unavailable".into()),
                    Some(version),
                    vec![],
                )?;
            }
        }
    }
    if baseline {
        snapshot.initialized = true;
        event(
            snapshot,
            MonitorEventType::BaselineObserved,
            None,
            None,
            None,
            vec![],
        )?;
    }
    let mut failures = projection.failures.clone();
    for lineage in snapshot
        .lineages
        .iter()
        .filter(|node| node.merged_into.is_none() && node.finding.active && !node.finding.complete)
    {
        failures.insert(crate::security_assessment::semantic_digest(&(
            "E_MONITOR_HISTORY_UNCONFIRMED",
            &lineage.finding.package_key,
        )));
    }
    for episode in failures
        .difference(&snapshot.failure_episodes)
        .cloned()
        .collect::<Vec<_>>()
    {
        event(
            snapshot,
            MonitorEventType::CheckIncomplete,
            None,
            Some(episode),
            None,
            vec![],
        )?;
    }
    snapshot.complete = projection.complete && failures.is_empty();
    snapshot.failure_episodes = failures;
    snapshot.diagnostics = projection.diagnostics.clone();
    if let Some(continuation) = &projection.continuation {
        snapshot.continuation = Some(continuation.clone());
    }
    Ok(())
}
/// Reported digest metadata may grow or shrink without changing the bytes.
/// No common strong digest is insufficient to negate an existing artifact.
fn artifact_agrees(prior: &ArtifactIdentity, current: &ArtifactIdentity) -> Option<bool> {
    if prior.filename != current.filename {
        return Some(false);
    }
    if prior.target_tag_digest != current.target_tag_digest {
        return None;
    }
    let mut equal = false;
    let mut different = false;
    for algorithm in ["sha256", "sha384", "sha512"] {
        if let Some((a, b)) = prior
            .hashes
            .get(algorithm)
            .zip(current.hashes.get(algorithm))
        {
            if a.eq_ignore_ascii_case(b) {
                equal = true;
            } else {
                different = true;
            }
        }
    }
    match (equal, different) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        (true, true) => None,
        (false, false) if prior.hashes.is_empty() && current.hashes.is_empty() => prior
            .url_identity
            .as_ref()
            .zip(current.url_identity.as_ref())
            .map(|(a, b)| a == b),
        _ => None,
    }
}
fn unavailable(
    candidate: &MonitorCandidate,
    package: &super::projection::PackageFacts<'_>,
) -> bool {
    use crate::security_assessment::CoverageStatus;
    if candidate.source_id != package.source.id
        || candidate.auth_scope_id != package.source.auth_scope_id
        || candidate.artifacts.is_empty()
    {
        return false;
    }
    candidate.artifacts.iter().all(|prior| {
        let mut negative = false;
        for (registry, fresh) in &package.registries {
            if !fresh {
                continue;
            }
            let complete = registry.catalog.coverage.status == CoverageStatus::Complete
                && !registry.catalog.enumeration_digest.is_empty();
            let release = registry.catalog.releases.iter().find(|release| {
                super::projection::canonical_version(&release.version)
                    .ok()
                    .as_ref()
                    == Some(&candidate.version)
            });
            let matches: Vec<_> = release
                .into_iter()
                .flat_map(|release| &release.files)
                .filter(|file| file.filename == prior.filename)
                .collect();
            if matches.is_empty() {
                negative |= complete;
                continue;
            }
            for file in matches {
                let current = super::projection::artifact(
                    file,
                    &package.source,
                    &candidate.version,
                    &prior.target_tag_digest,
                );
                match artifact_agrees(prior, &current) {
                    None => return false,
                    Some(false) => {
                        negative |= complete;
                        continue;
                    }
                    Some(true) => {}
                }
                if file.coverage.status != CoverageStatus::Complete {
                    continue;
                }
                let unfit = file.yanked == Some(true)
                    || file.requires_python_satisfied == Some(false)
                    || (!file.source_distribution && file.matched_tags.is_empty());
                if !unfit {
                    return false;
                }
                negative = true;
            }
        }
        negative
    })
}
fn candidate_meaning(candidate: &MonitorCandidate) -> String {
    crate::security_assessment::semantic_digest(&(
        &candidate.source_id,
        &candidate.auth_scope_id,
        &candidate.version,
        &candidate.artifacts,
        candidate.qualified_remediation,
        candidate.publication_available,
        candidate.constraint_status,
    ))
}
fn merge_evidence(
    old: &[MonitorEvidence],
    new: &[MonitorEvidence],
    package: &super::projection::PackageFacts<'_>,
    inventory_complete: bool,
) -> Vec<MonitorEvidence> {
    let mut result = old.to_vec();
    for item in &mut result {
        item.currently_fresh = false;
    }
    for incoming in new {
        result.retain(|item| {
            if item.provider_id != incoming.provider_id || item.record_id != incoming.record_id {
                return true;
            }
            if inventory_complete
                && !package.versions.contains(&item.evaluated_version)
                && incoming.was_authoritative
            {
                return false;
            }
            if item.evaluated_version != incoming.evaluated_version {
                return true;
            }
            if incoming.was_authoritative
                && (incoming.affected == AffectedStatus::Yes || incoming.withdrawn)
            {
                return false;
            }
            if !item.was_authoritative {
                return false;
            }
            incoming.was_authoritative && item.affected == AffectedStatus::Yes && !item.withdrawn
                || !incoming.was_authoritative
        });
        result.push(incoming.clone());
    }
    result.sort_by_key(|item| {
        (
            item.provider_id.clone(),
            item.record_id.clone(),
            item.evaluated_version.clone(),
            item.payload_digest.clone(),
        )
    });
    result.dedup();
    result
}
fn withdrawal_proven(
    old: &MonitorFinding,
    current: &MonitorFinding,
    package: &super::projection::PackageFacts<'_>,
    inventory_complete: bool,
) -> bool {
    old.evidence
        .iter()
        .filter(|item| {
            item.was_authoritative && item.affected == AffectedStatus::Yes && !item.withdrawn
        })
        .all(|previous| {
            current.evidence.iter().any(|item| {
                item.provider_id == previous.provider_id
                    && item.record_id == previous.record_id
                    && item.currently_fresh
                    && item.complete
                    && item.withdrawn
            }) || inventory_complete
                && !package.versions.contains(&previous.evaluated_version)
                && package.unaffected
        })
}
pub(crate) fn event(
    snapshot: &mut Snapshot,
    event_type: MonitorEventType,
    finding: Option<&MonitorFinding>,
    reason: Option<String>,
    candidate_version: Option<String>,
    related_lineages: Vec<String>,
) -> MonitorResult<()> {
    snapshot.sequence = snapshot
        .sequence
        .checked_add(1)
        .ok_or_else(|| MonitorError::new("E_MONITOR_LIMIT"))?;
    let encoded = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&(&snapshot.monitor_id, &snapshot.epoch_id, snapshot.sequence))
            .map_err(|_| MonitorError::new("E_MONITOR_STATE_SERIALIZE"))?,
    );
    snapshot.events.push(MonitorEvent {
        event_id: format!("event-v1.{encoded}"),
        monitor_id: snapshot.monitor_id.clone(),
        epoch_id: snapshot.epoch_id.clone(),
        sequence: snapshot.sequence,
        event_type,
        observed_at: snapshot.observed_at,
        finding_id: finding.map(|finding| finding.finding_id.clone()),
        package_key: finding.map(|finding| finding.package_key.clone()),
        reason,
        candidate_version,
        related_lineages,
    });
    snapshot.last_check.event_count += 1;
    Ok(())
}
pub(crate) fn retain(snapshot: &mut Snapshot, limits: &MonitorLimits, now: u64) {
    snapshot
        .events
        .retain(|event| now.saturating_sub(event.observed_at) <= limits.history_seconds);
    if snapshot.events.len() > limits.retained_events {
        snapshot
            .events
            .drain(..snapshot.events.len() - limits.retained_events);
    }
}
