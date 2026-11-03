//! Bounded circular candidate work. A continuation is traversal state, never
//! evidence that earlier candidates were excluded or a minimum was proven.

use crate::security_assessment::{ObservationDiagnostic, ObservationLimits, semantic_digest};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pep440_rs::Version;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_CONTINUATION_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentDomain {
    pub inventory_digest: String,
    pub scope_digest: String,
    pub provider_digest: String,
    pub policy_digest: String,
    pub tag_profile_digest: String,
    pub evidence_revision: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryInput {
    pub instance_id: String,
    pub enumeration_digest: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactCandidate {
    pub instance_id: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AssessmentContinuation(String);

impl AssessmentContinuation {
    pub fn parse(encoded: &str) -> Result<Self, ObservationDiagnostic> {
        if encoded.len() > MAX_CONTINUATION_BYTES {
            return Err(cursor_error());
        }
        let value = Self(encoded.into());
        value.decode()?;
        Ok(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Call this before metadata/network work; release-set validation follows
    /// only after authorized current metadata is available.
    pub fn validate_domain(&self, domain: &AssessmentDomain) -> Result<(), ObservationDiagnostic> {
        if self.decode()?.domain_digest != semantic_digest(domain) {
            return Err(cursor_error());
        }
        Ok(())
    }

    pub fn validate_inventory(
        &self,
        domain: &AssessmentDomain,
        instance_ids: &[String],
    ) -> Result<(), ObservationDiagnostic> {
        self.validate_domain(domain)?;
        let state = self.decode()?;
        let ids = ordered_instance_ids(instance_ids).map_err(|_| cursor_error())?;
        if state
            .packages
            .iter()
            .map(|package| package.instance_id.as_str())
            .collect::<Vec<_>>()
            != ids
        {
            return Err(cursor_error());
        }
        Ok(())
    }

    /// Check prior-candidate traversal bounds before fetching discovery metadata.
    /// A changed prior set invalidates its offset rather than proving exclusions.
    pub fn validate_previous(
        &self,
        domain: &AssessmentDomain,
        previous: &[ExactCandidate],
    ) -> Result<(), ObservationDiagnostic> {
        self.validate_domain(domain)?;
        let limits = ObservationLimits::default();
        if previous.len() > limits.max_inventory_instances.saturating_mul(20)
            || !serialized_within(&previous, limits.max_retained_evidence_bytes)
        {
            return Err(input_error());
        }
        let state = self.decode()?;
        let mut values: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for candidate in previous {
            if state
                .packages
                .binary_search_by(|package| package.instance_id.cmp(&candidate.instance_id))
                .is_err()
            {
                return Err(input_error());
            }
            values
                .entry(&candidate.instance_id)
                .or_default()
                .push(candidate.version.clone());
        }
        for package in &state.packages {
            let versions = ordered_versions(
                &values
                    .remove(package.instance_id.as_str())
                    .unwrap_or_default(),
            )?;
            if package.previous_digest == previous_digest(&versions)?
                && !valid_offset(package.revalidation_offset, versions.len())
            {
                return Err(cursor_error());
            }
        }
        Ok(())
    }

    /// Validate traversal context before any metadata effects. With no prior
    /// cursor the canonical initial order is returned; no release evidence is
    /// implied by either this order or a client-selected cursor position.
    pub fn metadata_order(
        domain: &AssessmentDomain,
        instance_ids: &[String],
        continuation: Option<&Self>,
    ) -> Result<Vec<String>, ObservationDiagnostic> {
        let ids = ordered_instance_ids(instance_ids)?;
        let start = if let Some(continuation) = continuation {
            continuation.validate_inventory(domain, instance_ids)?;
            continuation.decode()?.next_package
        } else {
            0
        };
        Ok((0..ids.len())
            .map(|delta| ids[(start + delta) % ids.len()].to_owned())
            .collect())
    }

    /// Advance metadata fairness only after an actual attempted instance. This
    /// changes priority alone: discovery/revalidation offsets and evidence are
    /// not inferred from the attempt or granted authority by the cursor.
    pub fn advance_after_metadata(
        &self,
        domain: &AssessmentDomain,
        instance_ids: &[String],
        last_attempted_id: &str,
    ) -> Result<Self, ObservationDiagnostic> {
        self.validate_inventory(domain, instance_ids)?;
        let mut state = self.decode()?;
        let index = state
            .packages
            .binary_search_by(|package| package.instance_id.as_str().cmp(last_attempted_id))
            .map_err(|_| cursor_error())?;
        state.next_package = (index + 1) % state.packages.len();
        encode_cursor(&state)
    }

    /// Preserve discovery traversal for packages whose current metadata could
    /// not be observed. The retained digest is not current metadata evidence;
    /// callers must still report that observation as incomplete.
    pub fn retain_unobserved_metadata(
        &self,
        previous: &Self,
        domain: &AssessmentDomain,
        instance_ids: &[String],
        unobserved_ids: &[String],
    ) -> Result<Self, ObservationDiagnostic> {
        self.validate_inventory(domain, instance_ids)?;
        previous.validate_inventory(domain, instance_ids)?;
        let unobserved = ordered_instance_ids(unobserved_ids).map_err(|_| cursor_error())?;
        let mut state = self.decode()?;
        let old = previous.decode()?;
        for id in unobserved {
            let index = state
                .packages
                .binary_search_by(|package| package.instance_id.as_str().cmp(id))
                .map_err(|_| cursor_error())?;
            state.packages[index]
                .enumeration_digest
                .clone_from(&old.packages[index].enumeration_digest);
            state.packages[index].discovery_offset = old.packages[index].discovery_offset;
        }
        encode_cursor(&state)
    }

    pub(crate) fn focus_instance(
        &self,
        domain: &AssessmentDomain,
        ids: &[String],
        target: &str,
    ) -> Result<Self, ObservationDiagnostic> {
        self.validate_inventory(domain, ids)?;
        let mut state = self.decode()?;
        state.next_package = state
            .packages
            .binary_search_by(|package| package.instance_id.as_str().cmp(target))
            .map_err(|_| cursor_error())?;
        encode_cursor(&state)
    }

    pub(crate) fn admission_width(&self) -> Result<usize, ObservationDiagnostic> {
        Ok(self.decode()?.admission_width)
    }

    pub(crate) fn with_admission_width(&self, width: usize) -> Result<Self, ObservationDiagnostic> {
        if width == 0 || width > default_admission_width() {
            return Err(cursor_error());
        }
        let mut state = self.decode()?;
        state.admission_width = width;
        encode_cursor(&state)
    }

    pub(crate) fn retain_deferred(
        &self,
        previous: &Self,
        domain: &AssessmentDomain,
        instance_ids: &[String],
        deferred: &[String],
    ) -> Result<Self, ObservationDiagnostic> {
        self.validate_inventory(domain, instance_ids)?;
        previous.validate_inventory(domain, instance_ids)?;
        let deferred = ordered_instance_ids(deferred).map_err(|_| cursor_error())?;
        let mut state = self.decode()?;
        let old = previous.decode()?;
        for id in deferred {
            let index = state
                .packages
                .binary_search_by(|package| package.instance_id.as_str().cmp(id))
                .map_err(|_| cursor_error())?;
            state.packages[index] = old.packages[index].clone();
        }
        encode_cursor(&state)
    }

    fn decode(&self) -> Result<CursorState, ObservationDiagnostic> {
        if self.0.len() > MAX_CONTINUATION_BYTES {
            return Err(cursor_error());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.0)
            .map_err(|_| cursor_error())?;
        let state: CursorState = serde_json::from_slice(&bytes).map_err(|_| cursor_error())?;
        let digest_valid =
            |value: &str| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit());
        if state.schema_version != 1
            || state.admission_width == 0
            || state.admission_width > default_admission_width()
            || state.packages.len() > 1000
            || !digest_valid(&state.domain_digest)
            || (!state.packages.is_empty() && state.next_package >= state.packages.len())
            || (state.packages.is_empty() && state.next_package != 0)
            || state
                .packages
                .windows(2)
                .any(|pair| pair[0].instance_id >= pair[1].instance_id)
            || state.packages.iter().any(|package| {
                !crate::security_assessment::source::opaque_id(&package.instance_id)
                    || !digest_valid(&package.previous_digest)
                    || package.enumeration_digest.len() > 200
                    || package.enumeration_digest.chars().any(char::is_control)
                    || package.discovery_offset > ObservationLimits::default().max_response_bytes
                    || package.revalidation_offset > 20_000
            })
        {
            return Err(cursor_error());
        }
        Ok(state)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateWork {
    pub instance_id: String,
    pub version: String,
    pub discovery: bool,
    pub revalidation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePlan {
    pub work: Vec<CandidateWork>,
    pub continuation: AssessmentContinuation,
    pub invalidated_instances: Vec<String>,
    pub unknown_remainder: bool,
    #[serde(skip)]
    checkpoint: Option<PlanCheckpoint>,
}

#[derive(Debug, Clone)]
struct PlanCheckpoint {
    baseline: CursorState,
    steps: Vec<(CandidateWork, PackageProgress)>,
}

impl CandidatePlan {
    /// At minimum admission an unfit head must not monopolize traversal. This
    /// records a retry rotation only, never successful observation or exclusion.
    pub(crate) fn defer_unfit_head(
        &self,
        domain: &AssessmentDomain,
    ) -> Result<Option<AssessmentContinuation>, ObservationDiagnostic> {
        let checkpoint = self.checkpoint.as_ref().ok_or_else(cursor_error)?;
        if checkpoint.baseline.domain_digest != semantic_digest(domain) {
            return Err(cursor_error());
        }
        let Some((work, progress)) = checkpoint.steps.first() else {
            return Ok(None);
        };
        let mut state = checkpoint.baseline.clone();
        let index = state
            .packages
            .binary_search_by(|package| package.instance_id.cmp(&work.instance_id))
            .map_err(|_| cursor_error())?;
        state.packages[index] = progress.clone();
        state.next_package = (index + 1) % state.packages.len();
        Ok(Some(encode_cursor(&state)?))
    }

    /// Commit only the observed prefix for each package. Public/deserialized
    /// plan fields never supply checkpoint state or evidence authority.
    pub fn commit_observed_candidates(
        &self,
        domain: &AssessmentDomain,
        observed: &[ExactCandidate],
    ) -> Result<AssessmentContinuation, ObservationDiagnostic> {
        let checkpoint = self.checkpoint.as_ref().ok_or_else(cursor_error)?;
        if checkpoint.baseline.domain_digest != semantic_digest(domain)
            || observed.len() > checkpoint.steps.len()
        {
            return Err(cursor_error());
        }
        let mut observed_keys = BTreeSet::new();
        for candidate in observed {
            if candidate.version.len() > 200 {
                return Err(input_error());
            }
            let version = candidate
                .version
                .parse::<Version>()
                .map_err(|_| input_error())?;
            if !checkpoint.steps.iter().any(|(work, _)| {
                work.instance_id == candidate.instance_id
                    && work
                        .version
                        .parse::<Version>()
                        .is_ok_and(|value| value == version)
            }) {
                return Err(input_error());
            }
            observed_keys.insert((candidate.instance_id.as_str(), version));
        }
        let mut state = checkpoint.baseline.clone();
        let mut blocked = BTreeSet::new();
        for (work, progress) in &checkpoint.steps {
            if blocked.contains(work.instance_id.as_str()) {
                continue;
            }
            let version = work.version.parse::<Version>().map_err(|_| input_error())?;
            if !observed_keys.contains(&(work.instance_id.as_str(), version)) {
                blocked.insert(work.instance_id.as_str());
                continue;
            }
            let index = state
                .packages
                .binary_search_by(|package| package.instance_id.cmp(&work.instance_id))
                .map_err(|_| cursor_error())?;
            state.packages[index] = progress.clone();
            state.next_package = (index + 1) % state.packages.len();
        }
        encode_cursor(&state)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorState {
    schema_version: u32,
    domain_digest: String,
    next_package: usize,
    #[serde(default = "default_admission_width")]
    admission_width: usize,
    packages: Vec<PackageProgress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProgress {
    instance_id: String,
    enumeration_digest: String,
    previous_digest: String,
    discovery_offset: usize,
    revalidation_offset: usize,
    prefer_revalidation: bool,
}

struct PackageWork {
    discovery: Vec<String>,
    previous: Vec<String>,
    seen_discovery: BTreeSet<usize>,
    seen_previous: BTreeSet<usize>,
    selected: usize,
}

pub fn plan_candidates(
    domain: &AssessmentDomain,
    inputs: &[DiscoveryInput],
    previous: &[ExactCandidate],
    limits: &ObservationLimits,
    continuation: Option<&AssessmentContinuation>,
) -> Result<CandidatePlan, ObservationDiagnostic> {
    plan_candidates_inner(domain, inputs, previous, limits, continuation, None)
}

pub(crate) fn plan_candidates_admitted(
    domain: &AssessmentDomain,
    inputs: &[DiscoveryInput],
    previous: &[ExactCandidate],
    limits: &ObservationLimits,
    continuation: Option<&AssessmentContinuation>,
    admitted: &[String],
) -> Result<CandidatePlan, ObservationDiagnostic> {
    plan_candidates_inner(
        domain,
        inputs,
        previous,
        limits,
        continuation,
        Some(admitted),
    )
}

fn plan_candidates_inner(
    domain: &AssessmentDomain,
    inputs: &[DiscoveryInput],
    previous: &[ExactCandidate],
    limits: &ObservationLimits,
    continuation: Option<&AssessmentContinuation>,
    admission: Option<&[String]>,
) -> Result<CandidatePlan, ObservationDiagnostic> {
    limits.validate()?;
    if inputs.len() > limits.max_inventory_instances
        || previous.len() > limits.max_inventory_instances.saturating_mul(20)
        || !serialized_within(&(inputs, previous), limits.max_retained_evidence_bytes)
    {
        return Err(input_error());
    }
    let mut sorted: Vec<_> = inputs.iter().collect();
    sorted.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
    if sorted.iter().any(|input| {
        !crate::security_assessment::source::opaque_id(&input.instance_id)
            || input.enumeration_digest.len() > 200
            || input.enumeration_digest.chars().any(char::is_control)
            || !serialized_within(&input.versions, limits.max_response_bytes)
    }) || sorted
        .windows(2)
        .any(|pair| pair[0].instance_id == pair[1].instance_id)
    {
        return Err(input_error());
    }
    let ids: BTreeSet<_> = sorted
        .iter()
        .map(|input| input.instance_id.as_str())
        .collect();
    let admitted = admission
        .map(ordered_instance_ids)
        .transpose()?
        .map(|ids| ids.into_iter().collect::<BTreeSet<_>>());
    if admitted
        .as_ref()
        .is_some_and(|set| set.iter().any(|id| !ids.contains(id)))
    {
        return Err(input_error());
    }
    let mut prior: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for item in previous {
        if !ids.contains(item.instance_id.as_str()) {
            return Err(input_error());
        }
        prior
            .entry(&item.instance_id)
            .or_default()
            .push(item.version.clone());
    }
    let digest = semantic_digest(domain);
    let old = continuation
        .map(AssessmentContinuation::decode)
        .transpose()?;
    if let Some(old) = &old
        && (old.domain_digest != digest
            || old.packages.len() != sorted.len()
            || old
                .packages
                .iter()
                .zip(&sorted)
                .any(|(state, input)| state.instance_id != input.instance_id)
            || (!sorted.is_empty() && old.next_package >= sorted.len())
            || (sorted.is_empty() && old.next_package != 0))
    {
        return Err(cursor_error());
    }
    let mut state = CursorState {
        schema_version: 1,
        domain_digest: digest,
        next_package: old.as_ref().map_or(0, |state| state.next_package),
        admission_width: old
            .as_ref()
            .map_or_else(default_admission_width, |state| state.admission_width),
        packages: vec![],
    };
    let mut packages = Vec::new();
    let mut invalidated = BTreeSet::new();
    for (index, input) in sorted.iter().enumerate() {
        let discovery = ordered_versions(&input.versions)?;
        let mut previous =
            ordered_versions(&prior.remove(input.instance_id.as_str()).unwrap_or_default())?;
        let mut spellings = BTreeMap::new();
        for value in &discovery {
            spellings.insert(
                value.parse::<Version>().map_err(|_| input_error())?,
                value.clone(),
            );
        }
        for value in &mut previous {
            let identity = value.parse::<Version>().map_err(|_| input_error())?;
            if let Some(spelling) = spellings.get(&identity) {
                *value = spelling.clone();
            }
        }
        let previous_digest = previous_digest(&previous)?;
        let mut progress = PackageProgress {
            instance_id: input.instance_id.clone(),
            enumeration_digest: input.enumeration_digest.clone(),
            previous_digest: previous_digest.clone(),
            discovery_offset: 0,
            revalidation_offset: 0,
            prefer_revalidation: true,
        };
        if let Some(old) = old.as_ref().map(|state| &state.packages[index]) {
            progress.prefer_revalidation = old.prefer_revalidation;
            if old.enumeration_digest == input.enumeration_digest {
                if !valid_offset(old.discovery_offset, discovery.len()) {
                    return Err(cursor_error());
                }
                progress.discovery_offset = old.discovery_offset;
            } else {
                invalidated.insert(input.instance_id.clone());
            }
            if old.previous_digest == previous_digest {
                if !valid_offset(old.revalidation_offset, previous.len()) {
                    return Err(cursor_error());
                }
                progress.revalidation_offset = old.revalidation_offset;
            } else {
                invalidated.insert(input.instance_id.clone());
            }
        }
        state.packages.push(progress);
        packages.push(PackageWork {
            discovery,
            previous,
            seen_discovery: BTreeSet::new(),
            seen_previous: BTreeSet::new(),
            selected: 0,
        });
    }
    let baseline = state.clone();
    let mut steps = Vec::new();
    let mut work: Vec<CandidateWork> = Vec::new();
    let mut selected: BTreeMap<(usize, String), usize> = BTreeMap::new();
    let count = packages.len();
    let start = state.next_package;
    loop {
        let mut progressed = false;
        for delta in 0..count {
            if work.len() >= limits.max_candidate_checks {
                break;
            }
            let index = (start + delta) % count;
            if admitted
                .as_ref()
                .is_some_and(|set| !set.contains(state.packages[index].instance_id.as_str()))
            {
                continue;
            }
            let package = &mut packages[index];
            if package.selected >= limits.max_candidates_per_package {
                continue;
            }
            let progress = &mut state.packages[index];
            let choice = if progress.prefer_revalidation {
                take_next(
                    &package.previous,
                    &mut package.seen_previous,
                    &mut progress.revalidation_offset,
                )
                .map(|version| (version, true))
                .or_else(|| {
                    take_next(
                        &package.discovery,
                        &mut package.seen_discovery,
                        &mut progress.discovery_offset,
                    )
                    .map(|version| (version, false))
                })
            } else {
                take_next(
                    &package.discovery,
                    &mut package.seen_discovery,
                    &mut progress.discovery_offset,
                )
                .map(|version| (version, false))
                .or_else(|| {
                    take_next(
                        &package.previous,
                        &mut package.seen_previous,
                        &mut progress.revalidation_offset,
                    )
                    .map(|version| (version, true))
                })
            };
            let Some((version, revalidation)) = choice else {
                continue;
            };
            progressed = true;
            progress.prefer_revalidation = !revalidation;
            let discovery = mark_matching(
                &package.discovery,
                &mut package.seen_discovery,
                &mut progress.discovery_offset,
                &version,
            );
            let revalidation = mark_matching(
                &package.previous,
                &mut package.seen_previous,
                &mut progress.revalidation_offset,
                &version,
            );
            state.next_package = (index + 1) % count;
            if let Some(existing) = selected.get(&(index, version.clone())) {
                work[*existing].revalidation |= revalidation;
                work[*existing].discovery |= discovery;
            } else {
                selected.insert((index, version.clone()), work.len());
                package.selected += 1;
                let selected_work = CandidateWork {
                    instance_id: progress.instance_id.clone(),
                    version,
                    discovery,
                    revalidation,
                };
                steps.push((selected_work.clone(), progress.clone()));
                work.push(selected_work);
            }
        }
        if !progressed || work.len() >= limits.max_candidate_checks {
            break;
        }
    }
    let unknown_remainder = admitted
        .as_ref()
        .is_some_and(|set| set.len() < packages.len())
        || packages.iter().any(|package| {
            package.seen_discovery.len() < package.discovery.len()
                || package.seen_previous.len() < package.previous.len()
        });
    let continuation = encode_cursor(&state)?;
    Ok(CandidatePlan {
        work,
        continuation,
        invalidated_instances: invalidated.into_iter().collect(),
        unknown_remainder,
        checkpoint: Some(PlanCheckpoint { baseline, steps }),
    })
}

fn default_admission_width() -> usize {
    ObservationLimits::default().max_candidate_checks
}

fn ordered_instance_ids(ids: &[String]) -> Result<Vec<&str>, ObservationDiagnostic> {
    if ids.len() > ObservationLimits::default().max_inventory_instances
        || ids
            .iter()
            .any(|id| !crate::security_assessment::source::opaque_id(id))
    {
        return Err(input_error());
    }
    let mut sorted: Vec<_> = ids.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(input_error());
    }
    Ok(sorted)
}
fn encode_cursor(state: &CursorState) -> Result<AssessmentContinuation, ObservationDiagnostic> {
    let bytes = serde_json::to_vec(state).map_err(|_| cursor_error())?;
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    if encoded.len() > MAX_CONTINUATION_BYTES {
        return Err(cursor_error());
    }
    Ok(AssessmentContinuation(encoded))
}

fn valid_offset(offset: usize, len: usize) -> bool {
    if len == 0 { offset == 0 } else { offset < len }
}

fn previous_digest(values: &[String]) -> Result<String, ObservationDiagnostic> {
    let mut canonical = Vec::with_capacity(values.len());
    for value in values {
        let version = value.parse::<Version>().map_err(|_| input_error())?;
        let release = version.release();
        let end = release
            .iter()
            .rposition(|part| *part != 0)
            .map_or(1, |index| index + 1);
        let parts = release[..end].to_vec();
        canonical.push(version.with_release(parts).to_string());
    }
    Ok(semantic_digest(&canonical))
}

fn ordered_versions(values: &[String]) -> Result<Vec<String>, ObservationDiagnostic> {
    let mut versions: BTreeMap<Version, String> = BTreeMap::new();
    for value in values {
        if value.len() > 200 {
            return Err(input_error());
        }
        let version = value.parse::<Version>().map_err(|_| input_error())?;
        let spelling = version.to_string();
        let existing = versions.entry(version).or_insert_with(|| spelling.clone());
        if spelling < *existing {
            *existing = spelling;
        }
    }
    Ok(versions.into_values().collect())
}

fn take_next(values: &[String], seen: &mut BTreeSet<usize>, offset: &mut usize) -> Option<String> {
    if seen.len() == values.len() {
        return None;
    }
    for _ in 0..values.len() {
        let index = *offset;
        *offset = (*offset + 1) % values.len();
        if seen.insert(index) {
            return Some(values[index].clone());
        }
    }
    None
}

fn mark_matching(
    values: &[String],
    seen: &mut BTreeSet<usize>,
    offset: &mut usize,
    version: &str,
) -> bool {
    let Some(index) = values.iter().position(|value| value == version) else {
        return false;
    };
    seen.insert(index);
    for _ in 0..values.len() {
        if !seen.contains(offset) {
            break;
        }
        *offset = (*offset + 1) % values.len();
    }
    true
}

// Count serialized bytes without allocating another copy of untrusted inputs.
fn serialized_within<T: Serialize>(value: &T, limit: usize) -> bool {
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.0 {
                return Err(std::io::ErrorKind::FileTooLarge.into());
            }
            self.0 -= bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Budget(limit), value).is_ok()
}

fn cursor_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_CONTINUATION",
        "Assessment continuation is malformed, unsupported, out of bounds, or belongs to another assessment domain.",
    )
}
fn input_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_CANDIDATE_INPUT",
        "Candidate work inputs are invalid, exceed service limits, or reference an instance outside the current inventory.",
    )
}
