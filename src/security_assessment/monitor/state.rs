use super::model::*;
use crate::security_assessment::{
    SourceIdentity,
    http::EvidenceFreshness,
    qualification::{
        constraints::ConstraintStatus, evidence::AffectedStatus, findings::FindingSeverity,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationMode {
    Online,
    Offline,
}
#[derive(Debug, Clone)]
pub struct CheckContext {
    pub domain: ComparisonDomain,
    pub mode: ObservationMode,
    pub inventory_freshness: EvidenceFreshness,
    pub now: u64,
    pub deadline: Instant,
}
impl CheckContext {
    pub fn online(domain: ComparisonDomain, now: u64) -> Self {
        Self {
            domain,
            mode: ObservationMode::Online,
            inventory_freshness: Default::default(),
            now,
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }
    pub fn offline(domain: ComparisonDomain, now: u64) -> Self {
        Self {
            mode: ObservationMode::Offline,
            ..Self::online(domain, now)
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct EventReplayCursor(pub(crate) String);
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CursorData {
    pub cursor_version: u32,
    pub monitor_id: String,
    pub epoch_id: String,
    pub sequence: u64,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MonitorEventType {
    BaselineObserved,
    NewAdvisory,
    FixCandidateAvailable,
    CandidateChanged,
    SeverityIncreased,
    CandidateUnavailable,
    FindingResolved,
    AdvisoryWithdrawn,
    CheckIncomplete,
    ObservationReset,
    FindingEvidenceChanged,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MonitorEvent {
    pub event_id: String,
    pub monitor_id: String,
    pub epoch_id: String,
    pub sequence: u64,
    pub event_type: MonitorEventType,
    pub observed_at: u64,
    pub finding_id: Option<String>,
    pub package_key: Option<String>,
    pub reason: Option<String>,
    pub candidate_version: Option<String>,
    pub related_lineages: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MonitorDiagnostic {
    pub code: String,
    pub scope: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub artifact_id: String,
    pub filename: String,
    pub hashes: BTreeMap<String, String>,
    pub url_identity: Option<String>,
    pub target_tag_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MonitorCandidate {
    pub source_id: String,
    pub auth_scope_id: String,
    pub version: String,
    pub artifacts: Vec<ArtifactIdentity>,
    pub qualified_remediation: bool,
    pub publication_available: bool,
    pub constraint_status: ConstraintStatus,
    pub last_confirmed_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MonitorEvidence {
    pub provider_id: String,
    pub record_id: String,
    pub payload_digest: String,
    pub fetched_at: u64,
    pub evaluated_version: String,
    pub affected: AffectedStatus,
    pub complete: bool,
    pub withdrawn: bool,
    pub currently_fresh: bool,
    pub was_authoritative: bool,
    pub severity: FindingSeverity,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MonitorFinding {
    pub finding_id: String,
    pub package_key: String,
    pub package_name: String,
    pub source: SourceIdentity,
    pub scope_variant: String,
    pub aliases: Vec<String>,
    pub vulnerable_versions: Vec<String>,
    pub active: bool,
    pub observed_affected: AffectedStatus,
    pub complete: bool,
    pub severity: FindingSeverity,
    pub last_known_severity: Option<FindingSeverity>,
    pub candidate: Option<MonitorCandidate>,
    pub evidence: Vec<MonitorEvidence>,
    pub related_lineages: Vec<String>,
    pub semantic_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MonitorSummary {
    pub monitor_id: String,
    pub epoch_id: String,
    pub config_revision: u64,
    pub generation: u64,
    pub initialized: bool,
    pub complete: bool,
    pub observed_at: u64,
    pub findings: Vec<MonitorFinding>,
    pub diagnostics: Vec<MonitorDiagnostic>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplayPage {
    pub events: Vec<MonitorEvent>,
    pub origin_cursor: EventReplayCursor,
    pub resync_cursor: EventReplayCursor,
    pub next_cursor: Option<EventReplayCursor>,
    pub low_water_mark: u64,
    pub high_water_mark: u64,
    pub has_more: bool,
    pub current: MonitorSummary,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CommittedEventReceipt {
    pub newly_committed_events: Vec<MonitorEvent>,
    pub newly_committed_count: u64,
    pub newly_committed_truncated: bool,
    pub newly_committed_gap: bool,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CheckResult {
    pub commit_status: CommitStatus,
    pub newly_committed_events: Vec<MonitorEvent>,
    pub newly_committed_count: u64,
    pub newly_committed_truncated: bool,
    pub newly_committed_gap: bool,
    pub replay: ReplayPage,
    pub current: MonitorSummary,
}
/// A stored witness locates evidence; it grants no provider or source authority.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct KnownAdvisoryWitness {
    pub package_key: String,
    pub provider_id: String,
    pub record_id: String,
}
#[derive(Debug, Clone)]
pub struct PreparedCheck {
    pub(crate) registration: Registration,
    pub(crate) generation: u64,
    pub(crate) check_id: String,
    pub(crate) prior_candidates: Vec<(String, String)>,
    pub(crate) known_advisories: Vec<KnownAdvisoryWitness>,
    pub(crate) continuation: Option<String>,
}
impl PreparedCheck {
    pub fn known_advisories(&self) -> &[KnownAdvisoryWitness] {
        &self.known_advisories
    }

    pub fn registration(&self) -> &Registration {
        &self.registration
    }
    pub fn assessment_options(
        &self,
        inventory: &crate::security_assessment::InventoryObservation,
    ) -> MonitorResult<crate::security_assessment::qualification::service::AssessmentOptions> {
        let mut previous = std::collections::BTreeSet::new();
        for package in &inventory.packages {
            let key = super::projection::logical_package_key(package)?;
            for (parent, version) in &self.prior_candidates {
                if parent == &key {
                    previous.insert((package.instance_id.clone(), version.clone()));
                }
            }
        }
        Ok(crate::security_assessment::qualification::service::AssessmentOptions {
            include_prereleases:self.registration.config.include_prereleases,
            continuation:self.continuation.as_ref().map(|cursor|crate::security_assessment::qualification::schedule::AssessmentContinuation::parse(cursor).map_err(|_|MonitorError::new("E_MONITOR_STATE_CORRUPT"))).transpose()?,
            previous_candidates:previous.into_iter().map(|(instance_id,version)|crate::security_assessment::qualification::schedule::ExactCandidate {instance_id,version}).collect(),
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LineageState {
    pub ordinal: u64,
    pub anchor: String,
    pub known_aliases: BTreeSet<String>,
    pub current_aliases: BTreeSet<String>,
    pub parents: Vec<String>,
    pub merged_into: Option<String>,
    pub finding: MonitorFinding,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckCommit {
    pub check_id: String,
    pub first_sequence: u64,
    pub event_count: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub comparison_domain: ComparisonDomain,
    pub monitor_id: String,
    pub epoch_id: String,
    pub config_revision: u64,
    pub generation: u64,
    pub sequence: u64,
    pub epoch_first_sequence: u64,
    pub reset_recorded: bool,
    pub initialized: bool,
    pub observed_at: u64,
    pub complete: bool,
    pub lineages: Vec<LineageState>,
    pub lineage_counter: u64,
    pub events: Vec<MonitorEvent>,
    pub failure_episodes: BTreeSet<String>,
    pub diagnostics: Vec<MonitorDiagnostic>,
    pub continuation: Option<String>,
    pub last_check: CheckCommit,
}
impl Snapshot {
    pub fn summary(&self) -> MonitorSummary {
        MonitorSummary {
            monitor_id: self.monitor_id.clone(),
            epoch_id: self.epoch_id.clone(),
            config_revision: self.config_revision,
            generation: self.generation,
            initialized: self.initialized,
            complete: self.complete,
            observed_at: self.observed_at,
            findings: self
                .lineages
                .iter()
                .filter(|lineage| {
                    lineage.merged_into.is_none()
                        && (lineage.finding.active
                            || lineage.finding.observed_affected != AffectedStatus::No)
                })
                .map(|lineage| lineage.finding.clone())
                .collect(),
            diagnostics: self.diagnostics.clone(),
        }
    }
}
