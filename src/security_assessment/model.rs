//! Source-aware observation contracts shared by assessment and monitoring.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservationDiagnostic {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
}

impl ObservationDiagnostic {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            instance_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    #[default]
    Complete,
    Partial,
    Unsupported,
    Error,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageUnit {
    pub status: CoverageStatus,
    pub requested: usize,
    pub complete: usize,
    pub partial: usize,
    pub unsupported: usize,
    pub errors: usize,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservationCoverage {
    pub inventory_instances: CoverageUnit,
    pub advisory_records: CoverageUnit,
    pub finding_clusters: CoverageUnit,
    pub candidate_checks: CoverageUnit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservationLimits {
    pub total_timeout_ms: u64,
    pub http_timeout_ms: u64,
    pub max_response_bytes: usize,
    pub max_metadata_bytes: usize,
    pub max_inventory_instances: usize,
    pub max_requests: usize,
    pub max_pages: usize,
    pub max_attempts: usize,
    pub concurrency: usize,
    pub max_candidates_per_package: usize,
    pub max_candidate_checks: usize,
}

impl Default for ObservationLimits {
    fn default() -> Self {
        Self {
            total_timeout_ms: 60_000,
            http_timeout_ms: 10_000,
            max_response_bytes: 5 * 1024 * 1024,
            max_metadata_bytes: 512 * 1024,
            max_inventory_instances: 1000,
            max_requests: 100,
            max_pages: 10,
            max_attempts: 2,
            concurrency: 4,
            max_candidates_per_package: 20,
            max_candidate_checks: 200,
        }
    }
}

impl ObservationLimits {
    /// Requested limits may only narrow the service's documented bounds.
    pub fn validate(&self) -> Result<(), ObservationDiagnostic> {
        let cap = Self::default();
        let pairs = [
            (self.total_timeout_ms as u128, cap.total_timeout_ms as u128),
            (self.http_timeout_ms as u128, cap.http_timeout_ms as u128),
            (
                self.max_response_bytes as u128,
                cap.max_response_bytes as u128,
            ),
            (
                self.max_metadata_bytes as u128,
                cap.max_metadata_bytes as u128,
            ),
            (
                self.max_inventory_instances as u128,
                cap.max_inventory_instances as u128,
            ),
            (self.max_requests as u128, cap.max_requests as u128),
            (self.max_pages as u128, cap.max_pages as u128),
            (self.max_attempts as u128, cap.max_attempts as u128),
            (self.concurrency as u128, cap.concurrency as u128),
            (
                self.max_candidates_per_package as u128,
                cap.max_candidates_per_package as u128,
            ),
            (
                self.max_candidate_checks as u128,
                cap.max_candidate_checks as u128,
            ),
        ];
        if pairs.iter().any(|(value, max)| *value == 0 || value > max) {
            return Err(ObservationDiagnostic::new(
                "E_SECURITY_LIMIT",
                "Observation limits must be positive and may not exceed service bounds.",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InventoryTarget {
    #[default]
    Installed,
    Locked,
    System,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InventoryBackend {
    #[default]
    Uv,
    Native,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InventoryScope {
    pub members: Vec<String>,
    pub groups: Vec<String>,
    pub extras: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetTagProfile {
    pub profile_version: u32,
    pub generator: String,
    pub generator_version: String,
    pub digest: String,
    pub tags: Vec<String>,
    pub implementation: String,
    pub python_version: String,
    pub os: String,
    pub architecture: String,
    pub libc: Option<String>,
    pub deployment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedTarget {
    pub project_root: PathBuf,
    pub environment_root: PathBuf,
    pub interpreter: PathBuf,
    pub inspector: PathBuf,
    pub interpreter_digest: String,
    pub interpreter_identity_evidence: String,
    pub kind: InventoryTarget,
    pub backend: InventoryBackend,
    pub scope: InventoryScope,
    pub tag_profile: TargetTagProfile,
    pub environment_fingerprint: String,
    pub project_digest: Option<String>,
    pub lock_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    PublicRegistry,
    PrivateRegistry,
    DirectUrl,
    Vcs,
    Editable,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub id: String,
    pub auth_scope_id: String,
    pub kind: SourceKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceMapping {
    pub ecosystem: String,
    pub upstream_name: String,
    pub assumption: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageSource {
    pub distribution: String,
    pub origin_identity: Option<String>,
    pub source: SourceIdentity,
    pub mapping: Option<SourceMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConstraintEvidence {
    pub requirement: String,
    pub origin: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageInstance {
    pub instance_id: String,
    pub name: String,
    pub version: String,
    pub source: SourceIdentity,
    pub source_mapping: Option<SourceMapping>,
    pub scope_variant: String,
    pub distribution_path: String,
    pub metadata_digest: String,
    pub direct_url_digest: Option<String>,
    pub origin_identity: Option<String>,
    pub requires_dist: Vec<ConstraintEvidence>,
    pub coverage: CoverageUnit,
}

impl PackageInstance {
    pub fn package_source(&self) -> PackageSource {
        PackageSource {
            distribution: self
                .distribution_path
                .rsplit('/')
                .next()
                .unwrap_or(&self.distribution_path)
                .into(),
            origin_identity: self.origin_identity.clone(),
            source: self.source.clone(),
            mapping: self.source_mapping.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InventoryObservation {
    pub observation_version: u32,
    pub inventory_id: String,
    pub observation_id: String,
    pub observed_at: u64,
    pub target: Option<ObservedTarget>,
    pub packages: Vec<PackageInstance>,
    pub direct_constraints: Vec<ConstraintEvidence>,
    pub coverage: ObservationCoverage,
    pub diagnostics: Vec<ObservationDiagnostic>,
}

pub fn semantic_digest<T: Serialize>(value: &T) -> String {
    // Serialization of these concrete model types cannot fail. Do not expose
    // serializer errors, which could contain untrusted metadata values.
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    crate::security::sha256_bytes(&bytes)
}
