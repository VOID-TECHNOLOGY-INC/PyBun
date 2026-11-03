//! Typed inputs and results for the shared read-only security check.
use super::{
    ObservationLimits, http::ObservationMode, qualification::schedule::AssessmentContinuation,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum CheckTarget {
    #[default]
    Installed,
    Locked,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum CheckMode {
    #[default]
    Online,
    Offline,
    OnlineWithCacheFallback,
}

impl From<CheckMode> for ObservationMode {
    fn from(mode: CheckMode) -> Self {
        match mode {
            CheckMode::Online => Self::Online,
            CheckMode::Offline => Self::Offline,
            CheckMode::OnlineWithCacheFallback => Self::OnlineWithCacheFallback,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum CheckSeverityThreshold {
    Low,
    Medium,
    High,
    Critical,
}

impl CheckSeverityThreshold {
    pub fn matches_severity(
        self,
        severity: &super::qualification::findings::FindingSeverity,
    ) -> bool {
        let threshold = match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        };
        severity.rank().is_none_or(|level| level >= threshold)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CheckUpdatesRequest {
    pub profile: Option<String>,
    pub project: Option<PathBuf>,
    pub target: CheckTarget,
    pub mode: CheckMode,
    pub limits: Option<ObservationLimits>,
    pub max_cache_age_seconds: Option<u64>,
    pub fail_on: Option<CheckSeverityThreshold>,
    pub continuation: Option<AssessmentContinuation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThresholdMatch {
    pub instance_id: String,
    pub advisory_ids: Vec<String>,
    pub severity: super::qualification::findings::FindingSeverity,
    pub threshold: CheckSeverityThreshold,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckUpdatesResult {
    pub contract_version: String,
    pub operation: String,
    pub assessment_version: u32,
    pub status: String,
    pub exit_code: i32,
    pub assessment_id: Option<String>,
    pub observation_id: Option<String>,
    pub profile_id: Option<String>,
    pub policy_digest: Option<String>,
    pub assessment: Option<super::qualification::service::SecurityAssessment>,
    pub threshold_matches: Vec<ThresholdMatch>,
    pub threshold_match_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omitted: Option<CheckOmissions>,
    pub diagnostics: Vec<super::ObservationDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckOmissions {
    pub inventory_instances: usize,
    pub advisory_records: usize,
    pub finding_clusters: usize,
    pub candidate_checks: usize,
    pub threshold_matches: usize,
}

pub fn failed_check(
    diagnostic: super::ObservationDiagnostic,
    exit_code: i32,
) -> CheckUpdatesResult {
    CheckUpdatesResult {
        contract_version: "2".into(),
        operation: "security_check".into(),
        assessment_version: 1,
        status: "error".into(),
        exit_code: if exit_code == 2 { 2 } else { 3 },
        assessment_id: None,
        observation_id: None,
        profile_id: None,
        policy_digest: None,
        assessment: None,
        threshold_matches: vec![],
        threshold_match_count: 0,
        omitted: None,
        diagnostics: vec![diagnostic],
    }
}

pub fn check_json(result: &CheckUpdatesResult) -> serde_json::Value {
    serde_json::to_value(result)
        .expect("security check results consist of serializable JSON values")
}

pub fn check_text(result: &CheckUpdatesResult) -> String {
    let Some(assessment) = &result.assessment else {
        return result
            .diagnostics
            .iter()
            .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
            .collect::<Vec<_>>()
            .join("\n");
    };
    let mut lines = vec![format!(
        "Security observation: {} ({} installed instances, {} threshold matches).",
        result.status,
        assessment.inventory.packages.len(),
        result.threshold_matches.len()
    )];
    for package in &assessment.packages {
        let name = assessment
            .inventory
            .packages
            .iter()
            .find(|instance| instance.instance_id == package.instance_id)
            .map_or(package.instance_id.as_str(), |instance| {
                instance.name.as_str()
            });
        for candidate in &package.candidates {
            use super::qualification::{candidate::CandidateKind, constraints::ConstraintStatus};
            let evidence = match candidate.qualification.candidate_kind {
                Some(CandidateKind::PublishedRemediationCandidate) => {
                    "published remediation candidate"
                }
                Some(CandidateKind::NonAffectedUpgradeObserved) => "observed unaffected upgrade",
                None => "not qualified by current evidence",
            };
            let constraints = match candidate.constraints.constraint_status {
                ConstraintStatus::PassesKnownConstraints => "passes known direct constraints",
                ConstraintStatus::BlockedByKnownConstraint => {
                    "blocked by a known direct constraint"
                }
                ConstraintStatus::Unknown => "direct constraints remain unknown",
            };
            lines.push(format!(
                "{name} {}: {evidence}; {constraints}.",
                candidate.qualification.version
            ));
        }
        if package.unknown_remainder {
            lines.push(format!("{name}: evidence remains incomplete."));
        }
    }
    lines.push("Resolution not checked; verification not run. Missing fix information does not prove no upstream fix exists.".into());
    lines.join("\n")
}

/// Bound current authorization and observation by the same absolute request deadline.
pub async fn authorize_and_run(
    prepared: super::config::PreparedCheck,
    observed_at: u64,
) -> CheckUpdatesResult {
    match authorize_prepared(prepared).await {
        Ok(authorized) => run_check(authorized, observed_at).await,
        Err(error) => failed_check(error, 3),
    }
}

pub(crate) async fn authorize_prepared(
    prepared: super::config::PreparedCheck,
) -> Result<super::config::AuthorizedCheck, super::ObservationDiagnostic> {
    let deadline = prepared.deadline();
    if std::time::Instant::now() >= deadline {
        return Err(check_deadline_error());
    }
    let authorization = tokio::task::spawn_blocking(move || {
        if std::time::Instant::now() >= deadline {
            return Err(check_deadline_error());
        }
        prepared.authorize()
    });
    match tokio::time::timeout_at(deadline.into(), authorization).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(super::ObservationDiagnostic::new(
            "E_SECURITY_AUTHORITY",
            "Current operator authority could not be verified.",
        )),
        Err(_) => Err(check_deadline_error()),
    }
}
fn check_deadline_error() -> super::ObservationDiagnostic {
    super::ObservationDiagnostic::new(
        "E_SECURITY_DEADLINE",
        "The shared security check deadline was exhausted.",
    )
}

/// Run only an operator-authorized check; transport adapters cannot construct authority.
pub async fn run_check(
    authorized: super::config::AuthorizedCheck,
    observed_at: u64,
) -> CheckUpdatesResult {
    use super::qualification::service::{AssessmentOptions, assess_project};
    let context = match RawCheckContext::new(authorized, observed_at) {
        Ok(context) => context,
        Err(error) => return failed_check(error, 3),
    };
    let authorized = &context.authorized;
    let session = &context.session;
    let options = AssessmentOptions {
        include_prereleases: authorized.include_prereleases,
        continuation: authorized.continuation.clone(),
        previous_candidates: vec![],
    };
    let graph = authorized
        .provenance
        .as_ref()
        .map(|(request, bindings)| (request, bindings.as_slice()));
    let assessment = match assess_project(
        session,
        &authorized.inventory,
        &authorized.providers,
        &authorized.sources,
        &options,
        graph,
    )
    .await
    {
        Ok(assessment) => assessment,
        Err(error) => return failed_check(error, 3),
    };
    context.finish(assessment).await
}

/// Internal raw observation context. Monitor checks persist the complete
/// assessment before calling the same bounded one-shot finalization.
pub(crate) struct RawCheckContext {
    pub(crate) authorized: super::config::AuthorizedCheck,
    pub(crate) session: super::http::HttpSession,
}
impl RawCheckContext {
    pub(crate) fn new(
        authorized: super::config::AuthorizedCheck,
        observed_at: u64,
    ) -> Result<Self, super::ObservationDiagnostic> {
        use super::{http::HttpSession, qualification::cache::ObservationCache};
        // One reserve covers projection, durable monitor commit when requested,
        // and rendering. It narrows I/O without extending the total deadline.
        let remaining = authorized
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        let reserve = (remaining / 10).min(std::time::Duration::from_millis(250));
        let session = HttpSession::new(authorized.inventory.limits.clone(), observed_at)?
            .with_deadline(authorized.deadline - reserve)?
            .with_max_cache_age_seconds(authorized.max_cache_age_seconds)?;
        let session = if let Some(root) = &authorized.cache_root {
            session.with_cache(
                ObservationCache::open(root, authorized.inventory.limits.max_response_bytes)?,
                authorized.mode,
            )?
        } else if authorized.mode != super::http::ObservationMode::Online {
            return Err(super::ObservationDiagnostic::new(
                "E_SECURITY_CACHE_UNAVAILABLE",
                "The selected offline/fallback profile has no approved cache.",
            ));
        } else {
            session
        };
        Ok(Self {
            authorized,
            session,
        })
    }

    pub(crate) async fn prepare_observed(
        self,
        assessment: super::qualification::service::SecurityAssessment,
    ) -> Result<CheckUpdatesResult, Box<CheckUpdatesResult>> {
        prepare_monitor_assessment(
            assessment,
            self.authorized.profile_id,
            self.authorized.policy_digest,
            self.authorized.fail_on,
            self.authorized.max_output_bytes,
            self.authorized.deadline,
        )
        .await
    }

    pub(crate) async fn finish(
        self,
        assessment: super::qualification::service::SecurityAssessment,
    ) -> CheckUpdatesResult {
        let authorized = self.authorized;
        let deadline = authorized.deadline;
        if std::time::Instant::now() >= deadline {
            return failed_check(check_deadline_error(), 3);
        }
        let finalization = tokio::task::spawn_blocking(move || {
            finish_assessment(
                assessment,
                authorized.profile_id,
                authorized.policy_digest,
                authorized.fail_on,
                authorized.max_output_bytes,
                deadline,
            )
        });
        match tokio::time::timeout_at(deadline.into(), finalization).await {
            Ok(Ok(result)) if std::time::Instant::now() < deadline => result,
            Ok(Err(_)) => failed_check(
                super::ObservationDiagnostic::new(
                    "E_SECURITY_CHECK_FAILED",
                    "Security observation finalization could not complete.",
                ),
                3,
            ),
            _ => failed_check(check_deadline_error(), 3),
        }
    }
}

fn finish_assessment(
    assessment: super::qualification::service::SecurityAssessment,
    profile_id: String,
    policy_digest: String,
    fail_on: Option<CheckSeverityThreshold>,
    max_output_bytes: usize,
    deadline: std::time::Instant,
) -> CheckUpdatesResult {
    if std::time::Instant::now() >= deadline {
        return failed_check(check_deadline_error(), 3);
    }
    let result = prepare_assessment(assessment, profile_id, policy_digest, fail_on);
    if std::time::Instant::now() >= deadline {
        return failed_check(check_deadline_error(), 3);
    }
    bound_output(result, max_output_bytes)
}

fn prepare_assessment(
    assessment: super::qualification::service::SecurityAssessment,
    profile_id: String,
    policy_digest: String,
    fail_on: Option<CheckSeverityThreshold>,
) -> CheckUpdatesResult {
    let matches = threshold_matches(&assessment, fail_on);
    let identities = (
        super::semantic::assessment_id(&assessment, &policy_digest),
        super::semantic::observation_id(&assessment),
    );
    assembled_assessment(assessment, profile_id, policy_digest, matches, identities)
}

fn threshold_matches(
    assessment: &super::qualification::service::SecurityAssessment,
    fail_on: Option<CheckSeverityThreshold>,
) -> Vec<ThresholdMatch> {
    use super::qualification::evidence::AffectedStatus;
    fail_on
        .map(|threshold| {
            assessment
                .packages
                .iter()
                .flat_map(|package| {
                    package
                        .installed
                        .clusters
                        .iter()
                        .filter(|cluster| {
                            cluster.affected == AffectedStatus::Yes
                                && threshold.matches_severity(&cluster.severity)
                        })
                        .map(move |cluster| ThresholdMatch {
                            instance_id: package.instance_id.clone(),
                            advisory_ids: cluster.ids.clone(),
                            severity: cluster.severity,
                            threshold,
                        })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn assembled_assessment(
    assessment: super::qualification::service::SecurityAssessment,
    profile_id: String,
    policy_digest: String,
    threshold_matches: Vec<ThresholdMatch>,
    identities: (String, String),
) -> CheckUpdatesResult {
    use super::CoverageStatus;
    let incomplete = assessment.coverage.status != CoverageStatus::Complete;
    CheckUpdatesResult {
        contract_version: "2".into(),
        operation: "security_check".into(),
        assessment_version: 1,
        status: if incomplete { "partial" } else { "complete" }.into(),
        exit_code: if incomplete {
            3
        } else if threshold_matches.is_empty() {
            0
        } else {
            1
        },
        assessment_id: Some(identities.0),
        observation_id: Some(identities.1),
        profile_id: Some(profile_id),
        policy_digest: Some(policy_digest),
        diagnostics: assessment.diagnostics.clone(),
        assessment: Some(assessment),
        threshold_match_count: threshold_matches.len(),
        threshold_matches,
        omitted: None,
    }
}

/// Cheap bounded evidence survives queued/failed semantic preparation or a
/// rejected commit. It is explicitly an observation summary, never durable state.
pub(crate) fn deferred_observation_summary(
    assessment: &super::qualification::service::SecurityAssessment,
    profile_id: &str,
    policy_digest: &str,
    fail_on: Option<CheckSeverityThreshold>,
    max_bytes: usize,
    error: super::ObservationDiagnostic,
) -> CheckUpdatesResult {
    use super::qualification::evidence::AffectedStatus;
    let mut result = failed_check(error, 3);
    result.status = "partial".into();
    result.profile_id = Some(profile_id.into());
    result.policy_digest = Some(policy_digest.into());
    let mut retained_bytes = 0;
    if let Some(threshold) = fail_on {
        for package in &assessment.packages {
            for cluster in &package.installed.clusters {
                if cluster.affected != AffectedStatus::Yes
                    || !threshold.matches_severity(&cluster.severity)
                {
                    continue;
                }
                result.threshold_match_count += 1;
                if result.threshold_matches.len() < 8 {
                    let bytes = 512
                        + 2 * package.instance_id.len()
                        + cluster.ids.iter().map(|id| 2 * id.len()).sum::<usize>();
                    if retained_bytes + bytes <= max_bytes / 4 {
                        retained_bytes += bytes;
                        result.threshold_matches.push(ThresholdMatch {
                            instance_id: package.instance_id.clone(),
                            advisory_ids: cluster.ids.clone(),
                            severity: cluster.severity,
                            threshold,
                        });
                    }
                }
            }
        }
    }
    result.omitted = Some(CheckOmissions {
        inventory_instances: assessment.inventory.packages.len(),
        advisory_records: assessment
            .providers
            .iter()
            .flat_map(|provider| &provider.instances)
            .map(|instance| instance.records.len())
            .sum(),
        finding_clusters: assessment
            .packages
            .iter()
            .map(|package| package.installed.clusters.len())
            .sum(),
        candidate_checks: assessment
            .packages
            .iter()
            .map(|package| package.candidates.len())
            .sum(),
        threshold_matches: result.threshold_match_count - result.threshold_matches.len(),
    });
    result
}

async fn prepare_monitor_assessment(
    assessment: super::qualification::service::SecurityAssessment,
    profile_id: String,
    policy_digest: String,
    fail_on: Option<CheckSeverityThreshold>,
    max_bytes: usize,
    deadline: std::time::Instant,
) -> Result<CheckUpdatesResult, Box<CheckUpdatesResult>> {
    let mut fallback = deferred_observation_summary(
        &assessment,
        &profile_id,
        &policy_digest,
        fail_on,
        max_bytes,
        check_deadline_error(),
    );
    let assessment = std::sync::Arc::new(assessment);
    let input = assessment.clone();
    let policy = policy_digest.clone();
    let mut work = tokio::task::spawn_blocking(move || {
        let check = || {
            if std::time::Instant::now() >= deadline {
                Err(check_deadline_error())
            } else {
                Ok(())
            }
        };
        check()?;
        let matches = threshold_matches(&input, fail_on);
        check()?;
        let semantic_id = super::semantic::assessment_id(&input, &policy);
        check()?;
        let observation_id = super::semantic::observation_id(&input);
        check()?;
        Ok::<_, super::ObservationDiagnostic>((matches, (semantic_id, observation_id)))
    });
    let (matches, identities) = match tokio::time::timeout_at(deadline.into(), &mut work).await {
        Ok(Ok(Ok(parts))) => parts,
        Ok(Ok(Err(error))) => {
            fallback.diagnostics = vec![error];
            return Err(Box::new(fallback));
        }
        Ok(Err(_)) => {
            fallback.diagnostics = vec![super::ObservationDiagnostic::new(
                "E_SECURITY_CHECK_FAILED",
                "Observed evidence could not be finalized.",
            )];
            return Err(Box::new(fallback));
        }
        Err(_) => {
            work.abort();
            return Err(Box::new(fallback));
        }
    };
    let assessment = std::sync::Arc::try_unwrap(assessment)
        .expect("completed pure identity worker releases its observation handle");
    Ok(assembled_assessment(
        assessment,
        profile_id,
        policy_digest,
        matches,
        identities,
    ))
}

pub(crate) fn bound_output(result: CheckUpdatesResult, max_bytes: usize) -> CheckUpdatesResult {
    let fits = |result: &CheckUpdatesResult| check_wire_fits(result, max_bytes, 2048);
    if fits(&result) {
        return result;
    }
    let omissions = CheckOmissions {
        inventory_instances: result
            .assessment
            .as_ref()
            .map_or(0, |a| a.inventory.packages.len()),
        advisory_records: result.assessment.as_ref().map_or(0, |a| {
            a.providers
                .iter()
                .flat_map(|p| &p.instances)
                .map(|i| i.records.len())
                .sum()
        }),
        finding_clusters: result.assessment.as_ref().map_or(0, |a| {
            a.packages.iter().map(|p| p.installed.clusters.len()).sum()
        }),
        candidate_checks: result
            .assessment
            .as_ref()
            .map_or(0, |a| a.packages.iter().map(|p| p.candidates.len()).sum()),
        threshold_matches: result.threshold_match_count,
    };
    let mut summary = failed_check(
        super::ObservationDiagnostic::new(
            "E_SECURITY_OUTPUT_LIMIT",
            "Assessment output exceeded its authorized size; evidence and matches were omitted as counted below.",
        ),
        3,
    );
    summary.assessment_id = result.assessment_id;
    summary.observation_id = result.observation_id;
    summary.profile_id = result.profile_id;
    summary.policy_digest = result.policy_digest;
    summary.threshold_match_count = result.threshold_match_count;
    summary.omitted = Some(omissions);
    for matched in result.threshold_matches {
        summary.threshold_matches.push(matched);
        summary
            .omitted
            .as_mut()
            .expect("omission summary")
            .threshold_matches -= 1;
        if !fits(&summary) {
            summary.threshold_matches.pop();
            summary
                .omitted
                .as_mut()
                .expect("omission summary")
                .threshold_matches += 1;
            break;
        }
    }
    summary
}

/// Count the escaped JSON text used by MCP without allocating an encoded copy.
/// Callers reserve bounded transport metadata/framing separately.
pub(crate) fn check_wire_fits(value: &impl Serialize, max_bytes: usize, reserve: usize) -> bool {
    serde_json::to_writer(
        &mut OutputCounter {
            remaining: max_bytes.saturating_sub(reserve),
        },
        value,
    )
    .is_ok()
}

struct OutputCounter {
    remaining: usize,
}
impl std::io::Write for OutputCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let cost = bytes.len()
            + bytes
                .iter()
                .filter(|&&byte| byte == b'\\' || byte == b'"')
                .count();
        if cost > self.remaining {
            return Err(std::io::Error::other("security output limit"));
        }
        self.remaining -= cost;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod output_tests {
    use super::*;
    #[tokio::test]
    async fn canonical_empty_v2_envelope_matches_fixture() {
        use super::super::{
            InventoryObservation, ObservationCoverage, ObservationLimits, SourcePolicy,
            http::{HttpSession, ProviderConfig, ProviderEndpoint},
            qualification::service::{AssessmentOptions, assess_inventory},
        };
        use serde_json::json;
        let target=serde_json::from_value(json!({
            "project_root":"/fixture","environment_root":"/fixture/.venv","interpreter":"/fixture/.venv/bin/python","inspector":"/operator/python","interpreter_digest":"d".repeat(64),"interpreter_identity_evidence":"controlled_fixture","kind":"installed","backend":"uv","scope":{"members":[],"groups":[],"extras":[]},
            "marker_environment":{"implementation_name":"cpython","implementation_version":"3.13.0","os_name":"posix","platform_machine":"x86_64","platform_python_implementation":"CPython","platform_release":"fixture","platform_system":"Linux","platform_version":"fixture","python_full_version":"3.13.0","python_version":"3.13","sys_platform":"linux"},
            "tag_profile":{"profile_version":1,"generator":"controlled_fixture","generator_version":"1","digest":"c".repeat(64),"tags":["py3-none-any"],"implementation":"cpython","python_version":"3.13.0","os":"linux","architecture":"x86_64","libc":"glibc-2.34","deployment":null},
            "environment_fingerprint":"e".repeat(64),"project_digest":null,"lock_digest":null
        })).unwrap();
        let inventory = InventoryObservation {
            observation_version: 1,
            inventory_id: "a".repeat(64),
            observation_id: "b".repeat(64),
            observed_at: 20,
            target: Some(target),
            packages: vec![],
            direct_constraints: vec![],
            coverage: ObservationCoverage::default(),
            diagnostics: vec![],
        };
        let provider = ProviderEndpoint::new(ProviderConfig {
            id: "fixture-advisory".into(),
            url: "https://example.invalid/v1/querybatch".into(),
            auth_scope_id: "fixture-public".into(),
            allow_insecure_loopback: false,
        })
        .unwrap();
        let session = HttpSession::new(ObservationLimits::default(), 20).unwrap();
        let assessment = assess_inventory(
            &session,
            &inventory,
            &SourcePolicy::default(),
            &[provider],
            &[],
            &AssessmentOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(session.request_count(), 0);
        let result = finish_assessment(
            assessment,
            "fixture-profile".into(),
            "f".repeat(64),
            None,
            65536,
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        );
        assert_eq!(result.exit_code, 0);
        let mut envelope = crate::schema::JsonEnvelope::new(
            "pybun audit check-updates",
            crate::schema::Status::Ok,
            std::time::Duration::ZERO,
            check_json(&result),
        );
        envelope.version = "2".into();
        let actual = serde_json::to_value(envelope).unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/security_check_v2.json");
        if std::env::var("PYBUN_UPDATE_SNAPSHOTS").as_deref() == Ok("1") {
            std::fs::write(&path, serde_json::to_string_pretty(&actual).unwrap() + "\n").unwrap();
        }
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn expired_finalization_cannot_turn_a_complete_input_into_success() {
        use super::super::{
            CoverageUnit, InventoryObservation, ObservationCoverage, ObservationLimits,
            qualification::{
                schedule::{AssessmentDomain, plan_candidates},
                service::SecurityAssessment,
            },
        };
        let domain = AssessmentDomain {
            inventory_digest: "i".into(),
            scope_digest: "s".into(),
            provider_digest: "p".into(),
            policy_digest: "p".into(),
            tag_profile_digest: "t".into(),
            evidence_revision: 1,
        };
        let plan = plan_candidates(&domain, &[], &[], &ObservationLimits::default(), None).unwrap();
        let assessment = SecurityAssessment {
            assessment_version: 1,
            inventory: InventoryObservation {
                observation_version: 1,
                inventory_id: "i".into(),
                observation_id: "o".into(),
                observed_at: 1,
                target: None,
                packages: vec![],
                direct_constraints: vec![],
                coverage: ObservationCoverage::default(),
                diagnostics: vec![],
            },
            providers: vec![],
            packages: vec![],
            provenance: None,
            continuation: plan.continuation,
            invalidated_instances: vec![],
            unknown_remainder: false,
            coverage: CoverageUnit::default(),
            evidence_coverage: ObservationCoverage::default(),
            diagnostics: vec![],
        };
        let result = finish_assessment(
            assessment,
            "app".into(),
            "policy".into(),
            None,
            4096,
            std::time::Instant::now() - std::time::Duration::from_secs(1),
        );
        assert_eq!(result.exit_code, 3);
        assert_eq!(result.diagnostics[0].code, "E_SECURITY_DEADLINE");
        assert!(result.assessment_id.is_none());
    }

    #[test]
    fn output_limit_keeps_threshold_match_count_and_explicit_omissions() {
        let mut result = failed_check(
            super::super::ObservationDiagnostic::new("E_TEST", &"x".repeat(20_000)),
            3,
        );
        result.threshold_matches = (0..100)
            .map(|i| ThresholdMatch {
                instance_id: format!("instance-{i}"),
                advisory_ids: vec![format!("A-{i}")],
                severity: super::super::qualification::findings::FindingSeverity::Unknown,
                threshold: CheckSeverityThreshold::Critical,
            })
            .collect();
        result.threshold_match_count = 100;
        let bounded = bound_output(result, 4096);
        assert_eq!(bounded.exit_code, 3);
        assert_eq!(bounded.threshold_match_count, 100);
        assert!(!bounded.threshold_matches.is_empty());
        assert!(bounded.threshold_matches.len() < 100);
        assert!(bounded.omitted.as_ref().unwrap().threshold_matches > 0);
        assert_eq!(bounded.diagnostics[0].code, "E_SECURITY_OUTPUT_LIMIT");
        assert!(serde_json::to_vec(&bounded).unwrap().len() <= 4096);
    }
}

#[cfg(test)]
mod monitor_deadline_tests;
