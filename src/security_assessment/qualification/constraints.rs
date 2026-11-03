//! Pure evaluation of captured project/root requirements, never graph pins or
//! a resolver. Passing these declarations does not prove full compatibility.
use crate::security_assessment::{
    ConstraintEvidence, CoverageStatus, CoverageUnit, InventoryObservation, ObservationDiagnostic,
    ObservedTarget, PackageInstance, normalize_name,
};
use pep440_rs::Version;
use pep508_rs::{
    ExtraName, MarkerEnvironment, MarkerEnvironmentBuilder, MarkerWarningKind, Requirement,
    VersionOrUrl,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintStatus {
    PassesKnownConstraints,
    BlockedByKnownConstraint,
    Unknown,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FullConstraintCompleteness {
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConstraintBlocker {
    pub candidate_version: String,
    pub requirement: String,
    pub origin: String,
    pub digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluatedConstraint {
    /// Uninterpretable declarations retain located digest evidence without
    /// returning raw malformed input or parser excerpts.
    pub requirement: Option<String>,
    pub origin: String,
    pub digest: String,
    pub applies: Option<bool>,
    pub satisfied: Option<bool>,
    pub reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintEvaluation {
    pub candidate_version: String,
    pub constraint_status: ConstraintStatus,
    pub known_direct_status: ConstraintStatus,
    /// True only when a matching root declaration is proven applicable.
    /// False does not prove absence when declaration/marker coverage is partial.
    pub is_direct_dependency: bool,
    pub full_constraint_completeness: FullConstraintCompleteness,
    pub blockers: Vec<ConstraintBlocker>,
    pub evaluated: Vec<EvaluatedConstraint>,
    /// Completeness of relevant/uninterpretable captured root declarations,
    /// independent from the always-unknown full/transitive constraint axis.
    pub coverage: CoverageUnit,
    pub diagnostics: Vec<ObservationDiagnostic>,
}

pub fn evaluate_constraints(
    inventory: &InventoryObservation,
    package: &PackageInstance,
    candidate_version: &str,
) -> ConstraintEvaluation {
    let mut result = ConstraintEvaluation {
        candidate_version: "[invalid_version]".into(),
        constraint_status: ConstraintStatus::Unknown,
        known_direct_status: ConstraintStatus::Unknown,
        is_direct_dependency: false,
        full_constraint_completeness: FullConstraintCompleteness::Unknown,
        blockers: vec![],
        evaluated: vec![],
        coverage: CoverageUnit::default(),
        diagnostics: vec![],
    };
    let Ok(candidate) = candidate_version.parse::<Version>() else {
        unknown(
            &mut result,
            package,
            "E_SECURITY_CONSTRAINT_VERSION_UNKNOWN",
        );
        return result;
    };
    result.candidate_version = candidate.to_string();
    let Ok(name) = normalize_name(&package.name) else {
        unknown(
            &mut result,
            package,
            "E_SECURITY_CONSTRAINT_IDENTITY_UNKNOWN",
        );
        return result;
    };
    let context = inventory
        .target
        .as_ref()
        .and_then(|target| marker_context(target).ok());
    for declaration in &inventory.direct_constraints {
        // Url's Pep508Url implementation does no ambient environment expansion.
        // VerbatimUrl would expand ${PROJECT_ROOT}/other environment variables.
        let mut uncertain_parse = false;
        let mut reporter = |kind: MarkerWarningKind, _message: String| {
            uncertain_parse |= kind != MarkerWarningKind::DeprecatedMarkerName;
        };
        let parsed = Requirement::<reqwest::Url>::parse_reporter(
            &declaration.requirement,
            std::path::Path::new("/"),
            &mut reporter,
        );
        let requirement = match parsed {
            Ok(requirement) if !uncertain_parse => requirement,
            _ => {
                result.coverage.requested += 1;
                result.coverage.partial += 1;
                let mut evidence = evidence(declaration, None);
                evidence.reason = Some("E_SECURITY_CONSTRAINT_DECLARATION_UNKNOWN".into());
                result.evaluated.push(evidence);
                unknown(
                    &mut result,
                    package,
                    "E_SECURITY_CONSTRAINT_DECLARATION_UNKNOWN",
                );
                continue;
            }
        };
        if requirement.name.as_ref() != name {
            continue;
        }
        result.coverage.requested += 1;
        let mut evidence = evidence(declaration, Some(redact(&declaration.requirement)));
        let applies = if requirement.marker.is_true() {
            Some(true)
        } else if requirement.marker.is_false() {
            Some(false)
        } else if let Some((environment, extras)) = &context {
            let mut uncertain_evaluation = false;
            let mut reporter = |kind: MarkerWarningKind, _message: String| {
                // String ordering is explicitly evaluated lexicographically by
                // the maintained implementation. Parse-time ignored comparisons
                // were rejected above; deprecated aliases retain defined values.
                uncertain_evaluation |= !matches!(
                    kind,
                    MarkerWarningKind::DeprecatedMarkerName
                        | MarkerWarningKind::LexicographicComparison
                );
            };
            let applies = requirement
                .marker
                .evaluate_reporter(environment, extras, &mut reporter);
            if uncertain_evaluation {
                None
            } else {
                Some(applies)
            }
        } else {
            None
        };
        evidence.applies = applies;
        match applies {
            None => {
                result.coverage.partial += 1;
                evidence.reason = Some("E_SECURITY_CONSTRAINT_MARKER_UNKNOWN".into());
                unknown(&mut result, package, "E_SECURITY_CONSTRAINT_MARKER_UNKNOWN");
            }
            Some(false) => {
                result.coverage.complete += 1;
            }
            Some(true) => {
                result.is_direct_dependency = true;
                let satisfied = match &requirement.version_or_url {
                    None => Some(true),
                    Some(VersionOrUrl::VersionSpecifier(specifier)) => {
                        Some(specifier.contains(&candidate))
                    }
                    Some(VersionOrUrl::Url(_)) => None,
                };
                evidence.satisfied = satisfied;
                match satisfied {
                    Some(false) => {
                        result.coverage.complete += 1;
                        result.blockers.push(ConstraintBlocker {
                            candidate_version: result.candidate_version.clone(),
                            requirement: redact(&declaration.requirement),
                            origin: redact(&declaration.origin),
                            digest: redact(&declaration.digest),
                        });
                    }
                    Some(true) => {
                        result.coverage.complete += 1;
                    }
                    None => {
                        result.coverage.partial += 1;
                        evidence.reason = Some("E_SECURITY_CONSTRAINT_SOURCE_UNKNOWN".into());
                        unknown(&mut result, package, "E_SECURITY_CONSTRAINT_SOURCE_UNKNOWN");
                    }
                }
            }
        }
        result.evaluated.push(evidence);
    }
    result.known_direct_status = if !result.blockers.is_empty() {
        ConstraintStatus::BlockedByKnownConstraint
    } else if result.coverage.status != CoverageStatus::Complete {
        ConstraintStatus::Unknown
    } else {
        ConstraintStatus::PassesKnownConstraints
    };
    result.constraint_status = if result.is_direct_dependency {
        result.known_direct_status
    } else {
        ConstraintStatus::Unknown
    };
    if !result.is_direct_dependency {
        result.diagnostics.push(ObservationDiagnostic {code:"E_SECURITY_NO_APPLICABLE_ROOT_CONSTRAINT".into(),message:"No proven applicable project/root declaration establishes direct constraint status; full and transitive constraints remain unknown.".into(),instance_id:Some(package.instance_id.clone())});
    }
    result
}

fn marker_context(target: &ObservedTarget) -> Result<(MarkerEnvironment, Vec<ExtraName>), ()> {
    let values = &target.marker_environment;
    let get = |key| values.get(key).map(String::as_str).ok_or(());
    let environment = MarkerEnvironmentBuilder {
        implementation_name: get("implementation_name")?,
        implementation_version: get("implementation_version")?,
        os_name: get("os_name")?,
        platform_machine: get("platform_machine")?,
        platform_python_implementation: get("platform_python_implementation")?,
        platform_release: get("platform_release")?,
        platform_system: get("platform_system")?,
        platform_version: get("platform_version")?,
        python_full_version: get("python_full_version")?,
        python_version: get("python_version")?,
        sys_platform: get("sys_platform")?,
    }
    .try_into()
    .map_err(|_| ())?;
    let extras = target
        .scope
        .extras
        .iter()
        .map(|value| value.parse::<ExtraName>().map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((environment, extras))
}
fn evidence(input: &ConstraintEvidence, requirement: Option<String>) -> EvaluatedConstraint {
    EvaluatedConstraint {
        requirement,
        origin: redact(&input.origin),
        digest: redact(&input.digest),
        applies: None,
        satisfied: None,
        reason: None,
    }
}
fn unknown(result: &mut ConstraintEvaluation, package: &PackageInstance, code: &str) {
    result.coverage.status = CoverageStatus::Partial;
    if !result.coverage.reasons.iter().any(|reason| reason == code) {
        result.coverage.reasons.push(code.into());
        result.diagnostics.push(ObservationDiagnostic {code:code.into(),message:"Captured root constraint evidence cannot be completely evaluated; no parser text or source execution is used.".into(),instance_id:Some(package.instance_id.clone())});
    }
}
fn redact(value: &str) -> String {
    crate::support_bundle::redact_text(value)
}
