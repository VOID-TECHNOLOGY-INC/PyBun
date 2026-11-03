//! Pure OSV/PyPI applicability. No transport, source authorization or mutation.
//!
//! Follows the OSV evaluation algorithm's union, sorted timelines and independent
//! limit ceilings, retaining original event positions for every fixed boundary.
use crate::security_assessment::{
    CoverageStatus, PackageInstance, osv::AdvisoryRecord, source::normalize_name,
};
use pep440_rs::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AffectedStatus {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDiagnostic {
    pub code: String,
    pub affected_index: Option<usize>,
    pub range_index: Option<usize>,
    pub event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FixedBoundaryEvidence {
    pub provider_id: String,
    pub record_id: String,
    pub payload_digest: String,
    pub affected_index: usize,
    pub range_index: usize,
    pub introduced_event_index: Option<usize>,
    pub fixed_event_index: usize,
    pub introduced: String,
    pub fixed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryEvaluation {
    pub provider_id: String,
    pub record_id: String,
    pub payload_digest: String,
    pub affected: AffectedStatus,
    /// Complete applicability of this record, not provider/query completeness.
    /// A positive union contribution remains Yes even when another is unknown.
    pub complete: bool,
    pub withdrawn: Option<String>,
    pub aliases: Vec<String>,
    /// Only fixed boundaries of intervals containing the evaluated version.
    /// Callers must require complete evidence and requery every provider before
    /// using any boundary to qualify a published remediation candidate.
    pub fixed_boundaries: Vec<FixedBoundaryEvidence>,
    pub diagnostics: Vec<EvidenceDiagnostic>,
}

impl AdvisoryEvaluation {
    fn unknown(
        &mut self,
        code: &str,
        affected_index: Option<usize>,
        range_index: Option<usize>,
        event_index: Option<usize>,
    ) {
        self.complete = false;
        self.diagnostics.push(EvidenceDiagnostic {
            code: code.into(),
            affected_index,
            range_index,
            event_index,
        });
    }
}

/// Evaluate an observed package at either its installed version or an explicit
/// candidate version. The caller supplies an already authorized observation;
/// serialized package/source evidence itself grants no authority to query.
pub fn evaluate_advisory(
    package: &PackageInstance,
    version: &str,
    provider_id: &str,
    record: &AdvisoryRecord,
) -> AdvisoryEvaluation {
    let mut result = AdvisoryEvaluation {
        provider_id: provider_id.into(),
        record_id: record.id.clone(),
        payload_digest: record.payload_digest.clone(),
        affected: AffectedStatus::Unknown,
        complete: true,
        withdrawn: None,
        aliases: vec![],
        fixed_boundaries: vec![],
        diagnostics: vec![],
    };
    if record.coverage.status != CoverageStatus::Complete {
        result.unknown("E_SECURITY_ADVISORY_INCOMPLETE", None, None, None);
    }
    let Some(mapping) = &package.source_mapping else {
        result.unknown("E_SECURITY_SOURCE_MAPPING_UNKNOWN", None, None, None);
        return result;
    };
    let Ok(upstream) = normalize_name(&mapping.upstream_name) else {
        result.unknown("E_SECURITY_SOURCE_MAPPING_UNKNOWN", None, None, None);
        return result;
    };
    if mapping.ecosystem != "PyPI" {
        result.unknown("E_SECURITY_SOURCE_MAPPING_UNKNOWN", None, None, None);
        return result;
    }
    let Ok(version) = version.parse::<Version>() else {
        result.unknown("E_SECURITY_VERSION_UNKNOWN", None, None, None);
        return result;
    };
    let payload = &record.payload;
    if payload.get("id").and_then(Value::as_str) != Some(record.id.as_str()) {
        result.unknown("E_SECURITY_ADVISORY_MALFORMED", None, None, None);
        return result;
    }
    if let Some(aliases) = payload.get("aliases") {
        match aliases.as_array() {
            Some(values) => {
                if values
                    .iter()
                    .any(|value| !value.as_str().is_some_and(valid_alias))
                {
                    result.unknown("E_SECURITY_ADVISORY_MALFORMED", None, None, None);
                }
                result.aliases = values
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|alias| valid_alias(alias))
                    .map(str::to_owned)
                    .collect();
                result.aliases.sort();
                result.aliases.dedup();
            }
            _ => result.unknown("E_SECURITY_ADVISORY_MALFORMED", None, None, None),
        }
    }
    for field in ["modified", "published", "withdrawn"] {
        match payload.get(field) {
            Some(Value::String(value)) if OffsetDateTime::parse(value, &Rfc3339).is_ok() => {
                if field == "withdrawn" {
                    result.withdrawn = Some(value.clone());
                }
            }
            Some(_) => result.unknown("E_SECURITY_ADVISORY_TIMESTAMP", None, None, None),
            None if field == "modified" => {
                result.unknown("E_SECURITY_ADVISORY_TIMESTAMP", None, None, None)
            }
            None => {}
        }
    }
    if result.withdrawn.is_some() {
        result.affected = if result.complete {
            AffectedStatus::No
        } else {
            AffectedStatus::Unknown
        };
        return result;
    }
    let Some(affected) = payload.get("affected").and_then(Value::as_array) else {
        result.unknown("E_SECURITY_ADVISORY_MALFORMED", None, None, None);
        return result;
    };
    let mut positive = false;
    for (affected_index, entry) in affected.iter().enumerate() {
        let Some(identity) = entry.get("package") else {
            result.unknown(
                "E_SECURITY_ADVISORY_PACKAGE_UNKNOWN",
                Some(affected_index),
                None,
                None,
            );
            continue;
        };
        let (Some(ecosystem), Some(name)) = (
            identity.get("ecosystem").and_then(Value::as_str),
            identity.get("name").and_then(Value::as_str),
        ) else {
            result.unknown(
                "E_SECURITY_ADVISORY_PACKAGE_UNKNOWN",
                Some(affected_index),
                None,
                None,
            );
            continue;
        };
        if ecosystem != "PyPI" {
            continue;
        }
        let normalized_name = if name == "*" {
            Ok(upstream.clone())
        } else {
            normalize_name(name)
        };
        let Ok(name) = normalized_name else {
            result.unknown(
                "E_SECURITY_ADVISORY_PACKAGE_UNKNOWN",
                Some(affected_index),
                None,
                None,
            );
            continue;
        };
        if name != upstream {
            continue;
        }
        let has_versions = entry
            .get("versions")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty());
        let has_ranges = entry
            .get("ranges")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty());
        if !has_versions && !has_ranges {
            result.unknown(
                "E_SECURITY_ADVISORY_VERSIONS_UNKNOWN",
                Some(affected_index),
                None,
                None,
            );
        }
        if let Some(versions) = entry.get("versions") {
            match versions.as_array() {
                Some(versions) => {
                    for declared in versions {
                        match declared
                            .as_str()
                            .and_then(|value| value.parse::<Version>().ok())
                        {
                            Some(declared) => positive |= declared == version,
                            None => result.unknown(
                                "E_SECURITY_ADVISORY_VERSION_MALFORMED",
                                Some(affected_index),
                                None,
                                None,
                            ),
                        }
                    }
                }
                None => result.unknown(
                    "E_SECURITY_ADVISORY_VERSION_MALFORMED",
                    Some(affected_index),
                    None,
                    None,
                ),
            }
        }
        if let Some(ranges) = entry.get("ranges") {
            let Some(ranges) = ranges.as_array() else {
                result.unknown(
                    "E_SECURITY_ADVISORY_RANGE_MALFORMED",
                    Some(affected_index),
                    None,
                    None,
                );
                continue;
            };
            for (range_index, range) in ranges.iter().enumerate() {
                if range.get("type").and_then(Value::as_str) != Some("ECOSYSTEM") {
                    result.unknown(
                        "E_SECURITY_ADVISORY_RANGE_UNSUPPORTED",
                        Some(affected_index),
                        Some(range_index),
                        None,
                    );
                    continue;
                }
                match evaluate_range(range, &version) {
                    Ok((hit, boundaries)) => {
                        positive |= hit;
                        for (introduced, fixed) in boundaries {
                            result.fixed_boundaries.push(FixedBoundaryEvidence {
                                provider_id: provider_id.into(),
                                record_id: record.id.clone(),
                                payload_digest: record.payload_digest.clone(),
                                affected_index,
                                range_index,
                                introduced_event_index: Some(introduced.index),
                                fixed_event_index: fixed.index,
                                introduced: introduced.raw,
                                fixed: fixed.raw,
                            });
                        }
                    }
                    Err((code, event_index)) => {
                        result.unknown(code, Some(affected_index), Some(range_index), event_index)
                    }
                }
            }
        }
    }
    result.affected = if positive {
        AffectedStatus::Yes
    } else if result.complete {
        AffectedStatus::No
    } else {
        AffectedStatus::Unknown
    };
    result
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EventKind {
    Introduced,
    Fixed,
    LastAffected,
    Limit,
}
#[derive(Clone)]
struct Event {
    kind: EventKind,
    version: Option<Version>,
    raw: String,
    index: usize,
}
type RangeResult = Result<(bool, Vec<(Event, Event)>), (&'static str, Option<usize>)>;

fn evaluate_range(range: &Value, version: &Version) -> RangeResult {
    const MALFORMED: &str = "E_SECURITY_ADVISORY_RANGE_MALFORMED";
    const CONTRADICTORY: &str = "E_SECURITY_ADVISORY_RANGE_CONTRADICTORY";
    let events = range
        .get("events")
        .and_then(Value::as_array)
        .ok_or((MALFORMED, None))?;
    let mut timeline = vec![];
    let mut limits = vec![];
    let mut has_fixed = false;
    let mut has_last = false;
    for (index, event) in events.iter().enumerate() {
        let object = event.as_object().ok_or((MALFORMED, Some(index)))?;
        if object.len() != 1 {
            return Err((MALFORMED, Some(index)));
        }
        let (key, value) = object.iter().next().ok_or((MALFORMED, Some(index)))?;
        let kind = match key.as_str() {
            "introduced" => EventKind::Introduced,
            "fixed" => EventKind::Fixed,
            "last_affected" => EventKind::LastAffected,
            "limit" => EventKind::Limit,
            _ => return Err((MALFORMED, Some(index))),
        };
        let raw = value.as_str().ok_or((MALFORMED, Some(index)))?;
        let parsed = if (kind == EventKind::Introduced && raw == "0")
            || (kind == EventKind::Limit && raw.contains('*'))
        {
            None
        } else {
            Some(
                raw.parse::<Version>()
                    .map_err(|_| (MALFORMED, Some(index)))?,
            )
        };
        let event = Event {
            kind,
            version: parsed,
            raw: raw.into(),
            index,
        };
        match kind {
            EventKind::Limit => limits.push(event),
            EventKind::Fixed => {
                has_fixed = true;
                timeline.push(event);
            }
            EventKind::LastAffected => {
                has_last = true;
                timeline.push(event);
            }
            EventKind::Introduced => timeline.push(event),
        }
    }
    if (has_fixed && has_last)
        || !timeline
            .iter()
            .any(|event| event.kind == EventKind::Introduced)
    {
        return Err((CONTRADICTORY, None));
    }
    timeline.sort_by(|left, right| left.version.cmp(&right.version));
    let within_limits = limits.is_empty()
        || limits
            .iter()
            .any(|event| event.version.as_ref().is_none_or(|limit| version < limit));
    let mut open: Option<Event> = None;
    let mut positive = false;
    let mut boundaries = vec![];
    for (index, event) in timeline.iter().enumerate() {
        if index > 0
            && timeline[index - 1].version == event.version
            && timeline[index - 1].kind != event.kind
        {
            return Err((CONTRADICTORY, Some(event.index)));
        }
        if event.kind == EventKind::Introduced {
            // Repeated introductions merely retain the current affected state.
            // Keep its first introduction so earlier affected versions retain
            // the same eventual fixed-boundary evidence.
            if open.is_none() {
                open = Some(event.clone());
            }
        } else {
            let Some(start) = open.take() else {
                // A redundant closing event cannot create a new interval.
                continue;
            };
            let end = event
                .version
                .as_ref()
                .ok_or((MALFORMED, Some(event.index)))?;
            let contains = within_limits
                && start.version.as_ref().is_none_or(|start| version >= start)
                && if event.kind == EventKind::Fixed {
                    version < end
                } else {
                    version <= end
                };
            positive |= contains;
            if contains && event.kind == EventKind::Fixed {
                boundaries.push((start, event.clone()));
            }
        }
    }
    if let Some(start) = open {
        positive |= within_limits && start.version.as_ref().is_none_or(|start| version >= start);
    }
    Ok((positive, boundaries))
}

fn valid_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}
