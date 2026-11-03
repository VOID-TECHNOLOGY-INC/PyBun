//! Source-authorized OSV observations retaining full hydrated records.

use super::http::{HttpSession, JsonEvidence, ProviderEndpoint};
use super::*;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryRecord {
    pub id: String,
    pub payload: Value,
    pub payload_digest: String,
    pub fetched_at: u64,
    pub coverage: CoverageUnit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceAdvisories {
    pub instance_id: String,
    pub version: String,
    pub source_id: String,
    pub auth_scope_id: String,
    pub upstream_name: Option<String>,
    pub ecosystem: Option<String>,
    pub mapping_assumption: Option<String>,
    pub records: Vec<AdvisoryRecord>,
    pub coverage: CoverageUnit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryObservation {
    pub observation_version: u32,
    pub provider_id: String,
    pub observed_at: u64,
    pub instances: Vec<InstanceAdvisories>,
    /// Provider coverage counts inventory instances; record coverage remains
    /// separate on every instance and hydrated advisory record.
    pub coverage: CoverageUnit,
    pub advisory_records: CoverageUnit,
    pub diagnostics: Vec<ObservationDiagnostic>,
}

pub async fn observe_advisories(
    session: &HttpSession,
    endpoint: &ProviderEndpoint,
    inventory: &InventoryObservation,
    policy: &SourcePolicy,
) -> AdvisoryObservation {
    let inventory_status = inventory.coverage.inventory_instances.status;
    if matches!(
        inventory_status,
        CoverageStatus::Error | CoverageStatus::Unsupported
    ) || inventory.target.is_none()
    {
        let mut coverage = failed_unit("E_SECURITY_INVENTORY", 0);
        if inventory_status == CoverageStatus::Unsupported {
            coverage.status = CoverageStatus::Unsupported;
        }
        return AdvisoryObservation {
            observation_version: 1,
            provider_id: endpoint.id().into(),
            observed_at: session.observed_at(),
            instances: vec![],
            coverage: coverage.clone(),
            advisory_records: coverage,
            diagnostics: vec![ObservationDiagnostic::new(
                "E_SECURITY_INVENTORY",
                "Advisory requests require an observed inventory; inventory failure is not an empty scan.",
            )],
        };
    }
    let mut observed = query_advisories(session, endpoint, &inventory.packages, policy).await;
    if inventory_status == CoverageStatus::Partial {
        observed.coverage.status = CoverageStatus::Partial;
        observed.advisory_records.status = CoverageStatus::Partial;
        observed
            .coverage
            .reasons
            .push("E_SECURITY_INVENTORY_PARTIAL".into());
        observed.diagnostics.push(ObservationDiagnostic::new("E_SECURITY_INVENTORY_PARTIAL", "Only the complete known inventory instances were observed; inventory coverage remains partial."));
    }
    observed
}

/// Candidate checks use the same source policy, HTTP budget and provider
/// protocol as installed-version observations; callers cannot opt out of
/// source/disclosure reauthorization by supplying earlier evidence.
pub async fn query_advisories(
    session: &HttpSession,
    endpoint: &ProviderEndpoint,
    packages: &[PackageInstance],
    policy: &SourcePolicy,
) -> AdvisoryObservation {
    let mut result = AdvisoryObservation {
        observation_version: 1,
        provider_id: endpoint.id().into(),
        observed_at: session.observed_at(),
        instances: vec![],
        coverage: CoverageUnit {
            requested: packages.len(),
            ..Default::default()
        },
        advisory_records: CoverageUnit::default(),
        diagnostics: vec![],
    };
    if packages.len() > session.limits().max_inventory_instances {
        result.coverage = failed_unit("E_SECURITY_INVENTORY_LIMIT", packages.len());
        result.diagnostics.push(ObservationDiagnostic::new(
            "E_SECURITY_INVENTORY_LIMIT",
            "The inventory exceeds the observation limit; no identities were submitted.",
        ));
        return result;
    }
    let mut authorized = BTreeMap::new();
    let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for package in packages {
        let index = result.instances.len();
        result.instances.push(InstanceAdvisories {
            instance_id: package.instance_id.clone(),
            version: package.version.clone(),
            source_id: package.source.id.clone(),
            auth_scope_id: package.source.auth_scope_id.clone(),
            upstream_name: None,
            ecosystem: None,
            mapping_assumption: None,
            records: vec![],
            coverage: CoverageUnit::default(),
        });
        let query = (|| {
            package.version.parse::<pep440_rs::Version>().map_err(|_| {
                ObservationDiagnostic::new(
                    "E_SECURITY_METADATA",
                    "Inventory contains an invalid PEP 440 version.",
                )
            })?;
            if package.coverage.status != CoverageStatus::Complete {
                return Err(ObservationDiagnostic::new(
                    "E_SECURITY_INVENTORY",
                    "An incomplete package instance cannot be submitted as a verified inventory observation.",
                ));
            }
            let distribution = Path::new(&package.distribution_path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            let current = policy.map_package_with_origin(
                &package.name,
                distribution,
                package.source.kind,
                package.origin_identity.as_deref(),
            )?;
            let query = policy.authorized_query(endpoint.id(), &package.name, &current)?;
            if current.source != package.source || current.mapping != package.source_mapping {
                return Err(ObservationDiagnostic::new(
                    "E_SECURITY_SOURCE_POLICY_CHANGED",
                    "Source configuration changed since inventory observation; obtain a fresh inventory.",
                ));
            }
            Ok(query)
        })();
        match query {
            Ok(query) => {
                result.instances[index].upstream_name = Some(query.name.clone());
                result.instances[index].ecosystem = Some(query.ecosystem.clone());
                result.instances[index].mapping_assumption = Some(query.assumption.clone());
                groups
                    .entry((query.source_id.clone(), query.auth_scope_id.clone()))
                    .or_default()
                    .push(index);
                authorized.insert(index, query);
            }
            Err(error) => record_failure(&mut result, index, error),
        }
    }
    let mut retained_bytes = 0;
    for indices in groups.values() {
        observe_group(
            session,
            endpoint,
            packages,
            indices,
            &authorized,
            &mut result,
            &mut retained_bytes,
        )
        .await;
    }
    result.coverage.complete = result
        .instances
        .iter()
        .filter(|instance| instance.coverage.status == CoverageStatus::Complete)
        .count();
    result.coverage.partial = result.instances.len() - result.coverage.complete;
    if result.coverage.partial > 0 {
        result.coverage.status = CoverageStatus::Partial;
    }
    result.coverage.reasons = result
        .diagnostics
        .iter()
        .map(|error| error.code.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    for instance in &result.instances {
        result.advisory_records.requested += instance.coverage.requested;
        result.advisory_records.complete += instance
            .records
            .iter()
            .filter(|record| record.coverage.status == CoverageStatus::Complete)
            .count();
        result.advisory_records.partial += instance
            .records
            .iter()
            .filter(|record| record.coverage.status != CoverageStatus::Complete)
            .count();
        result.advisory_records.errors += instance
            .coverage
            .requested
            .saturating_sub(instance.records.len());
    }
    if result.coverage.status != CoverageStatus::Complete {
        result.advisory_records.status = CoverageStatus::Partial;
        result.advisory_records.reasons = result.coverage.reasons.clone();
    }
    result
}

async fn observe_group(
    session: &HttpSession,
    endpoint: &ProviderEndpoint,
    packages: &[PackageInstance],
    indices: &[usize],
    authorized: &BTreeMap<usize, AuthorizedQuery>,
    result: &mut AdvisoryObservation,
    retained_bytes: &mut usize,
) {
    let mut active: Vec<(usize, Option<String>)> =
        indices.iter().map(|index| (*index, None)).collect();
    let mut tokens: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    let mut ids: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    for page in 0..session.limits().max_pages {
        if active.is_empty() {
            break;
        }
        if let Err(error) = session.reserve_provider_page(endpoint.id()) {
            for (index, _) in &active {
                record_failure(result, *index, error.clone());
            }
            break;
        }
        let queries: Vec<_> = active.iter().map(|(index, token)| {
            let query = &authorized[index];
            let mut value = json!({"package":{"name":query.name,"ecosystem":query.ecosystem},"version":packages[*index].version});
            if let Some(token) = token { value["page_token"] = json!(token); }
            value
        }).collect();
        let evidence = session
            .request_json(
                endpoint,
                Method::POST,
                endpoint.url().clone(),
                Some(json!({"queries":queries})),
                &authorized[&active[0].0],
            )
            .await;
        let evidence = match evidence {
            Ok(evidence) => evidence,
            Err(error) => {
                for (index, _) in &active {
                    record_failure(result, *index, error.clone());
                }
                break;
            }
        };
        let Some(responses) = evidence
            .value
            .get("results")
            .and_then(Value::as_array)
            .filter(|values| values.len() == active.len())
        else {
            for (index, _) in &active {
                record_failure(result, *index, schema_error());
            }
            break;
        };
        let mut next = Vec::new();
        for ((index, _), response) in active.iter().zip(responses) {
            if !response.is_object() {
                record_failure(result, *index, schema_error());
                continue;
            }
            if let Some(vulns) = response.get("vulns") {
                if let Some(vulns) = vulns.as_array() {
                    for vuln in vulns {
                        let Some(id) = vuln
                            .get("id")
                            .and_then(Value::as_str)
                            .filter(|id| endpoint.detail_url(id).is_ok())
                        else {
                            record_failure(result, *index, schema_error());
                            continue;
                        };
                        if !ids.entry(*index).or_default().insert(id.to_owned()) {
                            record_failure(
                                result,
                                *index,
                                ObservationDiagnostic::new(
                                    "E_SECURITY_PROVIDER_PAGE",
                                    "The provider repeated an advisory across pages.",
                                ),
                            );
                        }
                    }
                } else {
                    record_failure(result, *index, schema_error());
                }
            }
            if let Some(token) = response.get("next_page_token") {
                let Some(token) = token
                    .as_str()
                    .filter(|token| !token.is_empty() && token.len() <= 4096)
                else {
                    record_failure(result, *index, schema_error());
                    continue;
                };
                if page + 1 == session.limits().max_pages
                    || !tokens.entry(*index).or_default().insert(token.into())
                {
                    record_failure(
                        result,
                        *index,
                        ObservationDiagnostic::new(
                            "E_SECURITY_PROVIDER_PAGE",
                            "Provider pagination repeated a token or exceeded its page budget.",
                        ),
                    );
                } else {
                    next.push((*index, Some(token.into())));
                }
            }
        }
        active = next;
    }
    let mut records = BTreeMap::new();
    for index in indices {
        for id in ids.get(index).into_iter().flatten() {
            result.instances[*index].coverage.requested += 1;
            if !records.contains_key(id) {
                let fetched = match endpoint.detail_url(id) {
                    Ok(url) => session
                        .request_json(endpoint, Method::GET, url, None, &authorized[index])
                        .await
                        .and_then(|evidence| hydrate(id, evidence)),
                    Err(error) => Err(error),
                };
                // A single hydrated payload can belong to many installed
                // instances. Bound retained evidence across the whole run,
                // rather than multiplying the HTTP response cap per clone.
                let fetched = fetched.and_then(|record| {
                    let size = serde_json::to_vec(&record)
                        .map_err(|_| schema_error())?
                        .len();
                    // Reserve enough for the final per-instance coverage too:
                    // a scope failure adds a reason after the payload is read.
                    let current_coverage_size = serde_json::to_vec(&record.coverage)
                        .map_err(|_| schema_error())?
                        .len();
                    let failed_coverage_size =
                        serde_json::to_vec(&failed_unit("E_SECURITY_PROVIDER_SCOPE", 1))
                            .map_err(|_| schema_error())?
                            .len();
                    let size = size + failed_coverage_size.saturating_sub(current_coverage_size);
                    if size
                        > session
                            .limits()
                            .max_response_bytes
                            .saturating_sub(*retained_bytes)
                    {
                        Err(evidence_limit())
                    } else {
                        Ok((record, size))
                    }
                });
                records.insert(id.clone(), fetched);
            }
            match &records[id] {
                Ok((record, size)) => {
                    if *size
                        > session
                            .limits()
                            .max_response_bytes
                            .saturating_sub(*retained_bytes)
                    {
                        record_failure(result, *index, evidence_limit());
                        continue;
                    }
                    *retained_bytes += size;
                    let mut record = record.clone();
                    let scoped = matches_package(&record.payload, &authorized[index]);
                    if !scoped {
                        record.coverage = failed_unit("E_SECURITY_PROVIDER_SCOPE", 1);
                        record_failure(
                            result,
                            *index,
                            ObservationDiagnostic::new(
                                "E_SECURITY_PROVIDER_SCOPE",
                                "Hydrated advisory evidence does not identify the queried upstream package.",
                            ),
                        );
                    }
                    if record.coverage.status == CoverageStatus::Complete {
                        result.instances[*index].coverage.complete += 1;
                    } else {
                        record_failure(result, *index, schema_error());
                    }
                    result.instances[*index].records.push(record);
                }
                Err(error) => record_failure(result, *index, error.clone()),
            }
        }
    }
}

fn hydrate(
    requested: &str,
    evidence: JsonEvidence,
) -> Result<AdvisoryRecord, ObservationDiagnostic> {
    let value = &evidence.value;
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(schema_error)?;
    if id != requested
        && !value
            .get("aliases")
            .and_then(Value::as_array)
            .is_some_and(|aliases| {
                aliases
                    .iter()
                    .any(|alias| alias.as_str() == Some(requested))
            })
    {
        return Err(schema_error());
    }
    let version_supported = value.get("schema_version").is_none_or(|version| {
        version
            .as_str()
            .and_then(|version| semver::Version::parse(version).ok())
            .is_some_and(|version| version.major == 1)
    });
    let fields_valid = value
        .get("modified")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
        && value.get("aliases").is_none_or(|aliases| {
            aliases
                .as_array()
                .is_some_and(|aliases| aliases.iter().all(Value::is_string))
        })
        && (value.get("affected").is_some_and(Value::is_array)
            || (value.get("affected").is_none()
                && value
                    .get("withdrawn")
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.is_empty())));
    let coverage = if version_supported && fields_valid {
        CoverageUnit {
            requested: 1,
            complete: 1,
            ..Default::default()
        }
    } else {
        failed_unit("E_SECURITY_PROVIDER_SCHEMA", 1)
    };
    Ok(AdvisoryRecord {
        id: id.into(),
        payload: evidence.value,
        payload_digest: evidence.payload_digest,
        fetched_at: evidence.fetched_at,
        coverage,
    })
}

fn matches_package(payload: &Value, query: &AuthorizedQuery) -> bool {
    let affected = payload.get("affected").and_then(Value::as_array);
    if affected.is_none_or(Vec::is_empty)
        && payload
            .get("withdrawn")
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty())
    {
        return true;
    }
    affected.is_some_and(|items| {
        items.iter().any(|item| {
            item.pointer("/package/ecosystem").and_then(Value::as_str)
                == Some(query.ecosystem.as_str())
                && item
                    .pointer("/package/name")
                    .and_then(Value::as_str)
                    .and_then(|name| normalize_name(name).ok())
                    .as_deref()
                    == Some(query.name.as_str())
        })
    })
}

fn record_failure(
    result: &mut AdvisoryObservation,
    index: usize,
    mut error: ObservationDiagnostic,
) {
    let instance = &mut result.instances[index];
    instance.coverage.status = CoverageStatus::Partial;
    instance.coverage.reasons.push(error.code.clone());
    instance.coverage.reasons.sort();
    instance.coverage.reasons.dedup();
    error.instance_id = Some(instance.instance_id.clone());
    if !result.diagnostics.contains(&error) {
        result.diagnostics.push(error);
    }
}
fn failed_unit(reason: &str, requested: usize) -> CoverageUnit {
    CoverageUnit {
        status: CoverageStatus::Error,
        requested,
        errors: requested,
        reasons: vec![reason.into()],
        ..Default::default()
    }
}
fn schema_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_PROVIDER_SCHEMA",
        "Provider evidence is missing, malformed, mismatched, or uses an unsupported schema.",
    )
}

fn evidence_limit() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_EVIDENCE_LIMIT",
        "Aggregate hydrated evidence exceeded the run's bounded JSON size; remaining records are incomplete.",
    )
}
