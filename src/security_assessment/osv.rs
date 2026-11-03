//! Source-authorized OSV observations retaining full hydrated records.

use super::http::{EvidenceFreshness, HttpSession, JsonEvidence, ProviderEndpoint};
use super::*;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryRecord {
    pub freshness: EvidenceFreshness,
    pub id: String,
    pub payload: Value,
    pub payload_digest: String,
    pub fetched_at: u64,
    pub coverage: CoverageUnit,
}

/// A previously observed locator remapped to the current inventory instance.
/// It grants no authority: current source mapping and disclosure are checked
/// before any detail request, including when the query omits this record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownAdvisoryId {
    pub instance_id: String,
    pub provider_id: String,
    pub record_id: String,
}

type HydratedRecords =
    BTreeMap<String, (Result<(AdvisoryRecord, usize), ObservationDiagnostic>, bool)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceAdvisories {
    pub freshness: EvidenceFreshness,
    /// At least one required detail was actually attempted, or the query
    /// completed without needing details. Budget-only misses are false.
    pub work_attempted: bool,
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
    let inventory_over_limit = inventory.packages.len() > session.limits().max_inventory_instances;
    let inventory_error = if inventory_over_limit {
        "E_SECURITY_INVENTORY_LIMIT"
    } else {
        "E_SECURITY_INVENTORY"
    };
    if matches!(
        inventory_status,
        CoverageStatus::Error | CoverageStatus::Unsupported
    ) || inventory.target.is_none()
        || inventory_over_limit
    {
        let mut coverage = failed_unit(inventory_error, inventory.packages.len());
        if inventory_status == CoverageStatus::Unsupported && !inventory_over_limit {
            coverage.status = CoverageStatus::Unsupported;
        }
        return AdvisoryObservation {
            observation_version: 1,
            provider_id: endpoint.id().into(),
            observed_at: session.observed_at(),
            instances: vec![],
            coverage: coverage.clone(),
            advisory_records: CoverageUnit {
                requested: 0,
                complete: 0,
                partial: 0,
                errors: 0,
                ..coverage
            },
            diagnostics: vec![ObservationDiagnostic::new(
                inventory_error,
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
    query_authoritative_advisories(session, &[endpoint], packages, policy)
        .await
        .remove(0)
}

/// Hydrate each package/version across every required provider before spending
/// on the next version. Provider latency cannot consume another provider's
/// opportunity to complete the same candidate within the shared run budget.
pub async fn query_authoritative_advisories(
    session: &HttpSession,
    endpoints: &[&ProviderEndpoint],
    packages: &[PackageInstance],
    policy: &SourcePolicy,
) -> Vec<AdvisoryObservation> {
    query_stream(session, endpoints, packages, &[], policy, &[]).await
}

pub async fn query_authoritative_advisories_with_history(
    session: &HttpSession,
    endpoints: &[&ProviderEndpoint],
    packages: &[PackageInstance],
    policy: &SourcePolicy,
    history: &[KnownAdvisoryId],
) -> Vec<AdvisoryObservation> {
    query_stream(session, endpoints, packages, &[], policy, history).await
}

/// Current-version positive witnesses get an initial detail before candidate
/// work; remaining current details cannot consume every candidate's budget.
pub(crate) async fn query_assessment_advisories(
    session: &HttpSession,
    endpoints: &[&ProviderEndpoint],
    packages: &[PackageInstance],
    current_ids: &[String],
    policy: &SourcePolicy,
    history: &[KnownAdvisoryId],
) -> Vec<AdvisoryObservation> {
    query_stream(session, endpoints, packages, current_ids, policy, history).await
}
async fn query_stream(
    session: &HttpSession,
    endpoints: &[&ProviderEndpoint],
    packages: &[PackageInstance],
    current_ids: &[String],
    policy: &SourcePolicy,
    history: &[KnownAdvisoryId],
) -> Vec<AdvisoryObservation> {
    let mut prepared: Vec<_> = endpoints
        .iter()
        .map(|endpoint| prepare_advisories(session, endpoint, packages, policy))
        .collect();
    let indices: BTreeMap<_, _> = packages
        .iter()
        .enumerate()
        .map(|(index, package)| (package.instance_id.as_str(), index))
        .collect();
    for (prepared, endpoint) in prepared.iter_mut().zip(endpoints) {
        for prior in history {
            if session.remaining().is_err() {
                break;
            }
            if prior.provider_id != endpoint.id() {
                continue;
            }
            let Some(&index) = indices.get(prior.instance_id.as_str()) else {
                continue;
            };
            if !prepared.authorized.contains_key(&index) {
                continue;
            }
            if endpoint.detail_url(&prior.record_id).is_err() {
                record_failure(&mut prepared.result, index, schema_error());
                continue;
            }
            let ids = prepared.known_ids.entry(index).or_default();
            if ids.contains(&prior.record_id) {
                continue;
            }
            if let Err(error) = session
                .remaining()
                .and_then(|_| session.reserve_evidence(prior.record_id.len().saturating_add(128)))
            {
                record_failure(&mut prepared.result, index, error);
                break;
            }
            ids.insert(prior.record_id.clone());
        }
    }
    let count = prepared
        .iter()
        .map(|prepared| prepared.result.instances.len())
        .max()
        .unwrap_or(0);
    let current: BTreeSet<_> = current_ids.iter().map(String::as_str).collect();
    for (index, package) in packages.iter().enumerate().take(count) {
        futures::future::join_all(prepared.iter_mut().zip(endpoints).map(
            |(prepared, endpoint)| async {
                if current.contains(package.instance_id.as_str()) {
                    prime_current(session, endpoint, packages, index, prepared).await;
                } else {
                    observe_index(session, endpoint, packages, index, prepared).await;
                }
            },
        ))
        .await;
    }
    for (index, package) in packages.iter().enumerate().take(count) {
        if current.contains(package.instance_id.as_str()) {
            futures::future::join_all(prepared.iter_mut().zip(endpoints).map(
                |(prepared, endpoint)| observe_index(session, endpoint, packages, index, prepared),
            ))
            .await;
        }
    }
    prepared.into_iter().map(finish_advisories).collect()
}
struct PreparedAdvisories {
    result: AdvisoryObservation,
    authorized: BTreeMap<usize, AuthorizedQuery>,
    batches: Vec<Vec<usize>>,
    index_batch: BTreeMap<usize, usize>,
    loaded: BTreeSet<usize>,
    primed: BTreeMap<usize, String>,
    ids: BTreeMap<usize, BTreeSet<String>>,
    known_ids: BTreeMap<usize, BTreeSet<String>>,
    next: BTreeMap<usize, String>,
    tokens: BTreeMap<usize, BTreeSet<String>>,
    records: BTreeMap<(String, String), HydratedRecords>,
}
impl PreparedAdvisories {
    fn empty(result: AdvisoryObservation) -> Self {
        Self {
            result,
            authorized: BTreeMap::new(),
            batches: vec![],
            index_batch: BTreeMap::new(),
            loaded: BTreeSet::new(),
            primed: BTreeMap::new(),
            ids: BTreeMap::new(),
            known_ids: BTreeMap::new(),
            next: BTreeMap::new(),
            tokens: BTreeMap::new(),
            records: BTreeMap::new(),
        }
    }
}
fn prepare_advisories(
    session: &HttpSession,
    endpoint: &ProviderEndpoint,
    packages: &[PackageInstance],
    policy: &SourcePolicy,
) -> PreparedAdvisories {
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
    if packages.len()
        > session
            .limits()
            .max_inventory_instances
            .saturating_add(session.limits().max_candidate_checks)
    {
        result.coverage = failed_unit("E_SECURITY_QUERY_LIMIT", packages.len());
        result.advisory_records = failed_unit("E_SECURITY_QUERY_LIMIT", 0);
        result.diagnostics.push(ObservationDiagnostic::new(
            "E_SECURITY_QUERY_LIMIT",
            "Combined current and candidate query work exceeds the shared observation limit; no identities were submitted.",
        ));
        return PreparedAdvisories::empty(result);
    }
    let mut authorized = BTreeMap::new();
    let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for package in packages {
        let index = result.instances.len();
        result.instances.push(InstanceAdvisories {
            freshness: EvidenceFreshness::default(),
            work_attempted: false,
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
        if let Ok(query) = &query {
            result.instances[index].upstream_name = Some(query.name.clone());
            result.instances[index].ecosystem = Some(query.ecosystem.clone());
            result.instances[index].mapping_assumption = Some(query.assumption.clone());
        }
        if let Err(error) = &query {
            record_failure(&mut result, index, error.clone());
        }
        let metadata_bytes =
            serde_json::to_vec(&result.instances[index]).map_or(usize::MAX, |value| value.len());
        // Reserve space for bounded coverage reasons, counts and freshness in
        // addition to the captured instance identity. Empty advisory results
        // still retain source/provenance evidence and consume the shared cap.
        if session
            .reserve_evidence(metadata_bytes.saturating_add(1024))
            .is_err()
        {
            result.instances.pop();
            result.diagnostics.push(evidence_limit());
            break;
        }
        if let Ok(query) = query {
            groups
                .entry((query.source_id.clone(), query.auth_scope_id.clone()))
                .or_default()
                .push(index);
            authorized.insert(index, query);
        }
    }

    let mut ordered_groups: Vec<_> = groups.into_values().collect();
    ordered_groups.sort_by_key(|indices| indices[0]);
    let mut prepared = PreparedAdvisories::empty(result);
    prepared.authorized = authorized;
    for indices in ordered_groups {
        for chunk in indices.chunks(1000) {
            let batch = prepared.batches.len();
            for index in chunk {
                prepared.index_batch.insert(*index, batch);
            }
            prepared.batches.push(chunk.to_vec());
        }
    }
    prepared
}
async fn load_batch(
    session: &HttpSession,
    endpoint: &ProviderEndpoint,
    packages: &[PackageInstance],
    index: usize,
    prepared: &mut PreparedAdvisories,
) {
    let Some(batch) = prepared.index_batch.get(&index).copied() else {
        return;
    };
    if prepared.loaded.insert(batch) {
        let active: Vec<_> = prepared.batches[batch]
            .iter()
            .map(|index| (*index, None))
            .collect();
        query_page(session, endpoint, packages, &active, prepared).await;
    }
}
async fn prime_current(
    session: &HttpSession,
    endpoint: &ProviderEndpoint,
    packages: &[PackageInstance],
    index: usize,
    prepared: &mut PreparedAdvisories,
) {
    if !prepared.authorized.contains_key(&index) {
        return;
    }
    load_batch(session, endpoint, packages, index, prepared).await;
    let Some(id) = prepared
        .ids
        .get(&index)
        .and_then(|ids| ids.first())
        .or_else(|| prepared.known_ids.get(&index).and_then(|ids| ids.first()))
        .cloned()
    else {
        return;
    };
    let pending = BTreeMap::from([(index, BTreeSet::from([id.clone()]))]);
    let query = &prepared.authorized[&index];
    let records = prepared
        .records
        .entry((query.source_id.clone(), query.auth_scope_id.clone()))
        .or_default();
    hydrate_indices(
        session,
        endpoint,
        &[index],
        &prepared.authorized,
        &mut prepared.result,
        records,
        &pending,
    )
    .await;
    prepared.primed.insert(index, id);
}

async fn observe_index(
    session: &HttpSession,
    endpoint: &ProviderEndpoint,
    packages: &[PackageInstance],
    index: usize,
    prepared: &mut PreparedAdvisories,
) {
    if !prepared.authorized.contains_key(&index) {
        return;
    }
    load_batch(session, endpoint, packages, index, prepared).await;
    // Only this package/version's remaining pages precede its hydration.
    // A later candidate's pagination cannot consume its provider bundle.
    while let Some(token) = prepared.next.remove(&index) {
        query_page(
            session,
            endpoint,
            packages,
            &[(index, Some(token))],
            prepared,
        )
        .await;
    }
    let mut remaining = prepared.ids.remove(&index).unwrap_or_default();
    remaining.extend(prepared.known_ids.remove(&index).unwrap_or_default());
    if let Some(id) = prepared.primed.remove(&index) {
        remaining.remove(&id);
    }
    let pending = BTreeMap::from([(index, remaining)]);
    let query = &prepared.authorized[&index];
    let records = prepared
        .records
        .entry((query.source_id.clone(), query.auth_scope_id.clone()))
        .or_default();
    hydrate_indices(
        session,
        endpoint,
        &[index],
        &prepared.authorized,
        &mut prepared.result,
        records,
        &pending,
    )
    .await;
}

fn finish_advisories(prepared: PreparedAdvisories) -> AdvisoryObservation {
    let mut result = prepared.result;
    if result.instances.is_empty() && result.coverage.status == CoverageStatus::Error {
        return result;
    }
    for instance in &mut result.instances {
        instance.work_attempted |= instance.coverage.status == CoverageStatus::Complete;
    }
    result.coverage.complete = result
        .instances
        .iter()
        .filter(|instance| instance.coverage.status == CoverageStatus::Complete)
        .count();
    result.coverage.partial = result.coverage.requested - result.coverage.complete;
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

async fn query_page(
    session: &HttpSession,
    endpoint: &ProviderEndpoint,
    packages: &[PackageInstance],
    active: &[(usize, Option<String>)],
    prepared: &mut PreparedAdvisories,
) {
    let PreparedAdvisories {
        result,
        authorized,
        ids,
        next,
        tokens,
        ..
    } = prepared;
    if let Err(error) = session.reserve_provider_page(endpoint.id()) {
        for (index, _) in active {
            record_failure(result, *index, error.clone());
        }
        return;
    }
    let queries:Vec<_>=active.iter().map(|(index,token)| {
        let query=&authorized[index];
        let mut value=json!({"package":{"name":query.name,"ecosystem":query.ecosystem},"version":packages[*index].version});
        if let Some(token)=token {value["page_token"]=json!(token);}
        value
    }).collect();
    let (evidence, attempted) = session
        .request_json_tracked(
            endpoint,
            Method::POST,
            endpoint.url().clone(),
            Some(json!({"queries":queries})),
            &authorized[&active[0].0],
        )
        .await;
    // Only an individually followed page advances a partial candidate. A
    // batched first page must not mark its unvisited tail as assessed work.
    if attempted || evidence.is_ok() {
        for (index, token) in active {
            if token.is_some() {
                result.instances[*index].work_attempted = true;
            }
        }
    }
    let evidence = match evidence {
        Ok(evidence) => evidence,
        Err(error) => {
            for (index, _) in active {
                record_failure(result, *index, error.clone());
            }
            return;
        }
    };
    for (index, _) in active {
        result.instances[*index].freshness.merge(evidence.freshness);
    }
    let Some(responses) = evidence
        .value
        .get("results")
        .and_then(Value::as_array)
        .filter(|values| values.len() == active.len())
    else {
        for (index, _) in active {
            record_failure(result, *index, schema_error());
        }
        return;
    };
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
                    if !ids.entry(*index).or_default().insert(id.into()) {
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
            if !tokens.entry(*index).or_default().insert(token.into()) {
                record_failure(
                    result,
                    *index,
                    ObservationDiagnostic::new(
                        "E_SECURITY_PROVIDER_PAGE",
                        "Provider pagination repeated a token or exceeded its page budget.",
                    ),
                );
            } else {
                next.insert(*index, token.into());
            }
        }
    }
}

async fn hydrate_indices(
    session: &HttpSession,
    endpoint: &ProviderEndpoint,
    indices: &[usize],
    authorized: &BTreeMap<usize, AuthorizedQuery>,
    result: &mut AdvisoryObservation,
    records: &mut HydratedRecords,
    ids: &BTreeMap<usize, BTreeSet<String>>,
) {
    for index in indices {
        for id in ids.get(index).into_iter().flatten() {
            result.instances[*index].coverage.requested += 1;
            if !records.contains_key(id) {
                let (fetched, attempted) = match endpoint.detail_url(id) {
                    Ok(url) => {
                        let (evidence, attempted) = session
                            .request_json_tracked(
                                endpoint,
                                Method::GET,
                                url,
                                None,
                                &authorized[index],
                            )
                            .await;
                        (
                            evidence.and_then(|evidence| hydrate(id, evidence)),
                            attempted,
                        )
                    }
                    Err(error) => (Err(error), false),
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
                    if size > session.remaining_evidence_bytes() {
                        Err(evidence_limit())
                    } else {
                        Ok((record, size))
                    }
                });
                records.insert(id.clone(), (fetched, attempted));
            }
            result.instances[*index].work_attempted |= records[id].1;
            match &records[id].0 {
                Ok((record, size)) => {
                    if let Err(error) = session.reserve_evidence(size.saturating_add(1)) {
                        record_failure(result, *index, error);
                        continue;
                    }
                    let mut record = record.clone();
                    result.instances[*index].freshness.merge(record.freshness);
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
        freshness: evidence.freshness,
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
                    .and_then(|name| {
                        if name == "*" {
                            Some(query.name.clone())
                        } else {
                            normalize_name(name).ok()
                        }
                    })
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
