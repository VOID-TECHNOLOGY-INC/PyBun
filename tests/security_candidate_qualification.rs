use pybun::security_assessment::osv::{AdvisoryRecord, InstanceAdvisories};
use pybun::security_assessment::qualification::{
    candidate::{
        CandidateAvailability, CandidateKind, CandidateProviderEvidence, qualify_candidate,
    },
    evidence::AffectedStatus,
    registry::{RegistryCatalog, RegistryRelease, ReleaseAvailability},
    registry_source::RegistryObservation,
};
use pybun::security_assessment::{
    CoverageUnit, PackageInstance, SourceIdentity, SourceKind, SourceMapping,
};
use serde_json::json;

fn package() -> PackageInstance {
    PackageInstance {
        instance_id: "i".into(),
        name: "demo".into(),
        version: "1.5".into(),
        source: SourceIdentity::new("public", "public", SourceKind::PublicRegistry).unwrap(),
        source_mapping: Some(SourceMapping {
            ecosystem: "PyPI".into(),
            upstream_name: "demo".into(),
            assumption: "explicit".into(),
        }),
        scope_variant: "scope".into(),
        distribution_path: "demo.dist-info".into(),
        metadata_digest: "d".into(),
        direct_url_digest: None,
        origin_identity: None,
        requires_dist: vec![],
        coverage: CoverageUnit::default(),
    }
}
fn record(id: &str, events: serde_json::Value) -> AdvisoryRecord {
    AdvisoryRecord {
        freshness: Default::default(),
        id: id.into(),
        payload: json!({"id":id,"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":events}]}]}),
        payload_digest: id.into(),
        fetched_at: 1,
        coverage: CoverageUnit::default(),
    }
}
fn observation(version: &str, records: Vec<AdvisoryRecord>) -> InstanceAdvisories {
    InstanceAdvisories {
        freshness: Default::default(),
        work_attempted: true,
        instance_id: "i".into(),
        version: version.into(),
        source_id: "public".into(),
        auth_scope_id: "public".into(),
        upstream_name: Some("demo".into()),
        ecosystem: Some("PyPI".into()),
        mapping_assumption: Some("explicit".into()),
        records,
        coverage: CoverageUnit::default(),
    }
}
fn release(version: &str) -> RegistryObservation {
    RegistryObservation {
        freshness: Default::default(),
        source_id: "public".into(),
        source_auth_scope_id: "public".into(),
        provider_id: "registry".into(),
        provider_auth_scope_id: "public".into(),
        distribution: "demo".into(),
        fetched_at: 1,
        payload_digest: "registry-payload".into(),
        catalog: RegistryCatalog {
            distribution: "demo".into(),
            enumeration_digest: "releases".into(),
            releases: vec![RegistryRelease {
                version: version.into(),
                prerelease: false,
                availability: ReleaseAvailability::BinaryWheelAvailable,
                files: vec![],
                coverage: CoverageUnit::default(),
            }],
            unknown_files: 0,
            unknown_versions: 0,
            coverage: CoverageUnit::default(),
            diagnostics: vec![],
        },
    }
}

#[test]
fn explicit_current_fixed_boundary_and_complete_requery_are_both_required() {
    let current = observation(
        "1.5",
        vec![record(
            "A",
            json!([{"introduced":"1"},{"fixed":"2"},{"introduced":"3"},{"fixed":"4"}]),
        )],
    );
    for (version, expected, affected) in [
        (
            "2.5",
            Some(CandidateKind::PublishedRemediationCandidate),
            AffectedStatus::No,
        ),
        ("3.5", None, AffectedStatus::Yes),
    ] {
        let candidate = observation(version, vec![]);
        let result = qualify_candidate(
            &package(),
            version,
            Some(&release(version)),
            &["osv".into()],
            &[CandidateProviderEvidence {
                related: &[],
                candidate_instance_id: "i",
                provider_id: "osv",
                current: Some(&current),
                candidate: Some(&candidate),
            }],
        );
        assert_eq!(result.candidate_kind, expected);
        if expected == Some(CandidateKind::PublishedRemediationCandidate) {
            assert!(!result.published_remediation_basis.is_empty());
            assert_eq!(result.published_remediation_basis[0].fixed, "2");
        } else {
            assert!(result.published_remediation_basis.is_empty());
        }

        assert_eq!(
            result.affected, affected,
            "installed records must also be evaluated at the candidate"
        );
        assert_eq!(
            serde_json::to_value(&result).unwrap()["resolution_status"],
            "not_checked"
        );
        assert_eq!(
            serde_json::to_value(&result).unwrap()["verification_status"],
            "not_run"
        );
    }
}
#[test]
fn last_affected_and_versions_only_do_not_invent_a_published_patch() {
    let mut versions = record("V", json!([]));
    versions.payload["affected"][0] =
        json!({"package":{"name":"demo","ecosystem":"PyPI"},"versions":["1.5"]});
    for r in [
        record("L", json!([{"introduced":"0"},{"last_affected":"1.5"}])),
        versions,
    ] {
        let current = observation("1.5", vec![r]);
        let candidate = observation("2", vec![]);
        let result = qualify_candidate(
            &package(),
            "2",
            Some(&release("2")),
            &["osv".into()],
            &[CandidateProviderEvidence {
                related: &[],
                candidate_instance_id: "i",
                provider_id: "osv",
                current: Some(&current),
                candidate: Some(&candidate),
            }],
        );
        assert_eq!(
            result.candidate_kind,
            Some(CandidateKind::NonAffectedUpgradeObserved)
        );
        assert!(result.fixed_boundaries.is_empty());
    }
}
#[test]
fn another_advisory_or_missing_authoritative_provider_prevents_qualification() {
    let current = observation(
        "1.5",
        vec![record("A", json!([{"introduced":"0"},{"fixed":"2"}]))],
    );
    let clean = observation("2", vec![]);
    let affected = observation("2", vec![record("B", json!([{"introduced":"2"}]))]);
    for (candidate, providers, expected) in [
        (&affected, vec!["osv".into()], AffectedStatus::Yes),
        (
            &clean,
            vec!["osv".into(), "second".into()],
            AffectedStatus::Unknown,
        ),
    ] {
        let result = qualify_candidate(
            &package(),
            "2",
            Some(&release("2")),
            &providers,
            &[CandidateProviderEvidence {
                related: &[],
                candidate_instance_id: "i",
                provider_id: "osv",
                current: Some(&current),
                candidate: Some(candidate),
            }],
        );
        assert_eq!(result.affected, expected);
        assert_eq!(result.candidate_kind, None);
    }
}
#[test]
fn source_build_and_wrong_source_observation_are_not_binary_remediation() {
    let current = observation(
        "1.5",
        vec![record("A", json!([{"introduced":"0"},{"fixed":"2"}]))],
    );
    let mut candidate = observation("2", vec![]);
    let mut source_only = release("2");
    source_only.catalog.releases[0].availability = ReleaseAvailability::SourceBuildRequired;
    let result = qualify_candidate(
        &package(),
        "2",
        Some(&source_only),
        &["osv".into()],
        &[CandidateProviderEvidence {
            related: &[],
            candidate_instance_id: "i",
            provider_id: "osv",
            current: Some(&current),
            candidate: Some(&candidate),
        }],
    );
    assert_eq!(result.affected, AffectedStatus::No);
    assert_eq!(
        result.availability,
        CandidateAvailability::SourceBuildRequired
    );
    assert_eq!(result.candidate_kind, None);
    candidate.source_id = "other".into();
    let result = qualify_candidate(
        &package(),
        "2",
        Some(&release("2")),
        &["osv".into()],
        &[CandidateProviderEvidence {
            related: &[],
            candidate_instance_id: "i",
            provider_id: "osv",
            current: Some(&current),
            candidate: Some(&candidate),
        }],
    );
    assert_eq!(result.affected, AffectedStatus::Unknown);
}
#[test]
fn changed_record_withdrawal_is_correction_evidence_not_a_published_fix() {
    let current = observation(
        "1.5",
        vec![record("A", json!([{"introduced":"0"},{"fixed":"2"}]))],
    );
    let mut withdrawn = current.records[0].clone();
    withdrawn.payload["withdrawn"] = json!("2026-01-02T00:00:00Z");
    withdrawn.payload_digest = "withdrawn-revision".into();
    let candidate = observation("2", vec![withdrawn]);
    let result = qualify_candidate(
        &package(),
        "2",
        Some(&release("2")),
        &["osv".into()],
        &[CandidateProviderEvidence {
            related: &[],
            candidate_instance_id: "i",
            provider_id: "osv",
            current: Some(&current),
            candidate: Some(&candidate),
        }],
    );
    assert_eq!(result.candidate_kind, None);
    assert!(
        result.providers[0]
            .candidate
            .iter()
            .any(|record| record.withdrawn.is_some())
    );
}
#[test]
fn current_instance_mapping_assumption_and_provider_identity_must_match() {
    for mismatch in 0..3 {
        let mut current = observation(
            "1.5",
            vec![record("A", json!([{"introduced":"0"},{"fixed":"2"}]))],
        );
        let candidate = observation("2", vec![]);
        let provider = if mismatch == 2 { "" } else { "osv" };
        if mismatch == 0 {
            current.instance_id = "other-installed-variant".into();
        }
        if mismatch == 1 {
            current.mapping_assumption = Some("changed source equivalence".into());
        }
        let result = qualify_candidate(
            &package(),
            "2",
            Some(&release("2")),
            &[provider.into()],
            &[CandidateProviderEvidence {
                related: &[],
                candidate_instance_id: "i",
                provider_id: provider,
                current: Some(&current),
                candidate: Some(&candidate),
            }],
        );
        assert_eq!(result.candidate_kind, None, "mismatch {mismatch}");
    }
}

#[test]
fn registry_publication_from_another_source_cannot_qualify_the_candidate() {
    let current = observation(
        "1.5",
        vec![record("A", json!([{"introduced":"0"},{"fixed":"2"}]))],
    );
    let candidate = observation("2", vec![]);
    let mut published = release("2");
    published.source_id = "other-source".into();
    let result = qualify_candidate(
        &package(),
        "2",
        Some(&published),
        &["osv".into()],
        &[CandidateProviderEvidence {
            related: &[],
            provider_id: "osv",
            candidate_instance_id: "i",
            current: Some(&current),
            candidate: Some(&candidate),
        }],
    );
    assert_eq!(result.availability, CandidateAvailability::Unknown);
    assert_eq!(result.candidate_kind, None);
}

#[test]
fn cached_positive_is_retained_but_cannot_qualify_a_fresh_patch_observation() {
    let mut current = observation(
        "1.5",
        vec![record("A", json!([{"introduced":"0"},{"fixed":"2"}]))],
    );
    current.records[0].freshness = pybun::security_assessment::http::EvidenceFreshness {
        kind: pybun::security_assessment::http::FreshnessKind::OfflineCache,
        age_seconds: 30,
    };
    let candidate = observation("2", vec![]);
    let result = qualify_candidate(
        &package(),
        "2",
        Some(&release("2")),
        &["osv".into()],
        &[CandidateProviderEvidence {
            related: &[],
            provider_id: "osv",
            candidate_instance_id: "i",
            current: Some(&current),
            candidate: Some(&candidate),
        }],
    );
    assert_eq!(result.current_affected, AffectedStatus::Yes);
    assert_eq!(result.candidate_kind, None);
}

#[test]
fn known_fixed_boundary_is_independent_of_source_build_availability() {
    let current = observation(
        "1.5",
        vec![record("A", json!([{"introduced":"0"},{"fixed":"2"}]))],
    );
    let candidate = observation("2", vec![]);
    let mut registry = release("2");
    registry.catalog.releases[0].availability = ReleaseAvailability::SourceBuildRequired;
    let result = qualify_candidate(
        &package(),
        "2",
        Some(&registry),
        &["osv".into()],
        &[CandidateProviderEvidence {
            related: &[],
            provider_id: "osv",
            candidate_instance_id: "i",
            current: Some(&current),
            candidate: Some(&candidate),
        }],
    );
    assert_eq!(
        serde_json::to_value(&result).unwrap()["fix_evidence"],
        "known_boundary"
    );
    assert!(!result.fixed_boundaries.is_empty());
}

#[test]
fn cross_provider_alias_withdrawal_keeps_positive_but_cannot_qualify_a_patch() {
    let mut active = record("A", json!([{"introduced":"0"},{"fixed":"2"}]));
    active.payload["aliases"] = json!(["CVE-shared"]);
    let mut withdrawn = record("B", json!([{"introduced":"0"},{"fixed":"2"}]));
    withdrawn.payload["aliases"] = json!(["CVE-shared"]);
    withdrawn.payload["withdrawn"] = json!("2026-01-02T00:00:00Z");
    let a = observation("1.5", vec![active]);
    let b = observation("1.5", vec![withdrawn.clone()]);
    let ac = observation("2", vec![]);
    let bc = observation("2", vec![withdrawn]);
    let result = qualify_candidate(
        &package(),
        "2",
        Some(&release("2")),
        &["a".into(), "b".into()],
        &[
            CandidateProviderEvidence {
                related: &[],
                provider_id: "a",
                candidate_instance_id: "i",
                current: Some(&a),
                candidate: Some(&ac),
            },
            CandidateProviderEvidence {
                related: &[],
                provider_id: "b",
                candidate_instance_id: "i",
                current: Some(&b),
                candidate: Some(&bc),
            },
        ],
    );
    assert_eq!(result.current_affected, AffectedStatus::Yes);
    assert!(result.candidate_kind.is_none());
    assert!(!result.authoritative);
}
#[test]
fn prose_only_record_revision_does_not_erase_explicit_fixed_evidence() {
    let current = observation(
        "1.5",
        vec![record("A", json!([{"introduced":"0"},{"fixed":"2"}]))],
    );
    let mut revised = current.records[0].clone();
    revised.payload["summary"] = json!("updated description only");
    revised.payload_digest = "new-raw-body".into();
    let candidate = observation("2", vec![revised]);
    let result = qualify_candidate(
        &package(),
        "2",
        Some(&release("2")),
        &["osv".into()],
        &[CandidateProviderEvidence {
            related: &[],
            provider_id: "osv",
            candidate_instance_id: "i",
            current: Some(&current),
            candidate: Some(&candidate),
        }],
    );
    assert_eq!(
        result.candidate_kind,
        Some(CandidateKind::PublishedRemediationCandidate)
    );
}

#[test]
fn complete_registry_absence_is_not_observed_for_an_exact_previous_version() {
    let current = observation(
        "1.5",
        vec![record("A", json!([{"introduced":"0"},{"fixed":"2"}]))],
    );
    let candidate = observation("4", vec![]);
    let result = qualify_candidate(
        &package(),
        "4",
        Some(&release("2")),
        &["osv".into()],
        &[CandidateProviderEvidence {
            provider_id: "osv",
            related: &[],
            candidate_instance_id: "i",
            current: Some(&current),
            candidate: Some(&candidate),
        }],
    );
    assert_eq!(result.availability, CandidateAvailability::NotObserved);
    assert!(result.candidate_kind.is_none());
}

#[test]
fn stale_related_withdrawal_cannot_be_erased_by_fresh_empty_candidate_queries() {
    use pybun::security_assessment::qualification::findings::RelatedAdvisories;
    let mut active = record("A", json!([{"introduced":"0"},{"fixed":"2"}]));
    active.payload["aliases"] = json!(["CVE-shared"]);
    let mut withdrawn = record("B", json!([]));
    withdrawn.payload["aliases"] = json!(["CVE-shared"]);
    withdrawn.payload["withdrawn"] = json!("2026-01-02T00:00:00Z");
    withdrawn.freshness.kind = pybun::security_assessment::http::FreshnessKind::StaleCache;
    let a = observation("1.5", vec![active]);
    let b = observation("1.5", vec![]);
    let ac = observation("2", vec![]);
    let bc = observation("2", vec![]);
    let mut old = observation("3", vec![withdrawn]);
    old.freshness.kind = pybun::security_assessment::http::FreshnessKind::StaleCache;
    let related = [RelatedAdvisories {
        provider_id: "b",
        parent_instance_id: "i",
        instance: &old,
    }];
    let result = qualify_candidate(
        &package(),
        "2",
        Some(&release("2")),
        &["a".into(), "b".into()],
        &[
            CandidateProviderEvidence {
                provider_id: "a",
                related: &related,
                candidate_instance_id: "i",
                current: Some(&a),
                candidate: Some(&ac),
            },
            CandidateProviderEvidence {
                provider_id: "b",
                related: &related,
                candidate_instance_id: "i",
                current: Some(&b),
                candidate: Some(&bc),
            },
        ],
    );
    assert_eq!(result.current_affected, AffectedStatus::Yes);
    assert!(result.candidate_kind.is_none());
    assert!(!result.authoritative);
    assert!(
        result
            .providers
            .iter()
            .flat_map(|provider| &provider.current)
            .any(|record| record.withdrawn.is_some())
    );
}
