use pybun::security_assessment::{
    CoverageStatus, CoverageUnit, PackageInstance, SourceIdentity, SourceKind, SourceMapping,
    osv::{AdvisoryObservation, AdvisoryRecord, InstanceAdvisories},
    qualification::{
        evidence::AffectedStatus,
        findings::{RelatedAdvisories, assess_findings, assess_findings_with_related},
    },
    semantic_digest,
};
use serde_json::json;

fn package() -> PackageInstance {
    PackageInstance {
        instance_id: "instance".into(),
        name: "demo".into(),
        version: "1.5".into(),
        source: SourceIdentity::new("source", "scope", SourceKind::PublicRegistry).unwrap(),
        source_mapping: Some(SourceMapping {
            ecosystem: "PyPI".into(),
            upstream_name: "demo".into(),
            assumption: "explicit".into(),
        }),
        scope_variant: "selected".into(),
        distribution_path: "demo.dist-info".into(),
        metadata_digest: "metadata".into(),
        direct_url_digest: None,
        origin_identity: None,
        requires_dist: vec![],
        coverage: CoverageUnit::default(),
    }
}
fn observation(provider: &str, id: &str, aliases: &[&str]) -> AdvisoryObservation {
    let p = package();
    let payload = json!({"id":id,"aliases":aliases,"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"demo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]}]});
    AdvisoryObservation {
        observation_version: 1,
        provider_id: provider.into(),
        observed_at: 1,
        instances: vec![InstanceAdvisories {
            freshness: Default::default(),
            work_attempted: true,
            instance_id: p.instance_id,
            version: p.version,
            source_id: p.source.id,
            auth_scope_id: p.source.auth_scope_id,
            upstream_name: Some("demo".into()),
            ecosystem: Some("PyPI".into()),
            mapping_assumption: Some("explicit".into()),
            records: vec![AdvisoryRecord {
                id: id.into(),
                payload_digest: semantic_digest(&payload),
                payload,
                fetched_at: 1,
                freshness: Default::default(),
                coverage: CoverageUnit::default(),
            }],
            coverage: CoverageUnit::default(),
        }],
        coverage: CoverageUnit::default(),
        advisory_records: CoverageUnit::default(),
        diagnostics: vec![],
    }
}
fn providers() -> Vec<String> {
    vec!["a".into(), "b".into(), "c".into()]
}

#[test]
fn alias_chain_unifies_three_providers_and_preserves_exact_evidence() {
    let observations = vec![
        observation("a", "A", &["X"]),
        observation("b", "B", &["X", "Y"]),
        observation("c", "C", &["Y"]),
    ];
    let result = assess_findings(&package(), &providers(), &observations);
    assert!(result.complete);
    assert_eq!(result.affected, AffectedStatus::Yes);
    assert_eq!(result.clusters.len(), 1);
    let cluster = &result.clusters[0];
    assert_eq!(cluster.ids, vec!["A", "B", "C"]);
    assert_eq!(cluster.aliases, vec!["X", "Y"]);
    assert_eq!(cluster.records.len(), 3);
    assert!(
        cluster
            .records
            .iter()
            .all(|record| record.evaluation.fixed_boundaries[0].fixed == "2")
    );
    let mut reversed = observations.clone();
    reversed.reverse();
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        serde_json::to_value(assess_findings(&package(), &providers(), &reversed)).unwrap()
    );
    reversed[0].instances[0].records[0].fetched_at = 99;
    assert_eq!(
        result.clusters[0].cluster_digest,
        assess_findings(&package(), &providers(), &reversed).clusters[0].cluster_digest
    );
}

#[test]
fn missing_provider_is_unknown_without_erasing_positive_records() {
    let result = assess_findings(&package(), &providers(), &[observation("a", "A", &[])]);
    assert!(!result.complete);
    assert_eq!(result.affected, AffectedStatus::Yes);
    assert_eq!(result.coverage.status, CoverageStatus::Partial);
    assert_eq!(
        assess_findings(&package(), &[], &[]).affected,
        AffectedStatus::Unknown
    );
    assert_eq!(
        assess_findings(&package(), &providers(), &[]).affected,
        AffectedStatus::Unknown
    );
}

#[test]
fn source_auth_instance_and_mapping_mismatch_never_contribute_records() {
    for field in 0..6 {
        let mut obs = observation("a", "A", &[]);
        let instance = &mut obs.instances[0];
        match field {
            0 => instance.instance_id = "other".into(),
            1 => instance.source_id = "other".into(),
            2 => instance.auth_scope_id = "other".into(),
            3 => instance.upstream_name = Some("other".into()),
            4 => instance.mapping_assumption = Some("other".into()),
            _ => instance.ecosystem = Some("other".into()),
        }
        let result = assess_findings(&package(), &["a".into()], &[obs]);
        assert!(!result.complete);
        assert!(result.clusters.is_empty());
        assert_eq!(result.affected, AffectedStatus::Unknown);
    }
}

#[test]
fn withdrawn_alias_correction_retains_positive_but_prevents_complete_evidence() {
    let a = observation("a", "A", &["CVE-1"]);
    let mut b = observation("b", "B", &["CVE-1"]);
    let record = &mut b.instances[0].records[0];
    record.payload["withdrawn"] = json!("2026-02-01T00:00:00Z");
    record.payload_digest = semantic_digest(&record.payload);
    let result = assess_findings(&package(), &["a".into(), "b".into()], &[a, b]);
    assert_eq!(result.affected, AffectedStatus::Yes);
    assert!(!result.complete);
    assert_eq!(result.clusters[0].affected, AffectedStatus::Yes);
    assert!(!result.clusters[0].complete);
    assert!(
        result.clusters[0]
            .diagnostics
            .iter()
            .any(|code| code.contains("WITHDRAWAL"))
    );
    assert!(
        result.clusters[0]
            .records
            .iter()
            .any(|record| record.evaluation.withdrawn.is_some())
    );
}

#[test]
fn partial_observation_positive_survives_and_empty_authoritative_observation_is_clean() {
    let mut partial = observation("a", "A", &[]);
    partial.instances[0].coverage.status = CoverageStatus::Partial;
    let result = assess_findings(&package(), &["a".into()], &[partial]);
    assert_eq!(result.affected, AffectedStatus::Yes);
    assert!(!result.complete);
    let mut empty = observation("a", "A", &[]);
    empty.instances[0].records.clear();
    let result = assess_findings(&package(), &["a".into()], &[empty]);
    assert!(result.complete);
    assert_eq!(result.affected, AffectedStatus::No);
}

#[test]
fn malformed_aliases_and_payload_digest_cannot_create_complete_findings() {
    for malformed in [json!([" "]), json!([7]), json!("alias")] {
        let mut obs = observation("a", "A", &[]);
        let record = &mut obs.instances[0].records[0];
        record.payload["aliases"] = malformed;
        record.payload_digest = semantic_digest(&record.payload);
        let result = assess_findings(&package(), &["a".into()], &[obs]);
        assert!(!result.complete);
        assert!(!result.clusters[0].complete);
    }
    let mut obs = observation("a", "A", &[]);
    obs.instances[0].records[0].payload_digest = "forged".into();
    let result = assess_findings(&package(), &["a".into()], &[obs]);
    assert_eq!(result.affected, AffectedStatus::Unknown);
    assert!(!result.complete);
    assert!(
        result.clusters[0].records[0]
            .evaluation
            .fixed_boundaries
            .is_empty()
    );
}

#[test]
fn duplicate_providers_records_and_source_scopes_never_become_complete_or_share_digest() {
    let obs = observation("a", "A", &[]);
    for (required, observations) in [
        (vec!["a".into(), "a".into()], vec![obs.clone()]),
        (vec!["a".into()], vec![obs.clone(), obs.clone()]),
    ] {
        let result = assess_findings(&package(), &required, &observations);
        assert!(!result.complete);
        assert_eq!(result.affected, AffectedStatus::Yes);
    }
    let original = assess_findings(&package(), &["a".into()], std::slice::from_ref(&obs));
    let mut other = package();
    other.source.auth_scope_id = "other".into();
    let mut matched = obs.clone();
    matched.instances[0].auth_scope_id = "other".into();
    let alternate = assess_findings(&other, &["a".into()], &[matched]);
    assert_ne!(
        original.clusters[0].cluster_digest,
        alternate.clusters[0].cluster_digest
    );
    let mut equivalent = obs;
    equivalent.instances[0].version = "1.5.0".into();
    assert!(assess_findings(&package(), &["a".into()], &[equivalent]).complete);
}

#[test]
fn invalid_mapping_or_version_is_not_authoritative_even_for_empty_results() {
    for invalid in 0..3 {
        let mut p = package();
        let mut obs = observation("a", "A", &[]);
        obs.instances[0].records.clear();
        match invalid {
            0 => {
                p.source_mapping.as_mut().unwrap().upstream_name = "!invalid".into();
                obs.instances[0].upstream_name = Some("!invalid".into());
            }
            1 => obs.instances[0].version = "2".into(),
            _ => obs.instances[0].work_attempted = false,
        }
        let result = assess_findings(&p, &["a".into()], &[obs]);
        assert!(!result.complete);
        assert_eq!(result.affected, AffectedStatus::Unknown);
    }
}

#[test]
fn record_validation_and_duplicate_instance_evidence_are_explicitly_incomplete() {
    let mut malformed = observation("a", "A", &[]);
    malformed.instances[0].records[0].payload["id"] = json!("other");
    let record = &mut malformed.instances[0].records[0];
    record.payload_digest = semantic_digest(&record.payload);
    let result = assess_findings(&package(), &["a".into()], &[malformed]);
    assert!(!result.complete);
    assert_eq!(result.affected, AffectedStatus::Unknown);
    let mut duplicate = observation("a", "A", &[]);
    duplicate.instances.push(duplicate.instances[0].clone());
    let result = assess_findings(&package(), &["a".into()], &[duplicate]);
    assert!(!result.complete);
    assert_eq!(result.clusters[0].records.len(), 1);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|code| code.contains("PROVIDER_INCOMPLETE"))
    );
}

#[test]
fn same_advisory_ids_on_other_instances_do_not_join_the_selected_component() {
    let mut observation = observation("a", "A", &["shared"]);
    let mut foreign = observation.instances[0].clone();
    foreign.instance_id = "other-instance".into();
    foreign.records[0].payload["aliases"] = json!(["foreign-alias"]);
    foreign.records[0].payload_digest = semantic_digest(&foreign.records[0].payload);
    observation.instances.push(foreign);
    let selected = assess_findings(
        &package(),
        &["a".into()],
        std::slice::from_ref(&observation),
    );
    assert!(selected.complete);
    assert_eq!(selected.clusters[0].records.len(), 1);
    assert_eq!(selected.clusters[0].aliases, vec!["shared"]);
    let mut other = package();
    other.instance_id = "other-instance".into();
    let foreign = assess_findings(&other, &["a".into()], &[observation]);
    assert_eq!(foreign.clusters[0].aliases, vec!["foreign-alias"]);
    assert_ne!(
        selected.clusters[0].cluster_digest,
        foreign.clusters[0].cluster_digest
    );
}

#[test]
fn cached_positive_is_retained_but_record_or_query_freshness_prevents_authority() {
    use pybun::security_assessment::http::{EvidenceFreshness, FreshnessKind};
    for kind in [FreshnessKind::OfflineCache, FreshnessKind::StaleCache] {
        for record_only in [false, true] {
            let mut observation = observation("a", "A", &[]);
            let freshness = EvidenceFreshness {
                kind,
                age_seconds: 3600,
            };
            if record_only {
                observation.instances[0].records[0].freshness = freshness;
            } else {
                observation.instances[0].freshness = freshness;
            }
            let result = assess_findings(
                &package(),
                &["a".into()],
                std::slice::from_ref(&observation),
            );
            assert_eq!(result.affected, AffectedStatus::Yes);
            assert!(!result.complete);
            assert_eq!(result.coverage.status, CoverageStatus::Partial);
            assert!(
                result
                    .diagnostics
                    .iter()
                    .any(|code| code == "E_SECURITY_FINDING_NOT_FRESH")
            );
            assert_eq!(result.clusters[0].records[0].fetched_at, 1);
            observation.instances[0].freshness.age_seconds = 7200;
            observation.instances[0].records[0].freshness.age_seconds = 7200;
            let older = assess_findings(&package(), &["a".into()], &[observation]);
            assert_eq!(
                result.clusters[0].cluster_digest,
                older.clusters[0].cluster_digest
            );
        }
    }
}

#[test]
fn raw_http_digest_is_a_separate_proof_domain_from_parsed_payload() {
    let mut observation = observation("a", "A", &[]);
    observation.instances[0].records[0].payload_digest = "a".repeat(64);
    let result = assess_findings(&package(), &["a".into()], &[observation]);
    assert!(result.complete);
    assert_eq!(result.affected, AffectedStatus::Yes);
    assert_eq!(result.clusters[0].records[0].payload_digest, "a".repeat(64));
}

#[test]
fn unrelated_provider_aggregate_failure_does_not_taint_complete_target_instance() {
    let mut observation = observation("a", "A", &[]);
    observation.coverage.status = CoverageStatus::Partial;
    observation.advisory_records.status = CoverageStatus::Partial;
    observation.instances[0].records.clear();
    let result = assess_findings(&package(), &["a".into()], &[observation]);
    assert!(result.complete);
    assert_eq!(result.affected, AffectedStatus::No);
}

#[test]
fn semantic_cluster_digest_excludes_raw_proof_hashes_prose_and_fetch_times() {
    let before = observation("a", "A", &["alias"]);
    let mut after = before.clone();
    let record = &mut after.instances[0].records[0];
    record.payload["summary"] = json!("Updated explanatory prose");
    record.payload["references"] = json!([{"type":"WEB","url":"https://example.test/[REDACTED]"}]);
    record.payload_digest = "b".repeat(64);
    record.fetched_at = 1234;
    let first = assess_findings(&package(), &["a".into()], &[before]);
    let second = assess_findings(&package(), &["a".into()], std::slice::from_ref(&after));
    assert_eq!(
        first.clusters[0].cluster_digest,
        second.clusters[0].cluster_digest
    );
    assert_ne!(
        first.clusters[0].records[0].payload_digest,
        second.clusters[0].records[0].payload_digest
    );
    after.instances[0].records[0].payload["affected"][0]["ranges"][0]["events"][1]["fixed"] =
        json!("3");
    let changed = assess_findings(&package(), &["a".into()], &[after]);
    assert_ne!(
        first.clusters[0].cluster_digest,
        changed.clusters[0].cluster_digest
    );
}

#[test]
fn equivalent_fixed_version_spelling_and_event_positions_preserve_cluster_semantics() {
    let before = observation("a", "A", &[]);
    let mut after = before.clone();
    let record = &mut after.instances[0].records[0];
    record.payload["affected"][0]["ranges"][0]["events"] =
        json!([{"fixed":"2.0"},{"introduced":"0"}]);
    record.payload_digest = "c".repeat(64);
    let first = assess_findings(&package(), &["a".into()], &[before]);
    let second = assess_findings(&package(), &["a".into()], &[after]);
    assert_eq!(
        first.clusters[0].cluster_digest,
        second.clusters[0].cluster_digest
    );
}

#[test]
fn related_partial_candidate_query_reveals_installed_positive_with_same_parent() {
    let mut current = observation("a", "A", &[]);
    current.instances[0].records.clear();
    let mut candidate = observation("a", "B", &[]);
    candidate.instances[0].instance_id = "candidate-query".into();
    candidate.instances[0].version = "2".into();
    candidate.instances[0].coverage.status = CoverageStatus::Partial;
    let related = [RelatedAdvisories {
        provider_id: "a",
        parent_instance_id: "instance",
        instance: &candidate.instances[0],
    }];
    let result = assess_findings_with_related(&package(), &["a".into()], &[current], &related);
    assert_eq!(result.affected, AffectedStatus::Yes);
    assert!(result.complete);
    assert_eq!(result.clusters[0].ids, vec!["B"]);
}

#[test]
fn related_withdrawal_corrects_current_alias_and_identical_payloads_are_deduplicated() {
    let current = observation("a", "A", &["shared"]);
    let mut candidate = observation("a", "B", &["shared"]);
    candidate.instances[0].version = "2".into();
    candidate.instances[0].records[0].payload["withdrawn"] = json!("2026-02-01T00:00:00Z");
    candidate.instances[0].records[0].payload_digest = "d".repeat(64);
    let related = [
        RelatedAdvisories {
            provider_id: "a",
            parent_instance_id: "instance",
            instance: &candidate.instances[0],
        },
        RelatedAdvisories {
            provider_id: "a",
            parent_instance_id: "instance",
            instance: &current.instances[0],
        },
    ];
    let result = assess_findings_with_related(
        &package(),
        &["a".into()],
        std::slice::from_ref(&current),
        &related,
    );
    assert_eq!(result.affected, AffectedStatus::Yes);
    assert!(!result.complete);
    assert_eq!(result.clusters[0].records.len(), 2);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|code| code.contains("WITHDRAWAL"))
    );
}

#[test]
fn unrelated_parent_source_or_mapping_never_taints_current_empty_results() {
    for change in 0..4 {
        let mut current = observation("a", "A", &[]);
        current.instances[0].records.clear();
        let mut candidate = observation("a", "B", &[]);
        candidate.instances[0].version = "2".into();
        match change {
            1 => candidate.instances[0].source_id = "foreign".into(),
            2 => candidate.instances[0].mapping_assumption = Some("foreign".into()),
            3 => candidate.instances[0].version = "invalid".into(),
            _ => {}
        }
        let related = [RelatedAdvisories {
            provider_id: "a",
            parent_instance_id: if change == 0 { "other" } else { "instance" },
            instance: &candidate.instances[0],
        }];
        let result = assess_findings_with_related(&package(), &["a".into()], &[current], &related);
        assert_eq!(result.affected, AffectedStatus::No);
        assert!(result.complete);
        assert!(result.clusters.is_empty());
    }
}

#[test]
fn cached_related_negative_does_not_supply_current_evidence_or_age_taint() {
    use pybun::security_assessment::http::{EvidenceFreshness, FreshnessKind};
    for positive in [false, true] {
        let mut current = observation("a", "A", &[]);
        current.instances[0].records.clear();
        let mut candidate = observation("a", "B", &[]);
        candidate.instances[0].version = "3".into();
        if !positive {
            candidate.instances[0].records[0].payload["affected"][0]["ranges"][0]["events"] =
                json!([{"introduced":"3"},{"fixed":"4"}]);
        }
        candidate.instances[0].records[0].freshness = EvidenceFreshness {
            kind: FreshnessKind::OfflineCache,
            age_seconds: 3600,
        };
        candidate.instances[0].records[0].payload_digest = "e".repeat(64);
        let related = [RelatedAdvisories {
            provider_id: "a",
            parent_instance_id: "instance",
            instance: &candidate.instances[0],
        }];
        let result = assess_findings_with_related(&package(), &["a".into()], &[current], &related);
        assert_eq!(result.complete, !positive);
        assert_eq!(
            result.affected,
            if positive {
                AffectedStatus::Yes
            } else {
                AffectedStatus::No
            }
        );
        assert_eq!(result.clusters.is_empty(), !positive);
    }
}

#[test]
fn cached_related_unknown_remains_unknown_and_same_id_distinct_raw_proofs_are_retained() {
    use pybun::security_assessment::http::{EvidenceFreshness, FreshnessKind};
    let mut current = observation("a", "A", &[]);
    current.instances[0].records.clear();
    let mut candidate = observation("a", "B", &[]);
    candidate.instances[0].version = "3".into();
    let record = &mut candidate.instances[0].records[0];
    record.payload["affected"][0]["ranges"] = json!([{"type":"GIT","events":[{"introduced":"0"}]}]);
    record.payload_digest = "f".repeat(64);
    record.freshness = EvidenceFreshness {
        kind: FreshnessKind::StaleCache,
        age_seconds: 3600,
    };
    let result = assess_findings_with_related(
        &package(),
        &["a".into()],
        &[current],
        &[RelatedAdvisories {
            provider_id: "a",
            parent_instance_id: "instance",
            instance: &candidate.instances[0],
        }],
    );
    assert_eq!(result.affected, AffectedStatus::Unknown);
    assert!(!result.complete);
    assert_eq!(result.clusters.len(), 1);
    let current = observation("a", "A", &[]);
    let mut candidate = current.clone();
    candidate.instances[0].version = "3".into();
    candidate.instances[0].records[0].payload_digest = "a".repeat(64);
    let result = assess_findings_with_related(
        &package(),
        &["a".into()],
        &[current],
        &[RelatedAdvisories {
            provider_id: "a",
            parent_instance_id: "instance",
            instance: &candidate.instances[0],
        }],
    );
    assert_eq!(result.clusters[0].records.len(), 2);
}

#[test]
fn cached_related_withdrawal_is_retained_as_correction_to_current_active_alias() {
    use pybun::security_assessment::http::{EvidenceFreshness, FreshnessKind};
    let current = observation("a", "A", &["shared"]);
    let mut candidate = observation("a", "B", &["shared"]);
    candidate.instances[0].version = "3".into();
    let record = &mut candidate.instances[0].records[0];
    record.payload["withdrawn"] = json!("2026-02-01T00:00:00Z");
    record.payload_digest = "d".repeat(64);
    record.freshness = EvidenceFreshness {
        kind: FreshnessKind::StaleCache,
        age_seconds: 3600,
    };
    let result = assess_findings_with_related(
        &package(),
        &["a".into()],
        &[current],
        &[RelatedAdvisories {
            provider_id: "a",
            parent_instance_id: "instance",
            instance: &candidate.instances[0],
        }],
    );
    assert_eq!(result.affected, AffectedStatus::Yes);
    assert!(!result.complete);
    assert_eq!(result.clusters[0].records.len(), 2);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|code| code == "E_SECURITY_FINDING_NOT_FRESH")
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|code| code.contains("WITHDRAWAL"))
    );
    assert!(
        result.clusters[0]
            .records
            .iter()
            .any(|record| record.evaluation.withdrawn.is_some())
    );
}

#[test]
fn exact_provider_declared_severity_labels_have_levels_without_inventing_cvss_scores() {
    for (label, expected) in [
        ("LOW", "low"),
        ("MODERATE", "medium"),
        ("medium", "medium"),
        ("HIGH", "high"),
        ("CRITICAL", "critical"),
    ] {
        let mut observed = observation("a", "A", &[]);
        let record = &mut observed.instances[0].records[0];
        record.payload["database_specific"] = json!({"severity":label});
        record.payload_digest = semantic_digest(&record.payload);
        let result = assess_findings(&package(), &["a".into()], &[observed]);
        assert_eq!(
            serde_json::to_value(result.clusters[0].severity).unwrap(),
            json!(expected)
        );
        assert_eq!(
            serde_json::to_value(&result.clusters[0].records[0]).unwrap()["severity"],
            json!(expected)
        );
    }
    for value in [
        json!(null),
        json!(10),
        json!("IMPORTANT"),
        json!("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ] {
        let mut observed = observation("a", "A", &[]);
        observed.instances[0].records[0].payload["database_specific"] = json!({"severity":value});
        let result = assess_findings(&package(), &["a".into()], &[observed]);
        assert_eq!(
            serde_json::to_value(result.clusters[0].severity).unwrap(),
            json!("unknown")
        );
    }
}

#[test]
fn mixed_unknown_severity_stays_conservative_and_known_label_changes_are_semantic() {
    let mut a = observation("a", "A", &["B"]);
    a.instances[0].records[0].payload["database_specific"] = json!({"severity":"LOW"});
    let b = observation("b", "B", &[]);
    let mixed = assess_findings(&package(), &["a".into(), "b".into()], &[a.clone(), b]);
    assert_eq!(
        serde_json::to_value(mixed.clusters[0].severity).unwrap(),
        json!("unknown")
    );
    let low = assess_findings(&package(), &["a".into()], &[a.clone()]);
    a.instances[0].records[0].payload["database_specific"] = json!({"severity":"HIGH"});
    let high = assess_findings(&package(), &["a".into()], &[a]);
    assert_ne!(
        low.clusters[0].cluster_digest,
        high.clusters[0].cluster_digest
    );
}
