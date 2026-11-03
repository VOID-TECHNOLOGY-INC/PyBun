use pybun::security_assessment::{
    CoverageStatus, CoverageUnit, PackageInstance, SourceIdentity, SourceKind, SourceMapping,
    osv::AdvisoryRecord,
    qualification::evidence::{AffectedStatus, evaluate_advisory},
};
use serde_json::{Value, json};

fn package() -> PackageInstance {
    PackageInstance {
        instance_id: "instance".into(),
        name: "internal-demo".into(),
        version: "1.5".into(),
        source: SourceIdentity::new("mirror", "tenant", SourceKind::PrivateRegistry).unwrap(),
        source_mapping: Some(SourceMapping {
            ecosystem: "PyPI".into(),
            upstream_name: "demo".into(),
            assumption: "Operator maps mirror artifact to demo.".into(),
        }),
        scope_variant: "scope".into(),
        distribution_path: "demo.dist-info".into(),
        metadata_digest: "metadata".into(),
        direct_url_digest: None,
        origin_identity: None,
        requires_dist: vec![],
        coverage: CoverageUnit::default(),
    }
}
fn record(affected: Value) -> AdvisoryRecord {
    AdvisoryRecord {
        freshness: Default::default(),
        id: "OSV-1".into(),
        payload: json!({"id":"OSV-1","aliases":["CVE-1"],"modified":"2026-01-01T00:00:00Z","affected":affected}),
        payload_digest: "digest".into(),
        fetched_at: 42,
        coverage: CoverageUnit::default(),
    }
}
fn range(events: Value) -> AdvisoryRecord {
    record(
        json!([{"package":{"ecosystem":"PyPI","name":"demo"},"ranges":[{"type":"ECOSYSTEM","events":events}]}]),
    )
}
#[test]
fn union_intervals_reintroduction_and_current_fixed_boundary_keep_exact_provenance() {
    let r = range(json!([{"introduced":"1"},{"fixed":"2"},{"introduced":"3"},{"fixed":"4"}]));
    for (version, expected, fixed) in [
        ("1.5", AffectedStatus::Yes, Some("2")),
        ("2.5", AffectedStatus::No, None),
        ("3.5", AffectedStatus::Yes, Some("4")),
        ("4", AffectedStatus::No, None),
    ] {
        let e = evaluate_advisory(&package(), version, "osv", &r);
        assert!(e.complete, "{e:?}");
        assert_eq!(e.affected, expected);
        assert_eq!(e.fixed_boundaries.first().map(|f| f.fixed.as_str()), fixed);
        if let Some(f) = e.fixed_boundaries.first() {
            assert_eq!(f.provider_id, "osv");
            assert_eq!(f.record_id, "OSV-1");
            assert_eq!(f.payload_digest, "digest");
            assert_eq!(f.affected_index, 0);
            assert_eq!(f.range_index, 0);
            assert_eq!(f.fixed_event_index, if version == "1.5" { 1 } else { 3 });
        }
    }
}
#[test]
fn unsorted_events_are_sorted_without_losing_original_event_indices() {
    let r = range(json!([{"fixed":"4"},{"introduced":"3"},{"fixed":"2"},{"introduced":"1"}]));
    let e = evaluate_advisory(&package(), "1.5", "osv", &r);
    assert_eq!(e.affected, AffectedStatus::Yes);
    assert!(e.complete);
    assert_eq!(e.fixed_boundaries[0].introduced_event_index, Some(3));
    assert_eq!(e.fixed_boundaries[0].fixed_event_index, 2);
}
#[test]
fn explicit_versions_are_unioned_without_inventing_fixed_evidence() {
    let mut r = range(json!([{"introduced":"1"},{"fixed":"2"}]));
    r.payload["affected"][0]["versions"] = json!(["2.5"]);
    let e = evaluate_advisory(&package(), "2.5", "osv", &r);
    assert_eq!(e.affected, AffectedStatus::Yes);
    assert!(e.complete);
    assert!(e.fixed_boundaries.is_empty());
    let e = evaluate_advisory(&package(), "2.6", "osv", &r);
    assert_eq!(e.affected, AffectedStatus::No);
    assert!(e.fixed_boundaries.is_empty());
}
#[test]
fn last_affected_and_limit_boundaries_never_become_fix_information() {
    for (event, at_boundary) in [
        (json!({"last_affected":"2"}), AffectedStatus::Yes),
        (json!({"limit":"2"}), AffectedStatus::No),
    ] {
        let r = range(json!([{"introduced":"0"},event]));
        let e = evaluate_advisory(&package(), "2", "osv", &r);
        assert!(e.complete);
        assert_eq!(e.affected, at_boundary);
        assert!(e.fixed_boundaries.is_empty());
        assert_eq!(
            evaluate_advisory(&package(), "2.1", "osv", &r).affected,
            AffectedStatus::No
        );
    }
    let r = range(json!([{"limit":"2"},{"introduced":"0"},{"limit":"4"}]));
    assert_eq!(
        evaluate_advisory(&package(), "3", "osv", &r).affected,
        AffectedStatus::Yes
    );
    assert_eq!(
        evaluate_advisory(&package(), "4", "osv", &r).affected,
        AffectedStatus::No
    );
    let r = range(json!([{"limit":"*"},{"introduced":"0"}]));
    assert_eq!(
        evaluate_advisory(&package(), "999", "osv", &r).affected,
        AffectedStatus::Yes
    );
}
#[test]
fn pep440_epoch_local_prerelease_dev_and_zero_sentinel_use_python_ordering() {
    let r = range(json!([{"introduced":"1!1.0.dev1"},{"fixed":"1!1.0"}]));
    assert_eq!(
        evaluate_advisory(&package(), "1!1.0rc1", "osv", &r).affected,
        AffectedStatus::Yes
    );
    assert_eq!(
        evaluate_advisory(&package(), "1!1.0+linux", "osv", &r).affected,
        AffectedStatus::No
    );
    assert_eq!(
        evaluate_advisory(&package(), "9999", "osv", &r).affected,
        AffectedStatus::No
    );
    let r = range(json!([{"introduced":"0"},{"fixed":"1"}]));
    assert_eq!(
        evaluate_advisory(&package(), "0.dev1", "osv", &r).affected,
        AffectedStatus::Yes
    );
}
#[test]
fn malformed_and_contradictory_applicable_data_remain_unknown() {
    for events in [
        json!([]),
        json!([{"fixed":"2"}]),
        json!([{"introduced":"bad"}]),
        json!([{"introduced":"1","fixed":"2"}]),
        json!([{"introduced":"0"},{"fixed":"2"},{"last_affected":"3"}]),
        json!([{"introduced":"1"},{"fixed":"1"}]),
    ] {
        let e = evaluate_advisory(&package(), "1.5", "osv", &range(events));
        assert_eq!(e.affected, AffectedStatus::Unknown, "{e:?}");
        assert!(!e.complete);
        assert!(!e.diagnostics.is_empty());
        assert!(e.fixed_boundaries.is_empty());
    }
    let mut r = range(json!([{"introduced":"0"},{"fixed":"2"}]));
    r.payload["affected"][0]["versions"] = json!(["not-a-version"]);
    let e = evaluate_advisory(&package(), "3", "osv", &r);
    assert_eq!(e.affected, AffectedStatus::Unknown);
    assert!(!e.complete);
}
#[test]
fn git_unknown_does_not_erase_positive_ecosystem_facts_or_establish_negative_facts() {
    let mut r = range(json!([{"introduced":"0"},{"fixed":"2"}]));
    r.payload["affected"][0]["ranges"].as_array_mut().unwrap().push(json!({"type":"GIT","repo":"https://example.invalid/repo","events":[{"introduced":"0"}]}));
    let e = evaluate_advisory(&package(), "1", "osv", &r);
    assert_eq!(e.affected, AffectedStatus::Yes);
    assert!(!e.complete);
    assert_eq!(
        evaluate_advisory(&package(), "3", "osv", &r).affected,
        AffectedStatus::Unknown
    );
}
#[test]
fn package_mapping_and_withdrawal_are_explicit_and_never_cross_sources() {
    let mut r = range(json!([{"introduced":"0"},{"fixed":"2"}]));
    let mut p = package();
    p.source_mapping = None;
    assert_eq!(
        evaluate_advisory(&p, "1", "osv", &r).affected,
        AffectedStatus::Unknown
    );
    r.payload["affected"][0]["package"]["name"] = json!("other");
    assert_eq!(
        evaluate_advisory(&package(), "1", "osv", &r).affected,
        AffectedStatus::No
    );
    r.payload["withdrawn"] = json!("2026-01-02T00:00:00Z");
    let e = evaluate_advisory(&package(), "1", "osv", &r);
    assert_eq!(e.withdrawn.as_deref(), Some("2026-01-02T00:00:00Z"));
    assert!(e.fixed_boundaries.is_empty());
    assert_eq!(e.aliases, vec!["CVE-1"]);
    r.coverage.status = CoverageStatus::Partial;
    assert!(!evaluate_advisory(&package(), "1", "osv", &r).complete);
}

#[test]
fn union_across_matching_entries_preserves_each_record_range_and_ignores_other_packages() {
    let r = record(json!([
        {"package":{"ecosystem":"PyPI","name":"another"},"ranges":"malformed-unrelated"},
        {"package":{"ecosystem":"PyPI","name":"Demo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2"}]}]},
        {"package":{"ecosystem":"PyPI","name":"demo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1"},{"fixed":"3"}]}]}
    ]));
    let e = evaluate_advisory(&package(), "1.5", "osv", &r);
    assert!(e.complete);
    assert_eq!(e.affected, AffectedStatus::Yes);
    assert_eq!(e.fixed_boundaries.len(), 2);
    assert_eq!(e.fixed_boundaries[0].affected_index, 1);
    assert_eq!(e.fixed_boundaries[1].affected_index, 2);
    assert_eq!(e.fixed_boundaries[0].fixed, "2");
    assert_eq!(e.fixed_boundaries[1].fixed, "3");
    assert_eq!(
        evaluate_advisory(&package(), "2.5", "osv", &r).fixed_boundaries[0].fixed,
        "3"
    );
}

#[test]
fn malformed_record_identity_timestamps_aliases_and_shapes_cannot_prove_unaffected() {
    let template = range(json!([{"introduced":"0"},{"fixed":"2"}]));
    let cases = [
        ("id", json!("different-id")),
        ("modified", json!("not-a-timestamp")),
        ("published", json!(17)),
        ("withdrawn", json!("not-a-timestamp")),
        ("aliases", json!([17])),
        ("affected", json!(null)),
    ];
    for (key, value) in cases {
        let mut r = template.clone();
        r.payload[key] = value;
        let e = evaluate_advisory(&package(), "3", "osv", &r);
        assert_eq!(e.affected, AffectedStatus::Unknown, "{e:?}");
        assert!(!e.complete);
        assert!(!e.diagnostics.is_empty());
    }
    let mut r = template.clone();
    r.payload.as_object_mut().unwrap().remove("modified");
    assert_eq!(
        evaluate_advisory(&package(), "3", "osv", &r).affected,
        AffectedStatus::Unknown
    );
    let mut r = template;
    r.coverage.status = CoverageStatus::Partial;
    let e = evaluate_advisory(&package(), "1", "osv", &r);
    assert_eq!(e.affected, AffectedStatus::Yes);
    assert!(!e.complete);
    assert!(
        e.diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_ADVISORY_INCOMPLETE")
    );
}

#[test]
fn missing_applicable_identity_versions_and_invalid_event_shapes_have_indexed_uncertainty() {
    for entry in [
        json!({"ranges":[]}),
        json!({"package":{"ecosystem":"PyPI"},"versions":["1"]}),
        json!({"package":{"ecosystem":"PyPI","name":"demo"}}),
        json!({"package":{"ecosystem":"PyPI","name":"demo"},"versions":[],"ranges":[]}),
        json!({"package":{"ecosystem":"PyPI","name":"demo"},"ranges":null}),
        json!({"package":{"ecosystem":"PyPI","name":"demo"},"versions":null}),
    ] {
        let e = evaluate_advisory(&package(), "1", "osv", &record(json!([entry])));
        assert_eq!(e.affected, AffectedStatus::Unknown);
        assert!(!e.complete);
        assert_eq!(e.diagnostics[0].affected_index, Some(0));
    }
    for event in [
        json!(null),
        json!({}),
        json!({"introduced":17}),
        json!({"unsupported":"1"}),
    ] {
        let e = evaluate_advisory(&package(), "1", "osv", &range(json!([event])));
        assert_eq!(e.affected, AffectedStatus::Unknown);
        assert_eq!(e.diagnostics[0].range_index, Some(0));
        assert_eq!(e.diagnostics[0].event_index, Some(0));
    }
}

#[test]
fn normalized_versions_are_affected_but_newer_absent_versions_have_no_fixed_boundary() {
    let r = record(
        json!([{"package":{"ecosystem":"PyPI","name":"demo"},"versions":["1.0.0","1!2+private"]}]),
    );
    assert_eq!(
        evaluate_advisory(&package(), "1", "osv", &r).affected,
        AffectedStatus::Yes
    );
    assert_eq!(
        evaluate_advisory(&package(), "1!2+private", "osv", &r).affected,
        AffectedStatus::Yes
    );
    let e = evaluate_advisory(&package(), "1!3", "osv", &r);
    assert_eq!(e.affected, AffectedStatus::No);
    assert!(e.fixed_boundaries.is_empty());
    let e = evaluate_advisory(&package(), "invalid-version", "osv", &r);
    assert_eq!(e.affected, AffectedStatus::Unknown);
    assert!(!e.complete);
}

#[test]
fn redundant_status_events_follow_osv_timeline_without_fabricating_fixed_intervals() {
    let r = range(
        json!([{"introduced":"0"},{"introduced":"1"},{"introduced":"1"},{"fixed":"2"},{"fixed":"2"},{"fixed":"3"}]),
    );
    for version in ["0.5", "1.5"] {
        let e = evaluate_advisory(&package(), version, "osv", &r);
        assert!(e.complete, "{e:?}");
        assert_eq!(e.affected, AffectedStatus::Yes);
        assert_eq!(e.fixed_boundaries.len(), 1);
        assert_eq!(e.fixed_boundaries[0].fixed, "2");
        assert_eq!(e.fixed_boundaries[0].introduced_event_index, Some(0));
        assert_eq!(e.fixed_boundaries[0].fixed_event_index, 3);
    }
    for version in ["2", "2.5", "3"] {
        let e = evaluate_advisory(&package(), version, "osv", &r);
        assert!(e.complete);
        assert_eq!(e.affected, AffectedStatus::No);
        assert!(e.fixed_boundaries.is_empty());
    }
    let r = range(json!([{"fixed":"0.5"},{"introduced":"1"},{"fixed":"2"}]));
    assert_eq!(
        evaluate_advisory(&package(), "0.2", "osv", &r).affected,
        AffectedStatus::No
    );
    let e = evaluate_advisory(&package(), "1.5", "osv", &r);
    assert!(e.complete);
    assert_eq!(e.fixed_boundaries[0].introduced_event_index, Some(1));
    assert_eq!(e.fixed_boundaries[0].fixed_event_index, 2);
}

#[test]
fn ecosystem_wildcard_applies_only_to_explicitly_mapped_same_ecosystem() {
    let mut r = range(json!([{"introduced":"0"},{"fixed":"2"}]));
    r.payload["affected"][0]["package"]["name"] = json!("*");
    let e = evaluate_advisory(&package(), "1", "osv", &r);
    assert!(e.complete);
    assert_eq!(e.affected, AffectedStatus::Yes);
    assert_eq!(e.fixed_boundaries[0].fixed, "2");
    assert_eq!(e.fixed_boundaries[0].affected_index, 0);
    assert_eq!(
        evaluate_advisory(&package(), "2", "osv", &r).affected,
        AffectedStatus::No
    );
    let mut unmapped = package();
    unmapped.source_mapping = None;
    assert_eq!(
        evaluate_advisory(&unmapped, "1", "osv", &r).affected,
        AffectedStatus::Unknown
    );
    r.payload["affected"][0]["package"]["ecosystem"] = json!("npm");
    let e = evaluate_advisory(&package(), "1", "osv", &r);
    assert!(e.complete);
    assert_eq!(e.affected, AffectedStatus::No);
    assert!(e.fixed_boundaries.is_empty());
}

#[test]
fn malformed_alias_strings_never_provide_complete_qualification_evidence() {
    for alias in [
        "".to_string(),
        "line\nbreak".into(),
        "CVE 123".into(),
        "x".repeat(201),
    ] {
        let mut record = range(json!([{"introduced":"0"},{"fixed":"2"}]));
        record.payload["aliases"] = json!(["CVE-valid", alias]);
        let evaluated = evaluate_advisory(&package(), "1.5", "osv", &record);
        assert_eq!(evaluated.affected, AffectedStatus::Yes);
        assert!(!evaluated.complete);
        assert_eq!(evaluated.aliases, vec!["CVE-valid"]);
        assert!(
            evaluated
                .diagnostics
                .iter()
                .any(|reason| reason.code == "E_SECURITY_ADVISORY_MALFORMED")
        );
        assert_eq!(record.payload["aliases"].as_array().unwrap().len(), 2);
    }
}

#[test]
fn empty_alias_array_and_printable_unicode_aliases_remain_valid() {
    for aliases in [json!([]), json!(["CVE-valid", "脆弱性-一", "é-2026"])] {
        let mut record = range(json!([{"introduced":"0"},{"fixed":"2"}]));
        record.payload["aliases"] = aliases.clone();
        let evaluated = evaluate_advisory(&package(), "1.5", "osv", &record);
        assert!(evaluated.complete);
        assert_eq!(evaluated.affected, AffectedStatus::Yes);
        assert_eq!(evaluated.aliases.len(), aliases.as_array().unwrap().len());
    }
}
