use pybun::security_assessment::{
    CoverageUnit, InventoryObservation, ObservationCoverage, ObservationLimits,
    osv::{AdvisoryObservation, AdvisoryRecord, InstanceAdvisories},
    qualification::{
        schedule::{AssessmentDomain, plan_candidates},
        service::SecurityAssessment,
    },
    semantic::{assessment_id, observation_id},
};
use serde_json::json;

fn assessment() -> SecurityAssessment {
    let domain = AssessmentDomain {
        inventory_digest: "inventory".into(),
        scope_digest: "scope".into(),
        provider_digest: "providers".into(),
        policy_digest: "policy".into(),
        tag_profile_digest: "tags".into(),
        evidence_revision: 1,
    };
    let plan = plan_candidates(&domain, &[], &[], &ObservationLimits::default(), None).unwrap();
    SecurityAssessment {
        assessment_version: 1,
        inventory: InventoryObservation {
            observation_version: 1,
            inventory_id: "inventory".into(),
            observation_id: "observation".into(),
            observed_at: 20,
            target: None,
            packages: vec![],
            direct_constraints: vec![],
            coverage: ObservationCoverage::default(),
            diagnostics: vec![],
        },
        providers: vec![AdvisoryObservation {
            observation_version: 1,
            provider_id: "osv".into(),
            observed_at: 20,
            instances: vec![InstanceAdvisories {
                freshness: Default::default(),
                work_attempted: true,
                instance_id: "instance".into(),
                version: "1".into(),
                source_id: "source".into(),
                auth_scope_id: "auth".into(),
                upstream_name: Some("demo".into()),
                ecosystem: Some("PyPI".into()),
                mapping_assumption: Some("explicit".into()),
                records: vec![AdvisoryRecord {
                    freshness: Default::default(),
                    id: "A".into(),
                    payload: json!({"id":"A","modified":"2026-01-01T00:00:00Z","summary":"original","affected":[{"package":{"name":"demo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}),
                    payload_digest: "a".repeat(64),
                    fetched_at: 20,
                    coverage: CoverageUnit::default(),
                }],
                coverage: CoverageUnit::default(),
            }],
            coverage: CoverageUnit::default(),
            advisory_records: CoverageUnit::default(),
            diagnostics: vec![],
        }],
        packages: vec![],
        provenance: None,
        continuation: plan.continuation,
        invalidated_instances: vec![],
        unknown_remainder: false,
        coverage: CoverageUnit::default(),
        evidence_coverage: ObservationCoverage::default(),
        diagnostics: vec![],
    }
}

#[test]
fn capture_clocks_hashes_and_prose_do_not_change_semantics_but_change_observation_identity() {
    let original = assessment();
    let mut changed = original.clone();
    changed.inventory.observed_at = 40;
    changed.inventory.observation_id = "another-observation".into();
    changed.providers[0].observed_at = 40;
    let record = &mut changed.providers[0].instances[0].records[0];
    record.fetched_at = 40;
    record.payload_digest = "b".repeat(64);
    record.payload["summary"] = json!("rewritten");
    record.payload["modified"] = json!("2026-02-01T00:00:00Z");
    record.payload["affected"][0]["ranges"][0]["events"][1]["fixed"] = json!("2.0.0");
    assert_eq!(
        assessment_id(&original, "policy"),
        assessment_id(&changed, "policy")
    );
    assert_ne!(observation_id(&original), observation_id(&changed));
}

#[test]
fn substantive_ranges_scope_and_provider_changes_change_semantic_identity() {
    let original = assessment();
    let mut changed = original.clone();
    changed.providers[0].instances[0].records[0].payload["affected"][0]["ranges"][0]["events"][1]
        ["fixed"] = json!("3");
    assert_ne!(
        assessment_id(&original, "policy"),
        assessment_id(&changed, "policy")
    );
    assert_ne!(
        assessment_id(&original, "policy"),
        assessment_id(&original, "other-policy")
    );
    let mut changed = original.clone();
    changed.providers[0].provider_id = "another-provider".into();
    assert_ne!(
        assessment_id(&original, "policy"),
        assessment_id(&changed, "policy")
    );
}

#[test]
fn provider_record_and_alias_order_do_not_change_semantics() {
    let mut original = assessment();
    let mut second = original.providers[0].clone();
    second.provider_id = "second".into();
    original.providers.push(second);
    let mut second_record = original.providers[0].instances[0].records[0].clone();
    second_record.id = "B".into();
    second_record.payload["id"] = json!("B");
    original.providers[0].instances[0]
        .records
        .push(second_record);
    original.providers[0].instances[0].records[0].payload["aliases"] = json!(["X", "Y"]);
    let mut changed = original.clone();
    changed.providers[0].instances[0].records[0].payload["aliases"] = json!(["Y", "X"]);
    changed.providers[0].instances[0].records.reverse();
    changed.providers.reverse();
    assert_eq!(
        assessment_id(&original, "policy"),
        assessment_id(&changed, "policy")
    );
}

#[test]
fn normalized_provider_label_case_is_not_new_severity_evidence() {
    let mut original = assessment();
    original.providers[0].instances[0].records[0].payload["database_specific"] =
        json!({"severity":"HIGH"});
    let mut changed = original.clone();
    changed.providers[0].instances[0].records[0].payload["database_specific"] =
        json!({"severity":"high"});
    assert_eq!(
        assessment_id(&original, "policy"),
        assessment_id(&changed, "policy")
    );
}
