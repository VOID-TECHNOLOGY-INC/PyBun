use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pybun::security_assessment::ObservationLimits;
use pybun::security_assessment::qualification::schedule::AssessmentContinuation;
use pybun::security_assessment::qualification::schedule::{
    AssessmentDomain, DiscoveryInput, ExactCandidate, plan_candidates,
};
use std::collections::BTreeSet;

fn domain() -> AssessmentDomain {
    AssessmentDomain {
        inventory_digest: "inventory".into(),
        scope_digest: "scope".into(),
        provider_digest: "providers".into(),
        policy_digest: "policy".into(),
        tag_profile_digest: "tags".into(),
        evidence_revision: 1,
    }
}

fn input(name: &str, count: usize) -> DiscoveryInput {
    DiscoveryInput {
        instance_id: name.into(),
        enumeration_digest: format!("set-{count}"),
        versions: (1..=count).map(|v| format!("{v}.0")).collect(),
    }
}

#[test]
fn twenty_first_version_is_reached_and_cursor_does_not_prove_a_minimum() {
    let limits = ObservationLimits::default();
    let inputs = vec![input("package", 30)];
    let first = plan_candidates(&domain(), &inputs, &[], &limits, None).unwrap();
    assert_eq!(first.work.len(), 20);
    assert_eq!(first.work[0].version, "1.0");
    assert!(first.unknown_remainder);
    let second =
        plan_candidates(&domain(), &inputs, &[], &limits, Some(&first.continuation)).unwrap();
    assert_eq!(second.work[0].version, "21.0");
    assert_eq!(second.work.len(), 20);
    let encoded = serde_json::to_string(&second).unwrap();
    assert!(!encoded.contains("lowest_proven_candidate"));
}

#[test]
fn circular_packages_make_progress_with_more_than_ten_packages() {
    let inputs: Vec<_> = (0..12)
        .rev()
        .map(|i| input(&format!("p{i:02}"), 30))
        .collect();
    let limits = ObservationLimits {
        max_candidate_checks: 10,
        ..Default::default()
    };
    let mut continuation = None;
    let mut seen = BTreeSet::new();
    for _ in 0..3 {
        let planned =
            plan_candidates(&domain(), &inputs, &[], &limits, continuation.as_ref()).unwrap();
        assert_eq!(planned.work.len(), 10);
        seen.extend(planned.work.iter().map(|work| work.instance_id.clone()));
        continuation = Some(planned.continuation);
    }
    assert_eq!(seen.len(), 12);
}

#[test]
fn exact_previous_candidates_get_independent_revalidation_without_starving_discovery() {
    let inputs = vec![input("a", 30), input("b", 30)];
    let previous = vec![ExactCandidate {
        instance_id: "a".into(),
        version: "99.0".into(),
    }];
    let limits = ObservationLimits {
        max_candidate_checks: 1,
        ..Default::default()
    };
    let mut continuation = None;
    let mut prior = false;
    let mut discovery = false;
    for _ in 0..6 {
        let planned = plan_candidates(
            &domain(),
            &inputs,
            &previous,
            &limits,
            continuation.as_ref(),
        )
        .unwrap();
        for item in &planned.work {
            prior |= item.instance_id == "a" && item.version == "99.0" && item.revalidation;
            discovery |= item.instance_id == "a" && item.discovery;
        }
        continuation = Some(planned.continuation);
    }
    assert!(prior && discovery);
}

#[test]
fn changed_enumeration_resets_that_offset_and_changed_domain_rejects_cursor() {
    let initial = vec![input("a", 30)];
    let first = plan_candidates(
        &domain(),
        &initial,
        &[],
        &ObservationLimits::default(),
        None,
    )
    .unwrap();
    let changed = vec![input("a", 31)];
    let reset = plan_candidates(
        &domain(),
        &changed,
        &[],
        &ObservationLimits::default(),
        Some(&first.continuation),
    )
    .unwrap();
    assert_eq!(reset.invalidated_instances, vec!["a"]);
    assert_eq!(reset.work[0].version, "1.0");
    let mut other = domain();
    other.policy_digest = "revoked".into();
    assert!(
        plan_candidates(
            &other,
            &initial,
            &[],
            &ObservationLimits::default(),
            Some(&first.continuation)
        )
        .is_err()
    );
}

#[test]
fn equivalent_input_order_and_versions_produce_deterministic_work_and_cursor() {
    let a = input("a", 3);
    let b = input("b", 3);
    let first = plan_candidates(
        &domain(),
        &[a.clone(), b.clone()],
        &[],
        &ObservationLimits::default(),
        None,
    )
    .unwrap();
    let mut reverse_a = a;
    reverse_a.versions.reverse();
    let second = plan_candidates(
        &domain(),
        &[b, reverse_a],
        &[],
        &ObservationLimits::default(),
        None,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&second).unwrap()
    );
}

#[test]
fn unbound_prior_candidates_and_invalid_versions_are_rejected() {
    let previous = vec![ExactCandidate {
        instance_id: "outside".into(),
        version: "2.0".into(),
    }];
    assert!(
        plan_candidates(
            &domain(),
            &[input("a", 2)],
            &previous,
            &ObservationLimits::default(),
            None
        )
        .is_err()
    );
    let mut invalid = input("a", 2);
    invalid.versions.push("not-a-version".into());
    assert!(
        plan_candidates(
            &domain(),
            &[invalid],
            &[],
            &ObservationLimits::default(),
            None
        )
        .is_err()
    );
}

#[test]
fn equivalent_discovery_and_previous_versions_share_one_check() {
    let inputs = vec![DiscoveryInput {
        instance_id: "a".into(),
        enumeration_digest: "same".into(),
        versions: vec!["1.0".into()],
    }];
    let prior = vec![ExactCandidate {
        instance_id: "a".into(),
        version: "1".into(),
    }];
    let planned = plan_candidates(
        &domain(),
        &inputs,
        &prior,
        &ObservationLimits::default(),
        None,
    )
    .unwrap();
    assert_eq!(planned.work.len(), 1);
    assert!(planned.work[0].discovery && planned.work[0].revalidation);
}

#[test]
fn malformed_and_forged_cursor_shapes_are_rejected_before_metadata_work() {
    let initial = plan_candidates(
        &domain(),
        &[input("a", 30), input("b", 30)],
        &[],
        &ObservationLimits::default(),
        None,
    )
    .unwrap();
    let bytes = URL_SAFE_NO_PAD
        .decode(initial.continuation.as_str())
        .unwrap();
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for mode in 0..4 {
        let mut changed = original.clone();
        match mode {
            0 => changed["packages"][0]["discovery_offset"] = serde_json::json!(usize::MAX),
            1 => changed["packages"][1] = changed["packages"][0].clone(),
            2 => changed["next_package"] = serde_json::json!(99),
            _ => changed["lowest_proven_candidate"] = serde_json::json!(true),
        }
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed).unwrap());
        assert!(
            AssessmentContinuation::parse(&encoded).is_err(),
            "forged mode {mode}"
        );
    }
    assert!(AssessmentContinuation::parse("not base64").is_err());
    assert!(AssessmentContinuation::parse(&"a".repeat(512 * 1024 + 1)).is_err());
}

#[test]
fn metadata_priority_uses_validated_circular_order_and_actual_last_attempt() {
    let inputs = vec![input("a", 2), input("b", 2), input("c", 2)];
    let ids = vec!["c".into(), "a".into(), "b".into()];
    assert_eq!(
        AssessmentContinuation::metadata_order(&domain(), &ids, None).unwrap(),
        vec!["a", "b", "c"]
    );
    let limits = ObservationLimits {
        max_candidate_checks: 1,
        ..Default::default()
    };
    let planned = plan_candidates(&domain(), &inputs, &[], &limits, None).unwrap();
    assert_eq!(
        AssessmentContinuation::metadata_order(&domain(), &ids, Some(&planned.continuation))
            .unwrap(),
        vec!["b", "c", "a"]
    );
    let advanced = planned
        .continuation
        .advance_after_metadata(&domain(), &ids, "b")
        .unwrap();
    assert_eq!(
        AssessmentContinuation::metadata_order(&domain(), &ids, Some(&advanced)).unwrap(),
        vec!["c", "a", "b"]
    );
    let decode = |value: &AssessmentContinuation| {
        serde_json::from_slice::<serde_json::Value>(
            &URL_SAFE_NO_PAD.decode(value.as_str()).unwrap(),
        )
        .unwrap()
    };
    assert_eq!(
        decode(&advanced)["packages"],
        decode(&planned.continuation)["packages"]
    );
    assert!(
        advanced
            .advance_after_metadata(&domain(), &ids, "outside")
            .is_err()
    );
    let mut other = domain();
    other.policy_digest = "changed".into();
    assert!(AssessmentContinuation::metadata_order(&other, &ids, Some(&advanced)).is_err());
}

#[test]
fn twenty_overlapping_previous_and_discovery_versions_fill_both_obligations_in_twenty_checks() {
    let inputs = vec![input("a", 20)];
    let previous = inputs[0]
        .versions
        .iter()
        .map(|version| ExactCandidate {
            instance_id: "a".into(),
            version: version.clone(),
        })
        .collect::<Vec<_>>();
    let planned = plan_candidates(
        &domain(),
        &inputs,
        &previous,
        &ObservationLimits::default(),
        None,
    )
    .unwrap();
    assert_eq!(planned.work.len(), 20);
    assert!(
        planned
            .work
            .iter()
            .all(|work| work.discovery && work.revalidation)
    );
    assert!(!planned.unknown_remainder);
}

#[test]
fn producer_rejects_cursor_incompatible_ids_and_enumeration_digests() {
    for id in ["bad/id".to_string(), "x".repeat(129)] {
        assert!(
            plan_candidates(
                &domain(),
                &[input(&id, 1)],
                &[],
                &ObservationLimits::default(),
                None
            )
            .is_err()
        );
    }
    for digest in ["x".repeat(201), "bad\nvalue".into()] {
        let mut value = input("valid", 1);
        value.enumeration_digest = digest;
        assert!(
            plan_candidates(
                &domain(),
                &[value],
                &[],
                &ObservationLimits::default(),
                None
            )
            .is_err()
        );
    }
}

#[test]
fn serialized_candidate_inputs_respect_response_and_aggregate_budgets() {
    let inputs = vec![input("a", 20)];
    let size = serde_json::to_vec(&inputs[0].versions).unwrap().len();
    let limits = ObservationLimits {
        max_response_bytes: size - 1,
        ..Default::default()
    };
    assert!(plan_candidates(&domain(), &inputs, &[], &limits, None).is_err());
    let prior = vec![ExactCandidate {
        instance_id: "a".into(),
        version: "90".into(),
    }];
    let aggregate = serde_json::to_vec(&(&inputs, &prior)).unwrap().len();
    let limits = ObservationLimits {
        max_response_bytes: size,
        max_retained_evidence_bytes: aggregate,
        ..Default::default()
    };
    assert!(plan_candidates(&domain(), &inputs, &prior, &limits, None).is_ok());
    let limits = ObservationLimits {
        max_retained_evidence_bytes: aggregate - 1,
        ..limits
    };
    assert!(plan_candidates(&domain(), &inputs, &prior, &limits, None).is_err());
}

#[test]
fn discovery_catalog_above_twenty_thousand_is_supported_within_byte_budget() {
    let planned = plan_candidates(
        &domain(),
        &[input("a", 20_001)],
        &[],
        &ObservationLimits::default(),
        None,
    )
    .unwrap();
    assert_eq!(planned.work.len(), 20);
    assert!(planned.unknown_remainder);
}

#[test]
fn unobserved_metadata_preserves_discovery_progress_without_restoring_other_state() {
    let ids = vec!["a".to_string(), "b".to_string()];
    let old = plan_candidates(
        &domain(),
        &[input("a", 40), input("b", 40)],
        &[],
        &ObservationLimits::default(),
        None,
    )
    .unwrap();
    let new = plan_candidates(
        &domain(),
        &[input("a", 40), input("b", 0)],
        &[ExactCandidate {
            instance_id: "b".into(),
            version: "90".into(),
        }],
        &ObservationLimits::default(),
        Some(&old.continuation),
    )
    .unwrap();
    let retained = new
        .continuation
        .retain_unobserved_metadata(&old.continuation, &domain(), &ids, &["b".into()])
        .unwrap();
    let decode = |cursor: &AssessmentContinuation| -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(cursor.as_str()).unwrap()).unwrap()
    };
    let old_json = decode(&old.continuation);
    let mut expected = decode(&new.continuation);
    expected["packages"][1]["enumeration_digest"] =
        old_json["packages"][1]["enumeration_digest"].clone();
    expected["packages"][1]["discovery_offset"] =
        old_json["packages"][1]["discovery_offset"].clone();
    assert_eq!(decode(&retained), expected);
    let resumed = plan_candidates(
        &domain(),
        &[input("a", 40), input("b", 40)],
        &[],
        &ObservationLimits::default(),
        Some(&retained),
    )
    .unwrap();
    assert_eq!(
        resumed
            .work
            .iter()
            .find(|w| w.instance_id == "b")
            .unwrap()
            .version,
        "21.0"
    );
    for invalid in [
        vec!["missing".into()],
        vec!["b".into(), "b".into()],
        vec!["../b".into()],
    ] {
        assert!(
            new.continuation
                .retain_unobserved_metadata(&old.continuation, &domain(), &ids, &invalid)
                .is_err()
        );
    }
    let mut other = domain();
    other.policy_digest = "changed".into();
    assert!(
        new.continuation
            .retain_unobserved_metadata(&old.continuation, &other, &ids, &["b".into()])
            .is_err()
    );
    assert!(
        new.continuation
            .retain_unobserved_metadata(&old.continuation, &domain(), &["a".into()], &["a".into()])
            .is_err()
    );
}

#[test]
fn actual_observed_prefix_advances_two_of_twenty_and_reaches_all_forty() {
    let inputs = [input("a", 40)];
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    for _ in 0..20 {
        let planned = plan_candidates(
            &domain(),
            &inputs,
            &[],
            &ObservationLimits::default(),
            cursor.as_ref(),
        )
        .unwrap();
        let observed: Vec<_> = planned
            .work
            .iter()
            .take(2)
            .map(|work| ExactCandidate {
                instance_id: work.instance_id.clone(),
                version: work.version.clone(),
            })
            .collect();
        seen.extend(observed.iter().map(|value| value.version.clone()));
        cursor = Some(
            planned
                .commit_observed_candidates(&domain(), &observed)
                .unwrap(),
        );
    }
    assert_eq!(seen.len(), 40);
}

#[test]
fn checkpoint_does_not_skip_unobserved_prefix_or_accept_deserialized_plans() {
    let planned = plan_candidates(
        &domain(),
        &[input("a", 40)],
        &[],
        &ObservationLimits::default(),
        None,
    )
    .unwrap();
    let later = ExactCandidate {
        instance_id: "a".into(),
        version: planned.work[1].version.clone(),
    };
    let committed = planned
        .commit_observed_candidates(&domain(), &[later])
        .unwrap();
    let retry = plan_candidates(
        &domain(),
        &[input("a", 40)],
        &[],
        &ObservationLimits::default(),
        Some(&committed),
    )
    .unwrap();
    assert_eq!(retry.work[0].version, "1.0");
    let external: pybun::security_assessment::qualification::schedule::CandidatePlan =
        serde_json::from_value(serde_json::to_value(&planned).unwrap()).unwrap();
    assert!(external.commit_observed_candidates(&domain(), &[]).is_err());
}

#[test]
fn prior_offset_is_validated_before_metadata_and_checkpoint_preserves_overlap_phase() {
    let previous = vec![ExactCandidate {
        instance_id: "a".into(),
        version: "1".into(),
    }];
    let limits = ObservationLimits {
        max_candidate_checks: 1,
        ..Default::default()
    };
    let plan = plan_candidates(&domain(), &[input("a", 40)], &previous, &limits, None).unwrap();
    assert!(plan.work[0].discovery && plan.work[0].revalidation);
    let observed = [ExactCandidate {
        instance_id: "a".into(),
        version: "1.0".into(),
    }];
    let cursor = plan
        .commit_observed_candidates(&domain(), &observed)
        .unwrap();
    cursor.validate_previous(&domain(), &previous).unwrap();
    let next = plan_candidates(
        &domain(),
        &[input("a", 40)],
        &previous,
        &limits,
        Some(&cursor),
    )
    .unwrap();
    assert_eq!(next.work[0].version, "2.0");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(cursor.as_str()).unwrap()).unwrap();
    raw["packages"][0]["revalidation_offset"] = 1.into();
    let forged =
        AssessmentContinuation::parse(&URL_SAFE_NO_PAD.encode(serde_json::to_vec(&raw).unwrap()))
            .unwrap();
    assert!(forged.validate_previous(&domain(), &previous).is_err());
}

#[test]
fn package_prefixes_commit_independently_and_unattempted_prior_keeps_its_phase() {
    let inputs = [input("a", 40), input("b", 40)];
    let previous = [ExactCandidate {
        instance_id: "a".into(),
        version: "90".into(),
    }];
    let limits = ObservationLimits {
        max_candidate_checks: 1,
        ..Default::default()
    };
    let first = plan_candidates(&domain(), &inputs[..1], &previous, &limits, None).unwrap();
    assert_eq!(first.work[0].version, "90");
    let empty = first.commit_observed_candidates(&domain(), &[]).unwrap();
    let retry = plan_candidates(&domain(), &inputs[..1], &previous, &limits, Some(&empty)).unwrap();
    assert_eq!(retry.work[0].version, "90");
    let committed = retry
        .commit_observed_candidates(&domain(), &previous)
        .unwrap();
    let next = plan_candidates(
        &domain(),
        &inputs[..1],
        &previous,
        &limits,
        Some(&committed),
    )
    .unwrap();
    assert_eq!(next.work[0].version, "1.0");
    assert!(next.work[0].discovery && !next.work[0].revalidation);

    let plan =
        plan_candidates(&domain(), &inputs, &[], &ObservationLimits::default(), None).unwrap();
    let observed = [
        ExactCandidate {
            instance_id: "a".into(),
            version: "2.0".into(),
        },
        ExactCandidate {
            instance_id: "b".into(),
            version: "1.0".into(),
        },
    ];
    let cursor = plan
        .commit_observed_candidates(&domain(), &observed)
        .unwrap();
    let next = plan_candidates(
        &domain(),
        &inputs,
        &[],
        &ObservationLimits::default(),
        Some(&cursor),
    )
    .unwrap();
    assert_eq!(
        next.work
            .iter()
            .find(|w| w.instance_id == "a")
            .unwrap()
            .version,
        "1.0"
    );
    assert_eq!(
        next.work
            .iter()
            .find(|w| w.instance_id == "b")
            .unwrap()
            .version,
        "2.0"
    );
    let mut other = domain();
    other.policy_digest = "changed".into();
    assert!(plan.commit_observed_candidates(&other, &[]).is_err());
    for candidate in [
        ExactCandidate {
            instance_id: "outside".into(),
            version: "1".into(),
        },
        ExactCandidate {
            instance_id: "a".into(),
            version: "99".into(),
        },
        ExactCandidate {
            instance_id: "a".into(),
            version: "invalid".into(),
        },
    ] {
        assert!(
            plan.commit_observed_candidates(&domain(), &[candidate])
                .is_err()
        );
    }
}

#[test]
fn private_admission_hint_is_bounded_and_legacy_cursor_shape_remains_accepted() {
    let plan = plan_candidates(
        &domain(),
        &[input("a", 40)],
        &[],
        &ObservationLimits::default(),
        None,
    )
    .unwrap();
    let mut raw: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(plan.continuation.as_str()).unwrap())
            .unwrap();
    for invalid in [
        serde_json::json!(0),
        serde_json::json!(201),
        serde_json::json!("one"),
    ] {
        raw["admission_width"] = invalid;
        assert!(
            AssessmentContinuation::parse(
                &URL_SAFE_NO_PAD.encode(serde_json::to_vec(&raw).unwrap())
            )
            .is_err()
        );
    }
    raw.as_object_mut().unwrap().remove("admission_width");
    let legacy =
        AssessmentContinuation::parse(&URL_SAFE_NO_PAD.encode(serde_json::to_vec(&raw).unwrap()))
            .unwrap();
    let next = plan_candidates(
        &domain(),
        &[input("a", 40)],
        &[],
        &ObservationLimits::default(),
        Some(&legacy),
    )
    .unwrap();
    assert_eq!(next.work[0].version, "21.0");
}
