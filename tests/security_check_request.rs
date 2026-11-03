use pybun::security_assessment::check::{CheckMode, CheckTarget, CheckUpdatesRequest};
use serde_json::json;

#[test]
fn default_security_request_selects_only_the_installed_online_profile() {
    let request: CheckUpdatesRequest = serde_json::from_value(json!({})).unwrap();
    assert_eq!(request.target, CheckTarget::Installed);
    assert_eq!(request.mode, CheckMode::Online);
    assert!(request.profile.is_none());
    assert!(request.limits.is_none());
}

#[test]
fn unknown_fields_and_unapproved_target_spellings_are_usage_errors() {
    for value in [
        json!({"provider":"https://attacker.invalid"}),
        json!({"target":"system"}),
        json!({"mode":"automatic"}),
        json!({"cache_root":"/tmp"}),
        json!({"action":"install"}),
    ] {
        assert!(serde_json::from_value::<CheckUpdatesRequest>(value).is_err());
    }
}

#[test]
fn shared_failure_payload_preserves_operational_exit_and_never_invents_an_empty_assessment() {
    use pybun::security_assessment::{
        ObservationDiagnostic,
        check::{check_json, failed_check},
    };
    let result = failed_check(
        ObservationDiagnostic::new(
            "E_SECURITY_PROFILE_DENIED",
            "The selected profile is not authorized.",
        ),
        3,
    );
    let value = check_json(&result);
    assert_eq!(value["contract_version"], "2");
    assert_eq!(value["assessment_version"], 1);
    assert_eq!(value["exit_code"], 3);
    assert_eq!(value["status"], "error");
    assert!(value["assessment"].is_null());
    assert!(value["assessment_id"].is_null());
    assert!(value["observation_id"].is_null());
    assert!(value["profile_id"].is_null());
    assert_eq!(value["diagnostics"][0]["code"], "E_SECURITY_PROFILE_DENIED");
}
