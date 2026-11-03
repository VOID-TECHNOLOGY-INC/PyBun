use pybun::security_assessment::TargetTagProfile;
use pybun::security_assessment::qualification::registry::{
    ReleaseAvailability, parse_registry_catalog,
};
use serde_json::{Value, json};

fn target() -> TargetTagProfile {
    TargetTagProfile {
        profile_version: 1,
        generator: "fixture".into(),
        generator_version: "1".into(),
        digest: "exact-target".into(),
        tags: vec![
            "cp313-cp313-manylinux_2_34_x86_64".into(),
            "py3-none-any".into(),
        ],
        implementation: "cpython".into(),
        python_version: "3.13.0".into(),
        os: "linux".into(),
        architecture: "x86_64".into(),
        libc: Some("glibc-2.34".into()),
        deployment: None,
    }
}

fn file(filename: &str, requires_python: Value, yanked: Value) -> Value {
    json!({"filename":filename,"url":format!("https://files.example.invalid/{filename}"),"hashes":{},"requires-python":requires_python,"yanked":yanked,"size":123})
}

fn catalog(files: Vec<Value>) -> Value {
    json!({"meta":{"api-version":"1.0"},"name":"demo","files":files})
}

#[test]
fn wheel_qualification_is_per_file_and_uses_exact_tags_and_python() {
    let input = catalog(vec![
        file(
            "demo-2.0-cp313-cp313-manylinux_2_34_x86_64.whl",
            json!(">=3.10"),
            json!("withdrawn"),
        ),
        file(
            "demo-2.0-cp312-cp312-manylinux_2_34_x86_64.whl",
            json!(">=3.10"),
            json!(false),
        ),
        file("demo-3.0-py3-none-any.whl", json!(">=3.14"), json!(false)),
        file("demo-4.0-py2.py3-none-any.whl", Value::Null, json!(false)),
    ]);
    let observed = parse_registry_catalog("demo", &input, &target());
    assert_eq!(
        observed.releases[0].availability,
        ReleaseAvailability::Yanked
    );
    assert_eq!(
        observed.releases[1].availability,
        ReleaseAvailability::NoCompatibleWheel
    );
    assert_eq!(
        observed.releases[2].availability,
        ReleaseAvailability::BinaryWheelAvailable
    );
    assert!(!observed.releases[2].files[0].requires_python_declared);
    assert_eq!(
        observed.releases[2].files[0].matched_tags,
        vec!["py3-none-any"]
    );
}

#[test]
fn source_only_and_malformed_python_metadata_remain_explicit() {
    let input = catalog(vec![
        file("demo-2.0.tar.gz", json!(">=3.8"), json!(false)),
        file(
            "demo-3.0-py3-none-any.whl",
            json!("this is not a specifier"),
            json!(false),
        ),
    ]);
    let observed = parse_registry_catalog("demo", &input, &target());
    assert_eq!(
        observed.releases[0].availability,
        ReleaseAvailability::SourceBuildRequired
    );
    assert_eq!(
        observed.releases[1].availability,
        ReleaseAvailability::Unknown
    );
    assert!(!observed.diagnostics.is_empty());
}

#[test]
fn registry_name_is_the_installed_distribution_and_order_is_deterministic() {
    let mut input = catalog(vec![
        file("demo-1!2.0-py3-none-any.whl", Value::Null, json!(false)),
        file("demo-2.0rc1-py3-none-any.whl", Value::Null, json!(false)),
        file("demo-2.0.dev1-py3-none-any.whl", Value::Null, json!(false)),
        file("demo-2.0+local-py3-none-any.whl", Value::Null, json!(false)),
    ]);
    let first = parse_registry_catalog("demo", &input, &target());
    input["files"].as_array_mut().unwrap().reverse();
    let reversed = parse_registry_catalog("demo", &input, &target());
    assert_eq!(first.enumeration_digest, reversed.enumeration_digest);
    assert_eq!(
        first
            .releases
            .iter()
            .map(|r| r.version.as_str())
            .collect::<Vec<_>>(),
        vec!["2.0.dev1", "2.0rc1", "2.0+local", "1!2.0"]
    );
    assert!(first.releases[0].prerelease);
    assert!(first.releases[1].prerelease);
    let mismatch = parse_registry_catalog("public-upstream", &input, &target());
    assert!(mismatch.releases.is_empty());
    assert!(!mismatch.diagnostics.is_empty());
}

#[test]
fn unknown_lower_files_prevent_complete_enumeration() {
    let observed = parse_registry_catalog(
        "demo",
        &catalog(vec![
            file("demo-mystery-py3-none-any.whl", Value::Null, json!(false)),
            file("demo-2.0-py3-none-any.whl", Value::Null, json!(false)),
        ]),
        &target(),
    );
    assert_eq!(observed.releases.len(), 1);
    assert_eq!(observed.unknown_files, 1);
    assert_ne!(
        observed.coverage.status,
        pybun::security_assessment::CoverageStatus::Complete
    );
}

#[test]
fn relative_published_file_references_and_build_tags_are_valid_metadata() {
    let mut published = file(
        "demo-2.0-1build-py3-none-any.whl",
        Value::Null,
        json!(false),
    );
    published["url"] = json!("../files/demo-2.0-1build-py3-none-any.whl");
    published.as_object_mut().unwrap().remove("requires-python");
    let observed = parse_registry_catalog("demo", &catalog(vec![published]), &target());
    assert_eq!(
        observed.releases[0].availability,
        ReleaseAvailability::BinaryWheelAvailable
    );
    assert_eq!(
        observed.releases[0].files[0].url.as_deref(),
        Some("../files/demo-2.0-1build-py3-none-any.whl")
    );
    assert!(!observed.releases[0].files[0].requires_python_declared);
}

#[test]
fn malformed_hashes_are_incomplete_metadata() {
    for digest in [
        "not-a-hex-digest".to_string(),
        "".to_string(),
        "a".repeat(62),
    ] {
        let mut published = file("demo-2.0-py3-none-any.whl", Value::Null, json!(false));
        published["hashes"] = json!({"sha256":digest});
        let observed = parse_registry_catalog("demo", &catalog(vec![published]), &target());
        assert_eq!(
            observed.releases[0].availability,
            ReleaseAvailability::Unknown
        );
    }
}

#[test]
fn invalid_yank_reason_and_negative_file_size_are_not_availability_proofs() {
    for (field, value) in [("yanked", json!("")), ("size", json!(-1))] {
        let mut published = file("demo-2.0-py3-none-any.whl", Value::Null, json!(false));
        published[field] = value;
        let mut input = catalog(vec![published]);
        input["meta"]["api-version"] = json!("1.4");
        input["versions"] = json!(["2.0"]);
        let observed = parse_registry_catalog("demo", &input, &target());
        assert_eq!(
            observed.releases[0].availability,
            ReleaseAvailability::Unknown
        );
    }
}

#[test]
fn modern_simple_metadata_validates_release_set_and_required_file_size() {
    let mut input = catalog(vec![file(
        "demo-2.0-py3-none-any.whl",
        Value::Null,
        json!(false),
    )]);
    input["meta"]["api-version"] = json!("1.4");
    let missing_versions = parse_registry_catalog("demo", &input, &target());
    assert_ne!(
        missing_versions.coverage.status,
        pybun::security_assessment::CoverageStatus::Complete
    );
    input["versions"] = json!(["2.0", "3.0"]);
    let valid = parse_registry_catalog("demo", &input, &target());
    assert_eq!(
        valid.coverage.status,
        pybun::security_assessment::CoverageStatus::Complete
    );
    assert_eq!(
        valid.releases.len(),
        2,
        "fileless declared releases remain visible"
    );
    assert!(valid.releases[1].files.is_empty());
    input["files"][0].as_object_mut().unwrap().remove("size");
    let missing_size = parse_registry_catalog("demo", &input, &target());
    assert_eq!(
        missing_size.releases[0].availability,
        ReleaseAvailability::Unknown
    );
    input["files"][0]["size"] = json!(123);
    input["versions"] = json!(["3.0"]);
    let mismatch = parse_registry_catalog("demo", &input, &target());
    assert_ne!(
        mismatch.coverage.status,
        pybun::security_assessment::CoverageStatus::Complete
    );
}

#[test]
fn equivalent_declared_versions_have_an_order_independent_representative() {
    let mut input = catalog(vec![]);
    input["meta"]["api-version"] = json!("1.4");
    input["versions"] = json!(["1.0.0", "1"]);
    let first = parse_registry_catalog("demo", &input, &target());
    input["versions"].as_array_mut().unwrap().reverse();
    let second = parse_registry_catalog("demo", &input, &target());
    assert_eq!(first.enumeration_digest, second.enumeration_digest);
    assert_eq!(first.releases[0].version, "1");
}

#[test]
fn release_set_digest_ignores_file_metadata_but_tracks_semantic_version_keys() {
    let original = catalog(vec![file(
        "demo-2.0-py3-none-any.whl",
        json!(">=3"),
        json!(false),
    )]);
    let mut changed = original.clone();
    changed["files"][0]["url"] = json!("https://different.example.invalid/demo.whl");
    changed["files"][0]["hashes"] = json!({"sha256":"a".repeat(64)});
    changed["files"][0]["requires-python"] = json!("<3");
    let first = parse_registry_catalog("demo", &original, &target());
    let second = parse_registry_catalog("demo", &changed, &target());
    assert_ne!(
        first.releases[0].availability,
        second.releases[0].availability
    );
    assert_eq!(
        first.enumeration_digest, second.enumeration_digest,
        "file evidence changes must not restart traversal of an unchanged release set"
    );
    changed["files"][0]["filename"] = json!("demo-2-py3-none-any.whl");
    assert_eq!(
        first.enumeration_digest,
        parse_registry_catalog("demo", &changed, &target()).enumeration_digest,
        "PEP equivalent keys have the same position"
    );
    changed["files"].as_array_mut().unwrap().push(file(
        "demo-3-py3-none-any.whl",
        Value::Null,
        json!(false),
    ));
    assert_ne!(
        first.enumeration_digest,
        parse_registry_catalog("demo", &changed, &target()).enumeration_digest
    );
}
