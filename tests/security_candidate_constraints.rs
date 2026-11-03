use pybun::security_assessment::qualification::constraints::{
    ConstraintStatus, FullConstraintCompleteness, evaluate_constraints,
};
use pybun::security_assessment::{
    ConstraintEvidence, InventoryObservation, InventoryRequest, PackageInstance, SourceIdentity,
    SourceKind, SourceMapping, observe_inventory,
};
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;
fn fixture(requirements: &[&str]) -> (TempDir, InventoryObservation, PackageInstance) {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='test'\nversion='1'\n",
    )
    .unwrap();
    let name = std::env::var_os("PYBUN_SECURITY_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let out = Command::new(name)
        .args(["-I", "-S", "-B", "-c", "import sys;print(sys.executable)"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let python = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
    assert!(
        Command::new(&python)
            .args(["-I", "-B", "-m", "venv", "--without-pip"])
            .arg(dir.path().join(".venv"))
            .status()
            .unwrap()
            .success()
    );
    let mut inventory = observe_inventory(&InventoryRequest::installed(dir.path(), &python), 0);
    assert!(inventory.target.is_some());
    inventory.direct_constraints = requirements
        .iter()
        .map(|requirement| ConstraintEvidence {
            requirement: (*requirement).into(),
            origin: "pyproject.toml:project.dependencies".into(),
            digest: "project-digest".into(),
        })
        .collect();
    let package = PackageInstance {
        instance_id: "demo-instance".into(),
        name: "demo".into(),
        version: "1".into(),
        source: SourceIdentity::new("public", "public-auth", SourceKind::PublicRegistry).unwrap(),
        source_mapping: Some(SourceMapping {
            ecosystem: "PyPI".into(),
            upstream_name: "demo".into(),
            assumption: "Operator maps this artifact.".into(),
        }),
        scope_variant: "scope".into(),
        distribution_path: "demo-1.dist-info".into(),
        metadata_digest: "metadata".into(),
        direct_url_digest: None,
        origin_identity: None,
        requires_dist: vec![],
        coverage: Default::default(),
    };
    (dir, inventory, package)
}
#[test]
fn direct_blocker_preserves_candidate_and_exact_provenance_with_unknown_full_graph() {
    let (_dir, inventory, package) = fixture(&["demo<2", "unrelated>=100"]);
    let result = evaluate_constraints(&inventory, &package, "2");
    assert_eq!(
        result.constraint_status,
        ConstraintStatus::BlockedByKnownConstraint
    );
    assert_eq!(
        result.known_direct_status,
        ConstraintStatus::BlockedByKnownConstraint
    );
    assert!(result.is_direct_dependency);
    assert_eq!(
        result.full_constraint_completeness,
        FullConstraintCompleteness::Unknown
    );
    assert_eq!(result.blockers.len(), 1);
    assert_eq!(result.blockers[0].candidate_version, "2");
    assert_eq!(result.blockers[0].requirement, "demo<2");
    assert_eq!(
        result.blockers[0].origin,
        inventory.direct_constraints[0].origin
    );
    assert_eq!(result.blockers[0].digest, "project-digest");
    assert_eq!(result.evaluated.len(), 1);
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        serde_json::json!({
            "candidate_version":"2","constraint_status":"blocked_by_known_constraint","known_direct_status":"blocked_by_known_constraint","is_direct_dependency":true,"full_constraint_completeness":"unknown",
            "blockers":[{"candidate_version":"2","requirement":"demo<2","origin":"pyproject.toml:project.dependencies","digest":"project-digest"}],
            "evaluated":[{"requirement":"demo<2","origin":"pyproject.toml:project.dependencies","digest":"project-digest","applies":true,"satisfied":false,"reason":null}],
            "coverage":{"status":"complete","requested":1,"complete":1,"partial":0,"unsupported":0,"errors":0,"reasons":[]},"diagnostics":[]
        })
    );
}
#[test]
fn known_passing_root_constraint_is_separate_from_transitive_or_manual_unknown() {
    let (_dir, mut inventory, package) = fixture(&["demo<2"]);
    let direct = evaluate_constraints(&inventory, &package, "1.5");
    assert_eq!(
        direct.constraint_status,
        ConstraintStatus::PassesKnownConstraints
    );
    assert!(direct.is_direct_dependency);
    inventory.direct_constraints.clear();
    let transitive = evaluate_constraints(&inventory, &package, "1.5");
    assert_eq!(transitive.constraint_status, ConstraintStatus::Unknown);
    assert_eq!(
        transitive.known_direct_status,
        ConstraintStatus::PassesKnownConstraints
    );
    assert!(!transitive.is_direct_dependency);
    assert_eq!(
        transitive.full_constraint_completeness,
        FullConstraintCompleteness::Unknown
    );
}
#[test]
fn exact_machine_case_full_prerelease_and_selected_extras_control_applicability() {
    let (_dir, mut inventory, package) = fixture(&[
        "demo<2; platform_machine == 'AMD64'",
        "demo>=2; platform_machine == 'amd64'",
    ]);
    inventory
        .target
        .as_mut()
        .unwrap()
        .marker_environment
        .insert("platform_machine".into(), "AMD64".into());
    let result = evaluate_constraints(&inventory, &package, "2");
    assert_eq!(result.blockers.len(), 1);
    assert!(result.blockers[0].requirement.contains("AMD64"));
    assert_eq!(result.evaluated[1].applies, Some(false));
    inventory.direct_constraints[0].requirement = "demo<2; extra == 'security'".into();
    inventory.direct_constraints.truncate(1);
    inventory.target.as_mut().unwrap().scope.extras.clear();
    let not_selected = evaluate_constraints(&inventory, &package, "2");
    assert!(not_selected.blockers.is_empty());
    assert_eq!(not_selected.evaluated[0].applies, Some(false));
    inventory
        .target
        .as_mut()
        .unwrap()
        .scope
        .extras
        .push("security".into());
    assert_eq!(
        evaluate_constraints(&inventory, &package, "2")
            .blockers
            .len(),
        1
    );
    inventory.direct_constraints[0].requirement = "demo<2; python_full_version >= '3.15'".into();
    inventory
        .target
        .as_mut()
        .unwrap()
        .marker_environment
        .insert("python_full_version".into(), "3.15.0rc2".into());
    let result = evaluate_constraints(&inventory, &package, "2");
    assert!(result.blockers.is_empty());
    assert_eq!(result.evaluated[0].applies, Some(false));
}
#[test]
fn malformed_declarations_and_missing_marker_environment_are_unknown_without_erasing_blockers() {
    let (_dir, mut inventory, package) = fixture(&["demo<2", "not a requirement private-secret"]);
    let result = evaluate_constraints(&inventory, &package, "2");
    assert_eq!(
        result.constraint_status,
        ConstraintStatus::BlockedByKnownConstraint
    );
    assert_eq!(result.blockers.len(), 1);
    assert!(!result.diagnostics.is_empty());
    inventory.direct_constraints[0].requirement = "demo<2; platform_machine == 'AMD64'".into();
    inventory.direct_constraints.truncate(1);
    inventory
        .target
        .as_mut()
        .unwrap()
        .marker_environment
        .clear();
    let unknown = evaluate_constraints(&inventory, &package, "2");
    assert_eq!(unknown.constraint_status, ConstraintStatus::Unknown);
    assert!(unknown.blockers.is_empty());
    assert_eq!(unknown.evaluated[0].applies, None);
}
#[test]
fn source_url_constraints_are_unknown_without_fetch_or_build_and_diagnostics_are_redacted() {
    let (_dir, inventory, package) =
        fixture(&["demo @ https://user:private-secret@example.invalid/demo.whl"]);
    let result = evaluate_constraints(&inventory, &package, "2");
    assert_eq!(result.constraint_status, ConstraintStatus::Unknown);
    assert!(result.is_direct_dependency);
    assert!(result.blockers.is_empty());
    assert_eq!(result.evaluated[0].applies, Some(true));
    assert_eq!(result.evaluated[0].satisfied, None);
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("private-secret")
    );
}
#[test]
fn pep440_epoch_local_prerelease_and_dev_are_evaluated_without_a_semver_approximation() {
    let (_dir, mut inventory, package) = fixture(&["demo>=1!1"]);
    assert_eq!(
        evaluate_constraints(&inventory, &package, "999").known_direct_status,
        ConstraintStatus::BlockedByKnownConstraint
    );
    assert_eq!(
        evaluate_constraints(&inventory, &package, "1!1.1").known_direct_status,
        ConstraintStatus::PassesKnownConstraints
    );
    inventory.direct_constraints[0].requirement = "demo==1.0".into();
    assert_eq!(
        evaluate_constraints(&inventory, &package, "1.0+vendor").known_direct_status,
        ConstraintStatus::PassesKnownConstraints
    );
    inventory.direct_constraints[0].requirement = "demo>=2.0rc1".into();
    assert_eq!(
        evaluate_constraints(&inventory, &package, "2.0rc2").known_direct_status,
        ConstraintStatus::PassesKnownConstraints
    );
    inventory.direct_constraints[0].requirement = "demo>=2.0.dev2".into();
    assert_eq!(
        evaluate_constraints(&inventory, &package, "2.0.dev1").known_direct_status,
        ConstraintStatus::BlockedByKnownConstraint
    );
}

#[test]
fn ignored_invalid_markers_remain_unknown_without_echoing_parser_input() {
    let (_dir, inventory, package) =
        fixture(&["demo<2; python_version >= 'not-a-version-private-secret'"]);
    let result = evaluate_constraints(&inventory, &package, "2");
    assert_eq!(result.constraint_status, ConstraintStatus::Unknown);
    assert!(result.blockers.is_empty());
    assert_eq!(result.evaluated[0].requirement, None);
    assert!(result.evaluated[0].reason.is_some());
    assert_eq!(
        result.evaluated[0].origin,
        "pyproject.toml:project.dependencies"
    );
    assert_eq!(result.evaluated[0].digest, "project-digest");
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("private-secret")
    );
}

#[test]
fn invalid_candidate_and_marker_context_cannot_be_treated_as_passing() {
    let (_dir, mut inventory, package) = fixture(&["demo<2"]);
    let invalid = evaluate_constraints(
        &inventory,
        &package,
        "https://user:private-secret@example.invalid/not-a-version",
    );
    assert_eq!(invalid.known_direct_status, ConstraintStatus::Unknown);
    assert!(invalid.blockers.is_empty());
    assert!(
        !serde_json::to_string(&invalid)
            .unwrap()
            .contains("private-secret")
    );
    inventory.direct_constraints[0].requirement = "demo<2; platform_machine == 'AMD64'".into();
    inventory.target.as_mut().unwrap().scope.extras = vec!["invalid extra name".into()];
    let invalid_scope = evaluate_constraints(&inventory, &package, "2");
    assert_eq!(invalid_scope.constraint_status, ConstraintStatus::Unknown);
    assert!(invalid_scope.blockers.is_empty());
}

#[cfg(unix)]
#[test]
fn source_url_with_project_root_variable_is_unknown_even_when_process_cwd_is_deleted() {
    const CHILD: &str = "PYBUN_TEST_CONSTRAINTS_DELETED_CWD";
    if std::env::var_os(CHILD).is_some() {
        let (_dir, inventory, package) =
            fixture(&["demo @ https://example.invalid/${PROJECT_ROOT}/demo.whl"]);
        let doomed = std::env::current_dir().unwrap();
        fs::remove_dir(&doomed).unwrap();
        let result = evaluate_constraints(&inventory, &package, "2");
        assert_eq!(result.constraint_status, ConstraintStatus::Unknown);
        assert!(result.blockers.is_empty());
        return;
    }
    let doomed = TempDir::new().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "source_url_with_project_root_variable_is_unknown_even_when_process_cwd_is_deleted",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env_remove("PROJECT_ROOT")
        .current_dir(doomed.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated pure evaluation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
