use std::collections::HashMap;

use pybun::resolver::{InMemoryIndex, Requirement, ResolveError, resolve};

#[tokio::test]
async fn resolves_simple_dependency_tree() {
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib-a==1.0.0", "lib-b==2.0.0"]);
    index.add("lib-a", "1.0.0", ["lib-c==1.0.0"]);
    index.add("lib-b", "2.0.0", Vec::<&str>::new());
    index.add("lib-c", "1.0.0", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap();
    let expect: HashMap<&str, &str> = HashMap::from([
        ("app", "1.0.0"),
        ("lib-a", "1.0.0"),
        ("lib-b", "2.0.0"),
        ("lib-c", "1.0.0"),
    ]);

    assert_eq!(resolution.packages.len(), expect.len());
    for (name, pkg) in resolution.packages.iter() {
        assert_eq!(
            expect.get(name.as_str()).copied(),
            Some(pkg.version.as_str())
        );
    }
}

#[tokio::test]
async fn fails_on_missing_package() {
    let index = InMemoryIndex::default();
    let err = resolve(vec![Requirement::exact("missing", "1.0.0")], &index)
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::Missing { name, .. } if name == "missing"));
}

#[tokio::test]
async fn detects_version_conflict() {
    let mut index = InMemoryIndex::default();
    index.add("root", "1.0.0", ["lib==1.0.0", "lib==2.0.0"]);
    index.add("lib", "1.0.0", Vec::<&str>::new());
    index.add("lib", "2.0.0", Vec::<&str>::new());

    let err = resolve(vec![Requirement::exact("root", "1.0.0")], &index)
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::Conflict { name, .. } if name == "lib"));
}

#[tokio::test]
async fn selects_highest_version_for_minimum_requirement() {
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib>=1.0.0"]);
    index.add("lib", "1.0.0", Vec::<&str>::new());
    index.add("lib", "1.5.0", Vec::<&str>::new());
    index.add("lib", "2.0.0", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap();
    let lib = resolution.packages.get("lib").expect("lib resolved");
    assert_eq!(lib.version, "2.0.0");
}

#[tokio::test]
async fn errors_when_no_version_meets_minimum() {
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib>=2.0.0"]);
    index.add("lib", "1.5.0", Vec::<&str>::new());

    let err = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::Missing { name, .. } if name == "lib"));
}

// =============================================================================
// Additional version specifier tests (PR1.2 completion)
// =============================================================================

#[tokio::test]
async fn selects_highest_version_for_maximum_inclusive() {
    // <=2.0.0 should select 2.0.0 (not 2.1.0)
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib<=2.0.0"]);
    index.add("lib", "1.0.0", Vec::<&str>::new());
    index.add("lib", "2.0.0", Vec::<&str>::new());
    index.add("lib", "2.1.0", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap();
    let lib = resolution.packages.get("lib").expect("lib resolved");
    assert_eq!(lib.version, "2.0.0");
}

#[tokio::test]
async fn selects_highest_version_for_maximum_exclusive() {
    // <2.0.0 should select 1.9.0 (not 2.0.0)
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib<2.0.0"]);
    index.add("lib", "1.0.0", Vec::<&str>::new());
    index.add("lib", "1.9.0", Vec::<&str>::new());
    index.add("lib", "2.0.0", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap();
    let lib = resolution.packages.get("lib").expect("lib resolved");
    assert_eq!(lib.version, "1.9.0");
}

#[tokio::test]
async fn selects_highest_version_for_minimum_exclusive() {
    // >1.0.0 should select 2.0.0 (not 1.0.0)
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib>1.0.0"]);
    index.add("lib", "1.0.0", Vec::<&str>::new());
    index.add("lib", "1.5.0", Vec::<&str>::new());
    index.add("lib", "2.0.0", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap();
    let lib = resolution.packages.get("lib").expect("lib resolved");
    assert_eq!(lib.version, "2.0.0");
}

#[tokio::test]
async fn excludes_version_with_not_equal() {
    // !=1.5.0 should exclude 1.5.0 but allow 2.0.0
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib!=1.5.0"]);
    index.add("lib", "1.0.0", Vec::<&str>::new());
    index.add("lib", "1.5.0", Vec::<&str>::new());
    index.add("lib", "2.0.0", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap();
    let lib = resolution.packages.get("lib").expect("lib resolved");
    assert_eq!(lib.version, "2.0.0");
}

#[tokio::test]
async fn compatible_release_selects_within_major_minor() {
    // ~=1.4.0 is equivalent to >=1.4.0,<1.5.0
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib~=1.4.0"]);
    index.add("lib", "1.3.0", Vec::<&str>::new());
    index.add("lib", "1.4.0", Vec::<&str>::new());
    index.add("lib", "1.4.5", Vec::<&str>::new());
    index.add("lib", "1.5.0", Vec::<&str>::new());
    index.add("lib", "2.0.0", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap();
    let lib = resolution.packages.get("lib").expect("lib resolved");
    assert_eq!(lib.version, "1.4.5");
}

#[tokio::test]
async fn compatible_release_major_minor_only() {
    // ~=1.4 is equivalent to >=1.4,<2.0
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib~=1.4"]);
    index.add("lib", "1.3.0", Vec::<&str>::new());
    index.add("lib", "1.4.0", Vec::<&str>::new());
    index.add("lib", "1.9.0", Vec::<&str>::new());
    index.add("lib", "2.0.0", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap();
    let lib = resolution.packages.get("lib").expect("lib resolved");
    assert_eq!(lib.version, "1.9.0");
}

#[tokio::test]
async fn errors_when_no_version_meets_maximum() {
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib<1.0.0"]);
    index.add("lib", "1.0.0", Vec::<&str>::new());
    index.add("lib", "2.0.0", Vec::<&str>::new());

    let err = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::Missing { name, .. } if name == "lib"));
}

#[test]
fn parses_all_specifier_types_from_string() {
    // Test that FromStr parses all specifier types correctly
    let exact: Requirement = "pkg==1.0.0".parse().unwrap();
    assert_eq!(exact.name, "pkg");

    let min: Requirement = "pkg>=1.0.0".parse().unwrap();
    assert_eq!(min.name, "pkg");

    let max_incl: Requirement = "pkg<=1.0.0".parse().unwrap();
    assert_eq!(max_incl.name, "pkg");

    let max_excl: Requirement = "pkg<1.0.0".parse().unwrap();
    assert_eq!(max_excl.name, "pkg");

    let min_excl: Requirement = "pkg>1.0.0".parse().unwrap();
    assert_eq!(min_excl.name, "pkg");

    let not_equal: Requirement = "pkg!=1.0.0".parse().unwrap();
    assert_eq!(not_equal.name, "pkg");

    let compat: Requirement = "pkg~=1.4.0".parse().unwrap();
    assert_eq!(compat.name, "pkg");

    let any: Requirement = "pkg".parse().unwrap();
    assert_eq!(any.name, "pkg");
}
