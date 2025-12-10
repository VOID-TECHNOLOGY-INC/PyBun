use std::collections::HashMap;

use pybun::resolver::{InMemoryIndex, Requirement, ResolveError, resolve};

#[test]
fn resolves_simple_dependency_tree() {
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib-a==1.0.0", "lib-b==2.0.0"]);
    index.add("lib-a", "1.0.0", ["lib-c==1.0.0"]);
    index.add("lib-b", "2.0.0", Vec::<&str>::new());
    index.add("lib-c", "1.0.0", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index).unwrap();
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

#[test]
fn fails_on_missing_package() {
    let index = InMemoryIndex::default();
    let err = resolve(vec![Requirement::exact("missing", "1.0.0")], &index).unwrap_err();
    assert!(matches!(err, ResolveError::Missing { name, .. } if name == "missing"));
}

#[test]
fn detects_version_conflict() {
    let mut index = InMemoryIndex::default();
    index.add("root", "1.0.0", ["lib==1.0.0", "lib==2.0.0"]);
    index.add("lib", "1.0.0", Vec::<&str>::new());
    index.add("lib", "2.0.0", Vec::<&str>::new());

    let err = resolve(vec![Requirement::exact("root", "1.0.0")], &index).unwrap_err();
    assert!(matches!(err, ResolveError::Conflict { name, .. } if name == "lib"));
}

#[test]
fn selects_highest_version_for_minimum_requirement() {
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib>=1.0.0"]);
    index.add("lib", "1.0.0", Vec::<&str>::new());
    index.add("lib", "1.5.0", Vec::<&str>::new());
    index.add("lib", "2.0.0", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index).unwrap();
    let lib = resolution.packages.get("lib").expect("lib resolved");
    assert_eq!(lib.version, "2.0.0");
}

#[test]
fn errors_when_no_version_meets_minimum() {
    let mut index = InMemoryIndex::default();
    index.add("app", "1.0.0", ["lib>=2.0.0"]);
    index.add("lib", "1.5.0", Vec::<&str>::new());

    let err = resolve(vec![Requirement::exact("app", "1.0.0")], &index).unwrap_err();
    assert!(matches!(err, ResolveError::Missing { name, .. } if name == "lib"));
}
