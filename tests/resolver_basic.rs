use std::collections::HashMap;

use pybun::resolver::{
    InMemoryIndex, PackageArtifacts, PackageIndex, Requirement, ResolveError, ResolvedPackage,
    resolve,
};

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
async fn relaxed_semver_handles_two_segment_requirement() {
    // >=3.7 should accept 3.10.8 even though the specifier omits patch
    let mut index = InMemoryIndex::default();
    index.add("root", "1.0.0", ["lib>=3.7"]);
    index.add("lib", "3.10.8", Vec::<&str>::new());
    index.add("lib", "3.6.9", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("root", "1.0.0")], &index)
        .await
        .unwrap();
    let lib = resolution.packages.get("lib").expect("lib resolved");
    assert_eq!(lib.version, "3.10.8");
}

#[tokio::test]
async fn pre_release_treated_as_less_than_final() {
    // <2.4 should allow 2.4.0rc1 (pre-release) over 2.3.x
    let mut index = InMemoryIndex::default();
    index.add("root", "1.0.0", ["lib<2.4"]);
    index.add("lib", "2.4.0rc1", Vec::<&str>::new());
    index.add("lib", "2.3.5", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("root", "1.0.0")], &index)
        .await
        .unwrap();
    let lib = resolution.packages.get("lib").expect("lib resolved");
    assert_eq!(lib.version, "2.4.0rc1");
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

#[tokio::test]
async fn resolves_dependencies_fetched_after_selection() {
    struct LazyIndex {
        all_map: HashMap<String, Vec<ResolvedPackage>>,
        get_map: HashMap<(String, String), ResolvedPackage>,
    }

    impl PackageIndex for LazyIndex {
        async fn get(
            &self,
            name: &str,
            version: &str,
        ) -> Result<Option<ResolvedPackage>, ResolveError> {
            Ok(self
                .get_map
                .get(&(name.to_string(), version.to_string()))
                .cloned())
        }

        async fn all(&self, name: &str) -> Result<Vec<ResolvedPackage>, ResolveError> {
            Ok(self.all_map.get(name).cloned().unwrap_or_default())
        }
    }

    let mut all_map = HashMap::new();
    all_map.insert(
        "app".to_string(),
        vec![ResolvedPackage {
            name: "app".to_string(),
            version: "1.0.0".to_string(),
            dependencies: Vec::new(),
            source: None,
            artifacts: PackageArtifacts::default(),
        }],
    );
    all_map.insert(
        "dep".to_string(),
        vec![ResolvedPackage {
            name: "dep".to_string(),
            version: "1.0.0".to_string(),
            dependencies: Vec::new(),
            source: None,
            artifacts: PackageArtifacts::default(),
        }],
    );

    let mut get_map = HashMap::new();
    get_map.insert(
        ("app".to_string(), "1.0.0".to_string()),
        ResolvedPackage {
            name: "app".to_string(),
            version: "1.0.0".to_string(),
            dependencies: vec![Requirement::exact("dep", "1.0.0")],
            source: None,
            artifacts: PackageArtifacts::default(),
        },
    );

    let index = LazyIndex { all_map, get_map };
    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap();

    assert!(resolution.packages.contains_key("dep"));
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

#[tokio::test]
async fn filters_dependencies_with_non_matching_markers() {
    // Test that dependencies with environment markers that don't match the current
    // platform are filtered out during resolution (Issue #102)
    let mut index = InMemoryIndex::default();

    // Add a package with multiple platform-specific dependencies
    // Only one should be included based on the current platform
    index.add(
        "polars",
        "1.39.2",
        [
            "polars-runtime-32==1.39.2 ; platform_machine == 'i386'",
            "polars-runtime-64==1.39.2 ; platform_machine == 'x86_64'",
            "polars-runtime-arm==1.39.2 ; platform_machine == 'arm64'",
        ],
    );
    index.add("polars-runtime-32", "1.39.2", Vec::<&str>::new());
    index.add("polars-runtime-64", "1.39.2", Vec::<&str>::new());
    index.add("polars-runtime-arm", "1.39.2", Vec::<&str>::new());

    let resolution = resolve(vec![Requirement::exact("polars", "1.39.2")], &index)
        .await
        .unwrap();

    // polars itself should be resolved
    assert!(resolution.packages.contains_key("polars"));

    // On macOS arm64, only polars-runtime-arm should be included
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        assert!(resolution.packages.contains_key("polars-runtime-arm"));
        assert!(!resolution.packages.contains_key("polars-runtime-32"));
        assert!(!resolution.packages.contains_key("polars-runtime-64"));
    }

    // On Linux/macOS x86_64, only polars-runtime-64 should be included
    #[cfg(target_arch = "x86_64")]
    {
        assert!(resolution.packages.contains_key("polars-runtime-64"));
        assert!(!resolution.packages.contains_key("polars-runtime-32"));
        assert!(!resolution.packages.contains_key("polars-runtime-arm"));
    }

    // The 32-bit runtime should never be included on 64-bit systems
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        assert!(!resolution.packages.contains_key("polars-runtime-32"));
    }
}

#[test]
fn parses_pep508_marker_format() {
    // Test parsing PEP 508 format with parentheses and markers
    let req: Requirement = "package (>=1.0) ; platform_machine == 'x86_64'"
        .parse()
        .unwrap();
    assert_eq!(req.name, "package");
    assert!(req.marker.is_some());
    assert_eq!(req.marker.as_ref().unwrap(), "platform_machine == 'x86_64'");
}

/// Regression test for the PR #331 review of Issue #239 Phase 1: parallelizing
/// metadata fetches must not change *which* packages end up resolved for a
/// diamond dependency.
///
/// `appA` requires `c<3.0.0` and `appB` requires `c<1.6.0`; both requirements
/// land in the same resolution batch (both are dependencies of the two
/// top-level apps, discovered together). The index offers `c==2.0.0` (which
/// satisfies `c<3.0.0` but not `c<1.6.0`, and depends on `leftover-dep`) and
/// `c==1.5.0` (which satisfies both constraints and has no dependencies).
///
/// The resolver first selects `c==2.0.0` for `appA`'s requirement (the only
/// constraint known at that point), then reconciles down to `c==1.5.0` once
/// `appB`'s stricter requirement is processed. On `main` (pre-parallel-fetch),
/// the serial loop pushes `c==2.0.0`'s dependencies (`leftover-dep`) into the
/// next batch *before* the reconciliation happens, so `leftover-dep` remains
/// queued and ends up in `resolution.packages` even though the final `c` is
/// `1.5.0`. This test locks in that exact behavior for the parallel-fetch
/// implementation too.
#[tokio::test]
async fn diamond_dependency_reconciliation_preserves_first_candidate_deps() {
    let mut index = InMemoryIndex::default();
    index.add("appA", "1.0.0", ["c<3.0.0"]);
    index.add("appB", "1.0.0", ["c<1.6.0"]);
    index.add("c", "2.0.0", ["leftover-dep==1.0.0"]);
    index.add("c", "1.5.0", Vec::<&str>::new());
    index.add("leftover-dep", "1.0.0", Vec::<&str>::new());

    let resolution = resolve(
        vec![
            Requirement::exact("appA", "1.0.0"),
            Requirement::exact("appB", "1.0.0"),
        ],
        &index,
    )
    .await
    .unwrap();

    // The reconciled, final version of `c` must satisfy both constraints.
    let c = resolution.packages.get("c").expect("c resolved");
    assert_eq!(c.version, "1.5.0");

    // `leftover-dep` was a dependency of the first-picked (and ultimately
    // discarded) `c==2.0.0` candidate. Matching `main`'s serial behavior, it
    // must still show up in the resolved package set.
    assert!(
        resolution.packages.contains_key("leftover-dep"),
        "expected leftover-dep (a dependency of the first-picked c==2.0.0 \
         candidate) to remain resolved even though c reconciled to 1.5.0, \
         matching main's pre-parallel-fetch behavior; got packages: {:?}",
        resolution.packages.keys().collect::<Vec<_>>()
    );

    assert_eq!(
        resolution.packages.len(),
        4,
        "expected exactly appA, appB, c, leftover-dep; got: {:?}",
        resolution.packages.keys().collect::<Vec<_>>()
    );
}

/// Regression test for Issue #239 Phase 1: metadata fetches for sibling
/// dependencies at the same frontier must run concurrently, not one at a
/// time. Each simulated fetch sleeps for a fixed delay; if fetches ran
/// serially, N packages would take N * delay. Run concurrently they should
/// complete in roughly one delay's worth of wall time.
#[tokio::test]
async fn fetches_sibling_dependency_metadata_concurrently() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct DelayedIndex {
        all_map: HashMap<String, Vec<ResolvedPackage>>,
        get_map: HashMap<(String, String), ResolvedPackage>,
        in_flight: Arc<AtomicUsize>,
        max_in_flight: Arc<AtomicUsize>,
        delay: Duration,
    }

    impl PackageIndex for DelayedIndex {
        async fn get(
            &self,
            name: &str,
            version: &str,
        ) -> Result<Option<ResolvedPackage>, ResolveError> {
            let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(current, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(self
                .get_map
                .get(&(name.to_string(), version.to_string()))
                .cloned())
        }

        async fn all(&self, name: &str) -> Result<Vec<ResolvedPackage>, ResolveError> {
            Ok(self.all_map.get(name).cloned().unwrap_or_default())
        }
    }

    const SIBLING_COUNT: usize = 8;
    const DELAY: Duration = Duration::from_millis(50);

    let mut all_map = HashMap::new();
    let mut get_map = HashMap::new();

    let sibling_names: Vec<String> = (0..SIBLING_COUNT).map(|i| format!("dep-{i}")).collect();

    all_map.insert(
        "app".to_string(),
        vec![ResolvedPackage {
            name: "app".to_string(),
            version: "1.0.0".to_string(),
            dependencies: Vec::new(),
            source: None,
            artifacts: PackageArtifacts::default(),
        }],
    );
    get_map.insert(
        ("app".to_string(), "1.0.0".to_string()),
        ResolvedPackage {
            name: "app".to_string(),
            version: "1.0.0".to_string(),
            dependencies: sibling_names
                .iter()
                .map(|n| Requirement::exact(n, "1.0.0"))
                .collect(),
            source: None,
            artifacts: PackageArtifacts::default(),
        },
    );

    for name in &sibling_names {
        all_map.insert(
            name.clone(),
            vec![ResolvedPackage {
                name: name.clone(),
                version: "1.0.0".to_string(),
                dependencies: Vec::new(),
                source: None,
                artifacts: PackageArtifacts::default(),
            }],
        );
        get_map.insert(
            (name.clone(), "1.0.0".to_string()),
            ResolvedPackage {
                name: name.clone(),
                version: "1.0.0".to_string(),
                dependencies: Vec::new(),
                source: None,
                artifacts: PackageArtifacts::default(),
            },
        );
    }

    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let index = DelayedIndex {
        all_map,
        get_map,
        in_flight: in_flight.clone(),
        max_in_flight: max_in_flight.clone(),
        delay: DELAY,
    };

    let start = std::time::Instant::now();
    let resolution = resolve(vec![Requirement::exact("app", "1.0.0")], &index)
        .await
        .unwrap();
    let elapsed = start.elapsed();

    // Correctness: every sibling must still be resolved, regardless of the
    // non-deterministic order in which their delayed fetches complete.
    assert_eq!(resolution.packages.len(), SIBLING_COUNT + 1);
    for name in &sibling_names {
        assert!(resolution.packages.contains_key(name));
        assert_eq!(resolution.packages[name].version, "1.0.0");
    }

    // Concurrency: fetches for the sibling frontier must have overlapped in
    // time. Serial fetching would only ever observe max_in_flight == 1.
    assert!(
        max_in_flight.load(Ordering::SeqCst) > 1,
        "expected overlapping concurrent fetches, but max in-flight was {}",
        max_in_flight.load(Ordering::SeqCst)
    );

    // Wall-clock sanity check: SIBLING_COUNT sequential fetches would take at
    // least SIBLING_COUNT * DELAY. Concurrent fetches (bounded at 16) should
    // finish well under half that, even accounting for scheduler jitter.
    let serial_lower_bound = DELAY * SIBLING_COUNT as u32;
    assert!(
        elapsed < serial_lower_bound / 2,
        "resolve() took {elapsed:?}, expected well under {serial_lower_bound:?} \
         if fetches ran concurrently"
    );
}
