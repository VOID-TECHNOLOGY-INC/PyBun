use pybun::security_assessment::{
    CoverageStatus, DisclosureGrant, InventoryBackend, InventoryRequest, InventoryTarget,
    SourceIdentity, SourceKind, SourcePolicy, SourceRule, observe_inventory,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn environment(root: &Path) {
    fs::create_dir_all(root.join(".venv/lib/python3.13/site-packages")).unwrap();
    fs::write(
        root.join("pyproject.toml"),
        "[project]\nname='example'\nversion='1.0'\ndependencies=['demo<2']\n",
    )
    .unwrap();
    fs::write(
        root.join(".venv/pyvenv.cfg"),
        "implementation = CPython\nversion = 3.13.0\ninclude-system-site-packages = false\n",
    )
    .unwrap();
}

fn package(root: &Path, distribution: &str, name: &str, version: &str) {
    let dir = root
        .join(".venv/lib/python3.13/site-packages")
        .join(distribution);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("METADATA"),
        format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
    )
    .unwrap();
}

#[test]
fn source_mapping_and_disclosure_are_separate_decisions() {
    let source = SourceIdentity::new("tenant-a", "auth-a", SourceKind::PrivateRegistry).unwrap();
    let mut policy = SourcePolicy::default();
    policy.sources.push(source);
    policy.rules.push(SourceRule {
        name: "demo".into(),
        distribution: None,
        source_id: "tenant-a".into(),
        upstream_name: None,
        ecosystem: None,
        assumption: None,
    });
    policy.disclosure.push(DisclosureGrant {
        provider_id: "osv".into(),
        source_id: "tenant-a".into(),
        packages: vec!["demo".into()],
    });
    let mapped = policy
        .map_package("demo", "demo-1.0.dist-info", SourceKind::Unknown)
        .unwrap();
    assert!(policy.may_disclose("osv", &mapped.source.id, "demo"));
    assert!(mapped.mapping.is_none());
    assert_eq!(
        policy
            .authorized_query("osv", "demo", &mapped)
            .unwrap_err()
            .code,
        "E_SECURITY_SOURCE_MAPPING_UNKNOWN"
    );
}

#[test]
fn opaque_source_and_auth_scope_ids_preserve_tenant_identity() {
    let a = SourceIdentity::new("tenant-a", "scope-a", SourceKind::PrivateRegistry).unwrap();
    let b = SourceIdentity::new("tenant-b", "scope-b", SourceKind::PrivateRegistry).unwrap();
    assert_ne!(a, b);
    assert!(
        SourceIdentity::new(
            "https://user:password@example.com",
            "a",
            SourceKind::PublicRegistry
        )
        .is_err()
    );
}

#[test]
fn missing_environment_is_not_a_successful_empty_inventory() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='demo'\nversion='1'\n",
    )
    .unwrap();
    let result = observe_inventory(
        &InventoryRequest::installed(dir.path(), Path::new("/not/a/python")),
        42,
    );
    assert_eq!(
        result.coverage.inventory_instances.status,
        CoverageStatus::Error
    );
    assert!(!result.diagnostics.is_empty());
    assert!(result.packages.is_empty());
}

#[test]
fn unknown_packages_are_preserved_and_cannot_be_sent_to_public_providers() {
    let dir = TempDir::new().unwrap();
    environment(dir.path());
    package(dir.path(), "Demo-1.0.dist-info", "Demo", "1.0");
    let policy = SourcePolicy::default();
    let source = policy
        .map_package("demo", "Demo-1.0.dist-info", SourceKind::Unknown)
        .unwrap();
    assert_eq!(source.source.kind, SourceKind::Unknown);
    assert!(source.mapping.is_none());
    assert!(policy.authorized_query("osv", "demo", &source).is_err());
}

fn trusted_python() -> std::path::PathBuf {
    let python = std::env::var_os("PYBUN_SECURITY_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let out = std::process::Command::new(python)
        .args(["-I", "-S", "-c", "import sys; print(sys.executable)"])
        .output()
        .unwrap();
    assert!(out.status.success());
    Path::new(std::str::from_utf8(&out.stdout).unwrap().trim()).to_path_buf()
}

fn real_environment() -> (TempDir, InventoryRequest, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname='project'\nversion='1.0'\ndependencies=['demo<2']\n",
    )
    .unwrap();
    let python = trusted_python();
    assert!(
        std::process::Command::new(&python)
            .args(["-I", "-m", "venv", "--without-pip"])
            .arg(dir.path().join(".venv"))
            .status()
            .unwrap()
            .success()
    );
    let config = fs::read_to_string(dir.path().join(".venv/pyvenv.cfg")).unwrap();
    let version = config
        .lines()
        .find_map(|l| l.strip_prefix("version = "))
        .unwrap();
    let parts: Vec<_> = version.split('.').collect();
    let site = if cfg!(windows) {
        dir.path().join(".venv/Lib/site-packages")
    } else {
        dir.path().join(format!(
            ".venv/lib/python{}.{}/site-packages",
            parts[0], parts[1]
        ))
    };
    let mut request = InventoryRequest::installed(dir.path(), &python);
    request
        .source_policy
        .sources
        .push(SourceIdentity::new("public-pypi", "public", SourceKind::PublicRegistry).unwrap());
    for name in ["demo", "extra"] {
        request.source_policy.rules.push(SourceRule {
            name: name.into(),
            distribution: None,
            source_id: "public-pypi".into(),
            upstream_name: Some(name.into()),
            ecosystem: Some("PyPI".into()),
            assumption: Some(
                "Operator declares these installed distributions to be the public PyPI projects."
                    .into(),
            ),
        });
        request.source_policy.disclosure.push(DisclosureGrant {
            provider_id: "osv".into(),
            source_id: "public-pypi".into(),
            packages: vec![name.into()],
        });
    }
    (dir, request, site)
}

fn dist(site: &Path, stem: &str, name: &str, version: &str) {
    fs::create_dir_all(site.join(stem)).unwrap();
    fs::write(
        site.join(stem).join("METADATA"),
        format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
    )
    .unwrap();
}

fn tree_hash(root: &Path) -> std::collections::BTreeMap<String, String> {
    fn walk(root: &Path, path: &Path, result: &mut std::collections::BTreeMap<String, String>) {
        for entry in fs::read_dir(path).unwrap() {
            let p = entry.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                walk(root, &p, result);
            } else if m.is_file() {
                result.insert(
                    p.strip_prefix(root).unwrap().display().to_string(),
                    pybun::security::sha256_bytes(&fs::read(&p).unwrap()),
                );
            }
        }
    }
    let mut result = std::collections::BTreeMap::new();
    walk(root, root, &mut result);
    result
}

#[test]
fn installed_inventory_includes_unlocked_versions_and_has_no_startup_side_effects() {
    let (dir, request, site) = real_environment();
    dist(&site, "demo-1.0.dist-info", "Demo", "1.0");
    dist(&site, "demo-2.0.dist-info", "demo", "2.0");
    dist(&site, "extra-1.0.dist-info", "extra", "1.0");
    fs::write(
        dir.path().join("uv.lock"),
        "version=1\n[[package]]\nname='demo'\nversion='99.0'\n",
    )
    .unwrap();
    let marker = dir.path().join("executed");
    let code = format!(
        "from pathlib import Path; Path({:?}).write_text('executed')\n",
        marker.to_string_lossy()
    );
    for path in [
        site.join("sitecustomize.py"),
        site.join("usercustomize.py"),
        site.join("trigger.pth"),
        dir.path().join("platform.py"),
        dir.path().join("json.py"),
        dir.path().join("sysconfig.py"),
    ] {
        fs::write(path, &code).unwrap();
    }
    let before = tree_hash(dir.path());
    let observed = observe_inventory(&request, 42);
    assert_eq!(
        observed.coverage.inventory_instances.status,
        CoverageStatus::Partial,
        "{observed:?}"
    );
    assert_eq!(observed.packages.len(), 3, "{observed:?}");
    assert_ne!(
        observed.packages[0].instance_id,
        observed.packages[1].instance_id
    );
    assert!(observed.packages.iter().any(|p| p.name == "extra"));
    assert!(!observed.packages.iter().any(|p| p.version == "99.0"));
    let target = observed.target.as_ref().unwrap();
    assert!(
        target
            .tag_profile
            .tags
            .iter()
            .any(|tag| tag == "py3-none-any")
    );
    assert!(
        target
            .tag_profile
            .tags
            .iter()
            .any(|tag| tag.starts_with("cp"))
    );
    assert!(!target.tag_profile.digest.is_empty());
    assert!(!marker.exists());
    assert_eq!(tree_hash(dir.path()), before);
    assert_eq!(observed.direct_constraints[0].requirement, "demo<2");
    let later = observe_inventory(&request, 43);
    assert_eq!(later.inventory_id, observed.inventory_id);
    assert_ne!(later.observation_id, observed.observation_id);
}

#[test]
fn validated_empty_inventory_is_complete_but_corrupt_metadata_is_not_empty_success() {
    let (_dir, request, site) = real_environment();
    let empty = observe_inventory(&request, 1);
    assert_eq!(
        empty.coverage.inventory_instances.status,
        CoverageStatus::Complete,
        "{empty:?}"
    );
    assert!(empty.target.is_some());
    assert!(empty.packages.is_empty());
    dist(
        &site,
        "broken-1.0.dist-info",
        "broken",
        "not-a-pep440-version!",
    );
    let broken = observe_inventory(&request, 2);
    assert_eq!(
        broken.coverage.inventory_instances.status,
        CoverageStatus::Error,
        "{broken:?}"
    );
    assert!(broken.packages.is_empty());
    assert_eq!(broken.coverage.inventory_instances.errors, 1);
}

#[test]
fn explicit_direct_origins_are_never_remapped_by_a_public_name_assumption() {
    let (_dir, request, site) = real_environment();
    dist(&site, "demo-1.0.dist-info", "demo", "1.0");
    let file = site.join("demo-1.0.dist-info/direct_url.json");
    fs::write(&file,r#"{"url":"https://user:private-secret@private.example/repo?token=credential","vcs_info":{"vcs":"git","commit_id":"abc"}}"#).unwrap();
    let observed = observe_inventory(&request, 42);
    assert_eq!(observed.packages.len(), 1, "{observed:?}");
    let package = &observed.packages[0];
    assert_eq!(package.source.kind, SourceKind::Vcs);
    assert!(package.source_mapping.is_none());
    assert_eq!(package.coverage.status, CoverageStatus::Partial);
    let text = serde_json::to_string(&observed).unwrap();
    assert!(
        !text.contains("private-secret")
            && !text.contains("credential")
            && !text.contains("private.example")
    );
    let source_id = package.source.id.clone();
    fs::write(&file,r#"{"url":"https://user:rotated-secret@private.example/repo?token=rotated","vcs_info":{"vcs":"git","commit_id":"abc"}}"#).unwrap();
    let rotated = observe_inventory(&request, 42);
    assert_eq!(rotated.packages[0].source.id, source_id);
    assert_eq!(rotated.inventory_id, observed.inventory_id);
    assert_ne!(rotated.observation_id, observed.observation_id);
}

#[test]
fn missing_or_mismatched_inventory_profiles_never_fall_back_to_system() {
    let (dir, mut request, _site) = real_environment();
    for target in [InventoryTarget::Locked, InventoryTarget::System] {
        request.target = target;
        let observed = observe_inventory(&request, 0);
        assert_eq!(
            observed.coverage.inventory_instances.status,
            CoverageStatus::Unsupported
        );
        assert!(observed.target.is_none());
    }
    request.target = InventoryTarget::Installed;
    fs::write(
        dir.path().join(".venv/pyvenv.cfg"),
        "implementation = PyPy\nversion = 3.13.0\n",
    )
    .unwrap();
    let observed = observe_inventory(&request, 0);
    assert_eq!(
        observed.coverage.inventory_instances.status,
        CoverageStatus::Unsupported
    );
    assert!(observed.target.is_none());
}

#[test]
fn native_selection_is_explicit_and_inventory_semantics_ignore_prose_and_timestamps() {
    let (dir, mut request, site) = real_environment();
    dist(&site, "demo-1.0.dist-info", "demo", "1.0");
    fs::create_dir(dir.path().join(".pybun")).unwrap();
    fs::rename(dir.path().join(".venv"), dir.path().join(".pybun/venv")).unwrap();
    request.backend = InventoryBackend::Native;
    let first = observe_inventory(&request, 42);
    assert_eq!(
        first.coverage.inventory_instances.status,
        CoverageStatus::Complete,
        "{first:?}"
    );
    fs::write(
        dir.path().join("pyproject.toml"),
        "# harmless comment\n[project]\nname='project'\nversion='1.0'\ndependencies=['demo<2']\n",
    )
    .unwrap();
    let second = observe_inventory(&request, 42);
    assert_eq!(second.inventory_id, first.inventory_id);
    assert_ne!(second.observation_id, first.observation_id);
}

#[test]
fn malformed_and_oversized_metadata_remain_explicitly_incomplete() {
    let (_dir, mut request, site) = real_environment();
    dist(&site, "demo-1.0.dist-info", "demo", "1.0");
    dist(&site, "extra-1.0.dist-info", "extra", "1.0");
    request.limits.max_inventory_instances = 1;
    let limited = observe_inventory(&request, 42);
    assert_ne!(
        limited.coverage.inventory_instances.status,
        CoverageStatus::Complete
    );
    assert!(
        limited
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_LIMIT")
    );
    request.limits.max_inventory_instances = 1000;
    request.limits.max_metadata_bytes = 32;
    let oversized = observe_inventory(&request, 42);
    assert_ne!(
        oversized.coverage.inventory_instances.status,
        CoverageStatus::Complete
    );
}

#[cfg(unix)]
#[test]
fn metadata_symlinks_cannot_read_outside_authorized_roots() {
    use std::os::unix::fs::symlink;
    let (_dir, request, site) = real_environment();
    let outside = TempDir::new().unwrap();
    fs::write(
        outside.path().join("secret"),
        "Name: stolen-package\nVersion: 1\n",
    )
    .unwrap();
    fs::create_dir(site.join("demo-1.0.dist-info")).unwrap();
    symlink(
        outside.path().join("secret"),
        site.join("demo-1.0.dist-info/METADATA"),
    )
    .unwrap();
    let observed = observe_inventory(&request, 42);
    assert_eq!(
        observed.coverage.inventory_instances.status,
        CoverageStatus::Error
    );
    assert!(observed.packages.is_empty());
    assert!(
        observed
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_INVENTORY_PATH")
    );
}

#[test]
fn revoked_distribution_mapping_cannot_reuse_another_distribution_rule() {
    let (_dir, mut request, _site) = real_environment();
    let policy = &mut request.source_policy;
    policy.rules.retain(|r| r.name != "extra");
    policy.rules[0].distribution = Some("demo-1.dist-info".into());
    let mut other = policy.rules[0].clone();
    other.distribution = Some("demo-2.dist-info".into());
    policy.rules.push(other);
    let mapped = policy
        .map_package("demo", "demo-1.dist-info", SourceKind::Unknown)
        .unwrap();
    assert!(policy.authorized_query("osv", "demo", &mapped).is_ok());
    policy.rules.remove(0);
    assert!(policy.authorized_query("osv", "demo", &mapped).is_err());
}

#[test]
fn direct_origin_changes_identity_without_revealing_origin() {
    let (_dir, request, site) = real_environment();
    dist(&site, "demo-1.dist-info", "demo", "1");
    let path = site.join("demo-1.dist-info/direct_url.json");
    fs::write(&path, r#"{"url":"https://u:secret@private.example/repo-a","vcs_info":{"vcs":"git","commit_id":"a"}}"#).unwrap();
    let a = observe_inventory(&request, 0);
    fs::write(&path, r#"{"url":"https://u:secret@private.example/repo-b","vcs_info":{"vcs":"git","commit_id":"a"}}"#).unwrap();
    let b = observe_inventory(&request, 0);
    assert_ne!(a.packages[0].source.id, b.packages[0].source.id);
    assert_ne!(a.packages[0].instance_id, b.packages[0].instance_id);
    assert!(
        !serde_json::to_string(&b)
            .unwrap()
            .contains("private.example")
    );
}

#[cfg(unix)]
#[test]
fn untrusted_selected_interpreter_is_never_executed_and_exact_copy_is_proven() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, request, _site) = real_environment();
    let selected = dir.path().join(".venv/bin/python");
    fs::remove_file(&selected).unwrap();
    let marker = dir.path().join("executed");
    fs::write(
        &selected,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o755)).unwrap();
    let fake = observe_inventory(&request, 0);
    assert_eq!(
        fake.coverage.inventory_instances.status,
        CoverageStatus::Unsupported,
        "{fake:?}"
    );
    assert!(!marker.exists());
    fs::remove_file(&selected).unwrap();
    fs::copy(request.trusted_python.canonicalize().unwrap(), &selected).unwrap();
    let copied = observe_inventory(&request, 0);
    assert_eq!(
        copied.coverage.inventory_instances.status,
        CoverageStatus::Complete,
        "{copied:?}"
    );
    assert_eq!(
        copied.target.unwrap().interpreter_identity_evidence,
        "byte_identical_trusted_interpreter_copy"
    );
}

#[cfg(unix)]
#[test]
fn fifo_metadata_is_rejected_without_waiting_for_a_writer() {
    let (_dir, request, site) = real_environment();
    dist(&site, "demo-1.dist-info", "demo", "1");
    let path = site.join("demo-1.dist-info/METADATA");
    fs::remove_file(&path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let started = std::time::Instant::now();
    let observed = observe_inventory(&request, 0);
    assert_ne!(
        observed.coverage.inventory_instances.status,
        CoverageStatus::Complete
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn path_extensions_are_incomplete_without_executing_or_traversing_them() {
    let (dir, request, site) = real_environment();
    dist(&site, "demo-1.dist-info", "demo", "1");
    let outside = dir.path().join("extended");
    fs::create_dir(&outside).unwrap();
    dist(&outside, "extra-1.dist-info", "extra", "1");
    let pth = site.join("extension.pth");
    fs::write(&pth, "# harmless comment\n\n").unwrap();
    assert_eq!(
        observe_inventory(&request, 0)
            .coverage
            .inventory_instances
            .status,
        CoverageStatus::Complete
    );
    for content in [outside.to_str().unwrap(), "import project_hook"] {
        fs::write(&pth, content).unwrap();
        let observed = observe_inventory(&request, 0);
        assert_eq!(
            observed.coverage.inventory_instances.status,
            CoverageStatus::Partial,
            "{observed:?}"
        );
        assert_eq!(observed.packages.len(), 1);
        assert_eq!(
            observed.packages[0].coverage.status,
            CoverageStatus::Complete
        );
        assert!(
            observed
                .diagnostics
                .iter()
                .any(|d| d.code == "E_SECURITY_UNSUPPORTED_PATH_EXTENSION")
        );
    }
    fs::remove_file(&pth).unwrap();
    fs::write(site.join("legacy.egg-link"), outside.to_str().unwrap()).unwrap();
    assert_eq!(
        observe_inventory(&request, 0)
            .coverage
            .inventory_instances
            .status,
        CoverageStatus::Partial
    );
}

#[cfg(unix)]
#[test]
fn trusted_helper_deadline_and_output_are_bounded() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, mut request, _site) = real_environment();
    let helper = dir.path().join("trusted-test-helper");
    request.trusted_python = helper.clone();
    request.limits.total_timeout_ms = 100;
    fs::write(&helper, "#!/bin/sh\nexec /bin/sleep 10\n").unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
    let started = std::time::Instant::now();
    let timed = observe_inventory(&request, 0);
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    assert!(
        timed
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_LIMIT")
    );
    assert_ne!(
        timed.coverage.inventory_instances.status,
        CoverageStatus::Complete
    );
    request.limits.total_timeout_ms = 3000;
    request.limits.max_response_bytes = 100;
    fs::write(&helper, "#!/bin/sh\nexec /usr/bin/yes oversized\n").unwrap();
    let oversized = observe_inventory(&request, 0);
    assert!(
        oversized
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_LIMIT")
    );
    assert!(oversized.target.is_none());
}

#[test]
#[ignore = "requires the supported uv executable; run explicitly in CI and local backend verification"]
fn actual_uv_environment_is_observed_without_running_its_hooks() {
    let (dir, request, _site) = real_environment();
    fs::remove_dir_all(dir.path().join(".venv")).unwrap();
    assert!(
        std::process::Command::new("uv")
            .args(["venv", "--no-project", "--no-python-downloads", "--python"])
            .arg(&request.trusted_python)
            .arg(dir.path().join(".venv"))
            .status()
            .unwrap()
            .success()
    );
    let before = tree_hash(dir.path());
    let observed = observe_inventory(&request, 0);
    assert!(observed.target.is_some(), "{:?}", observed.diagnostics);
    assert!(matches!(
        observed.coverage.inventory_instances.status,
        CoverageStatus::Complete | CoverageStatus::Partial
    ));
    assert_eq!(tree_hash(dir.path()), before);
    if observed.coverage.inventory_instances.status == CoverageStatus::Partial {
        assert!(
            observed
                .diagnostics
                .iter()
                .any(|d| d.code == "E_SECURITY_UNSUPPORTED_PATH_EXTENSION")
        );
    }
}

#[test]
fn explicitly_mapped_private_mirror_requires_its_own_disclosure_grant() {
    let mut policy = SourcePolicy::default();
    policy
        .sources
        .push(SourceIdentity::new("mirror-a", "tenant-a", SourceKind::PrivateRegistry).unwrap());
    policy.rules.push(SourceRule {
        name: "internal-demo".into(),
        distribution: Some("internal_demo-1.dist-info".into()),
        source_id: "mirror-a".into(),
        upstream_name: Some("public-demo".into()),
        ecosystem: Some("PyPI".into()),
        assumption: Some(
            "Operator declares this mirror artifact equivalent to public-demo on PyPI.".into(),
        ),
    });
    let source = policy
        .map_package(
            "internal-demo",
            "internal_demo-1.dist-info",
            SourceKind::Unknown,
        )
        .unwrap();
    assert_eq!(source.source.kind, SourceKind::PrivateRegistry);
    assert_eq!(
        policy
            .authorized_query("osv", "internal-demo", &source)
            .unwrap_err()
            .code,
        "E_SECURITY_DISCLOSURE_DENIED"
    );
    policy.disclosure.push(DisclosureGrant {
        provider_id: "osv".into(),
        source_id: "mirror-a".into(),
        packages: vec!["internal-demo".into()],
    });
    let query = policy
        .authorized_query("osv", "internal-demo", &source)
        .unwrap();
    assert_eq!(query.name(), "public-demo");
    assert_eq!(query.ecosystem(), "PyPI");
    assert_eq!(query.source_id(), "mirror-a");
    assert_eq!(query.auth_scope_id(), "tenant-a");
    assert!(query.assumption().contains("mirror artifact equivalent"));
    assert!(
        policy
            .authorized_query("other-provider", "internal-demo", &source)
            .is_err()
    );
}

#[test]
fn same_name_and_version_preserve_distinct_source_and_scope_instances() {
    let (dir, mut request, site) = real_environment();
    dist(&site, "demo_public-1.dist-info", "demo", "1");
    dist(&site, "demo_mirror-1.dist-info", "demo", "1");
    request
        .source_policy
        .sources
        .push(SourceIdentity::new("mirror-a", "tenant-a", SourceKind::PrivateRegistry).unwrap());
    request
        .source_policy
        .rules
        .retain(|rule| rule.name != "demo");
    for (distribution, source_id) in [
        ("demo_public-1.dist-info", "public-pypi"),
        ("demo_mirror-1.dist-info", "mirror-a"),
    ] {
        request.source_policy.rules.push(SourceRule {
            name: "demo".into(),
            distribution: Some(distribution.into()),
            source_id: source_id.into(),
            upstream_name: Some("demo".into()),
            ecosystem: Some("PyPI".into()),
            assumption: Some(
                "Operator declares this distribution equivalent to demo on PyPI.".into(),
            ),
        });
    }
    let first = observe_inventory(&request, 0);
    assert_eq!(first.packages.len(), 2);
    assert!(
        first
            .packages
            .iter()
            .all(|package| package.name == "demo" && package.version == "1")
    );
    assert_ne!(first.packages[0].source.id, first.packages[1].source.id);
    assert_ne!(first.packages[0].instance_id, first.packages[1].instance_id);
    fs::write(dir.path().join("pyproject.toml"), "[project]\nname='project'\nversion='1'\ndependencies=['demo<2']\n[project.optional-dependencies]\nselected=[]\n").unwrap();
    request.scope.extras.push("selected".into());
    let scoped = observe_inventory(&request, 0);
    assert_eq!(scoped.packages.len(), 2);
    for original in &first.packages {
        let changed = scoped
            .packages
            .iter()
            .find(|package| package.source.id == original.source.id)
            .unwrap();
        assert_ne!(original.scope_variant, changed.scope_variant);
        assert_ne!(original.instance_id, changed.instance_id);
        assert_eq!(original.source, changed.source);
    }
}

fn assert_inventory_diagnostic(request: &InventoryRequest, expected: &str) {
    let observed = observe_inventory(request, 0);
    assert_ne!(
        observed.coverage.inventory_instances.status,
        CoverageStatus::Complete
    );
    assert!(
        observed
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == expected),
        "{:?}",
        observed.diagnostics
    );
}

#[test]
fn invalid_project_and_venv_configuration_never_become_empty_success() {
    let (dir, request, _site) = real_environment();
    let project = dir.path().join("pyproject.toml");
    let config = dir.path().join(".venv/pyvenv.cfg");
    let project_original = fs::read(&project).unwrap();
    let config_original = fs::read(&config).unwrap();
    for content in [b"[invalid TOML".as_slice(), b"\xff"] {
        fs::write(&project, content).unwrap();
        assert_inventory_diagnostic(&request, "E_SECURITY_METADATA");
    }
    fs::remove_file(&project).unwrap();
    assert_inventory_diagnostic(&request, "E_SECURITY_INVENTORY");
    fs::write(&project, project_original).unwrap();
    for content in [
        b"version=3.11.0\nversion=3.12.0".as_slice(),
        b"invalid without separator",
        b"\xff",
        b"include-system-site-packages=true\nversion=3.11.0",
        b"version=unparseable",
        b"home=/somewhere",
        b"version=3.0.0",
    ] {
        fs::write(&config, content).unwrap();
        assert_inventory_diagnostic(&request, "E_SECURITY_UNSUPPORTED_INVENTORY");
    }
    fs::remove_file(&config).unwrap();
    assert_inventory_diagnostic(&request, "E_SECURITY_UNSUPPORTED_INVENTORY");
    fs::write(&config, config_original).unwrap();
    let mut absent_inspector = request.clone();
    absent_inspector.trusted_python = dir.path().join("missing-python");
    assert_inventory_diagnostic(&absent_inspector, "E_SECURITY_UNSUPPORTED_INVENTORY");
    let mut absent_project = request.clone();
    absent_project.project_root = dir.path().join("missing-project");
    assert_inventory_diagnostic(&absent_project, "E_SECURITY_INVENTORY");
}

#[test]
fn supported_egg_metadata_and_requires_dist_retain_constraint_provenance() {
    let (_dir, request, site) = real_environment();
    let dir = site.join("demo-1.egg-info");
    fs::create_dir(&dir).unwrap();
    fs::write(
        dir.join("PKG-INFO"),
        "Name: demo\nVersion: 1\nRequires-Dist: extra>=1\n\nDescription body is not a header\n",
    )
    .unwrap();
    fs::write(
        site.join("extra-1.egg-info"),
        "Name: extra\nVersion: 1\nRequires-Dist: demo<2\n",
    )
    .unwrap();
    let observed = observe_inventory(&request, 0);
    assert_eq!(
        observed.coverage.inventory_instances.status,
        CoverageStatus::Complete
    );
    assert_eq!(observed.packages.len(), 2);
    let dependency = &observed
        .packages
        .iter()
        .find(|package| package.name == "demo")
        .unwrap()
        .requires_dist[0];
    assert_eq!(dependency.requirement, "extra>=1");
    let demo = observed
        .packages
        .iter()
        .find(|package| package.name == "demo")
        .unwrap();
    assert_eq!(
        dependency.origin,
        format!("{}/PKG-INFO:Requires-Dist", demo.distribution_path)
    );
    let extra = observed
        .packages
        .iter()
        .find(|package| package.name == "extra")
        .unwrap();
    assert_eq!(
        extra.requires_dist[0].origin,
        format!("{}:Requires-Dist", extra.distribution_path)
    );
    assert!(!dependency.digest.is_empty());
}

#[test]
fn malformed_distribution_headers_and_missing_metadata_are_explicit_errors() {
    let (_dir, request, site) = real_environment();
    let dir = site.join("demo-1.dist-info");
    fs::create_dir(&dir).unwrap();
    assert_inventory_diagnostic(&request, "E_SECURITY_METADATA");
    let metadata = dir.join("METADATA");
    let cases = [
        b"\xff".to_vec(),
        b" continuation without a header\n".to_vec(),
        b"Missing-colon\n".to_vec(),
        b"Name: demo\nName: another\nVersion: 1\n".to_vec(),
        b"Name: de\n mo\nVersion: 1\n".to_vec(),
        b"Name: demo\nVersion: 1.\n 0\n".to_vec(),
        b"Name: demo\n".to_vec(),
        b"Invalid Key: value\nName: demo\nVersion: 1\n".to_vec(),
        format!("Name: demo\nVersion: 1\nOversized: {}\n", "x".repeat(16385)).into_bytes(),
    ];
    for bytes in cases {
        fs::write(&metadata, bytes).unwrap();
        assert_inventory_diagnostic(&request, "E_SECURITY_METADATA");
    }
    fs::remove_dir_all(&dir).unwrap();
    fs::write(&dir, "Name: demo\nVersion: 1").unwrap();
    assert_inventory_diagnostic(&request, "E_SECURITY_METADATA");
}

#[test]
fn untrusted_direct_url_metadata_has_bounded_generic_diagnostics_and_typed_kinds() {
    let (_dir, request, site) = real_environment();
    dist(&site, "demo-1.dist-info", "demo", "1");
    let path = site.join("demo-1.dist-info/direct_url.json");
    for invalid in [
        "{malformed secret-token",
        r#"{"vcs_info":{}}"#,
        r#"{"url":"not-a-url-secret-token"}"#,
    ] {
        fs::write(&path, invalid).unwrap();
        let observed = observe_inventory(&request, 0);
        assert!(observed.packages.is_empty());
        assert_inventory_diagnostic(&request, "E_SECURITY_METADATA");
        assert!(
            !serde_json::to_string(&observed)
                .unwrap()
                .contains("secret-token")
        );
    }
    for (value, kind) in [
        (
            r#"{"url":"https://private.example/archive.whl"}"#,
            SourceKind::DirectUrl,
        ),
        (
            r#"{"url":"file:///project","dir_info":{"editable":true}}"#,
            SourceKind::Editable,
        ),
    ] {
        fs::write(&path, value).unwrap();
        let observed = observe_inventory(&request, 0);
        assert_eq!(observed.packages.len(), 1);
        assert_eq!(observed.packages[0].source.kind, kind);
        assert!(observed.packages[0].source_mapping.is_none());
        assert!(observed.packages[0].origin_identity.is_some());
    }
}

#[test]
fn selected_extras_and_dependency_groups_preserve_constraints_and_reject_unknown_scopes() {
    let (dir, mut request, _site) = real_environment();
    let path = dir.path().join("pyproject.toml");
    fs::write(&path, "[project]\nname='example'\nversion='1'\ndependencies=['demo<2']\n[project.optional-dependencies]\ntests=['extra>=1']\n[dependency-groups]\ndev=['demo!=1.5']\n").unwrap();
    request.scope.extras = vec!["tests".into()];
    request.scope.groups = vec!["dev".into()];
    let observed = observe_inventory(&request, 0);
    assert_eq!(
        observed.coverage.inventory_instances.status,
        CoverageStatus::Complete
    );
    assert_eq!(observed.direct_constraints.len(), 3);
    for origin in [
        "project.dependencies",
        "project.optional-dependencies.tests",
        "dependency-groups.dev",
    ] {
        assert!(
            observed
                .direct_constraints
                .iter()
                .any(|constraint| constraint.origin.ends_with(origin))
        );
    }
    request.scope.extras = vec!["missing".into()];
    assert_inventory_diagnostic(&request, "E_SECURITY_UNSUPPORTED_SCOPE");
    request.scope.extras.clear();
    request.scope.groups = vec!["missing".into()];
    assert_inventory_diagnostic(&request, "E_SECURITY_UNSUPPORTED_SCOPE");
    request.scope.groups.clear();
    request.scope.members = vec!["member".into()];
    assert_inventory_diagnostic(&request, "E_SECURITY_UNSUPPORTED_SCOPE");
    request.scope.members.clear();
    fs::write(
        &path,
        "[project]\nname='example'\nversion='1'\ndependencies='not-an-array'\n",
    )
    .unwrap();
    assert_inventory_diagnostic(&request, "E_SECURITY_METADATA");
    fs::write(&path, "[project]\nname='example'\nversion='1'\n[dependency-groups]\ndev=[{include-group='other'}]\n").unwrap();
    request.scope.groups = vec!["dev".into()];
    assert_inventory_diagnostic(&request, "E_SECURITY_UNSUPPORTED_SCOPE");
}

#[test]
fn invalid_observation_limits_are_rejected_before_inventory_access() {
    let dir = TempDir::new().unwrap();
    let mut request = InventoryRequest::installed(dir.path(), &dir.path().join("missing-python"));
    request.limits.max_requests = 0;
    assert_inventory_diagnostic(&request, "E_SECURITY_LIMIT");
    request.limits.max_requests = 101;
    assert_inventory_diagnostic(&request, "E_SECURITY_LIMIT");
}

#[test]
fn folded_requirement_headers_preserve_token_separating_whitespace() {
    let (_dir, request, site) = real_environment();
    dist(&site, "demo-1.dist-info", "demo", "1");
    fs::write(site.join("demo-1.dist-info/METADATA"), "Name: demo\nVersion: 1\nRequires-Dist: extra>=1; python_version < '4' and\n os_name == 'posix'\n").unwrap();
    let observed = observe_inventory(&request, 0);
    assert_eq!(
        observed.packages[0].requires_dist[0].requirement,
        "extra>=1; python_version < '4' and os_name == 'posix'"
    );
}
