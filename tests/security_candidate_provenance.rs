use pybun::security_assessment::{
    CoverageStatus, InventoryRequest, SourceIdentity, SourceKind, SourceRule, observe_inventory,
    qualification::provenance::{
        ApprovedRegistryBinding, ParentActivation, ProvenanceRequest, observe_provenance,
    },
};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const LOCK: &str = r#"version=1
revision=3
requires-python=">=3.11"
[[package]]
name="example"
version="1"
source={virtual="."}
dependencies=[{name="requests"}]
[package.metadata]
requires-dist=[{name="requests",specifier=">=2"}]
[[package]]
name="requests"
version="2.32.5"
source={registry="https://pypi.org/simple"}
dependencies=[{name="urllib3"}]
[[package]]
name="urllib3"
version="2.5.0"
source={registry="https://pypi.org/simple"}
"#;
fn fixture() -> (
    TempDir,
    TempDir,
    InventoryRequest,
    ProvenanceRequest,
    Vec<ApprovedRegistryBinding>,
) {
    let project = TempDir::new().unwrap();
    let cache = TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(project.path().join("pyproject.toml"),"[project]\nname='example'\nversion='1'\nrequires-python='>=3.11'\ndependencies=['requests>=2']\n").unwrap();
    fs::write(project.path().join("uv.lock"), LOCK).unwrap();
    let name = std::env::var_os("PYBUN_SECURITY_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let out=Command::new(name).args(["-I","-S","-B","-c","import sys,json;print(json.dumps([sys.executable,str(sys.version_info.major)+'.'+str(sys.version_info.minor)]))"]).output().unwrap();
    assert!(out.status.success());
    let values: Vec<String> = serde_json::from_slice(&out.stdout).unwrap();
    let python = PathBuf::from(&values[0]);
    assert!(
        Command::new(&python)
            .args(["-I", "-B", "-m", "venv", "--without-pip"])
            .arg(project.path().join(".venv"))
            .status()
            .unwrap()
            .success()
    );
    let site = if cfg!(windows) {
        project.path().join(".venv/Lib/site-packages")
    } else {
        project
            .path()
            .join(format!(".venv/lib/python{}/site-packages", values[1]))
    };
    for (name, version, requires) in [
        ("requests", "2.32.5", "Requires-Dist: urllib3>=1.21.1,<3\n"),
        ("urllib3", "2.5.0", ""),
    ] {
        let dir = site.join(format!("{name}-{version}.dist-info"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("METADATA"),
            format!("Name: {name}\nVersion: {version}\n{requires}"),
        )
        .unwrap();
    }
    let mut inventory = InventoryRequest::installed(project.path(), &python);
    inventory
        .source_policy
        .sources
        .push(SourceIdentity::new("public", "public-auth", SourceKind::PublicRegistry).unwrap());
    for name in ["requests", "urllib3"] {
        inventory.source_policy.rules.push(SourceRule{name:name.into(),distribution:None,source_id:"public".into(),upstream_name:Some(name.into()),ecosystem:Some("PyPI".into()),assumption:Some("Operator declares these registry fixture artifacts equivalent to their public projects.".into())});
    }
    let request = ProvenanceRequest {
        trusted_uv: pybun::env::find_uv_executable()
            .expect("install the supported uv test dependency"),
        approved_cache_root: cache.path().canonicalize().unwrap(),
        authorized_roots: vec![project.path().canonicalize().unwrap()],
        limits: inventory.limits.clone(),
    };
    let bindings = vec![ApprovedRegistryBinding {
        source_id: "public".into(),
        auth_scope_id: "public-auth".into(),
        registry_url: "https://pypi.org/simple".into(),
    }];
    (project, cache, inventory, request, bindings)
}
#[test]
fn real_frozen_public_graph_retains_installed_parent_constraint_and_honest_locked_paths() {
    let (project, _cache, inventory, request, bindings) = fixture();
    let before = fs::read(project.path().join("uv.lock")).unwrap();
    let observed = observe_inventory(&inventory, 0);
    let proof = observe_provenance(
        &request,
        &observed,
        &inventory.source_policy,
        &bindings,
        Instant::now() + Duration::from_secs(60),
    );
    let child = observed
        .packages
        .iter()
        .find(|p| p.name == "urllib3")
        .unwrap();
    let parent = observed
        .packages
        .iter()
        .find(|p| p.name == "requests")
        .unwrap();
    let entry = proof
        .instances
        .iter()
        .find(|p| p.instance_id == child.instance_id)
        .unwrap();
    assert_eq!(entry.parents.len(), 1, "{proof:?}");
    assert_eq!(entry.parents[0].parent_instance_id, parent.instance_id);
    assert_eq!(entry.parents[0].activation, ParentActivation::Proven);
    assert_eq!(entry.parents[0].requirements[0], parent.requires_dist[0]);
    assert_eq!(
        entry.parents[0].requirements[0].requirement,
        "urllib3>=1.21.1,<3"
    );
    assert_eq!(
        entry.locked_paths.as_ref().unwrap()["activation"],
        "not_evaluated"
    );
    assert_eq!(
        entry.locked_paths.as_ref().unwrap()["scope"],
        "locked_dependency_graph"
    );
    assert!(
        entry.locked_paths.as_ref().unwrap()["paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path["provenance"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kind| kind == "transitive"))
    );
    assert_eq!(fs::read(project.path().join("uv.lock")).unwrap(), before);
}
#[test]
fn changed_lock_and_unapproved_external_layout_are_incomplete_before_backend_execution() {
    let (project, _cache, inventory, mut request, bindings) = fixture();
    let observed = observe_inventory(&inventory, 0);
    fs::write(
        project.path().join("uv.lock"),
        LOCK.replace("2.5.0", "2.4.0"),
    )
    .unwrap();
    request.trusted_uv = PathBuf::from("/never-execute-this-backend");
    let proof = observe_provenance(
        &request,
        &observed,
        &inventory.source_policy,
        &bindings,
        Instant::now() + Duration::from_secs(60),
    );
    assert_ne!(proof.coverage.status, CoverageStatus::Complete);
    assert!(
        proof
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_GRAPH_INPUT_CHANGED")
    );
    fs::write(project.path().join("uv.lock"), LOCK).unwrap();
    fs::write(
        project.path().join("pyproject.toml"),
        "[project]\nname='example'\nversion='1'\n[tool.uv.workspace]\nmembers=['../outside']\n",
    )
    .unwrap();
    let observed = observe_inventory(&inventory, 0);
    let proof = observe_provenance(
        &request,
        &observed,
        &inventory.source_policy,
        &bindings,
        Instant::now() + Duration::from_secs(60),
    );
    assert!(
        proof
            .diagnostics
            .iter()
            .any(|d| d.code == "E_SECURITY_GRAPH_LAYOUT_UNSUPPORTED")
    );
}

fn run(
    inventory: &InventoryRequest,
    request: &ProvenanceRequest,
    bindings: &[ApprovedRegistryBinding],
) -> pybun::security_assessment::qualification::provenance::ProvenanceObservation {
    observe_provenance(
        request,
        &observe_inventory(inventory, 0),
        &inventory.source_policy,
        bindings,
        Instant::now() + Duration::from_secs(60),
    )
}
fn child<'a>(
    proof: &'a pybun::security_assessment::qualification::provenance::ProvenanceObservation,
    inventory: &InventoryRequest,
) -> &'a pybun::security_assessment::qualification::provenance::InstanceProvenance {
    let observed = observe_inventory(inventory, 0);
    let id = &observed
        .packages
        .iter()
        .find(|package| package.name == "urllib3")
        .unwrap()
        .instance_id;
    proof
        .instances
        .iter()
        .find(|entry| entry.instance_id == *id)
        .unwrap()
}
#[test]
fn divergent_installed_versions_and_ambiguous_registry_auth_scopes_never_flatten_parent_identity() {
    let (_project, _cache, inventory, request, mut bindings) = fixture();
    let mut observed = observe_inventory(&inventory, 0);
    observed
        .packages
        .iter_mut()
        .find(|package| package.name == "requests")
        .unwrap()
        .version = "2.31.0".into();
    let proof = observe_provenance(
        &request,
        &observed,
        &inventory.source_policy,
        &bindings,
        Instant::now() + Duration::from_secs(60),
    );
    let child = child(&proof, &inventory);
    assert!(child.parents.is_empty());
    assert_eq!(child.coverage.status, CoverageStatus::Partial);
    bindings.push(ApprovedRegistryBinding {
        source_id: "other-tenant".into(),
        auth_scope_id: "other-auth".into(),
        registry_url: "https://pypi.org/simple".into(),
    });
    let proof = run(&inventory, &request, &bindings);
    assert!(
        proof
            .instances
            .iter()
            .all(|entry| entry.parents.is_empty()
                && entry.coverage.status == CoverageStatus::Partial)
    );
}
#[test]
fn conditional_or_missing_parent_declarations_remain_unknown_and_never_use_lock_pins_as_constraints()
 {
    let (_project, _cache, inventory, request, bindings) = fixture();
    let mut observed = observe_inventory(&inventory, 0);
    let parent = observed
        .packages
        .iter_mut()
        .find(|package| package.name == "requests")
        .unwrap();
    parent.requires_dist[0].requirement = "urllib3<3; extra == 'security'".into();
    let proof = observe_provenance(
        &request,
        &observed,
        &inventory.source_policy,
        &bindings,
        Instant::now() + Duration::from_secs(60),
    );
    let entry = child(&proof, &inventory);
    assert_eq!(entry.parents[0].activation, ParentActivation::Unknown);
    assert_eq!(
        entry.parents[0].requirements[0].requirement,
        "urllib3<3; extra == 'security'"
    );
    assert_eq!(entry.coverage.status, CoverageStatus::Partial);
    observed
        .packages
        .iter_mut()
        .find(|package| package.name == "requests")
        .unwrap()
        .requires_dist[0]
        .requirement = "urllib3<3; python_version >= 'invalid-version'".into();
    let ignored_marker = observe_provenance(
        &request,
        &observed,
        &inventory.source_policy,
        &bindings,
        Instant::now() + Duration::from_secs(60),
    );
    assert_eq!(
        child(&ignored_marker, &inventory).parents[0].activation,
        ParentActivation::Unknown,
        "invalid marker must not become an unconditional parent fact"
    );
    observed
        .packages
        .iter_mut()
        .find(|package| package.name == "requests")
        .unwrap()
        .requires_dist
        .clear();
    let proof = observe_provenance(
        &request,
        &observed,
        &inventory.source_policy,
        &bindings,
        Instant::now() + Duration::from_secs(60),
    );
    let entry = child(&proof, &inventory);
    assert_eq!(entry.parents[0].activation, ParentActivation::Unknown);
    assert!(entry.parents[0].requirements.is_empty());
}
#[test]
fn explicit_snapshot_boundary_ignores_ancestor_workspace_and_keeps_target_and_cache_inputs_unchanged()
 {
    let (project, cache, inventory, request, bindings) = fixture();
    let sentinel = cache.path().join("pyproject.toml");
    fs::write(
        &sentinel,
        "[tool.uv.workspace]\nmembers=['outside-member']\n",
    )
    .unwrap();
    let outside = cache.path().join("outside-member");
    fs::create_dir(&outside).unwrap();
    fs::write(
        outside.join("pyproject.toml"),
        "malformed external workspace sentinel credential=private-secret",
    )
    .unwrap();
    let before_project = fs::read(project.path().join("pyproject.toml")).unwrap();
    let before_lock = fs::read(project.path().join("uv.lock")).unwrap();
    let proof = run(&inventory, &request, &bindings);
    assert_eq!(child(&proof, &inventory).parents.len(), 1, "{proof:?}");
    assert_eq!(
        fs::read(project.path().join("pyproject.toml")).unwrap(),
        before_project
    );
    assert_eq!(
        fs::read(project.path().join("uv.lock")).unwrap(),
        before_lock
    );
    assert_eq!(
        fs::read_to_string(&sentinel).unwrap(),
        "[tool.uv.workspace]\nmembers=['outside-member']\n"
    );
    assert_eq!(
        fs::read_dir(cache.path()).unwrap().count(),
        2,
        "temporary snapshot must be removed"
    );
    assert!(
        !serde_json::to_string(&proof)
            .unwrap()
            .contains("private-secret")
    );
}
#[cfg(unix)]
#[test]
fn bounded_backend_caps_output_deadline_and_version_header_without_echoing_stderr() {
    use std::os::unix::fs::PermissionsExt;
    let (project, _cache, inventory, mut request, bindings) = fixture();
    let mock = project.path().join("trusted-uv-fixture");
    request.trusted_uv = mock.clone();
    let cases = [
        (
            "#!/bin/sh\necho 'other 0.12.13'\n",
            "E_SECURITY_GRAPH_VERSION",
        ),
        (
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'uv 0.12.13'; else exec /usr/bin/yes oversized; fi\n",
            "E_SECURITY_GRAPH_LIMIT",
        ),
        ("#!/bin/sh\nexec /bin/sleep 10\n", "E_SECURITY_GRAPH_LIMIT"),
        (
            "#!/bin/sh\necho 'private-secret' >&2\nexit 2\n",
            "E_SECURITY_GRAPH_BACKEND",
        ),
    ];
    request.limits.max_response_bytes = 4096;
    for (script, code) in cases {
        request.limits.total_timeout_ms = if script.contains("sleep") { 200 } else { 1000 };
        fs::write(&mock, script).unwrap();
        fs::set_permissions(&mock, fs::Permissions::from_mode(0o755)).unwrap();
        let start = Instant::now();
        let proof = run(&inventory, &request, &bindings);
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(
            proof
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == code),
            "{proof:?}"
        );
        assert!(
            !serde_json::to_string(&proof)
                .unwrap()
                .contains("private-secret")
        );
    }
}

#[cfg(unix)]
#[test]
fn projected_snapshot_is_private_and_excludes_unneeded_credentials_before_real_uv_runs() {
    use std::os::unix::fs::PermissionsExt;
    let (project, cache, inventory, mut request, bindings) = fixture();
    let original_project = fs::read_to_string(project.path().join("pyproject.toml")).unwrap();
    fs::write(
        project.path().join("pyproject.toml"),
        format!(
            "{original_project}description='https://user:private-secret@example.invalid/config'\n"
        ),
    )
    .unwrap();
    fs::write(project.path().join("uv.lock"),format!("{LOCK}\n[[package.wheels]]\nurl='https://user:private-secret@example.invalid/wheel.whl'\n")).unwrap();
    let real_uv = request.trusted_uv.canonicalize().unwrap();
    let spy = cache.path().join("spy.py");
    fs::write(
        &spy,
        format!(
            r#"import os,stat,sys
uv={uv:?}
if '--version' not in sys.argv:
    assert stat.S_IMODE(os.stat('.').st_mode)==0o700
    for name in ['pyproject.toml','uv.lock']:
        assert stat.S_ISREG(os.lstat(name).st_mode)
        assert stat.S_IMODE(os.stat(name).st_mode)==0o600
        assert 'private-secret' not in open(name).read()
    assert stat.S_IMODE(os.stat(sys.argv[sys.argv.index('--cache-dir')+1]).st_mode)==0o700
os.execv(uv,[uv]+sys.argv[1:])
"#,
            uv = real_uv.to_string_lossy()
        ),
    )
    .unwrap();
    let mock = cache.path().join("spy-uv");
    fs::write(
        &mock,
        format!(
            "#!/bin/sh\nexec '{}' -I -S -B '{}' \"$@\"\n",
            inventory.trusted_python.display(),
            spy.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&mock, fs::Permissions::from_mode(0o700)).unwrap();
    request.trusted_uv = mock;
    let before_project = fs::read(project.path().join("pyproject.toml")).unwrap();
    let before_lock = fs::read(project.path().join("uv.lock")).unwrap();
    let proof = run(&inventory, &request, &bindings);
    assert_eq!(child(&proof, &inventory).parents.len(), 1, "{proof:?}");
    assert!(
        !serde_json::to_string(&proof)
            .unwrap()
            .contains("private-secret")
    );
    assert_eq!(
        fs::read(project.path().join("pyproject.toml")).unwrap(),
        before_project
    );
    assert_eq!(
        fs::read(project.path().join("uv.lock")).unwrap(),
        before_lock
    );
}
#[cfg(unix)]
#[test]
fn backend_lock_change_and_expired_shared_deadline_remain_explicitly_incomplete() {
    use std::os::unix::fs::PermissionsExt;
    let (project, _cache, inventory, mut request, bindings) = fixture();
    let real_uv = request.trusted_uv.canonicalize().unwrap();
    let mock = project.path().join("trusted-changing-backend");
    fs::write(&mock,format!("#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'uv 0.12.13'; else '{}' \"$@\"; printf '\\n# changed\\n' >> uv.lock; fi\n",real_uv.display())).unwrap();
    fs::set_permissions(&mock, fs::Permissions::from_mode(0o755)).unwrap();
    request.trusted_uv = mock;
    let proof = run(&inventory, &request, &bindings);
    assert!(
        proof
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "E_SECURITY_GRAPH_INPUT_CHANGED"),
        "{proof:?}"
    );
    assert_eq!(
        fs::read_to_string(project.path().join("uv.lock")).unwrap(),
        LOCK
    );
    let observed = observe_inventory(&inventory, 0);
    request.trusted_uv = PathBuf::from("/never-execute-expired-graph");
    let proof = observe_provenance(
        &request,
        &observed,
        &inventory.source_policy,
        &bindings,
        Instant::now() - Duration::from_millis(1),
    );
    assert!(
        proof
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "E_SECURITY_GRAPH_LIMIT")
    );
}

#[test]
fn explicit_private_registry_source_binding_retains_parent_provenance_without_public_name_flattening()
 {
    let (project, _cache, mut inventory, request, mut bindings) = fixture();
    inventory.source_policy.sources[0].kind = SourceKind::PrivateRegistry;
    inventory.source_policy.sources[0].id = "tenant-registry".into();
    for rule in &mut inventory.source_policy.rules {
        rule.source_id = "tenant-registry".into();
    }
    let url = "https://mirror.example.invalid/simple";
    fs::write(
        project.path().join("uv.lock"),
        LOCK.replace("https://pypi.org/simple", url),
    )
    .unwrap();
    bindings[0].source_id = "tenant-registry".into();
    bindings[0].registry_url = url.into();
    let proof = run(&inventory, &request, &bindings);
    let entry = child(&proof, &inventory);
    assert_eq!(entry.parents.len(), 1, "{proof:?}");
    assert_eq!(entry.parents[0].source_id, "tenant-registry");
    assert_eq!(entry.parents[0].activation, ParentActivation::Proven);
}
#[test]
fn unsupported_dynamic_local_and_credential_config_is_rejected_without_creating_snapshot_files() {
    let (project, cache, inventory, mut request, bindings) = fixture();
    request.trusted_uv = PathBuf::from("/never-execute-unconfined-graph");
    for declaration in [
        "[project]\nname='example'\nversion='1'\ndynamic=['dependencies']\n",
        "[project]\nname='example'\nversion='1'\ndependencies=['requests @ file:///outside/requests']\n",
        "[project]\nname='example'\nversion='1'\nrequires-python='https://user:private-secret@example.invalid'\n",
        "[project]\nname='example'\nversion='1'\n[build-system]\nrequires=[]\nbuild-backend='outside'\nbackend-path=['../outside']\n",
    ] {
        fs::write(project.path().join("pyproject.toml"), declaration).unwrap();
        let proof = run(&inventory, &request, &bindings);
        assert!(
            proof
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "E_SECURITY_GRAPH_LAYOUT_UNSUPPORTED"),
            "{proof:?}"
        );
        assert_eq!(fs::read_dir(cache.path()).unwrap().count(), 0);
        assert!(
            !serde_json::to_string(&proof)
                .unwrap()
                .contains("private-secret")
        );
    }
}

#[cfg(unix)]
#[test]
fn replacing_the_observed_root_with_a_symlink_cannot_expand_approved_authority() {
    let (project, _cache, inventory, mut request, bindings) = fixture();
    let observed = observe_inventory(&inventory, 0);
    let outside = TempDir::new().unwrap();
    let moved = TempDir::new().unwrap();
    for name in ["pyproject.toml", "uv.lock"] {
        fs::copy(project.path().join(name), outside.path().join(name)).unwrap();
    }
    fs::rename(project.path(), moved.path().join("original-project")).unwrap();
    std::os::unix::fs::symlink(outside.path(), project.path()).unwrap();
    request.trusted_uv = PathBuf::from("/must-not-run-after-authority-replacement");
    let proof = observe_provenance(
        &request,
        &observed,
        &inventory.source_policy,
        &bindings,
        Instant::now() + Duration::from_secs(60),
    );
    fs::remove_file(project.path()).unwrap();
    assert!(
        proof.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic.code.as_str(),
            "E_SECURITY_GRAPH_PATH" | "E_SECURITY_GRAPH_INPUT_CHANGED"
        )),
        "{proof:?}"
    );
}

#[cfg(unix)]
#[test]
fn symlink_cache_roots_with_trailing_separator_or_symlink_ancestors_are_rejected_before_writes() {
    use std::os::unix::fs::PermissionsExt;
    let (project, _cache, inventory, mut request, bindings) = fixture();
    let outside = TempDir::new().unwrap();
    fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let nested = outside.path().join("nested");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    let link = project.path().join("unapproved-cache-link");
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    request.trusted_uv = PathBuf::from("/must-not-execute-for-unapproved-cache");
    for path in [
        PathBuf::from(format!("{}/", link.display())),
        link.join("nested"),
    ] {
        request.approved_cache_root = path;
        let proof = run(&inventory, &request, &bindings);
        assert!(
            proof
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "E_SECURITY_GRAPH_PATH"),
            "{proof:?}"
        );
        assert_eq!(fs::read_dir(&nested).unwrap().count(), 0);
    }
}

#[cfg(unix)]
#[test]
fn cache_replacement_between_backend_stages_cannot_redirect_child_reads_or_cache_writes() {
    use std::os::unix::fs::PermissionsExt;
    let (project, _cache, inventory, mut request, bindings) = fixture();
    let outside = TempDir::new().unwrap();
    let moved = TempDir::new().unwrap();
    let moved_cache = moved.path().join("original-cache");
    let real_uv = request.trusted_uv.canonicalize().unwrap();
    let driver = project.path().join("replace-cache.py");
    fs::write(
        &driver,
        format!(
            r#"import os,pathlib,sys
uv={uv:?}
cache=pathlib.Path({cache:?})
moved=pathlib.Path({moved:?})
outside=pathlib.Path({outside:?})
if '--version' in sys.argv:
    name=pathlib.Path.cwd().name
    project=pathlib.Path('pyproject.toml').read_bytes()
    lock=pathlib.Path('uv.lock').read_bytes()
    os.rename(cache,moved)
    os.symlink(outside,cache)
    bait=outside/name
    bait.mkdir()
    (bait/'pyproject.toml').write_bytes(project)
    (bait/'uv.lock').write_bytes(lock)
    print('uv 0.12.13')
else:
    os.execv(uv,[uv]+sys.argv[1:])
"#,
            uv = real_uv.to_string_lossy(),
            cache = request.approved_cache_root.to_string_lossy(),
            moved = moved_cache.to_string_lossy(),
            outside = outside.path().to_string_lossy()
        ),
    )
    .unwrap();
    let mock = project.path().join("trusted-racing-backend");
    fs::write(
        &mock,
        format!(
            "#!/bin/sh\nexec '{}' -I -S -B '{}' \"$@\"\n",
            inventory.trusted_python.display(),
            driver.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&mock, fs::Permissions::from_mode(0o700)).unwrap();
    request.trusted_uv = mock;
    let proof = run(&inventory, &request, &bindings);
    if fs::symlink_metadata(&request.approved_cache_root)
        .unwrap()
        .file_type()
        .is_symlink()
    {
        fs::remove_file(&request.approved_cache_root).unwrap();
        fs::rename(&moved_cache, &request.approved_cache_root).unwrap();
    }
    assert_eq!(proof.coverage.status, CoverageStatus::Partial, "{proof:?}");
    assert!(
        proof.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic.code.as_str(),
            "E_SECURITY_GRAPH_INVALID" | "E_SECURITY_GRAPH_PATH"
        )),
        "{proof:?}"
    );
    let bait = fs::read_dir(outside.path())
        .unwrap()
        .next()
        .expect("version stage must have performed the controlled swap")
        .unwrap()
        .path();
    assert!(
        !bait.join("cache").exists(),
        "backend cache writes escaped the pinned working directory"
    );
    assert_eq!(fs::read_dir(&bait).unwrap().count(), 2);
    assert_eq!(
        fs::read_dir(&request.approved_cache_root).unwrap().count(),
        0,
        "cleanup must use the original cache capability"
    );
}

#[cfg(unix)]
#[test]
fn graph_url_preflight_does_not_expand_project_root_or_panic_in_deleted_process_cwd() {
    const CHILD: &str = "PYBUN_TEST_GRAPH_DELETED_CWD";
    if std::env::var_os(CHILD).is_some() {
        let (project, _cache, inventory, mut request, bindings) = fixture();
        fs::write(project.path().join("pyproject.toml"),"[project]\nname='example'\nversion='1'\nrequires-python='>=3.11'\ndependencies=['requests @ https://example.invalid/${PROJECT_ROOT}/requests.whl']\n").unwrap();
        let observed = observe_inventory(&inventory, 0);
        assert!(observed.target.is_some());
        request.trusted_uv = PathBuf::from("/must-not-execute-for-url-preflight");
        let doomed = std::env::current_dir().unwrap();
        fs::remove_dir(&doomed).unwrap();
        let proof = observe_provenance(
            &request,
            &observed,
            &inventory.source_policy,
            &bindings,
            Instant::now() + Duration::from_secs(60),
        );
        assert!(
            proof
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "E_SECURITY_GRAPH_LAYOUT_UNSUPPORTED")
        );
        return;
    }
    let doomed = TempDir::new().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "graph_url_preflight_does_not_expand_project_root_or_panic_in_deleted_process_cwd",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env_remove("PROJECT_ROOT")
        .current_dir(doomed.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated graph preflight failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
