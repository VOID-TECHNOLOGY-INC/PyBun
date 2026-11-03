#![cfg(unix)]

use pybun::security_assessment::{
    InventoryBackend, ObservationLimits,
    check::{CheckMode, CheckTarget, CheckUpdatesRequest},
    config::SecurityAuthority,
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};
use tempfile::TempDir;

fn fixture() -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("app")).unwrap();
    fs::create_dir(dir.path().join("app/.venv")).unwrap();
    fs::create_dir(dir.path().join("cache")).unwrap();
    fs::set_permissions(dir.path().join("cache"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        dir.path().join("app/pyproject.toml"),
        "[project]\nname='app'\nversion='1'\n",
    )
    .unwrap();
    fs::write(dir.path().join("app/.venv/pyvenv.cfg"), "version=3.13.0\n").unwrap();
    fs::write(dir.path().join("python"), "#!/bin/sh\ntouch helper-ran\n").unwrap();
    fs::set_permissions(dir.path().join("python"), fs::Permissions::from_mode(0o755)).unwrap();
    let text = r#"
[security_assessment]
config_version=1
default_profile="app"
[[security_assessment.profiles]]
id="app"
project_root="app"
environment="app/.venv"
backend="uv"
trusted_python="python"
source_policy_id="explicit"
provider_ids=["advisory"]
registry_source_ids=["public"]
cache_root="cache"
allowed_modes=["online", "offline"]
[[security_assessment.providers]]
id="advisory"
url="https://api.osv.dev/v1/querybatch"
auth_scope_id="public"
[[security_assessment.registries]]
source_id="public"
provider={id="registry", url="https://pypi.org/simple/", auth_scope_id="public"}
[security_assessment.source_policies.explicit]
sources=[{id="public", auth_scope_id="public", kind="public_registry"}]
rules=[{name="six", source_id="public", upstream_name="six", ecosystem="PyPI", assumption="Operator mapping."}]
disclosure=[{provider_id="advisory", source_id="public", packages=["six"]}, {provider_id="registry", source_id="public", packages=["six"]}]
[security_assessment.limits]
total_timeout_ms=1000
max_requests=3
max_output_bytes=65536
"#.to_owned();
    (dir, text)
}
fn auth(text: &str, base: &Path) -> SecurityAuthority {
    SecurityAuthority::from_toml(text, base).unwrap()
}
fn code<T>(result: Result<T, pybun::security_assessment::ObservationDiagnostic>) -> String {
    match result {
        Ok(_) => panic!("expected denial"),
        Err(error) => error.code,
    }
}

#[test]
fn missing_section_does_not_approve_any_profile_or_public_mapping() {
    let authority = auth("[project]\nname='anything'\n", Path::new("/"));
    assert_eq!(
        code(authority.authorize(&CheckUpdatesRequest::default(), None)),
        "E_SECURITY_AUTHORITY"
    );
    assert!(authority.profile_permissions(None).is_err());
}
#[test]
fn strict_section_and_every_reference_are_validated_without_secret_diagnostics() {
    let (dir, text) = fixture();
    for changed in [
        text.replace("config_version=1", "config_version=99"),
        text.replace(
            "config_version=1",
            "config_version=1\nunknown='TOKEN-CANARY'",
        ),
        text.replace(
            "source_policy_id=\"explicit\"",
            "source_policy_id=\"missing\"",
        ),
        text.replace("provider_ids=[\"advisory\"]", "provider_ids=[\"missing\"]"),
        text.replace(
            "registry_source_ids=[\"public\"]",
            "registry_source_ids=[\"missing\"]",
        ),
        text.replace(
            "id=\"advisory\"\nurl=",
            "id=\"advisory\"\nsecret='TOKEN-CANARY'\nurl=",
        ),
        text.replace(
            "https://api.osv.dev",
            "https://user:TOKEN-CANARY@api.osv.dev",
        ),
        text.replace("max_requests=3", "unknown_limit=3"),
        text.replace("total_timeout_ms=1000", "total_timeout_ms=60001"),
    ] {
        let error = match SecurityAuthority::from_toml(&changed, dir.path()) {
            Ok(_) => panic!("accepted invalid config"),
            Err(error) => error,
        };
        assert!(!format!("{error:?}").contains("TOKEN-CANARY"));
    }
    assert!(!dir.path().join("helper-ran").exists());
}
#[test]
fn permissions_are_frozen_and_selection_cannot_retarget_or_widen_budgets() {
    let (dir, text) = fixture();
    let authority = auth(&text, dir.path());
    let permissions = authority.profile_permissions(None).unwrap();
    assert_eq!(permissions.backend, InventoryBackend::Uv);
    assert_eq!(
        permissions.project_root,
        dir.path().join("app").canonicalize().unwrap()
    );
    assert!(
        authority
            .authorize(&CheckUpdatesRequest::default(), Some(0))
            .is_ok()
    );
    let request = CheckUpdatesRequest {
        project: Some(dir.path().into()),
        ..Default::default()
    };
    assert!(authority.authorize(&request, None).is_err());
    let request = CheckUpdatesRequest {
        limits: Some(ObservationLimits::default()),
        ..Default::default()
    };
    assert_eq!(
        code(authority.authorize(&request, None)),
        "E_SECURITY_LIMIT"
    );
    let request = CheckUpdatesRequest {
        max_cache_age_seconds: Some(86401),
        ..Default::default()
    };
    assert_eq!(
        code(authority.authorize(&request, None)),
        "E_SECURITY_LIMIT"
    );
    let request = CheckUpdatesRequest {
        mode: CheckMode::OnlineWithCacheFallback,
        ..Default::default()
    };
    assert!(authority.authorize(&request, None).is_err());
}
#[test]
fn replaced_environment_cache_project_and_executable_revoke_before_effects() {
    for relative in ["app/.venv", "cache", "app", "python"] {
        let (dir, text) = fixture();
        let authority = auth(&text, dir.path());
        let path = dir.path().join(relative);
        let old = dir.path().join("saved");
        fs::rename(&path, &old).unwrap();
        if relative == "python" {
            fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        } else {
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert!(
            authority.profile_permissions(None).is_ok(),
            "frozen lookup must not perform filesystem checks"
        );
        assert!(
            authority
                .authorize(&CheckUpdatesRequest::default(), None)
                .is_err(),
            "{relative}"
        );
        assert!(!dir.path().join("helper-ran").exists());
    }
}
#[test]
fn symlink_retarget_and_cache_permission_revocation_are_rejected() {
    let (dir, text) = fixture();
    symlink(dir.path().join("python"), dir.path().join("python-link")).unwrap();
    let text = text.replace(
        "trusted_python=\"python\"",
        "trusted_python=\"python-link\"",
    );
    let authority = auth(&text, dir.path());
    fs::remove_file(dir.path().join("python-link")).unwrap();
    symlink("/bin/sh", dir.path().join("python-link")).unwrap();
    assert!(
        authority
            .authorize(&CheckUpdatesRequest::default(), None)
            .is_err()
    );
    let (dir, text) = fixture();
    let authority = auth(&text, dir.path());
    fs::set_permissions(dir.path().join("cache"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        authority
            .authorize(&CheckUpdatesRequest::default(), None)
            .is_err()
    );
}
#[test]
fn locked_is_unsupported_before_any_target_io() {
    let (dir, text) = fixture();
    let authority = auth(&text, dir.path());
    fs::remove_dir_all(dir.path().join("app")).unwrap();
    let request = CheckUpdatesRequest {
        target: CheckTarget::Locked,
        ..Default::default()
    };
    assert_eq!(
        code(authority.authorize(&request, None)),
        "E_SECURITY_UNSUPPORTED_INVENTORY"
    );
}
#[test]
fn loader_refuses_symlinks_fifo_and_oversized_input_without_waiting() {
    let (dir, text) = fixture();
    let path = dir.path().join("config.toml");
    fs::write(&path, text).unwrap();
    assert!(SecurityAuthority::load(&path).is_ok());
    symlink(&path, dir.path().join("link")).unwrap();
    assert!(SecurityAuthority::load(&dir.path().join("link")).is_err());
    fs::write(&path, vec![b'x'; 1024 * 1024]).unwrap();
    assert!(SecurityAuthority::load(&path).is_err());
    let fifo = dir.path().join("fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    let now = std::time::Instant::now();
    assert!(SecurityAuthority::load(&fifo).is_err());
    assert!(now.elapsed().as_secs() < 2);
}

#[test]
fn explicit_external_environment_is_approved_but_alias_retarget_is_not() {
    let (dir, text) = fixture();
    let outside = TempDir::new().unwrap();
    let original = outside.path().join("original");
    let replacement = outside.path().join("replacement");
    fs::create_dir(&original).unwrap();
    fs::create_dir(&replacement).unwrap();
    let alias = outside.path().join("env");
    symlink(&original, &alias).unwrap();
    let text = text.replace(
        "environment=\"app/.venv\"",
        &format!("environment={:?}", alias),
    );
    let authority = auth(&text, dir.path());
    let approved = authority
        .authorize(&CheckUpdatesRequest::default(), None)
        .unwrap();
    assert_eq!(
        approved.permissions().environment_root,
        original.canonicalize().unwrap()
    );
    fs::remove_file(&alias).unwrap();
    symlink(&replacement, &alias).unwrap();
    assert!(
        authority
            .authorize(&CheckUpdatesRequest::default(), None)
            .is_err()
    );
}
#[test]
fn narrowed_timeout_and_profile_bounds_are_effective_and_zero_server_cap_is_not_unbounded() {
    let (dir, text) = fixture();
    let authority = auth(&text, dir.path());
    let approved = authority
        .authorize(&CheckUpdatesRequest::default(), Some(5))
        .unwrap();
    assert_eq!(approved.limits().total_timeout_ms, 5);
    assert_eq!(approved.limits().http_timeout_ms, 5);
    let approved = authority
        .authorize(&CheckUpdatesRequest::default(), Some(0))
        .unwrap();
    assert_eq!(approved.limits().total_timeout_ms, 1000);
    let mut narrower = approved.limits().clone();
    narrower.max_requests = 2;
    narrower.total_timeout_ms = 500;
    let request = CheckUpdatesRequest {
        limits: Some(narrower),
        ..Default::default()
    };
    assert!(authority.authorize(&request, None).is_ok());
    let text = text.replace(
        "max_requests=3",
        "max_requests=3\n[security_assessment.profiles.limits]\nmax_requests=4",
    );
    assert!(SecurityAuthority::from_toml(&text, dir.path()).is_err());
}
#[test]
fn executable_content_change_and_removed_access_revoke_current_authority() {
    let (dir, text) = fixture();
    let authority = auth(&text, dir.path());
    fs::write(dir.path().join("python"), "#!/bin/sh\ntouch compromised\n").unwrap();
    assert!(
        authority
            .authorize(&CheckUpdatesRequest::default(), None)
            .is_err()
    );
    let (dir, text) = fixture();
    let authority = auth(&text, dir.path());
    fs::set_permissions(
        dir.path().join("app/.venv"),
        fs::Permissions::from_mode(0o0),
    )
    .unwrap();
    assert!(
        authority
            .authorize(&CheckUpdatesRequest::default(), None)
            .is_err()
    );
    fs::set_permissions(
        dir.path().join("app/.venv"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}
#[test]
fn unsupported_scope_is_rejected_before_helper_or_cache_validation() {
    let (dir, text) = fixture();
    let text = text.replace(
        "backend=\"uv\"",
        "scope={members=[\"member\"], groups=[], extras=[]}\nbackend=\"uv\"",
    );
    let authority = auth(&text, dir.path());
    fs::remove_dir(dir.path().join("cache")).unwrap();
    assert_eq!(
        code(authority.authorize(&CheckUpdatesRequest::default(), None)),
        "E_SECURITY_UNSUPPORTED_SCOPE"
    );
    assert!(!dir.path().join("helper-ran").exists());
}
#[test]
fn pyproject_section_and_loaded_snapshot_do_not_accept_later_config_grants() {
    let (dir, text) = fixture();
    let nested = text.replace("security_assessment", "tool.pybun.security_assessment");
    assert!(SecurityAuthority::from_toml(&nested, dir.path()).is_ok());
    let path = dir.path().join("operator.toml");
    fs::write(&path, &text).unwrap();
    let authority = SecurityAuthority::load(&path).unwrap();
    fs::write(&path, text.replace("id=\"app\"", "id=\"new-profile\"")).unwrap();
    assert!(authority.profile_permissions(Some("app")).is_ok());
    assert!(authority.profile_permissions(Some("new-profile")).is_err());
    assert!(
        authority
            .authorize(&CheckUpdatesRequest::default(), None)
            .is_ok()
    );
}

#[test]
fn selected_policy_digest_ignores_order_credentials_and_unselected_profiles() {
    let (dir, text) = fixture();
    let one = auth(&text, dir.path())
        .authorize(&CheckUpdatesRequest::default(), None)
        .unwrap();
    let changed = text.replace("packages=[\"six\"]", "packages=[\"SIX\", \"six\"]");
    let two = auth(&changed, dir.path())
        .authorize(&CheckUpdatesRequest::default(), None)
        .unwrap();
    assert_eq!(one.policy_digest(), two.policy_digest());
    let changed = format!(
        "{text}\n[[security_assessment.profiles]]\nid='other'\nproject_root='app'\nenvironment='app/.venv'\nbackend='native'\ntrusted_python='python'\nsource_policy_id='none'\n[security_assessment.source_policies.none]\n"
    );
    let other = auth(&changed, dir.path())
        .authorize(&CheckUpdatesRequest::default(), None)
        .unwrap();
    assert_eq!(one.policy_digest(), other.policy_digest());
    let changed = text.replace("auth_scope_id=\"public\"", "auth_scope_id=\"different\"");
    let other = auth(&changed, dir.path())
        .authorize(&CheckUpdatesRequest::default(), None)
        .unwrap();
    assert_ne!(one.policy_digest(), other.policy_digest());
}

#[test]
fn credentials_are_not_part_of_policy_identity_or_errors_and_backend_is_frozen() {
    const CHILD: &str = "PYBUN_SECURITY_CONFIG_CREDENTIAL_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "credentials_are_not_part_of_policy_identity_or_errors_and_backend_is_frozen",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("PYBUN_CONFIG_TOKEN_A", "CANARY-ALPHA")
            .env("PYBUN_CONFIG_TOKEN_B", "CANARY-BETA")
            .env("PYBUN_CONFIG_TOKEN_BAD", "CANARY-BAD\nHEADER")
            .env("PYBUN_BACKEND", "native")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let (dir, text) = fixture();
    let credential_text = text.replace(
        "id=\"advisory\"\nurl=",
        "id=\"advisory\"\nbearer_token_env=\"PYBUN_CONFIG_TOKEN_A\"\nurl=",
    );
    let first = auth(&credential_text, dir.path())
        .authorize(&CheckUpdatesRequest::default(), None)
        .unwrap();
    assert_eq!(first.permissions().backend, InventoryBackend::Uv);
    let second = auth(&credential_text.replace("TOKEN_A", "TOKEN_B"), dir.path())
        .authorize(&CheckUpdatesRequest::default(), None)
        .unwrap();
    assert_eq!(first.policy_digest(), second.policy_digest());
    let bad = match SecurityAuthority::from_toml(
        &credential_text.replace("TOKEN_A", "TOKEN_BAD"),
        dir.path(),
    ) {
        Ok(_) => panic!("accepted invalid header"),
        Err(error) => error,
    };
    assert!(!format!("{bad:?}").contains("CANARY"));
}

#[test]
fn selected_endpoint_array_order_is_semantically_irrelevant() {
    let (dir, text) = fixture();
    let text=text.replace("provider_ids=[\"advisory\"]","provider_ids=[\"advisory\",\"other-advisory\"]")
        .replace("registry_source_ids=[\"public\"]","registry_source_ids=[\"public\",\"other\"]")
        .replace("sources=[{id=\"public\", auth_scope_id=\"public\", kind=\"public_registry\"}]","sources=[{id=\"public\", auth_scope_id=\"public\", kind=\"public_registry\"},{id=\"other\", auth_scope_id=\"private\", kind=\"private_registry\"}]");
    let extra = "\n[[security_assessment.providers]]\nid='other-advisory'\nurl='https://other.invalid/v1/querybatch'\nauth_scope_id='other-auth'\n[[security_assessment.registries]]\nsource_id='other'\nprovider={id='registry-other',url='https://other.invalid/simple/',auth_scope_id='private'}\n";
    let first_text = format!("{text}{extra}");
    let second_text = first_text
        .replace(
            "[\"advisory\",\"other-advisory\"]",
            "[\"other-advisory\",\"advisory\"]",
        )
        .replace("[\"public\",\"other\"]", "[\"other\",\"public\"]");
    let first = auth(&first_text, dir.path())
        .authorize(&CheckUpdatesRequest::default(), None)
        .unwrap();
    let second = auth(&second_text, dir.path())
        .authorize(&CheckUpdatesRequest::default(), None)
        .unwrap();
    assert_eq!(first.policy_digest(), second.policy_digest());
}

#[test]
fn effective_mode_and_bounds_change_identity_while_fail_on_does_not() {
    use pybun::security_assessment::check::CheckSeverityThreshold;
    let (dir, text) = fixture();
    let authority = auth(&text, dir.path());
    let one = authority
        .authorize(&CheckUpdatesRequest::default(), None)
        .unwrap();
    let threshold = CheckUpdatesRequest {
        fail_on: Some(CheckSeverityThreshold::Critical),
        ..Default::default()
    };
    assert_eq!(
        one.policy_digest(),
        authority
            .authorize(&threshold, None)
            .unwrap()
            .policy_digest()
    );
    for request in [
        CheckUpdatesRequest {
            mode: CheckMode::Offline,
            ..Default::default()
        },
        CheckUpdatesRequest {
            max_cache_age_seconds: Some(60),
            ..Default::default()
        },
    ] {
        assert_ne!(
            one.policy_digest(),
            authority.authorize(&request, None).unwrap().policy_digest()
        );
    }
    assert_ne!(
        one.policy_digest(),
        authority
            .authorize(&CheckUpdatesRequest::default(), Some(500))
            .unwrap()
            .policy_digest()
    );
}

#[test]
fn current_group_declarations_are_checked_before_cache_or_helper_access() {
    let (dir, text) = fixture();
    let text = text.replace(
        "backend=\"uv\"",
        "scope={members=[],groups=[\"dev\"],extras=[]}\nbackend=\"uv\"",
    );
    fs::write(
        dir.path().join("app/pyproject.toml"),
        "[project]\nname='app'\nversion='1'\n[dependency-groups]\ndev=['six']\n",
    )
    .unwrap();
    let authority = auth(&text, dir.path());
    assert!(
        authority
            .authorize(&CheckUpdatesRequest::default(), None)
            .is_ok()
    );
    fs::write(
        dir.path().join("app/pyproject.toml"),
        "[project]\nname='app'\nversion='1'\n",
    )
    .unwrap();
    fs::remove_dir(dir.path().join("cache")).unwrap();
    assert_eq!(
        code(authority.authorize(&CheckUpdatesRequest::default(), None)),
        "E_SECURITY_UNSUPPORTED_SCOPE"
    );
    assert!(!dir.path().join("helper-ran").exists());
}

#[test]
fn optional_provenance_requires_bound_registry_and_current_private_cache() {
    let (dir, text) = fixture();
    let cache = dir.path().join("graph-cache");
    fs::create_dir(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    let text=text.replace("trusted_python=\"python\"","trusted_python=\"python\"\ntrusted_uv=\"python\"\nprovenance_cache_root=\"graph-cache\"\nregistry_bindings=[{source_id=\"public\",auth_scope_id=\"public\",registry_url=\"https://pypi.org/simple\"}]");
    let authority = auth(&text, dir.path());
    assert!(
        authority
            .authorize(&CheckUpdatesRequest::default(), None)
            .is_ok()
    );
    for changed in [
        text.replace("backend=\"uv\"", "backend=\"native\""),
        text.replace(
            "registry_url=\"https://pypi.org/simple\"",
            "registry_url=\"https://wrong.invalid/simple\"",
        ),
        text.replace("trusted_uv=\"python\"\n", ""),
    ] {
        assert!(SecurityAuthority::from_toml(&changed, dir.path()).is_err());
    }
    fs::set_permissions(cache, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        authority
            .authorize(&CheckUpdatesRequest::default(), None)
            .is_err()
    );
}

#[test]
fn raw_typed_continuation_is_parsed_before_cache_or_helper_validation() {
    use pybun::security_assessment::qualification::schedule::AssessmentContinuation;
    let (dir, text) = fixture();
    let authority = auth(&text, dir.path());
    fs::remove_dir(dir.path().join("cache")).unwrap();
    let continuation: AssessmentContinuation =
        serde_json::from_value(serde_json::json!("invalid-cursor")).unwrap();
    let request = CheckUpdatesRequest {
        continuation: Some(continuation),
        ..Default::default()
    };
    assert_eq!(
        code(authority.authorize(&request, None)),
        "E_SECURITY_CONTINUATION"
    );
    assert!(!dir.path().join("helper-ran").exists());
}

#[test]
fn preparation_is_pure_and_expired_work_cannot_touch_replaced_targets() {
    let (dir, text) = fixture();
    let authority = auth(&text, dir.path());
    let expected = authority.profile_permissions(None).unwrap();
    fs::remove_dir_all(dir.path().join("app")).unwrap();
    fs::remove_dir(dir.path().join("cache")).unwrap();
    fs::remove_file(dir.path().join("python")).unwrap();
    let prepared = authority
        .prepare(&CheckUpdatesRequest::default(), Some(1))
        .unwrap();
    assert_eq!(prepared.permissions().project_root, expected.project_root);
    assert_eq!(prepared.limits().total_timeout_ms, 1);
    while std::time::Instant::now() < prepared.deadline() {
        std::hint::spin_loop();
    }
    assert_eq!(code(prepared.authorize()), "E_SECURITY_DEADLINE");
    assert!(!dir.path().join("helper-ran").exists());
}

#[test]
fn executable_revalidation_hash_spends_the_same_deadline_before_cache_access() {
    let (dir, text) = fixture();
    let executable = dir.path().join("large-python");
    fs::File::create(&executable)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let text = text.replace(
        "trusted_python=\"python\"",
        "trusted_python=\"large-python\"",
    );
    let authority = auth(&text, dir.path());
    fs::remove_dir(dir.path().join("cache")).unwrap();
    let prepared = authority
        .prepare(&CheckUpdatesRequest::default(), Some(1))
        .unwrap();
    let started = std::time::Instant::now();
    assert_eq!(code(prepared.authorize()), "E_SECURITY_DEADLINE");
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert!(!dir.path().join("helper-ran").exists());
}
