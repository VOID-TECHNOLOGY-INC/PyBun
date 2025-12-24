use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use httpmock::prelude::*;
use pybun::lockfile::Lockfile;
use serde_json::json;
use std::fs;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

fn setup_package_mocks(server: &MockServer) -> String {
    let base = server.base_url();

    let project_body = json!({
        "info": { "name": "app", "version": "1.0.0" },
        "releases": {
            "1.0.0": [
                {
                    "filename": "app-1.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": format!("{}/files/app-1.0.0-py3-none-any.whl", base),
                    "yanked": false,
                    "digests": { "sha256": "abc" }
                },
                {
                    "filename": "app-1.0.0.tar.gz",
                    "packagetype": "sdist",
                    "url": format!("{}/files/app-1.0.0.tar.gz", base),
                    "yanked": false,
                    "digests": { "sha256": "def" }
                }
            ]
        }
    })
    .to_string();

    server.mock(|when, then| {
        when.method(GET).path("/pypi/app/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .header("ETag", "\"v1\"")
            .body(project_body.clone());
    });

    let project_meta_body = json!({
        "info": {
            "name": "app",
            "version": "1.0.0",
            "requires_dist": ["dep==2.0.0"]
        }
    })
    .to_string();

    server.mock(|when, then| {
        when.method(GET).path("/pypi/app/1.0.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(project_meta_body.clone());
    });

    let dep_body = json!({
        "info": { "name": "dep", "version": "2.0.0" },
        "releases": {
            "2.0.0": [
                {
                    "filename": "dep-2.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": format!("{}/files/dep-2.0.0-py3-none-any.whl", base),
                    "yanked": false,
                    "digests": { "sha256": "ghi" }
                }
            ]
        }
    })
    .to_string();

    server.mock(|when, then| {
        when.method(GET).path("/pypi/dep/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(dep_body.clone());
    });

    let dep_meta_body = json!({
        "info": {
            "name": "dep",
            "version": "2.0.0",
            "requires_dist": []
        }
    })
    .to_string();

    server.mock(|when, then| {
        when.method(GET).path("/pypi/dep/2.0.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(dep_meta_body.clone());
    });

    base
}

#[test]
fn install_defaults_to_pypi_with_dependencies() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let server = MockServer::start();
    let base_url = setup_package_mocks(&server);

    let pyproject = temp.path().join("pyproject.toml");
    fs::write(
        &pyproject,
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["app==1.0.0"]
"#,
    )
    .unwrap();

    bin()
        .current_dir(temp.path())
        .env("PYBUN_PYPI_BASE_URL", &base_url)
        .env("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap())
        .args(["install"])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(temp.path().join("pybun.lockb")).unwrap();
    assert!(lock.packages.contains_key("app"));
    assert!(lock.packages.contains_key("dep"));
}

#[test]
fn install_offline_uses_cached_metadata() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let server = MockServer::start();
    let base_url = setup_package_mocks(&server);

    let pyproject = temp.path().join("pyproject.toml");
    fs::write(
        &pyproject,
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["app==1.0.0"]
"#,
    )
    .unwrap();

    // First run online to populate cache
    bin()
        .current_dir(temp.path())
        .env("PYBUN_PYPI_BASE_URL", &base_url)
        .env("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap())
        .args(["install"])
        .assert()
        .success();

    // Second run offline using cache only (no server needed)
    bin()
        .current_dir(temp.path())
        .env("PYBUN_PYPI_BASE_URL", "http://127.0.0.1:9") // should not be hit
        .env("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap())
        .args(["install", "--offline"])
        .assert()
        .success();
}

#[test]
fn install_offline_without_cache_fails() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("cache");

    fs::write(
        temp.path().join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["app==1.0.0"]
"#,
    )
    .unwrap();

    bin()
        .current_dir(temp.path())
        .env("PYBUN_PYPI_BASE_URL", "http://127.0.0.1:9")
        .env("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap())
        .args(["install", "--offline"])
        .assert()
        .failure();
}
