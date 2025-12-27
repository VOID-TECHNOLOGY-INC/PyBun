use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use httpmock::prelude::*;
use pybun::pypi::{PyPiClient, PyPiIndex};
use pybun::resolver::PackageIndex;
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

#[tokio::test]
async fn concurrent_metadata_fetch_is_deduped() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let server = MockServer::start();
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
                }
            ]
        }
    })
    .to_string();

    let project_mock = server.mock(|when, then| {
        when.method(GET).path("/pypi/app/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(project_body.clone());
    });

    let meta_body = json!({
        "info": {
            "name": "app",
            "version": "1.0.0",
            "requires_dist": ["dep==1.0.0"]
        }
    })
    .to_string();

    let meta_mock = server.mock(|when, then| {
        when.method(GET).path("/pypi/app/1.0.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(meta_body.clone());
    });

    let prev_base = std::env::var("PYBUN_PYPI_BASE_URL").ok();
    let prev_cache = std::env::var("PYBUN_PYPI_CACHE_DIR").ok();
    unsafe {
        std::env::set_var("PYBUN_PYPI_BASE_URL", &base);
        std::env::set_var("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap());
    }

    let client = PyPiClient::from_env(false).unwrap();
    let index = PyPiIndex::new(client);

    let fut1 = index.get("app", "1.0.0");
    let fut2 = index.get("app", "1.0.0");
    let fut3 = index.get("app", "1.0.0");
    let (r1, r2, r3) = tokio::join!(fut1, fut2, fut3);
    assert!(r1.unwrap().is_some());
    assert!(r2.unwrap().is_some());
    assert!(r3.unwrap().is_some());

    assert_eq!(project_mock.hits(), 1);
    assert_eq!(meta_mock.hits(), 1);

    unsafe {
        if let Some(value) = prev_base {
            std::env::set_var("PYBUN_PYPI_BASE_URL", value);
        } else {
            std::env::remove_var("PYBUN_PYPI_BASE_URL");
        }
        if let Some(value) = prev_cache {
            std::env::set_var("PYBUN_PYPI_CACHE_DIR", value);
        } else {
            std::env::remove_var("PYBUN_PYPI_CACHE_DIR");
        }
    }
}

#[test]
fn install_does_not_prefetch_all_version_metadata() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let server = MockServer::start();
    let base = server.base_url();

    let project_body = json!({
        "info": { "name": "app", "version": "2.0.0" },
        "releases": {
            "1.0.0": [
                {
                    "filename": "app-1.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": format!("{}/files/app-1.0.0-py3-none-any.whl", base),
                    "yanked": false,
                    "digests": { "sha256": "abc" }
                }
            ],
            "2.0.0": [
                {
                    "filename": "app-2.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": format!("{}/files/app-2.0.0-py3-none-any.whl", base),
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
            .body(project_body.clone());
    });

    server.mock(|when, then| {
        when.method(GET).path("/pypi/app/1.0.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "info": {
                        "name": "app",
                        "version": "1.0.0",
                        "requires_dist": []
                    }
                })
                .to_string(),
            );
    });

    let unused_meta = server.mock(|when, then| {
        when.method(GET).path("/pypi/app/2.0.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "info": {
                        "name": "app",
                        "version": "2.0.0",
                        "requires_dist": []
                    }
                })
                .to_string(),
            );
    });

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
        .env("PYBUN_PYPI_BASE_URL", base)
        .env("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap())
        .args(["install"])
        .assert()
        .success();

    assert_eq!(unused_meta.hits(), 0);
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

#[test]
fn install_uses_fresh_cache_without_network() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let server = MockServer::start();
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
                }
            ]
        }
    })
    .to_string();

    let project_mock = server.mock(|when, then| {
        when.method(GET).path("/pypi/app/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .header("Cache-Control", "max-age=3600")
            .header("ETag", "\"v1\"")
            .body(project_body.clone());
    });

    let meta_mock = server.mock(|when, then| {
        when.method(GET).path("/pypi/app/1.0.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "info": {
                        "name": "app",
                        "version": "1.0.0",
                        "requires_dist": []
                    }
                })
                .to_string(),
            );
    });

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
        .env("PYBUN_PYPI_BASE_URL", &base)
        .env("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap())
        .args(["install"])
        .assert()
        .success();

    bin()
        .current_dir(temp.path())
        .env("PYBUN_PYPI_BASE_URL", &base)
        .env("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap())
        .args(["install"])
        .assert()
        .success();

    assert_eq!(project_mock.hits(), 1);
    assert_eq!(meta_mock.hits(), 1);
}
