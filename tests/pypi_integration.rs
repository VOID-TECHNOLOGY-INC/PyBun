use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use httpmock::prelude::*;
use pybun::lockfile::Lockfile;
use pybun::pypi::{PyPiClient, PyPiIndex};
use pybun::resolver::PackageIndex;
use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

fn ensure_venv(project_root: &Path) -> PathBuf {
    let venv = project_root.join(".venv");
    if !venv.exists() {
        let status = std::process::Command::new("python3")
            .args(["-m", "venv", ".venv"])
            .current_dir(project_root)
            .status()
            .expect("Failed to create venv");
        assert!(status.success(), "Failed to create venv: {:?}", status);
    }
    venv
}

fn wheel_bytes() -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::FileOptions::default();
    zip.start_file("dummy.txt", options)
        .expect("start wheel entry");
    zip.write_all(b"ok").expect("write wheel entry");
    let cursor = zip.finish().expect("finish wheel zip");
    cursor.into_inner()
}

fn sdist_bytes(dist_name: &str, module_name: &str, version: &str) -> Vec<u8> {
    let root = format!("{dist_name}-{version}");
    let wheel_stem = dist_name.replace('-', "_");
    let pyproject = r#"[build-system]
requires = []
build-backend = "backend"
backend-path = ["."]
"#;
    let backend = format!(
        r#"from __future__ import annotations
import base64
import hashlib
import pathlib
import zipfile

MODULE_NAME = "{module_name}"
DIST_NAME = "{dist_name}"
WHEEL_STEM = "{wheel_stem}"
VERSION = "{version}"

def _wheel_name() -> str:
    return f"{{WHEEL_STEM}}-{{VERSION}}-py3-none-any.whl"

def _dist_info() -> str:
    return f"{{WHEEL_STEM}}-{{VERSION}}.dist-info"

def _record_line(path: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
    return f"{{path}},sha256={{digest}},{{len(data)}}\n"

def build_wheel(wheel_directory: str, config_settings=None, metadata_directory=None) -> str:
    root = pathlib.Path(__file__).resolve().parent
    wheel_dir = pathlib.Path(wheel_directory)
    wheel_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = wheel_dir / _wheel_name()
    package_bytes = (root / MODULE_NAME / "__init__.py").read_bytes()
    metadata = f"Metadata-Version: 2.1\nName: {{DIST_NAME}}\nVersion: {{VERSION}}\n\n".encode()
    wheel = b"Wheel-Version: 1.0\nGenerator: backend\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    record_path = f"{{_dist_info()}}/RECORD"
    record = (
        _record_line(f"{{MODULE_NAME}}/__init__.py", package_bytes)
        + _record_line(f"{{_dist_info()}}/METADATA", metadata)
        + _record_line(f"{{_dist_info()}}/WHEEL", wheel)
        + f"{{record_path}},,\n"
    ).encode()
    with zipfile.ZipFile(wheel_path, "w") as zf:
        zf.writestr(f"{{MODULE_NAME}}/__init__.py", package_bytes)
        zf.writestr(f"{{_dist_info()}}/METADATA", metadata)
        zf.writestr(f"{{_dist_info()}}/WHEEL", wheel)
        zf.writestr(record_path, record)
    return wheel_path.name

def prepare_metadata_for_build_wheel(metadata_directory: str, config_settings=None) -> str:
    dist_info = pathlib.Path(metadata_directory) / _dist_info()
    dist_info.mkdir(parents=True, exist_ok=True)
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {{DIST_NAME}}\nVersion: {{VERSION}}\n\n",
        encoding="utf-8",
    )
    (dist_info / "WHEEL").write_text(
        "Wheel-Version: 1.0\nGenerator: backend\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        encoding="utf-8",
    )
    (dist_info / "RECORD").write_text("", encoding="utf-8")
    return dist_info.name

def get_requires_for_build_wheel(config_settings=None):
    return []
"#
    );

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::FileOptions::default();
    zip.start_file(format!("{root}/pyproject.toml"), options)
        .expect("start pyproject entry");
    zip.write_all(pyproject.as_bytes())
        .expect("write pyproject entry");
    zip.start_file(format!("{root}/backend.py"), options)
        .expect("start backend entry");
    zip.write_all(backend.as_bytes())
        .expect("write backend entry");
    zip.start_file(format!("{root}/{module_name}/__init__.py"), options)
        .expect("start package entry");
    zip.write_all(b"VALUE = 'installed from sdist'\n")
        .expect("write package entry");
    let cursor = zip.finish().expect("finish sdist zip");
    cursor.into_inner()
}

fn mock_download(server: &MockServer, filename: &str) {
    let path = format!("/files/{}", filename);
    let body = wheel_bytes();
    server.mock(move |when, then| {
        when.method(GET).path(path.as_str());
        then.status(200)
            .header("Content-Type", "application/octet-stream")
            .body(body.clone());
    });
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
                    "digests": { "sha256": "placeholder" }
                },
                {
                    "filename": "app-1.0.0.tar.gz",
                    "packagetype": "sdist",
                    "url": format!("{}/files/app-1.0.0.tar.gz", base),
                    "yanked": false,
                    "digests": { "sha256": "placeholder" }
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
                    "digests": { "sha256": "placeholder" }
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

    mock_download(server, "app-1.0.0-py3-none-any.whl");
    mock_download(server, "dep-2.0.0-py3-none-any.whl");

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
                    "digests": { "sha256": "placeholder" }
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
    let venv = ensure_venv(temp.path());

    let project_body = json!({
        "info": { "name": "app", "version": "2.0.0" },
        "releases": {
            "1.0.0": [
                {
                    "filename": "app-1.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": format!("{}/files/app-1.0.0-py3-none-any.whl", base),
                    "yanked": false,
                    "digests": { "sha256": "placeholder" }
                }
            ],
            "2.0.0": [
                {
                    "filename": "app-2.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": format!("{}/files/app-2.0.0-py3-none-any.whl", base),
                    "yanked": false,
                    "digests": { "sha256": "placeholder" }
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

    mock_download(&server, "app-1.0.0-py3-none-any.whl");
    mock_download(&server, "app-2.0.0-py3-none-any.whl");

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
        .env("PYBUN_ENV", venv.to_str().unwrap())
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
    let venv = ensure_venv(temp.path());

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
        .env("PYBUN_ENV", venv.to_str().unwrap())
        .args(["install"])
        .assert()
        .success();

    let lock = Lockfile::load_from_path(temp.path().join("pybun.lockb")).unwrap();
    assert!(lock.packages.contains_key("app"));
    assert!(lock.packages.contains_key("dep"));
}

#[test]
fn install_resolves_requested_extras_from_root_requirement() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let server = MockServer::start();
    let base = server.base_url();
    let venv = ensure_venv(temp.path());

    let app_body = json!({
        "info": { "name": "app", "version": "1.0.0" },
        "releases": {
            "1.0.0": [
                {
                    "filename": "app-1.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": format!("{}/files/app-1.0.0-py3-none-any.whl", base),
                    "yanked": false,
                    "digests": { "sha256": "placeholder" }
                }
            ]
        }
    })
    .to_string();

    let app_mock = server.mock(|when, then| {
        when.method(GET).path("/pypi/app/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(app_body.clone());
    });

    let app_meta = json!({
        "info": {
            "name": "app",
            "version": "1.0.0",
            "requires_dist": [
                "dep==2.0.0",
                "dep-extra==3.0.0; extra == 'all'"
            ]
        }
    })
    .to_string();
    server.mock(|when, then| {
        when.method(GET).path("/pypi/app/1.0.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(app_meta.clone());
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
                    "digests": { "sha256": "placeholder" }
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
    server.mock(|when, then| {
        when.method(GET).path("/pypi/dep/2.0.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
                json!({ "info": { "name": "dep", "version": "2.0.0", "requires_dist": [] } })
                    .to_string(),
            );
    });

    let dep_extra_body = json!({
        "info": { "name": "dep-extra", "version": "3.0.0" },
        "releases": {
            "3.0.0": [
                {
                    "filename": "dep_extra-3.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": format!("{}/files/dep_extra-3.0.0-py3-none-any.whl", base),
                    "yanked": false,
                    "digests": { "sha256": "placeholder" }
                }
            ]
        }
    })
    .to_string();
    server.mock(|when, then| {
        when.method(GET).path("/pypi/dep-extra/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(dep_extra_body.clone());
    });
    server.mock(|when, then| {
        when.method(GET).path("/pypi/dep-extra/3.0.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
                json!({ "info": { "name": "dep-extra", "version": "3.0.0", "requires_dist": [] } })
                    .to_string(),
            );
    });

    mock_download(&server, "app-1.0.0-py3-none-any.whl");
    mock_download(&server, "dep-2.0.0-py3-none-any.whl");
    mock_download(&server, "dep_extra-3.0.0-py3-none-any.whl");

    fs::write(
        temp.path().join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["app[all]==1.0.0"]
"#,
    )
    .unwrap();

    bin()
        .current_dir(temp.path())
        .env("PYBUN_PYPI_BASE_URL", &base)
        .env("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap())
        .env("PYBUN_ENV", venv.to_str().unwrap())
        .args(["install"])
        .assert()
        .success();

    assert_eq!(
        app_mock.hits(),
        1,
        "should query the base package name once"
    );

    let lock = Lockfile::load_from_path(temp.path().join("pybun.lockb")).unwrap();
    assert!(lock.packages.contains_key("app"));
    assert!(lock.packages.contains_key("dep"));
    assert!(lock.packages.contains_key("dep-extra"));
    assert!(
        lock.packages["app"]
            .dependencies
            .iter()
            .any(|dep| dep == "dep-extra==3.0.0")
    );
}

#[test]
fn install_builds_from_sdist_when_wheel_is_unavailable() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let server = MockServer::start();
    let base = server.base_url();
    let venv = ensure_venv(temp.path());
    let sdist = sdist_bytes("source-only", "source_only", "0.5.0");

    let project_body = json!({
        "info": { "name": "source-only", "version": "0.5.0" },
        "releases": {
            "0.5.0": [
                {
                    "filename": "source-only-0.5.0.zip",
                    "packagetype": "sdist",
                    "url": format!("{}/files/source-only-0.5.0.zip", base),
                    "yanked": false,
                    "digests": { "sha256": "placeholder" }
                }
            ]
        }
    })
    .to_string();
    server.mock(|when, then| {
        when.method(GET).path("/pypi/source-only/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(project_body.clone());
    });
    server.mock(|when, then| {
        when.method(GET).path("/pypi/source-only/0.5.0/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(
            json!({ "info": { "name": "source-only", "version": "0.5.0", "requires_dist": [] } })
                .to_string(),
        );
    });
    server.mock(|when, then| {
        when.method(GET).path("/files/source-only-0.5.0.zip");
        then.status(200)
            .header("Content-Type", "application/zip")
            .body(sdist.clone());
    });

    fs::write(
        temp.path().join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["source-only==0.5.0"]
"#,
    )
    .unwrap();

    bin()
        .current_dir(temp.path())
        .env("PYBUN_PYPI_BASE_URL", &base)
        .env("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap())
        .env("PYBUN_ENV", venv.to_str().unwrap())
        .args(["install"])
        .assert()
        .success();

    let python = if cfg!(windows) {
        venv.join("Scripts").join("python.exe")
    } else {
        venv.join("bin").join("python")
    };
    let output = std::process::Command::new(&python)
        .args(["-c", "import source_only; print(source_only.VALUE, end='')"])
        .output()
        .expect("import installed sdist package");
    assert!(
        output.status.success(),
        "python import failed: {:?}",
        output
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "installed from sdist"
    );

    let lock = Lockfile::load_from_path(temp.path().join("pybun.lockb")).unwrap();
    let pkg = lock.packages.get("source-only").expect("lock entry exists");
    assert_eq!(pkg.wheel, "source-only-0.5.0.zip");
}

#[test]
fn install_offline_uses_cached_metadata() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let server = MockServer::start();
    let base_url = setup_package_mocks(&server);
    let venv = ensure_venv(temp.path());

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
        .env("PYBUN_ENV", venv.to_str().unwrap())
        .args(["install"])
        .assert()
        .success();

    // Second run offline using cache only (no server needed)
    bin()
        .current_dir(temp.path())
        .env("PYBUN_PYPI_BASE_URL", "http://127.0.0.1:9") // should not be hit
        .env("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap())
        .env("PYBUN_ENV", venv.to_str().unwrap())
        .args(["install", "--offline"])
        .assert()
        .success();
}

#[test]
fn install_offline_without_cache_fails() {
    let temp = tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let venv = ensure_venv(temp.path());

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
        .env("PYBUN_ENV", venv.to_str().unwrap())
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
    let venv = ensure_venv(temp.path());

    let project_body = json!({
        "info": { "name": "app", "version": "1.0.0" },
        "releases": {
            "1.0.0": [
                {
                    "filename": "app-1.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": format!("{}/files/app-1.0.0-py3-none-any.whl", base),
                    "yanked": false,
                    "digests": { "sha256": "placeholder" }
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

    mock_download(&server, "app-1.0.0-py3-none-any.whl");

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
        .env("PYBUN_ENV", venv.to_str().unwrap())
        .args(["install"])
        .assert()
        .success();

    bin()
        .current_dir(temp.path())
        .env("PYBUN_PYPI_BASE_URL", &base)
        .env("PYBUN_PYPI_CACHE_DIR", cache_dir.to_str().unwrap())
        .env("PYBUN_ENV", venv.to_str().unwrap())
        .args(["install"])
        .assert()
        .success();

    assert_eq!(project_mock.hits(), 1);
    assert_eq!(meta_mock.hits(), 1);
}
