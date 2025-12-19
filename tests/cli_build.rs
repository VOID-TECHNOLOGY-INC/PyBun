use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

fn setup_fake_build_project() -> (TempDir, PathBuf, std::ffi::OsString) {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("project");
    fs::create_dir_all(&project_dir).unwrap();

    // Minimal pyproject for build backends
    fs::write(
        project_dir.join("pyproject.toml"),
        r#"[project]
name = "demo-build"
version = "0.1.0"
"#,
    )
    .unwrap();

    // Stub `build` module so tests don't depend on external packages.
    let fake_build_dir = temp.path().join("fake_build");
    let package_dir = fake_build_dir.join("build");
    fs::create_dir_all(&package_dir).unwrap();
    fs::write(package_dir.join("__init__.py"), "").unwrap();
    fs::write(
        package_dir.join("__main__.py"),
        r#"
import pathlib
import sys
import os

def main():
    root = pathlib.Path.cwd()
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    # Write predictable artifacts for assertions
    (dist / "demo-build-0.1.0.tar.gz").write_text("sdist")
    (dist / "demo-build-0.1.0-py3-none-any.whl").write_text("wheel")
    marker = os.environ.get("PYBUN_BUILD_MARKER")
    if marker:
        pathlib.Path(marker).write_text("ran")
    print("fake build completed", file=sys.stdout)

if __name__ == "__main__":
    main()
"#,
    )
    .unwrap();

    // Compose PYTHONPATH that ensures our stub takes precedence.
    let mut paths = vec![fake_build_dir.into_os_string()];
    if let Some(existing) = std::env::var_os("PYTHONPATH") {
        paths.push(existing);
    }
    let pythonpath = std::env::join_paths(paths).unwrap();

    (temp, project_dir, pythonpath)
}

#[test]
fn build_invokes_python_module_and_collects_artifacts() {
    let (_temp, project_dir, pythonpath) = setup_fake_build_project();

    let mut cmd = bin();
    cmd.current_dir(&project_dir)
        .env("PYTHONPATH", pythonpath)
        .env("PYBUN_BUILD_NO_CACHE", "1")
        .arg("build");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Built 2 artifacts"))
        .stdout(predicate::str::contains("dist"));

    // Dist artifacts should be created by the stubbed build backend
    let dist_dir = project_dir.join("dist");
    assert!(dist_dir.join("demo-build-0.1.0.tar.gz").exists());
    assert!(dist_dir.join("demo-build-0.1.0-py3-none-any.whl").exists());
}

#[test]
fn build_json_reports_artifacts_and_sbom_stub() {
    let (_temp, project_dir, pythonpath) = setup_fake_build_project();

    let output = bin()
        .current_dir(&project_dir)
        .env("PYTHONPATH", pythonpath)
        .args(["--format=json", "build", "--sbom"])
        .output()
        .expect("failed to run pybun build");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");

    assert_eq!(json["command"], "pybun build");
    assert_eq!(json["status"], "ok");

    let detail = &json["detail"];
    let artifacts: Vec<String> = detail["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        artifacts
            .iter()
            .any(|a| a.ends_with("demo-build-0.1.0.tar.gz")),
        "tar.gz artifact should be reported"
    );
    assert!(
        artifacts
            .iter()
            .any(|a| a.ends_with("demo-build-0.1.0-py3-none-any.whl")),
        "wheel artifact should be reported"
    );

    assert_eq!(detail["builder"], "python -m build");
    assert_eq!(detail["sbom"]["status"], "stub");
    let sbom_path = detail["sbom"]["path"].as_str().expect("sbom path missing");
    assert!(
        Path::new(sbom_path).exists(),
        "sbom stub file should exist on disk"
    );
}

#[test]
fn build_cache_reuses_artifacts_on_hit_and_misses_on_change() {
    let (temp, project_dir, pythonpath) = setup_fake_build_project();
    let cache_home = temp.path().join("cache_home");
    let marker_path = project_dir.join("build.marker");

    let dist_dir = project_dir.join("dist");
    let source_path = project_dir.join("src").join("demo.c");
    fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    fs::write(&source_path, "int demo() { return 1; }\n").unwrap();

    let mut cmd = bin();
    cmd.current_dir(&project_dir)
        .env("PYTHONPATH", &pythonpath)
        .env("PYBUN_HOME", &cache_home)
        .env("PYBUN_BUILD_MARKER", &marker_path)
        .arg("build");
    cmd.assert().success();
    assert!(marker_path.exists(), "build should execute on first run");

    fs::remove_dir_all(&dist_dir).unwrap();
    fs::remove_file(&marker_path).unwrap();

    let mut cached = bin();
    cached
        .current_dir(&project_dir)
        .env("PYTHONPATH", &pythonpath)
        .env("PYBUN_HOME", &cache_home)
        .env("PYBUN_BUILD_MARKER", &marker_path)
        .arg("build");
    cached.assert().success();
    assert!(
        !marker_path.exists(),
        "cache hit should skip invoking build backend"
    );
    assert!(
        dist_dir.join("demo-build-0.1.0.tar.gz").exists(),
        "cached artifacts should be restored"
    );

    fs::write(&source_path, "int demo() { return 2; }\n").unwrap();
    fs::remove_dir_all(&dist_dir).unwrap();
    let _ = fs::remove_file(&marker_path);

    let mut missed = bin();
    missed
        .current_dir(&project_dir)
        .env("PYTHONPATH", &pythonpath)
        .env("PYBUN_HOME", &cache_home)
        .env("PYBUN_BUILD_MARKER", &marker_path)
        .arg("build");
    missed.assert().success();
    assert!(marker_path.exists(), "cache miss should rebuild artifacts");
}
