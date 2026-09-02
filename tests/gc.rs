//! Tests for the GC (garbage collection) command
//!
//! PR6.1: Local LRU GC `pybun gc --max-size`

use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn pybun_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pybun"))
}

#[test]
fn gc_help_shows_max_size_option() {
    let output = pybun_bin().args(["gc", "--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("max-size"),
        "gc should have --max-size option"
    );
}

#[test]
fn gc_without_args_runs_default_gc() {
    // Set up a temp cache directory
    let temp = tempdir().unwrap();
    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "gc"])
        .output()
        .unwrap();

    assert!(output.status.success(), "gc should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["status"], "ok");
    // With no --max-size and an empty cache, nothing should be removed.
    assert_eq!(json["detail"]["dry_run"], false);
    assert_eq!(json["detail"]["files_removed"], 0);
    assert!(
        temp.path().join("packages").exists(),
        "gc should have ensured the cache dirs exist"
    );
}

#[test]
fn gc_with_max_size_enforces_limit() {
    let temp = tempdir().unwrap();

    // Create a fake cache structure with some files
    let packages_dir = temp.path().join("packages");
    let pkg_dir = packages_dir.join("test-package");
    fs::create_dir_all(&pkg_dir).unwrap();

    // Create some dummy wheel files with known sizes
    let wheel1 = pkg_dir.join("test-package-1.0.0-py3-none-any.whl");
    let wheel2 = pkg_dir.join("test-package-2.0.0-py3-none-any.whl");

    // Write 1KB files
    fs::write(&wheel1, vec![0u8; 1024]).unwrap();
    // Small delay to ensure different mtime
    std::thread::sleep(std::time::Duration::from_millis(100));
    fs::write(&wheel2, vec![0u8; 1024]).unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "gc", "--max-size", "1K"])
        .output()
        .unwrap();

    assert!(output.status.success(), "gc should succeed with max-size");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    // 2KB of wheels against a 1K cap must evict the older-mtime file (wheel1)
    // and keep total on-disk usage at or under the cap.
    assert_eq!(
        json["detail"]["files_removed"], 1,
        "expected exactly one file evicted to respect the 1K cap: {json}"
    );
    assert!(!wheel1.exists(), "older wheel1 should have been evicted");
    assert!(wheel2.exists(), "newer wheel2 should have been retained");
}

#[test]
fn gc_json_output_format() {
    let temp = tempdir().unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "gc"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should be valid JSON
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");

    // Check envelope structure
    assert_eq!(json["version"], "1");
    assert!(json["command"].as_str().unwrap().contains("gc"));
    assert!(json["status"].as_str().is_some());
    assert!(json["detail"].is_object());
}

#[test]
fn gc_reports_freed_space() {
    let temp = tempdir().unwrap();

    // Create a cache with a known amount of data, then force full eviction
    // with --max-size 0.
    let packages_dir = temp.path().join("packages");
    let pkg_dir = packages_dir.join("test-package");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("test-package-1.0.0-py3-none-any.whl"),
        vec![0u8; 2048],
    )
    .unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "gc", "--max-size", "0"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let detail = &json["detail"];
    assert_eq!(
        detail["freed_bytes"].as_u64(),
        Some(2048),
        "expected the 2KB wheel to be fully freed: {detail}"
    );
    assert_eq!(detail["files_removed"], 1);
}

#[test]
fn gc_parse_size_units() {
    // Test various size formats
    let test_cases = vec![
        ("100", true),      // bytes
        ("1K", true),       // kilobytes
        ("10M", true),      // megabytes
        ("1G", true),       // gigabytes
        ("500KB", true),    // kilobytes with B
        ("2GB", true),      // gigabytes with B
        ("invalid", false), // invalid format
    ];

    for (size_str, should_succeed) in test_cases {
        let temp = tempdir().unwrap();
        let output = pybun_bin()
            .env("PYBUN_HOME", temp.path())
            .args(["gc", "--max-size", size_str])
            .output()
            .unwrap();

        if should_succeed {
            assert!(
                output.status.success(),
                "gc with --max-size {} should succeed",
                size_str
            );
        } else {
            assert!(
                !output.status.success(),
                "gc with --max-size {} should fail as an invalid size format",
                size_str
            );
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                combined.contains("invalid size format"),
                "expected an 'invalid size format' error for {size_str}: {combined}"
            );
        }
    }
}

#[test]
fn gc_dry_run_reports_stale_pypi_cache_entries() {
    // Regression test for issue #202: a `.bin` PyPI metadata cache entry
    // written by a pre-v0.1.19 pybun (incompatible `CacheEntry` layout)
    // should be reported as a removal candidate by `pybun gc --dry-run`,
    // and `pybun doctor` should surface it as a stale entry.
    let temp = tempdir().unwrap();
    let pypi_cache = temp.path().join("pypi-cache");
    fs::create_dir_all(&pypi_cache).unwrap();
    let stale_entry = pypi_cache.join("requests.bin");
    fs::write(&stale_entry, b"\xff\xff\xff\xffnot-bincode").unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path().join("home"))
        .env("PYBUN_PYPI_CACHE_DIR", &pypi_cache)
        .args(["--format=json", "gc", "--dry-run"])
        .output()
        .unwrap();

    assert!(output.status.success(), "gc --dry-run should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let would_remove = json["detail"]["pypi_cache"]["would_remove"]
        .as_array()
        .expect("pypi_cache.would_remove should be an array");
    assert!(
        would_remove
            .iter()
            .any(|p| p.as_str().unwrap().contains("requests.bin")),
        "expected requests.bin in would_remove: {:?}",
        would_remove
    );

    // The stale entry must not have been deleted in dry-run mode.
    assert!(stale_entry.exists());
}

#[test]
fn gc_removes_stale_pypi_cache_entries() {
    let temp = tempdir().unwrap();
    let pypi_cache = temp.path().join("pypi-cache");
    fs::create_dir_all(&pypi_cache).unwrap();
    let stale_entry = pypi_cache.join("requests.bin");
    fs::write(&stale_entry, b"\xff\xff\xff\xffnot-bincode").unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path().join("home"))
        .env("PYBUN_PYPI_CACHE_DIR", &pypi_cache)
        .args(["--format=json", "gc"])
        .output()
        .unwrap();

    assert!(output.status.success(), "gc should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["detail"]["pypi_cache"]["files_removed"], 1);

    // The stale entry should have been deleted.
    assert!(!stale_entry.exists());
}

#[test]
fn doctor_reports_stale_pypi_cache_count() {
    let temp = tempdir().unwrap();
    let pypi_cache = temp.path().join("pypi-cache");
    fs::create_dir_all(&pypi_cache).unwrap();
    fs::write(
        pypi_cache.join("requests.bin"),
        b"\xff\xff\xff\xffnot-bincode",
    )
    .unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path().join("home"))
        .env("PYBUN_PYPI_CACHE_DIR", &pypi_cache)
        .args(["--format=json", "doctor"])
        .output()
        .unwrap();

    assert!(output.status.success(), "doctor should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let checks = json["detail"]["checks"]
        .as_array()
        .expect("checks should be an array");
    let pypi_check = checks
        .iter()
        .find(|c| c["name"] == "pypi_cache")
        .expect("doctor should report a pypi_cache check");
    assert_eq!(pypi_check["stale_count"], 1);
    assert_eq!(pypi_check["path"], pypi_cache.display().to_string());
}

#[test]
fn gc_dry_run_shows_what_would_be_deleted() {
    let temp = tempdir().unwrap();

    // Create some files
    let packages_dir = temp.path().join("packages");
    let pkg_dir = packages_dir.join("old-package");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("old-package-1.0.0-py3-none-any.whl"),
        vec![0u8; 1024],
    )
    .unwrap();

    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "gc", "--dry-run", "--max-size", "0"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(
        json["detail"]["dry_run"], true,
        "dry_run flag should be reflected in the detail: {json}"
    );
    let would_remove = json["detail"]["would_remove"]
        .as_array()
        .expect("would_remove should be an array");
    assert!(
        would_remove.iter().any(|p| p
            .as_str()
            .unwrap()
            .contains("old-package-1.0.0-py3-none-any.whl")),
        "expected the wheel to be listed in would_remove: {would_remove:?}"
    );

    // Dry-run must not actually delete the file.
    assert!(pkg_dir.join("old-package-1.0.0-py3-none-any.whl").exists());
}
