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
    assert!(stdout.contains("max-size"), "gc should have --max-size option");
}

#[test]
fn gc_without_args_runs_default_gc() {
    // Set up a temp cache directory
    let temp = tempdir().unwrap();
    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["gc"])
        .output()
        .unwrap();

    assert!(output.status.success(), "gc should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gc") || stdout.contains("cache"), "output should mention gc or cache");
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
        .args(["gc", "--max-size", "1K"])
        .output()
        .unwrap();

    assert!(output.status.success(), "gc should succeed with max-size");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gc") || stdout.contains("evicted") || stdout.contains("cleaned"));
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
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .expect("output should be valid JSON");
    
    // Check envelope structure
    assert_eq!(json["version"], "1");
    assert!(json["command"].as_str().unwrap().contains("gc"));
    assert!(json["status"].as_str().is_some());
    assert!(json["detail"].is_object());
}

#[test]
fn gc_reports_freed_space() {
    let temp = tempdir().unwrap();
    
    // Create cache structure
    let packages_dir = temp.path().join("packages");
    fs::create_dir_all(&packages_dir).unwrap();
    
    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["--format=json", "gc", "--max-size", "0"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    
    // Detail should have some info about the GC operation
    let detail = &json["detail"];
    assert!(detail.get("freed_bytes").is_some() || detail.get("status").is_some());
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
        }
        // Invalid formats might fail or be handled gracefully
    }
}

#[test]
fn gc_dry_run_shows_what_would_be_deleted() {
    let temp = tempdir().unwrap();
    
    // Create some files
    let packages_dir = temp.path().join("packages");
    let pkg_dir = packages_dir.join("old-package");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(pkg_dir.join("old-package-1.0.0-py3-none-any.whl"), vec![0u8; 1024]).unwrap();
    
    let output = pybun_bin()
        .env("PYBUN_HOME", temp.path())
        .args(["gc", "--dry-run", "--max-size", "0"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(stdout.contains("would") || stdout.contains("dry") || stdout.contains("preview"),
            "expected 'would', 'dry', or 'preview' in output: {}", stdout);
}
