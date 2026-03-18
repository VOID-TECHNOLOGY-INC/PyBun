//! E2E tests for lazy import functionality.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::TempDir;

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn test_lazy_import_help() {
    pybun()
        .args(["lazy-import", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("lazy-import"));
}

#[test]
fn test_lazy_import_show_config() {
    pybun()
        .args(["lazy-import", "--show-config"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Enabled"))
        .stdout(predicate::str::contains("Denylist"));
}

#[test]
fn test_lazy_import_show_config_json() {
    pybun()
        .args(["--format=json", "lazy-import", "--show-config"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"enabled\""))
        .stdout(predicate::str::contains("\"denylist\""));
}

#[test]
fn test_lazy_import_check_denied_module() {
    pybun()
        .args(["lazy-import", "--check", "sys"])
        .assert()
        .success()
        .stdout(predicate::str::contains("denied"));
}

#[test]
fn test_lazy_import_check_allowed_module() {
    pybun()
        .args(["lazy-import", "--check", "numpy"])
        .assert()
        .success()
        .stdout(predicate::str::contains("lazy"));
}

#[test]
fn test_lazy_import_check_json() {
    pybun()
        .args(["--format=json", "lazy-import", "--check", "pandas"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"decision\""))
        .stdout(predicate::str::contains("\"lazy\""));
}

#[test]
fn test_lazy_import_generate() {
    pybun()
        .args(["lazy-import", "--generate"])
        .assert()
        .success()
        .stdout(predicate::str::contains("class LazyModule"))
        .stdout(predicate::str::contains("class LazyFinder"));
}

#[test]
fn test_lazy_import_generate_with_allowlist() {
    pybun()
        .args(["lazy-import", "--generate", "--allow", "numpy"])
        .assert()
        .success()
        .stdout(predicate::str::contains("numpy"));
}

#[test]
fn test_lazy_import_generate_with_log() {
    pybun()
        .args(["lazy-import", "--generate", "--log-imports"])
        .assert()
        .success()
        .stdout(predicate::str::contains("_LOG_IMPORTS = True"));
}

#[test]
fn test_lazy_import_generate_to_file() {
    let temp = TempDir::new().unwrap();
    let output_file = temp.path().join("lazy_import.py");

    pybun()
        .args([
            "lazy-import",
            "--generate",
            "-o",
            output_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated"));

    // Verify file was created
    assert!(output_file.exists());
    let content = std::fs::read_to_string(&output_file).unwrap();
    assert!(content.contains("class LazyModule"));
}

#[test]
fn test_lazy_import_check_with_custom_denylist() {
    pybun()
        .args(["lazy-import", "--check", "mymodule", "--deny", "mymodule"])
        .assert()
        .success()
        .stdout(predicate::str::contains("denied"));
}

#[test]
fn test_lazy_import_default_shows_usage() {
    pybun()
        .args(["lazy-import"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));
}

#[test]
fn test_lazy_import_generate_includes_output_module_in_denylist() {
    // Test for Issue #101: generated module should be in denylist to prevent recursion
    let temp = TempDir::new().unwrap();
    let output_file = temp.path().join("lazy_setup.py");

    pybun()
        .args([
            "lazy-import",
            "--generate",
            "-o",
            output_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Read the generated file and verify lazy_setup is in the denylist
    let content = std::fs::read_to_string(&output_file).unwrap();
    assert!(content.contains("lazy_setup"));
    assert!(content.contains("_DENYLIST"));

    // Verify lazy_setup appears in the _DENYLIST section
    let denylist_start = content.find("_DENYLIST = {").unwrap();
    let denylist_end = content[denylist_start..].find('}').unwrap() + denylist_start;
    let denylist_section = &content[denylist_start..denylist_end];
    assert!(
        denylist_section.contains("\"lazy_setup\""),
        "lazy_setup should be in denylist to prevent recursion (Issue #101)"
    );
}

#[test]
fn test_lazy_import_generate_with_different_output_names() {
    // Test that different output file names are correctly added to denylist
    let temp = TempDir::new().unwrap();

    let test_cases = vec!["my_lazy.py", "lazy_bootstrap.py", "imports.py"];

    for output_name in test_cases {
        let output_file = temp.path().join(output_name);
        let expected_module = output_name.trim_end_matches(".py");

        pybun()
            .args([
                "lazy-import",
                "--generate",
                "-o",
                output_file.to_str().unwrap(),
            ])
            .assert()
            .success();

        let content = std::fs::read_to_string(&output_file).unwrap();
        let denylist_start = content.find("_DENYLIST = {").unwrap();
        let denylist_end = content[denylist_start..].find('}').unwrap() + denylist_start;
        let denylist_section = &content[denylist_start..denylist_end];

        assert!(
            denylist_section.contains(&format!("\"{}\"", expected_module)),
            "Output module {} should be in denylist",
            expected_module
        );
    }
}

#[test]
fn test_lazy_import_generate_to_stdout_no_self_reference() {
    // When generating to stdout (no -o flag), there should be no self-reference in denylist
    let output = pybun()
        .args(["lazy-import", "--generate"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let content = String::from_utf8(output).unwrap();

    // The default denylist should be present but no specific output module
    assert!(content.contains("_DENYLIST"));
    assert!(content.contains("sys"));
    assert!(content.contains("importlib"));

    // Should not contain references to common output file names in denylist
    // (beyond what might already be in the default denylist)
    let denylist_start = content.find("_DENYLIST = {").unwrap();
    let denylist_end = content[denylist_start..].find('}').unwrap() + denylist_start;
    let denylist_section = &content[denylist_start..denylist_end];

    // Verify that temporary/generated module names are not in denylist when outputting to stdout
    assert!(!denylist_section.contains("\"lazy_setup\""));
    assert!(!denylist_section.contains("\"lazy_import\""));
}
