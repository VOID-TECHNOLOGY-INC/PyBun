//! E2E tests for hot reload/watch functionality.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::TempDir;

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn test_watch_help() {
    pybun()
        .args(["watch", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("watch"));
}

#[test]
fn test_watch_no_target_shows_usage() {
    pybun()
        .args(["watch"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));
}

#[test]
fn test_watch_show_config() {
    pybun()
        .args(["watch", "--show-config"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Watch Configuration"))
        .stdout(predicate::str::contains("Debounce"));
}

#[test]
fn test_watch_show_config_json() {
    pybun()
        .args(["--format=json", "watch", "--show-config"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"watch_paths\""))
        .stdout(predicate::str::contains("\"debounce_ms\""));
}

#[test]
fn test_watch_with_target() {
    // Use --dry-run to avoid starting the actual watch loop
    pybun()
        .args(["watch", "main.py", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Would watch"));
}

#[test]
fn test_watch_with_custom_path() {
    let temp = TempDir::new().unwrap();

    pybun()
        .args([
            "watch",
            "--show-config",
            "-p",
            temp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Watch Configuration"));
}

#[test]
fn test_watch_shell_command() {
    pybun()
        .args(["watch", "main.py", "--shell-command"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn test_watch_shell_command_json() {
    pybun()
        .args(["--format=json", "watch", "main.py", "--shell-command"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"shell_command\""));
}

#[test]
fn test_watch_custom_debounce() {
    pybun()
        .args(["watch", "--show-config", "--debounce", "500"])
        .assert()
        .success()
        .stdout(predicate::str::contains("500ms"));
}

#[test]
fn test_watch_with_include_pattern() {
    pybun()
        .args([
            "watch",
            "--show-config",
            "--include",
            "*.py",
            "--include",
            "*.pyw",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("*.py"));
}

#[test]
fn test_watch_with_exclude_pattern() {
    pybun()
        .args(["watch", "--show-config", "--exclude", "test_*"])
        .assert()
        .success();
}

#[test]
fn test_watch_clear_flag() {
    pybun()
        .args(["watch", "--show-config", "--clear"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Clear on reload: true"));
}

#[test]
fn test_watch_no_target_shows_native_status() {
    // The help should indicate whether native watching is available
    pybun()
        .args(["watch"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Native file watching:"));
}

#[test]
fn test_watch_json_shows_native_available() {
    pybun()
        .args(["--format=json", "watch"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"native_watch_available\""));
}

// Tests for native-watch feature CLI output (only run when feature is enabled)
#[cfg(feature = "native-watch")]
mod native_watch_cli_tests {
    use super::*;

    #[test]
    fn test_watch_native_enabled_in_help() {
        // When compiled with native-watch, the help should say "enabled"
        pybun()
            .args(["watch"])
            .assert()
            .success()
            .stdout(predicate::str::contains("enabled"));
    }

    #[test]
    fn test_watch_json_native_available_true() {
        pybun()
            .args(["--format=json", "watch"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"native_watch_available\":true"));
    }
}

// Note: Unit tests for native file watching (event detection, debouncing, etc.)
// are in src/hot_reload.rs under #[cfg(test)] mod native_watch_tests
