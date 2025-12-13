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
    pybun()
        .args(["watch", "main.py"])
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
