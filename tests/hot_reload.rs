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

// Tests for the polling watch fallback (used when native-watch is disabled).
#[cfg(not(feature = "native-watch"))]
mod polling_watch_cli_tests {
    use super::*;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::{Command as StdCommand, Stdio};

    #[test]
    fn test_watch_polling_fallback_detects_file_change_and_reruns() {
        let temp = TempDir::new().unwrap();
        let py_file = temp.path().join("main.py");
        File::create(&py_file).unwrap();

        let mut child = StdCommand::new(env!("CARGO_BIN_EXE_pybun"))
            .args([
                "watch",
                "main.py",
                "-p",
                temp.path().to_str().unwrap(),
                "--debounce",
                "100",
            ])
            .env("PYBUN_WATCH_MAX_ITERATIONS", "20")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to start pybun watch");

        // Wait for the watcher to confirm it has taken its baseline
        // snapshot and is ready to detect changes, then modify the file so
        // the change is observed on a later poll. This avoids flakiness
        // from fixed sleeps when the test suite is under load.
        let mut reader = BufReader::new(child.stderr.take().unwrap());
        let mut banner = String::new();
        loop {
            let mut line = String::new();
            let bytes = reader.read_line(&mut line).expect("read stderr");
            if bytes == 0 {
                break;
            }
            banner.push_str(&line);
            if line.contains("watching for changes...") {
                break;
            }
        }

        let mut file = File::create(&py_file).unwrap();
        writeln!(file, "print('changed')").unwrap();
        file.sync_all().unwrap();
        drop(file);

        let mut rest = String::new();
        reader.read_to_string(&mut rest).expect("read stderr");
        let stderr = banner + &rest;

        let status = child.wait().expect("failed to wait on child");

        assert!(
            status.success(),
            "watch should exit cleanly after max iterations, stderr: {stderr}"
        );
        assert!(
            stderr.contains("Modified") && stderr.contains("main.py"),
            "expected change detection in stderr, got: {stderr}"
        );
        assert!(
            stderr.contains("running:"),
            "expected the configured command to be re-run, got: {stderr}"
        );
    }

    #[test]
    fn test_watch_polling_fallback_no_target_directory_errors() {
        let output = StdCommand::new(env!("CARGO_BIN_EXE_pybun"))
            .args([
                "--format=json",
                "watch",
                "main.py",
                "-p",
                "/nonexistent/path/for/pybun/tests",
                "--debounce",
                "50",
            ])
            .env("PYBUN_WATCH_MAX_ITERATIONS", "1")
            .output()
            .expect("failed to run pybun watch");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"status\":\"error\""), "stdout: {stdout}");
        assert!(
            stdout.contains("No valid paths to watch"),
            "stdout: {stdout}"
        );
    }
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
