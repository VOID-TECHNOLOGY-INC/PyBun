use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[test]
fn init_creates_pyproject_toml() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y"])
        .assert()
        .success();

    let pyproject = temp.path().join("pyproject.toml");
    assert!(pyproject.exists(), "pyproject.toml should be created");

    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(
        content.contains("[project]"),
        "should have [project] section"
    );
}

#[test]
fn init_creates_gitignore() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y"])
        .assert()
        .success();

    let gitignore = temp.path().join(".gitignore");
    assert!(gitignore.exists(), ".gitignore should be created");

    let content = fs::read_to_string(&gitignore).unwrap();
    assert!(
        content.contains("__pycache__"),
        "should have Python patterns"
    );
}

#[test]
fn init_creates_readme() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y"])
        .assert()
        .success();

    let readme = temp.path().join("README.md");
    assert!(readme.exists(), "README.md should be created");
}

#[test]
fn init_uses_directory_name_as_project_name() {
    let temp = tempdir().unwrap();
    let project_dir = temp.path().join("my-awesome-project");
    fs::create_dir(&project_dir).unwrap();

    bin()
        .current_dir(&project_dir)
        .args(["init", "-y"])
        .assert()
        .success();

    let pyproject = project_dir.join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(
        content.contains("my-awesome-project") || content.contains("my_awesome_project"),
        "should use directory name as project name"
    );
}

#[test]
fn init_with_custom_name() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--name", "custom-project"])
        .assert()
        .success();

    let pyproject = temp.path().join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(content.contains("custom-project"), "should use custom name");
}

#[test]
fn init_with_description() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--description", "A test project"])
        .assert()
        .success();

    let pyproject = temp.path().join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(
        content.contains("A test project"),
        "should have description"
    );
}

#[test]
fn init_with_author() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--author", "Test Author <test@example.com>"])
        .assert()
        .success();

    let pyproject = temp.path().join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(content.contains("Test Author"), "should have author");
}

#[test]
fn init_package_template_creates_src_layout() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--template", "package"])
        .assert()
        .success();

    // Check src directory structure
    let src_dir = temp.path().join("src");
    assert!(
        src_dir.exists(),
        "src/ directory should be created for package template"
    );
}

#[test]
fn init_yes_default_creates_buildable_src_layout() {
    let temp = tempdir().unwrap();
    let project_dir = temp.path().join("demo");
    fs::create_dir(&project_dir).unwrap();

    bin()
        .current_dir(&project_dir)
        .args(["init", "-y"])
        .assert()
        .success();

    let package_init = project_dir.join("src").join("demo").join("__init__.py");
    assert!(
        package_init.exists(),
        "default init -y should create a src package layout that hatchling can build"
    );
}

#[test]
fn init_minimal_template_flat_layout() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--template", "minimal"])
        .assert()
        .success();

    // Minimal template should NOT create src/ directory by default
    assert!(temp.path().join("pyproject.toml").exists());
    // No src/ in minimal mode
}

#[test]
fn init_json_output() {
    let temp = tempdir().unwrap();

    let output = bin()
        .current_dir(temp.path())
        .args(["--format=json", "init", "-y"])
        .output()
        .expect("command runs");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid JSON output");

    assert_eq!(json["status"], "ok");
    assert!(
        json["detail"]["files_created"].is_array(),
        "should list created files"
    );
}

#[test]
fn init_fails_if_pyproject_exists() {
    let temp = tempdir().unwrap();
    let pyproject = temp.path().join("pyproject.toml");
    fs::write(&pyproject, "[project]\nname = \"existing\"\n").unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y"])
        .assert()
        .failure()
        .stdout(
            predicate::str::contains("already exists")
                .or(predicate::str::contains("pyproject.toml")),
        );
}

#[test]
fn init_help_shows_options() {
    bin()
        .args(["init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--name"))
        .stdout(predicate::str::contains("--template"));
}

// Issue #133: non-TTY without --yes should produce an actionable hint
#[test]
fn init_non_tty_without_yes_fails_with_hint() {
    let temp = tempdir().unwrap();

    // Pipe empty stdin to simulate non-TTY
    let output = bin()
        .current_dir(temp.path())
        .args(["init"])
        .write_stdin("")
        .output()
        .expect("command runs");

    assert!(
        !output.status.success(),
        "should fail in non-TTY without --yes"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        combined.contains("--yes") || combined.contains("-y"),
        "error output should mention --yes flag, got: {}",
        combined
    );
}

#[test]
fn init_non_tty_without_yes_json_fails_with_hint() {
    let temp = tempdir().unwrap();

    let output = bin()
        .current_dir(temp.path())
        .args(["--format=json", "init"])
        .write_stdin("")
        .output()
        .expect("command runs");

    assert!(
        !output.status.success(),
        "should fail in non-TTY without --yes"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("expected JSON output, got: {}", stdout));

    assert_eq!(json["status"], "error", "JSON status should be error");

    let diagnostics = json["diagnostics"].as_array().expect("diagnostics array");
    assert_eq!(
        diagnostics.len(),
        1,
        "should have exactly one diagnostic (no duplicates), got: {}",
        stdout
    );

    let hint_found = diagnostics.iter().any(|d| {
        d["suggestion"]
            .as_str()
            .map(|h| h.contains("--yes") || h.contains("-y"))
            .unwrap_or(false)
    });
    assert!(
        hint_found,
        "diagnostic should contain --yes suggestion, got: {}",
        stdout
    );

    // Verify structured diagnostic fields
    let diag = &diagnostics[0];
    assert_eq!(diag["level"], "error");
    assert_eq!(diag["code"], "E_INIT_NOT_INTERACTIVE");
}

#[test]
fn init_non_tty_with_yes_succeeds() {
    let temp = tempdir().unwrap();

    // With --yes flag, non-TTY should succeed even with piped stdin
    bin()
        .current_dir(temp.path())
        .args(["init", "--yes"])
        .write_stdin("")
        .assert()
        .success();

    assert!(temp.path().join("pyproject.toml").exists());
}

#[test]
fn init_with_python_version() {
    let temp = tempdir().unwrap();

    bin()
        .current_dir(temp.path())
        .args(["init", "-y", "--python", "3.11"])
        .assert()
        .success();

    let pyproject = temp.path().join("pyproject.toml");
    let content = fs::read_to_string(&pyproject).unwrap();
    assert!(
        content.contains("3.11") || content.contains("requires-python"),
        "should have python version specification"
    );
}
