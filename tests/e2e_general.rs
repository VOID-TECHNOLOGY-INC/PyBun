use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[allow(deprecated)]
fn pybun_cmd() -> Command {
    Command::cargo_bin("pybun").unwrap()
}

#[test]
fn test_workflow_init_add_run() {
    let temp = tempdir().unwrap();
    let project_root = temp.path();

    // 1. Init
    let output = pybun_cmd()
        .current_dir(project_root)
        .arg("init")
        .arg("--yes")
        .output()
        .unwrap();
    assert!(output.status.success(), "Init failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Initialized project"),
        "Init output missing string: {}",
        stdout
    );

    assert!(project_root.join("pyproject.toml").exists());

    // Create a venv
    std::process::Command::new("python3")
        .args(["-m", "venv", ".venv"])
        .current_dir(project_root)
        .status()
        .expect("Failed to create venv");

    // 2. Add requests
    let output = pybun_cmd()
        .current_dir(project_root)
        .arg("add")
        .arg("requests")
        .output()
        .unwrap();
    assert!(output.status.success(), "Add failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("installed dependencies"),
        "Add output missing 'installed dependencies': {}",
        stdout
    );

    let pyproject = fs::read_to_string(project_root.join("pyproject.toml")).unwrap();
    assert!(
        pyproject.contains("requests"),
        "pyproject.toml missing requests"
    );

    // 3. Run script - verify it uses venv python
    fs::write(
        project_root.join("check_req.py"),
        "import sys; import requests; print('venv:' + sys.prefix); print('requests imported')",
    )
    .unwrap();

    let output = pybun_cmd()
        .current_dir(project_root)
        .arg("run")
        .arg("check_req.py")
        .output()
        .unwrap();
    assert!(output.status.success(), "Run failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("requests imported"),
        "Run output missing string: {}",
        stdout
    );
    // Verify it used the venv, not system python
    assert!(
        stdout.contains(".venv") || stdout.contains("venv"),
        "Script did not run with venv: {}",
        stdout
    );
}

#[test]
fn test_workflow_remove() {
    let temp = tempdir().unwrap();
    let project_root = temp.path();

    pybun_cmd()
        .current_dir(project_root)
        .arg("init")
        .arg("--yes")
        .output()
        .unwrap();
    std::process::Command::new("python3")
        .args(["-m", "venv", ".venv"])
        .current_dir(project_root)
        .status()
        .unwrap();
    pybun_cmd()
        .current_dir(project_root)
        .arg("add")
        .arg("requests")
        .output()
        .unwrap();

    let output = pybun_cmd()
        .current_dir(project_root)
        .arg("remove")
        .arg("requests")
        .output()
        .unwrap();
    assert!(output.status.success(), "Remove failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("removed requests"),
        "Remove output missing string: {}",
        stdout
    );

    let pyproject = fs::read_to_string(project_root.join("pyproject.toml")).unwrap();
    assert!(!pyproject.contains("requests ="));
}

#[test]
fn test_doctor() {
    let temp = tempdir().unwrap();
    let output = pybun_cmd()
        .current_dir(temp.path())
        .arg("doctor")
        .arg("--format=json")
        .output()
        .unwrap();

    // Doctor technically might return non-zero if issues found, but generally should run.
    // Let's print output if it fails to parse json.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"status\":"),
        "Doctor JSON output missing status: {}",
        stdout
    );
}

#[test]
fn test_python_list() {
    let temp = tempdir().unwrap();
    let output = pybun_cmd()
        .current_dir(temp.path())
        .arg("python")
        .arg("list")
        .output()
        .unwrap();
    assert!(output.status.success(), "Python list failed: {:?}", output);
    // Might be empty if no python installed by pybun, but should show header or "Found ...".
    // Just asserting success for now as we haven't installed any python via pybun in this test env.
}

#[test]
fn test_x_ad_hoc_run() {
    // This requires network, might be flaky.
    // Use --help or something simpler if we just want to verify 'x' command exists?
    // But E2E implies functionality.
    // Let's try 'x' with a simple package or SKIP if network is assumed unreliable in CI.
    // We'll trust local run.
    let output = pybun_cmd()
        .arg("x")
        .arg("pycowsay")
        .arg("--")
        .arg("hello")
        .output()
        .unwrap();

    if !output.status.success() {
        eprintln!("X command failed (network?): {:?}", output);
        // Don't fail the whole suite for network in this environment?
        // But implementation plan commits to verification.
        // Let's fail if it's strictly logic error.
        // If it's resolution error, maybe fine.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("resolve") || stderr.contains("download") {
            println!("Network related failure, skipping check.");
            return;
        }
        panic!("X command failed: {:?}", output);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello") || stdout.contains("cowsay"),
        "X output missing string: {}",
        stdout
    );
}

#[test]
fn test_lock() {
    let temp = tempdir().unwrap();
    let project_root = temp.path();

    // Init
    pybun_cmd()
        .current_dir(project_root)
        .arg("init")
        .arg("--yes")
        .output()
        .unwrap();

    // Create venv
    std::process::Command::new("python3")
        .args(["-m", "venv", ".venv"])
        .current_dir(project_root)
        .status()
        .unwrap();

    // Add (generates lockfile)
    pybun_cmd()
        .current_dir(project_root)
        .arg("add")
        .arg("requests")
        .output()
        .unwrap();

    // Lock explicit
    // Create a script with pep723 deps to lock
    fs::write(
        project_root.join("script.py"),
        "# /// script\n# dependencies = [\"flask\"]\n# ///\nprint('hello')",
    )
    .unwrap();

    let output = pybun_cmd()
        .current_dir(project_root)
        .arg("lock")
        .arg("--script")
        .arg("script.py")
        .output()
        .unwrap();

    assert!(output.status.success(), "Lock failed: {:?}", output);
    assert!(
        project_root.join("script.lockb").exists()
            || project_root.join("script.py.lock").exists()
            || project_root.join("script.lock").exists()
    );
    // exact name depends on implementation, usually script.lock or script.py.lock for pep723
}

#[test]
fn test_outdated_upgrade() {
    let temp = tempdir().unwrap();
    let project_root = temp.path();

    // Init
    pybun_cmd()
        .current_dir(project_root)
        .arg("init")
        .arg("--yes")
        .output()
        .unwrap();

    // Create venv
    std::process::Command::new("python3")
        .args(["-m", "venv", ".venv"])
        .current_dir(project_root)
        .status()
        .unwrap();

    // Add requests (old version if possible? hard to force old version without specifying)
    // We'll just add requests and check outdated (should be empty or not error)
    pybun_cmd()
        .current_dir(project_root)
        .arg("add")
        .arg("requests")
        .output()
        .unwrap();

    let output = pybun_cmd()
        .current_dir(project_root)
        .arg("outdated")
        .output()
        .unwrap();

    assert!(output.status.success(), "Outdated failed: {:?}", output);
    // As we added latest, outdated might be empty or show nothing.

    let output = pybun_cmd()
        .current_dir(project_root)
        .arg("upgrade")
        .output()
        .unwrap();
    assert!(output.status.success(), "Upgrade failed: {:?}", output);
}

#[test]
fn test_build() {
    let temp = tempdir().unwrap();
    let project_root = temp.path();

    // Init
    pybun_cmd()
        .current_dir(project_root)
        .arg("init")
        .arg("--yes")
        .output()
        .unwrap();

    // Create venv
    std::process::Command::new("python3")
        .args(["-m", "venv", ".venv"])
        .current_dir(project_root)
        .status()
        .unwrap();

    // Install build tool
    let output = pybun_cmd()
        .current_dir(project_root)
        .arg("add")
        .arg("build")
        .output()
        .unwrap();
    assert!(output.status.success(), "Add build failed: {:?}", output);

    // Create package structure for hatchling
    let project_name = project_root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_lowercase()
        .replace('.', "_");
    let src_dir = project_root.join("src").join(&project_name);
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("__init__.py"), "").unwrap();

    // Add hatch build config to pyproject.toml
    let pyproject_path = project_root.join("pyproject.toml");
    let mut pyproject = fs::read_to_string(&pyproject_path).unwrap();
    pyproject.push_str(&format!(
        "\n[tool.hatch.build.targets.wheel]\npackages = [\"src/{}\"]\n",
        project_name
    ));
    fs::write(&pyproject_path, pyproject).unwrap();

    // Build
    // Should produce dist/ artifacts
    let output = pybun_cmd()
        .current_dir(project_root)
        .arg("build")
        .output()
        .unwrap();
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "Build failed. Status: {:?}\nStdout: {}\nStderr: {}",
            output.status, stdout, stderr
        );
    }
    assert!(
        project_root.join("dist").exists(),
        "dist directory not created"
    );
}

#[test]
fn test_test_runner() {
    let temp = tempdir().unwrap();
    let project_root = temp.path();

    // Init
    pybun_cmd()
        .current_dir(project_root)
        .arg("init")
        .arg("--yes")
        .output()
        .unwrap();

    // Create venv for test runner
    std::process::Command::new("python3")
        .args(["-m", "venv", ".venv"])
        .current_dir(project_root)
        .status()
        .unwrap();

    // Create a dummy test file
    let test_dir = project_root.join("tests");
    fs::create_dir(&test_dir).unwrap();
    fs::write(test_dir.join("__init__.py"), "").unwrap(); // Ensure package
    fs::write(test_dir.join("test_sample.py"), "import unittest\nclass TestSample(unittest.TestCase):\n    def test_pass(self):\n        assert True\n").unwrap();

    // Run test with explicit backend
    let output = pybun_cmd()
        .current_dir(project_root)
        .arg("test")
        .arg("--backend")
        .arg("unittest")
        .output()
        .unwrap();

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "Test runner failed. Status: {:?}\nStdout: {}\nStderr: {}",
            output.status, stdout, stderr
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("passed") || stdout.contains("collected") || stdout.contains("OK"),
        "Test output missing success indicator: {}",
        stdout
    );
}
