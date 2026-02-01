use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use std::fs;
use tempfile::tempdir;

fn bin() -> Command {
    cargo_bin_cmd!("pybun")
}

#[cfg(unix)]
#[test]
fn test_detects_python3_only_venv() {
    let temp = tempdir().unwrap();
    let venv_dir = temp.path().join(".venv");
    let bin_dir = venv_dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    
    // Create python3 binary but NOT python
    let python3 = bin_dir.join("python3");
    
    // Create a fake executable script
    use std::os::unix::fs::PermissionsExt;
    {
        let mut file = fs::File::create(&python3).unwrap();
        use std::io::Write;
        file.write_all(b"#!/bin/sh\necho 'Python 3.11.0'\n").unwrap();
        let mut perms = file.metadata().unwrap().permissions();
        perms.set_mode(0o755);
        file.set_permissions(perms).unwrap();
    }
    
    // Create pyvenv.cfg
    fs::write(venv_dir.join("pyvenv.cfg"), "version = 3.11.0\n").unwrap();

    // Create a dummy python script
    let script = temp.path().join("main.py");
    fs::write(&script, "print('hello')").unwrap();

    // Run pybun run main.py
    // It should detect the venv and use python3 (failing currently if it expects 'python')
    // We can check debug output or side effects. 
    // Since we created a fake python that prints "Python 3.11.0", we can check if that output appears
    // OR significantly, check if `pybun` logs that it found the venv.

    // Let's use `pybun run`'s verbose output to see which python it picked.
    // Or simpler: `pybun run` will fail to execute the python script because our "fake python" is just echo.
    // BUT the output should contain "Python 3.11.0" IF it invoked our fake python.
    // IF it fell back to system python, it would actually run `print('hello')` and output "hello".
    
    // So:
    // If it uses OUR venv -> outputs "Python 3.11.0" (from our fake echo script)
    // If it uses SYSTEM -> outputs "hello" (from main.py using real python)

    let output = bin()
        .current_dir(temp.path())
        .env("PYBUN_TRACE", "1") // Disable color eyre usually
        .arg("run")
        .arg("main.py")
        .output()
        .expect("Failed to execute pybun");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT:\n{}", stdout);
    println!("STDERR:\n{}", stderr);

    // If bug exists (fallback to system), we see "hello".
    // If bug fixed (uses venv), we should see "Python 3.11.0".
    
    // NOTE: `pybun run` invokes the python binary with the script as argument.
    // Our fake script: `#!/bin/sh\necho 'Python 3.11.0'`
    // So `python3 main.py` -> effectively ignores main.py and just prints "Python 3.11.0".

    if stdout.contains("hello") {
        panic!("FAILURE: PyBun fell back to system python instead of using local .venv/bin/python3");
    }
    
    assert!(stdout.contains("Python 3.11.0") || stderr.contains("Python 3.11.0"), 
            "PyBun should have successfully invoked our fake python3");
}
