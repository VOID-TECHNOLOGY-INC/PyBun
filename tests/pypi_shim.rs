use std::fs;
use std::io::Read;
#[cfg(not(windows))]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use pybun::release_manifest::current_release_target;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn sha256sum(path: &Path) -> String {
    let mut file = fs::File::open(path).expect("open archive");
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer).expect("read archive");
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    hex::encode(hasher.finalize())
}

#[cfg(not(windows))]
#[test]
fn pypi_shim_bootstraps_from_manifest() {
    let temp = tempdir().unwrap();
    let target = current_release_target().expect("supported release target");
    let bin_dir = temp.path().join(format!("pybun-{}", target));
    fs::create_dir_all(&bin_dir).unwrap();

    let bin_path = bin_dir.join("pybun");
    fs::write(
        &bin_path,
        "#!/usr/bin/env bash\nif [ \"$1\" = \"--version\" ]; then\n  echo \"pybun test\"\n  exit 0\nfi\necho \"pybun test\"\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&bin_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&bin_path, perms).unwrap();

    let tar_available = Command::new("tar").arg("--version").output().is_ok();
    if !tar_available {
        eprintln!("tar not available; skipping pypi shim test");
        return;
    }

    let tar_path = temp
        .path()
        .join(format!("pybun-{}.tar.gz", target));
    let dir_name = bin_dir.file_name().expect("dir name");
    let status = Command::new("tar")
        .args([
            "-czf",
            tar_path.to_str().expect("tar path"),
            "-C",
            temp.path().to_str().expect("temp path"),
            dir_name.to_str().expect("dir name"),
        ])
        .status()
        .expect("tar command failed to spawn");
    assert!(status.success(), "tarball creation failed");

    let sha = sha256sum(&tar_path);
    let manifest_path = temp.path().join("pybun-release.json");
    let manifest = json!({
        "version": "9.9.9",
        "channel": "stable",
        "published_at": "2025-01-01T00:00:00Z",
        "assets": [
            {
                "name": tar_path.file_name().unwrap().to_string_lossy(),
                "target": target,
                "url": format!("file://{}", tar_path.display()),
                "sha256": sha,
            }
        ]
    });
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();

    let python_available = Command::new("python3")
        .arg("--version")
        .output()
        .is_ok();
    if !python_available {
        eprintln!("python3 not available; skipping pypi shim test");
        return;
    }

    let repo_root = env!("CARGO_MANIFEST_DIR");
    let pybun_home = temp.path().join("pybun-home");
    let output = Command::new("python3")
        .args(["-m", "pybun", "--version"])
        .env("PYTHONPATH", repo_root)
        .env("PYBUN_PYPI_MANIFEST", &manifest_path)
        .env("PYBUN_HOME", &pybun_home)
        .output()
        .expect("run python shim");

    assert!(
        output.status.success(),
        "shim should exit cleanly: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pybun test"), "stdout: {}", stdout);
}
