//! Native wheel installer.
//!
//! Unzips generic wheels into a target directory (site-packages).
//! Handles `.dist-info` creation and basic script installation if needed.
//!
//! Note: This is a minimal implementation focusing on pure-python wheels or
//! platform-compatible binary wheels for the current system.

use std::fs;
use std::io;
use std::path::{Path};
use thiserror::Error;
use zip::ZipArchive;

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("invalid wheel: {0}")]
    InvalidWheel(String),
}

pub type Result<T> = std::result::Result<T, InstallError>;

/// Install a wheel into the specified site-packages directory.
pub fn install_wheel(wheel_path: &Path, site_packages: &Path) -> Result<()> {
    let file = fs::File::open(wheel_path)?;
    let mut archive = ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => site_packages.join(path),
            None => continue,
        };

        if file.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)?;
                }
            }
            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
        }

        // Preserve permissions (unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
            }
        }
    }

    Ok(())
}

// Create a direct symlink for the python executable to avoid venv overhead?
// Or simpler: Just stick to standard venv creation for now, but use `install_wheel` for deps.
//
// venv creation takes ~15ms (warm) to ~100s ms.
// `python -m venv` is slow because it copies files.
// We can optimize venv creation later if needed.
// Focusing on `pip install` replacement first.
