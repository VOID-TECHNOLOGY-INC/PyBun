//! Native wheel installer.
//!
//! Installs a wheel into a target Python installation following the wheel
//! install scheme described by PEP 427 / the current Wheel spec:
//!
//! - Root content (anything outside `<distribution>-<version>.data/`) is
//!   relocated to `purelib` or `platlib`, chosen by the `Root-Is-Purelib`
//!   field of the wheel's `<dist>.dist-info/WHEEL` metadata.
//! - `<distribution>-<version>.data/{purelib,platlib,scripts,headers,data}/...`
//!   entries are relocated to their corresponding installation-scheme
//!   destination instead of being left nested under site-packages.
//! - `.data/scripts` entries get executable permissions, and a leading
//!   `#!python`/`#!pythonw` placeholder shebang (as produced by wheel
//!   builders) is rewritten to the target interpreter.
//!
//! Console/GUI entry-point *generation* (`entry_points.txt` -> generated
//! executable shim) is intentionally out of scope here — only `.data/scripts`
//! content shipped inside the wheel archive itself is installed. See Issue
//! #402.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zip::ZipArchive;
use zip::read::ZipFile;

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

/// Installation-scheme destinations a wheel's contents may be relocated to.
///
/// Mirrors the subset of `sysconfig.get_paths()` keys that PEP 427 `.data`
/// directories can reference (`purelib`, `platlib`, `scripts`, `headers`
/// i.e. `include`, and `data`).
#[derive(Debug, Clone)]
pub struct InstallScheme {
    pub purelib: PathBuf,
    pub platlib: PathBuf,
    pub scripts: PathBuf,
    /// Base include directory; per-distribution header files are installed
    /// under `headers/<distribution>/...`.
    pub headers: PathBuf,
    pub data: PathBuf,
    /// Interpreter path used to rewrite `#!python`/`#!pythonw` placeholder
    /// shebangs in `.data/scripts` entries. `None` skips shebang rewriting.
    pub python_executable: Option<PathBuf>,
}

impl InstallScheme {
    /// Build a scheme from a `sysconfig.get_paths()`-shaped JSON object, as
    /// produced by:
    /// `python -c "import sysconfig, json; print(json.dumps(sysconfig.get_paths()))"`
    ///
    /// Returns `None` if any of the required keys are missing.
    pub fn from_sysconfig_json(
        paths: &serde_json::Value,
        python_executable: PathBuf,
    ) -> Option<Self> {
        let get = |key: &str| paths.get(key)?.as_str().map(PathBuf::from);
        Some(Self {
            purelib: get("purelib")?,
            platlib: get("platlib")?,
            scripts: get("scripts")?,
            headers: get("include")?,
            data: get("data")?,
            python_executable: Some(python_executable),
        })
    }

    /// Build a scheme for a freshly created venv, deriving standard
    /// POSIX/Windows layout paths from the venv root directly (mirrors the
    /// layout `python -m venv` creates) without shelling out to `sysconfig`.
    pub fn from_venv(venv_path: &Path, major_minor: &str) -> Self {
        let (site_packages, scripts, python_executable) = if cfg!(windows) {
            (
                venv_path.join("Lib").join("site-packages"),
                venv_path.join("Scripts"),
                venv_path.join("Scripts").join("python.exe"),
            )
        } else {
            (
                venv_path
                    .join("lib")
                    .join(format!("python{major_minor}"))
                    .join("site-packages"),
                venv_path.join("bin"),
                venv_path.join("bin").join("python"),
            )
        };
        Self {
            purelib: site_packages.clone(),
            platlib: site_packages,
            scripts,
            headers: venv_path.join("include"),
            data: venv_path.to_path_buf(),
            python_executable: Some(python_executable),
        }
    }
}

/// Install a wheel into the target described by `scheme`.
pub fn install_wheel_with_scheme(wheel_path: &Path, scheme: &InstallScheme) -> Result<()> {
    let file = fs::File::open(wheel_path)?;
    let mut archive = ZipArchive::new(file)?;

    let dist_info_prefix = find_dist_info_prefix(&mut archive)?;
    let distribution = dist_info_prefix
        .rsplit_once('-')
        .map(|(name, _version)| name.to_string())
        .unwrap_or_else(|| dist_info_prefix.clone());
    let root_is_purelib = read_root_is_purelib(&mut archive, &dist_info_prefix)?;
    let data_prefix = format!("{dist_info_prefix}.data/");
    let root_target = if root_is_purelib {
        &scheme.purelib
    } else {
        &scheme.platlib
    };

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let rel_path = match entry.enclosed_name() {
            Some(path) => path,
            None => continue,
        };
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");

        let (outpath, is_script) = if let Some(rest) = rel_str.strip_prefix(&data_prefix) {
            if rest.is_empty() {
                continue;
            }
            let mut parts = rest.splitn(2, '/');
            let category = parts.next().unwrap_or("");
            let remainder = parts.next().unwrap_or("");
            if remainder.is_empty() {
                // The `<dist>.data/<category>` directory entry itself, or a
                // stray file directly under `.data/` with no category —
                // nothing to relocate.
                continue;
            }
            let target_base: PathBuf = match category {
                "purelib" => scheme.purelib.clone(),
                "platlib" => scheme.platlib.clone(),
                "scripts" => scheme.scripts.clone(),
                "headers" => scheme.headers.join(&distribution),
                "data" => scheme.data.clone(),
                other => {
                    return Err(InstallError::InvalidWheel(format!(
                        "unsupported wheel .data category '{other}' in entry '{rel_str}' \
                         (expected one of purelib, platlib, scripts, headers, data)"
                    )));
                }
            };
            (target_base.join(remainder), category == "scripts")
        } else {
            (root_target.join(&rel_path), false)
        };

        if entry.is_dir() {
            fs::create_dir_all(&outpath)?;
            continue;
        }

        if let Some(p) = outpath.parent().filter(|p| !p.exists()) {
            fs::create_dir_all(p)?;
        }

        if is_script {
            install_script_entry(&mut entry, &outpath, scheme.python_executable.as_deref())?;
        } else {
            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut entry, &mut outfile)?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if is_script {
                // Wheel builders don't reliably preserve the executable bit
                // (or ship scripts with no unix metadata at all), so always
                // force it on `.data/scripts` entries — matches pip/distlib.
                Some(entry.unix_mode().unwrap_or(0o644) | 0o111)
            } else {
                entry.unix_mode()
            };
            if let Some(mode) = mode {
                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
            }
        }
    }

    Ok(())
}

/// Locate the wheel's `<distribution>-<version>` prefix by finding its
/// top-level `<prefix>.dist-info/` directory.
fn find_dist_info_prefix<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> Result<String> {
    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        let name = entry.name();
        if let Some(idx) = name.find(".dist-info/")
            && !name[..idx].contains('/')
        {
            return Ok(name[..idx].to_string());
        }
    }
    Err(InstallError::InvalidWheel(
        "wheel is missing a top-level <distribution>-<version>.dist-info directory".to_string(),
    ))
}

/// Read `Root-Is-Purelib` from `<dist_info_prefix>.dist-info/WHEEL`.
///
/// Defaults to `true` (purelib) when the `WHEEL` metadata file is missing or
/// doesn't declare the field, preserving the pre-existing behavior of
/// installing everything as a single purelib target.
fn read_root_is_purelib<R: io::Read + io::Seek>(
    archive: &mut ZipArchive<R>,
    dist_info_prefix: &str,
) -> Result<bool> {
    let wheel_meta_name = format!("{dist_info_prefix}.dist-info/WHEEL");
    match archive.by_name(&wheel_meta_name) {
        Ok(mut entry) => {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            Ok(parse_root_is_purelib(&content))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(true),
        Err(e) => Err(e.into()),
    }
}

fn parse_root_is_purelib(wheel_metadata: &str) -> bool {
    for line in wheel_metadata.lines() {
        if let Some((key, value)) = line.split_once(':')
            && key.trim().eq_ignore_ascii_case("Root-Is-Purelib")
        {
            return value.trim().eq_ignore_ascii_case("true");
        }
    }
    true
}

/// Write a `.data/scripts` entry to `outpath`, rewriting a `#!python` /
/// `#!pythonw` placeholder shebang (as emitted by wheel builders) to the
/// real interpreter path when `python_executable` is known.
fn install_script_entry(
    entry: &mut ZipFile<'_, impl Read>,
    outpath: &Path,
    python_executable: Option<&Path>,
) -> Result<()> {
    let mut content = Vec::new();
    entry.read_to_end(&mut content)?;

    if let Some(python) = python_executable
        && content.starts_with(b"#!python")
    {
        let rest_start = content.iter().position(|&b| b == b'\n').map(|i| i + 1);
        let mut rewritten = format!("#!{}\n", python.display()).into_bytes();
        if let Some(start) = rest_start {
            rewritten.extend_from_slice(&content[start..]);
        }
        content = rewritten;
    }

    fs::write(outpath, &content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    /// Build a synthetic wheel zip from `(path, content)` entries and an
    /// optional `WHEEL` metadata body (defaults to a minimal purelib-true
    /// wheel).
    fn build_wheel(
        dist_info_prefix: &str,
        wheel_metadata: Option<&str>,
        entries: &[(&str, &[u8])],
        script_entries: &[&str],
    ) -> PathBuf {
        let dir = tempdir().unwrap();
        let wheel_path = dir.keep().join("pkg-1.0-py3-none-any.whl");
        let file = fs::File::create(&wheel_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        let wheel_body = wheel_metadata.unwrap_or(
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        );
        zip.start_file(format!("{dist_info_prefix}.dist-info/WHEEL"), options)
            .unwrap();
        zip.write_all(wheel_body.as_bytes()).unwrap();
        zip.start_file(format!("{dist_info_prefix}.dist-info/METADATA"), options)
            .unwrap();
        zip.write_all(b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n")
            .unwrap();

        for (path, content) in entries {
            let opts = if script_entries.contains(path) {
                options.unix_permissions(0o644)
            } else {
                options
            };
            zip.start_file(*path, opts).unwrap();
            zip.write_all(content).unwrap();
        }

        zip.finish().unwrap();
        wheel_path
    }

    fn test_scheme(root: &Path) -> InstallScheme {
        InstallScheme {
            purelib: root.join("purelib"),
            platlib: root.join("platlib"),
            scripts: root.join("scripts"),
            headers: root.join("include"),
            data: root.join("data"),
            python_executable: Some(PathBuf::from("/opt/venv/bin/python")),
        }
    }

    #[test]
    fn installs_pure_python_root_content_into_purelib() {
        let dir = tempdir().unwrap();
        let scheme = test_scheme(dir.path());
        let wheel = build_wheel("pkg-1.0", None, &[("pkg/__init__.py", b"x = 1\n")], &[]);

        install_wheel_with_scheme(&wheel, &scheme).unwrap();

        assert_eq!(
            fs::read_to_string(scheme.purelib.join("pkg/__init__.py")).unwrap(),
            "x = 1\n"
        );
        assert!(!scheme.platlib.join("pkg/__init__.py").exists());
    }

    #[test]
    fn root_is_purelib_false_installs_root_content_into_platlib() {
        let dir = tempdir().unwrap();
        let scheme = test_scheme(dir.path());
        let wheel = build_wheel(
            "pkg-1.0",
            Some("Wheel-Version: 1.0\nRoot-Is-Purelib: false\n"),
            &[("pkg/_native.so", b"binary")],
            &[],
        );

        install_wheel_with_scheme(&wheel, &scheme).unwrap();

        assert_eq!(
            fs::read(scheme.platlib.join("pkg/_native.so")).unwrap(),
            b"binary"
        );
        assert!(!scheme.purelib.join("pkg/_native.so").exists());
    }

    #[test]
    fn relocates_data_purelib_platlib_scripts_and_data_categories() {
        let dir = tempdir().unwrap();
        let scheme = test_scheme(dir.path());
        let wheel = build_wheel(
            "pkg-1.0",
            None,
            &[
                ("pkg/__init__.py", b""),
                ("pkg-1.0.data/purelib/extra_module.py", b"y = 2\n"),
                ("pkg-1.0.data/platlib/native_extra.so", b"bin"),
                (
                    "pkg-1.0.data/scripts/example-tool",
                    b"#!python\nprint('hi')\n",
                ),
                ("pkg-1.0.data/data/example/config.json", b"{\"a\": 1}"),
            ],
            &["pkg-1.0.data/scripts/example-tool"],
        );

        install_wheel_with_scheme(&wheel, &scheme).unwrap();

        assert!(scheme.purelib.join("pkg/__init__.py").exists());
        assert!(!scheme.purelib.join("pkg-1.0.data").exists());
        assert_eq!(
            fs::read_to_string(scheme.purelib.join("extra_module.py")).unwrap(),
            "y = 2\n"
        );
        assert_eq!(
            fs::read(scheme.platlib.join("native_extra.so")).unwrap(),
            b"bin"
        );
        assert_eq!(
            fs::read_to_string(scheme.data.join("example/config.json")).unwrap(),
            "{\"a\": 1}"
        );

        let script_path = scheme.scripts.join("example-tool");
        let script_content = fs::read_to_string(&script_path).unwrap();
        assert_eq!(script_content, "#!/opt/venv/bin/python\nprint('hi')\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&script_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "script should be executable");
        }
    }

    #[test]
    fn relocates_data_headers_under_distribution_subdir() {
        let dir = tempdir().unwrap();
        let scheme = test_scheme(dir.path());
        let wheel = build_wheel(
            "pkg-1.0",
            None,
            &[("pkg-1.0.data/headers/pkg.h", b"/* header */")],
            &[],
        );

        install_wheel_with_scheme(&wheel, &scheme).unwrap();

        assert_eq!(
            fs::read_to_string(scheme.headers.join("pkg/pkg.h")).unwrap(),
            "/* header */"
        );
    }

    #[test]
    fn unknown_data_category_fails_loudly() {
        let dir = tempdir().unwrap();
        let scheme = test_scheme(dir.path());
        let wheel = build_wheel(
            "pkg-1.0",
            None,
            &[("pkg-1.0.data/nonsense/whatever.txt", b"???")],
            &[],
        );

        let err = install_wheel_with_scheme(&wheel, &scheme).unwrap_err();
        match err {
            InstallError::InvalidWheel(msg) => assert!(msg.contains("nonsense")),
            other => panic!("expected InvalidWheel error, got {other:?}"),
        }
    }

    #[test]
    fn missing_dist_info_fails_loudly() {
        let dir = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        let wheel_path = dir2.keep().join("broken.whl");
        let file = fs::File::create(&wheel_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("loose_file.py", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"x = 1\n").unwrap();
        zip.finish().unwrap();

        let scheme = test_scheme(dir.path());
        let err = install_wheel_with_scheme(&wheel_path, &scheme).unwrap_err();
        assert!(matches!(err, InstallError::InvalidWheel(_)));
    }
}
