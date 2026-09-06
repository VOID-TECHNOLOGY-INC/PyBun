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

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zip::ZipArchive;
use zip::read::ZipFile;

const INSTALL_TRANSACTION_DIR: &str = ".pybun-install-transaction";
const INSTALL_JOURNAL_FILE: &str = "journal.json";
const INSTALL_COMMITTED_FILE: &str = "committed";

#[derive(Debug)]
struct StagedFile {
    source: PathBuf,
    destination: PathBuf,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct InstallJournal {
    entries: Vec<InstallJournalEntry>,
    created_dirs: Vec<PathBuf>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct InstallJournalEntry {
    destination: PathBuf,
    backup_name: Option<String>,
}

#[derive(Debug)]
struct InstallTransaction {
    path: PathBuf,
    journal: InstallJournal,
}

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
    // An interrupted previous install may have published only part of a wheel.
    // Restore its pre-install state before inspecting or publishing another one.
    recover_install_transaction(scheme)?;

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
    let staging = tempfile::tempdir()?;
    let mut staged_files = Vec::new();

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
            continue;
        }

        let staged_path = staging.path().join(i.to_string());

        if is_script {
            install_script_entry(
                &mut entry,
                &staged_path,
                scheme.python_executable.as_deref(),
            )?;
        } else {
            let mut outfile = fs::File::create(&staged_path)?;
            io::copy(&mut entry, &mut outfile)?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if is_script {
                // Wheel builders don't reliably preserve the executable bit
                // (or ship scripts with no unix metadata at all), so always
                // force it on `.data/scripts` entries — matches pip/distlib.
                entry.unix_mode().unwrap_or(0o644) | 0o111
            } else {
                entry.unix_mode().unwrap_or(0o644)
            };
            fs::set_permissions(&staged_path, fs::Permissions::from_mode(mode))?;
        }

        staged_files.push(StagedFile {
            source: staged_path,
            destination: outpath,
        });
    }

    publish_staged_files(&staged_files, scheme)
}

fn install_transaction_path(scheme: &InstallScheme) -> PathBuf {
    scheme.data.join(INSTALL_TRANSACTION_DIR)
}

impl InstallTransaction {
    fn prepare(staged_files: &[StagedFile], scheme: &InstallScheme) -> io::Result<Self> {
        recover_install_transaction(scheme)?;

        let path = install_transaction_path(scheme);
        let mut destinations = HashSet::new();
        for staged in staged_files {
            if !destinations.insert(staged.destination.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "wheel contains duplicate install destination {}",
                        staged.destination.display()
                    ),
                ));
            }
            if staged.destination.starts_with(&path) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "wheel destination overlaps installer transaction state: {}",
                        staged.destination.display()
                    ),
                ));
            }
            if let Ok(metadata) = fs::symlink_metadata(&staged.destination)
                && !metadata.file_type().is_file()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "wheel destination is not a regular file: {}",
                        staged.destination.display()
                    ),
                ));
            }
        }

        let created_dirs = collect_missing_directories(staged_files, scheme);
        fs::create_dir_all(&scheme.data)?;
        fs::create_dir(&path)?;
        sync_install_directory(&scheme.data)?;
        let backups = path.join("backups");
        fs::create_dir(&backups)?;

        let preparation = (|| {
            let mut entries = Vec::with_capacity(staged_files.len());
            for (index, staged) in staged_files.iter().enumerate() {
                let backup_name = if staged.destination.is_file() {
                    let name = index.to_string();
                    crate::atomic_fs::atomic_copy(&staged.destination, &backups.join(&name))?;
                    Some(name)
                } else {
                    None
                };
                entries.push(InstallJournalEntry {
                    destination: staged.destination.clone(),
                    backup_name,
                });
            }

            let journal = InstallJournal {
                entries,
                created_dirs,
            };
            let serialized = serde_json::to_vec_pretty(&journal)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            crate::atomic_fs::atomic_write(&path.join(INSTALL_JOURNAL_FILE), &serialized)?;
            sync_install_directory(&path)?;
            sync_install_directory(&scheme.data)?;
            for directory in &journal.created_dirs {
                fs::create_dir_all(directory)?;
                sync_install_directory(directory)?;
                sync_nearest_existing_directory(parent_dir(directory))?;
            }
            Ok(journal)
        })();

        match preparation {
            Ok(journal) => Ok(Self { path, journal }),
            Err(error) => {
                let cleanup = if path.join(INSTALL_JOURNAL_FILE).exists() {
                    recover_install_transaction(scheme)
                } else {
                    fs::remove_dir_all(&path)
                };
                match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(io::Error::new(
                        error.kind(),
                        format!(
                            "failed to prepare wheel transaction ({error}); cleanup also failed ({cleanup_error})"
                        ),
                    )),
                }
            }
        }
    }

    fn publish(&self, staged: &StagedFile) -> io::Result<()> {
        crate::atomic_fs::atomic_copy(&staged.source, &staged.destination)
    }

    fn rollback(&self) -> io::Result<()> {
        rollback_install_transaction(&self.path, &self.journal)
    }

    fn commit(self) -> io::Result<()> {
        crate::atomic_fs::atomic_write(&self.path.join(INSTALL_COMMITTED_FILE), b"")?;
        sync_install_directory(&self.path)?;
        fs::remove_dir_all(&self.path)?;
        cleanup_created_directories(&self.journal.created_dirs);
        sync_nearest_existing_directory(parent_dir(&self.path))
    }
}

fn publish_staged_files(staged_files: &[StagedFile], scheme: &InstallScheme) -> Result<()> {
    publish_staged_files_with(staged_files, scheme, |_| Ok(()))
}

fn publish_staged_files_with<F>(
    staged_files: &[StagedFile],
    scheme: &InstallScheme,
    mut before_publish: F,
) -> Result<()>
where
    F: FnMut(usize) -> io::Result<()>,
{
    if staged_files.is_empty() {
        return Ok(());
    }

    let transaction = InstallTransaction::prepare(staged_files, scheme)?;
    for (index, staged) in staged_files.iter().enumerate() {
        let publish = before_publish(index).and_then(|()| transaction.publish(staged));
        if let Err(publish_error) = publish {
            return match transaction.rollback() {
                Ok(()) => Err(publish_error.into()),
                Err(rollback_error) => Err(io::Error::new(
                    publish_error.kind(),
                    format!(
                        "failed to publish wheel ({publish_error}); rollback also failed ({rollback_error})"
                    ),
                )
                .into()),
            };
        }
    }
    transaction.commit()?;
    Ok(())
}

fn recover_install_transaction(scheme: &InstallScheme) -> io::Result<()> {
    let path = install_transaction_path(scheme);
    if !path.exists() {
        return Ok(());
    }

    let journal_path = path.join(INSTALL_JOURNAL_FILE);
    if !journal_path.exists() {
        // Publication starts only after the durable journal exists, so an
        // unjournaled directory contains preparation debris only.
        fs::remove_dir_all(&path)?;
        return Ok(());
    }

    let journal: InstallJournal = serde_json::from_slice(&fs::read(&journal_path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if path.join(INSTALL_COMMITTED_FILE).exists() {
        fs::remove_dir_all(&path)?;
        cleanup_created_directories(&journal.created_dirs);
        return sync_nearest_existing_directory(parent_dir(&path));
    }

    rollback_install_transaction(&path, &journal)
}

fn rollback_install_transaction(path: &Path, journal: &InstallJournal) -> io::Result<()> {
    for entry in journal.entries.iter().rev() {
        if let Some(backup_name) = &entry.backup_name {
            crate::atomic_fs::atomic_copy(
                &path.join("backups").join(backup_name),
                &entry.destination,
            )?;
        } else {
            match fs::symlink_metadata(&entry.destination) {
                Ok(metadata)
                    if metadata.file_type().is_file() || metadata.file_type().is_symlink() =>
                {
                    fs::remove_file(&entry.destination)?;
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "cannot roll back non-file destination {}",
                            entry.destination.display()
                        ),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }

    fs::remove_dir_all(path)?;
    cleanup_created_directories(&journal.created_dirs);
    sync_nearest_existing_directory(parent_dir(path))
}

fn collect_missing_directories(
    staged_files: &[StagedFile],
    scheme: &InstallScheme,
) -> Vec<PathBuf> {
    let mut missing = HashSet::new();
    for start in std::iter::once(scheme.data.as_path()).chain(
        staged_files
            .iter()
            .filter_map(|staged| staged.destination.parent()),
    ) {
        let mut current = Some(start);
        while let Some(directory) = current {
            if directory.exists() {
                break;
            }
            missing.insert(directory.to_path_buf());
            current = directory.parent();
        }
    }
    let mut missing: Vec<_> = missing.into_iter().collect();
    missing.sort_by_key(|path| path.components().count());
    missing
}

fn cleanup_created_directories(created_dirs: &[PathBuf]) {
    for directory in created_dirs.iter().rev() {
        match fs::remove_dir(directory) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(_) => {}
        }
    }
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_nearest_existing_directory(path: &Path) -> io::Result<()> {
    let mut current = path;
    while !current.exists() {
        current = parent_dir(current);
    }
    sync_install_directory(current)
}

#[cfg(unix)]
fn sync_install_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_install_directory(_path: &Path) -> io::Result<()> {
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
    fn late_invalid_entry_leaves_install_scheme_unchanged() {
        let dir = tempdir().unwrap();
        let scheme = test_scheme(dir.path());
        let wheel = build_wheel(
            "pkg-1.0",
            None,
            &[
                ("pkg/__init__.py", b"installed too early"),
                ("pkg-1.0.data/nonsense/whatever.txt", b"invalid"),
            ],
            &[],
        );

        let err = install_wheel_with_scheme(&wheel, &scheme).unwrap_err();

        assert!(matches!(err, InstallError::InvalidWheel(_)));
        for root in [
            &scheme.purelib,
            &scheme.platlib,
            &scheme.scripts,
            &scheme.headers,
            &scheme.data,
        ] {
            assert!(
                !root.exists(),
                "failed extraction must not publish staged files to {}",
                root.display()
            );
        }
    }

    #[test]
    fn publish_failure_rolls_back_files_already_replaced() {
        let dir = tempdir().unwrap();
        let scheme = test_scheme(dir.path());
        fs::create_dir_all(&scheme.purelib).unwrap();
        let first = scheme.purelib.join("first.py");
        let second = scheme.purelib.join("second.py");
        fs::write(&first, b"old first").unwrap();
        fs::write(&second, b"old second").unwrap();

        let staging = tempdir().unwrap();
        let staged_first = staging.path().join("first");
        let staged_second = staging.path().join("second");
        fs::write(&staged_first, b"new first").unwrap();
        fs::write(&staged_second, b"new second").unwrap();
        let staged_files = vec![
            StagedFile {
                source: staged_first,
                destination: first.clone(),
            },
            StagedFile {
                source: staged_second,
                destination: second.clone(),
            },
        ];

        let result = publish_staged_files_with(&staged_files, &scheme, |index| {
            if index == 1 {
                Err(io::Error::other("injected second-publish failure"))
            } else {
                Ok(())
            }
        });

        assert!(result.is_err());
        assert_eq!(fs::read(first).unwrap(), b"old first");
        assert_eq!(fs::read(second).unwrap(), b"old second");
        assert!(!install_transaction_path(&scheme).exists());
    }

    #[test]
    fn interrupted_publish_is_recovered_before_the_next_install() {
        let dir = tempdir().unwrap();
        let scheme = test_scheme(dir.path());
        fs::create_dir_all(&scheme.purelib).unwrap();
        let first = scheme.purelib.join("first.py");
        let second = scheme.purelib.join("second.py");
        fs::write(&first, b"old first").unwrap();
        fs::write(&second, b"old second").unwrap();

        let staging = tempdir().unwrap();
        let staged_first = staging.path().join("first");
        let staged_second = staging.path().join("second");
        fs::write(&staged_first, b"new first").unwrap();
        fs::write(&staged_second, b"new second").unwrap();
        let staged_files = vec![
            StagedFile {
                source: staged_first,
                destination: first.clone(),
            },
            StagedFile {
                source: staged_second,
                destination: second.clone(),
            },
        ];

        let transaction = InstallTransaction::prepare(&staged_files, &scheme).unwrap();
        transaction.publish(&staged_files[0]).unwrap();
        drop(transaction); // Simulate process termination before commit/rollback.
        assert_eq!(fs::read(&first).unwrap(), b"new first");

        recover_install_transaction(&scheme).unwrap();

        assert_eq!(fs::read(first).unwrap(), b"old first");
        assert_eq!(fs::read(second).unwrap(), b"old second");
        assert!(!install_transaction_path(&scheme).exists());
    }

    #[test]
    fn rollback_removes_new_files_and_directories() {
        let dir = tempdir().unwrap();
        let scheme = test_scheme(dir.path());
        let destination = scheme.purelib.join("new-package/module.py");
        let staging = tempdir().unwrap();
        let staged_source = staging.path().join("module.py");
        fs::write(&staged_source, b"new").unwrap();
        let staged_files = vec![StagedFile {
            source: staged_source,
            destination: destination.clone(),
        }];

        let transaction = InstallTransaction::prepare(&staged_files, &scheme).unwrap();
        transaction.publish(&staged_files[0]).unwrap();
        transaction.rollback().unwrap();

        assert!(!destination.exists());
        assert!(!scheme.purelib.exists());
        assert!(!scheme.data.exists());
    }

    #[test]
    fn committed_interrupted_transaction_keeps_published_files() {
        let dir = tempdir().unwrap();
        let scheme = test_scheme(dir.path());
        fs::create_dir_all(&scheme.purelib).unwrap();
        let destination = scheme.purelib.join("module.py");
        fs::write(&destination, b"old").unwrap();
        let staging = tempdir().unwrap();
        let staged_source = staging.path().join("module.py");
        fs::write(&staged_source, b"new").unwrap();
        let staged_files = vec![StagedFile {
            source: staged_source,
            destination: destination.clone(),
        }];

        let transaction = InstallTransaction::prepare(&staged_files, &scheme).unwrap();
        transaction.publish(&staged_files[0]).unwrap();
        crate::atomic_fs::atomic_write(&transaction.path.join(INSTALL_COMMITTED_FILE), b"")
            .unwrap();
        drop(transaction); // Simulate interruption after the durable commit marker.

        recover_install_transaction(&scheme).unwrap();

        assert_eq!(fs::read(destination).unwrap(), b"new");
        assert!(!install_transaction_path(&scheme).exists());
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
