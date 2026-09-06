//! Crash-safe filesystem publication helpers.
//!
//! Files are written to a sibling temporary file and synced before an atomic
//! rename. Directory trees are fully copied to a sibling staging directory
//! before the old and staged trees are atomically exchanged on supported
//! platforms.

use std::fs::{self, File, Permissions};
use std::io::{self, Write};
use std::path::Path;

#[cfg(any(test, not(any(target_os = "linux", target_os = "macos"))))]
const DIRECTORY_TRANSACTION_PREPARED: &[u8] = b"prepared";
#[cfg(any(test, not(any(target_os = "linux", target_os = "macos"))))]
const DIRECTORY_TRANSACTION_COMMITTED: &[u8] = b"committed";

/// Atomically replace `path` with `contents`.
pub(crate) fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    atomic_write_with(path, None, |file| file.write_all(contents))
}

/// Atomically copy a file while preserving its permissions.
pub(crate) fn atomic_copy(source: &Path, destination: &Path) -> io::Result<()> {
    let permissions = fs::metadata(source)?.permissions();
    atomic_write_with(destination, Some(permissions), |output| {
        let mut input = File::open(source)?;
        io::copy(&mut input, output)?;
        Ok(())
    })
}

fn atomic_write_with<F>(path: &Path, permissions: Option<Permissions>, write: F) -> io::Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    let parent = parent_dir(path);
    fs::create_dir_all(parent)?;

    let existing_permissions = fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::PermissionsExt;
        // Match File::create/fs::write: tempfile applies the process umask to
        // the requested 0666 mode. Existing files are restored to their exact
        // previous mode below, and atomic_copy supplies its source mode.
        let mut builder = tempfile::Builder::new();
        builder.permissions(Permissions::from_mode(0o666));
        builder
    };
    #[cfg(not(unix))]
    let builder = tempfile::Builder::new();
    let mut temporary = builder.tempfile_in(parent)?;
    write(temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;
    if let Some(permissions) = permissions.or(existing_permissions) {
        temporary.as_file().set_permissions(permissions)?;
    }
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_directory(parent)
}

/// Replace a directory with a fully staged copy of `source`.
///
/// The old destination remains untouched if staging fails. Linux and macOS use
/// their atomic directory-exchange operations, so there is no interval where
/// the destination is missing. Other platforms use a locked, deterministic
/// transaction marker and recover an interrupted replacement on the next call.
pub(crate) fn atomic_replace_dir_from(source: &Path, destination: &Path) -> io::Result<()> {
    let parent = parent_dir(destination);
    fs::create_dir_all(parent)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _lock = lock_directory_replacement(destination)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    recover_directory_replacement(destination)?;
    let transaction = tempfile::Builder::new()
        .prefix(".pybun-dir-")
        .tempdir_in(parent)?;
    let staged = transaction.path().join("staged");
    copy_dir_recursive(source, &staged)?;
    sync_tree(&staged)?;

    if !destination.exists() {
        fs::rename(&staged, destination)?;
        sync_directory(parent)?;
        return Ok(());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        exchange_directories(&staged, destination)?;
        sync_directory(parent)?;
        remove_path(&staged)?;
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        replace_directory_with_recovery(&staged, destination)?;
    }

    sync_directory(parent)
}

#[cfg(any(test, not(any(target_os = "linux", target_os = "macos"))))]
fn directory_transaction_marker(destination: &Path) -> std::path::PathBuf {
    sibling_with_suffix(destination, ".pybun-transaction")
}

#[cfg(any(test, not(any(target_os = "linux", target_os = "macos"))))]
fn directory_transaction_backup(destination: &Path) -> std::path::PathBuf {
    sibling_with_suffix(destination, ".pybun-backup")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn directory_transaction_lock(destination: &Path) -> std::path::PathBuf {
    sibling_with_suffix(destination, ".pybun-lock")
}

#[cfg(any(test, not(any(target_os = "linux", target_os = "macos"))))]
fn sibling_with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("destination"))
        .to_os_string();
    name.push(suffix);
    parent_dir(path).join(name)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn replace_directory_with_recovery(staged: &Path, destination: &Path) -> io::Result<()> {
    let marker = directory_transaction_marker(destination);
    let backup = directory_transaction_backup(destination);
    if backup.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "refusing to replace {} while an unjournaled backup exists at {}",
                destination.display(),
                backup.display()
            ),
        ));
    }

    atomic_write(&marker, DIRECTORY_TRANSACTION_PREPARED)?;
    fs::rename(destination, &backup)?;
    sync_directory(parent_dir(destination))?;
    if let Err(publish_error) = fs::rename(staged, destination) {
        return match recover_directory_replacement(destination) {
            Ok(()) => Err(publish_error),
            Err(recovery_error) => Err(io::Error::new(
                publish_error.kind(),
                format!(
                    "failed to publish staged directory ({publish_error}); recovery also failed ({recovery_error})"
                ),
            )),
        };
    }
    sync_directory(parent_dir(destination))?;
    atomic_write(&marker, DIRECTORY_TRANSACTION_COMMITTED)?;
    if backup.exists() {
        remove_path(&backup)?;
    }
    fs::remove_file(&marker)?;
    sync_directory(parent_dir(destination))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn lock_directory_replacement(destination: &Path) -> io::Result<File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory_transaction_lock(destination))?;
    fs2::FileExt::lock_exclusive(&file)?;
    Ok(file)
}

#[cfg(any(test, not(any(target_os = "linux", target_os = "macos"))))]
fn recover_directory_replacement(destination: &Path) -> io::Result<()> {
    let marker = directory_transaction_marker(destination);
    let backup = directory_transaction_backup(destination);
    if !marker.exists() {
        if backup.exists() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "found unjournaled directory backup at {}; refusing to delete it",
                    backup.display()
                ),
            ));
        }
        return Ok(());
    }

    let state = fs::read(&marker)?;
    match state.as_slice() {
        DIRECTORY_TRANSACTION_PREPARED => {
            if backup.exists() {
                if destination.exists() {
                    remove_path(destination)?;
                }
                fs::rename(&backup, destination)?;
            } else if !destination.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory transaction has neither destination nor backup",
                ));
            }
        }
        DIRECTORY_TRANSACTION_COMMITTED => {
            if destination.exists() {
                if backup.exists() {
                    remove_path(&backup)?;
                }
            } else if backup.exists() {
                // A committed destination should already be durable. Restore
                // the old tree rather than leave the destination absent if
                // external filesystem damage violates that invariant.
                fs::rename(&backup, destination)?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "committed directory transaction lost both trees",
                ));
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid directory transaction marker at {}",
                    marker.display()
                ),
            ));
        }
    }

    fs::remove_file(marker)?;
    sync_directory(parent_dir(destination))
}

#[cfg(target_os = "linux")]
fn exchange_directories(first: &Path, second: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let first = CString::new(first.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let second = CString::new(second.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    // SAFETY: both C strings are NUL-terminated and remain alive for the
    // syscall. AT_FDCWD makes both paths process-relative; the caller stages
    // both directories under the same parent, satisfying renameat2's
    // same-filesystem requirement.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            first.as_ptr(),
            libc::AT_FDCWD,
            second.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn exchange_directories(first: &Path, second: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let first = CString::new(first.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let second = CString::new(second.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    // SAFETY: both pointers reference live, NUL-terminated C strings.
    // RENAME_SWAP atomically exchanges the two same-filesystem directories.
    let result = unsafe { libc::renamex_np(first.as_ptr(), second.as_ptr(), libc::RENAME_SWAP) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_dir_recursive(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported file type while staging {}",
                    source_path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn sync_tree(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_tree(&entry.path())?;
        } else if entry.file_type()?.is_file() {
            File::open(entry.path())?.sync_all()?;
        }
    }
    sync_directory(path)
}

fn remove_path(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn failed_atomic_writer_preserves_previous_file() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("state");
        fs::write(&path, b"previous").unwrap();

        let result = atomic_write_with(&path, None, |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("injected failure"))
        });

        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"previous");
        let entries: Vec<_> = fs::read_dir(temp.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries, vec![path]);
    }

    #[test]
    #[cfg(unix)]
    fn new_atomic_file_uses_normal_creation_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let reference = temp.path().join("reference");
        let atomic = temp.path().join("atomic");
        fs::write(&reference, b"reference").unwrap();

        atomic_write(&atomic, b"atomic").unwrap();

        let reference_mode = fs::metadata(reference).unwrap().permissions().mode() & 0o777;
        let atomic_mode = fs::metadata(atomic).unwrap().permissions().mode() & 0o777;
        assert_eq!(atomic_mode, reference_mode);
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn exchanges_existing_directories_in_one_operation() {
        let temp = tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        fs::write(first.join("first.txt"), b"first").unwrap();
        fs::write(second.join("second.txt"), b"second").unwrap();

        exchange_directories(&first, &second).unwrap();

        assert_eq!(fs::read(first.join("second.txt")).unwrap(), b"second");
        assert_eq!(fs::read(second.join("first.txt")).unwrap(), b"first");
    }

    #[test]
    fn fallback_recovery_restores_destination_after_backup_rename() {
        let temp = tempdir().unwrap();
        let destination = temp.path().join("destination");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("old.txt"), b"old").unwrap();
        let marker = directory_transaction_marker(&destination);
        let backup = directory_transaction_backup(&destination);
        atomic_write(&marker, DIRECTORY_TRANSACTION_PREPARED).unwrap();
        fs::rename(&destination, &backup).unwrap();

        recover_directory_replacement(&destination).unwrap();

        assert_eq!(fs::read(destination.join("old.txt")).unwrap(), b"old");
        assert!(!marker.exists());
        assert!(!backup.exists());
    }

    #[test]
    #[cfg(unix)]
    fn failed_directory_staging_preserves_previous_tree() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("fresh.whl"), b"fresh").unwrap();
        symlink("missing-target", source.join("unsupported-link")).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("previous.whl"), b"previous").unwrap();

        let result = atomic_replace_dir_from(&source, &destination);

        assert!(result.is_err());
        assert_eq!(
            fs::read(destination.join("previous.whl")).unwrap(),
            b"previous"
        );
        assert!(!destination.join("fresh.whl").exists());
    }
}
