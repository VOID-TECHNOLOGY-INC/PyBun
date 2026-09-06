//! Crash-safe filesystem publication helpers.
//!
//! Files are written to a sibling temporary file and synced before an atomic
//! rename. Directory trees are fully copied to a sibling staging directory
//! before the previous tree is moved aside and the staged tree is published.

use std::fs::{self, File, Permissions};
use std::io::{self, Write};
use std::path::Path;

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
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
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
/// The old destination remains untouched if staging fails. Portable filesystems
/// do not provide a single operation that replaces a non-empty directory, so
/// publication uses a short rename window and rolls the old tree back if the
/// second rename fails.
pub(crate) fn atomic_replace_dir_from(source: &Path, destination: &Path) -> io::Result<()> {
    let parent = parent_dir(destination);
    fs::create_dir_all(parent)?;
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

    let backup = transaction.path().join("backup");
    fs::rename(destination, &backup)?;
    if let Err(publish_error) = fs::rename(&staged, destination) {
        if let Err(rollback_error) = fs::rename(&backup, destination) {
            return Err(io::Error::new(
                publish_error.kind(),
                format!(
                    "failed to publish staged directory ({publish_error}); rollback also failed ({rollback_error})"
                ),
            ));
        }
        return Err(publish_error);
    }

    sync_directory(parent)?;
    remove_path(&backup)?;
    sync_directory(parent)
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
