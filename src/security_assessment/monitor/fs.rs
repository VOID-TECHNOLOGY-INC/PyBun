//! Private, handle-relative publication. Rename is the linearization point;
//! errors after it are explicitly indeterminate, never claimed rollbacks.
use super::model::*;
use cap_std::fs::{Dir, OpenOptions};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitTarget {
    Registry,
    Checkpoint,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitStage {
    BeforeTempWrite,
    AfterTempSync,
    BeforeReplace,
    AfterReplace,
    BeforeDirectorySync,
    AfterDirectorySync,
    BeforeResponse,
}
/// Optional operational instrumentation. Production callers normally use no
/// observer; environment variables never enable fault injection.
pub trait CommitObserver: Send + Sync {
    fn observe(&self, target: CommitTarget, stage: CommitStage) -> std::io::Result<()>;
}
pub(crate) struct NoObserver;
impl CommitObserver for NoObserver {
    fn observe(&self, _: CommitTarget, _: CommitStage) -> std::io::Result<()> {
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    state_version: u32,
    digest: String,
    payload: T,
}
pub(crate) struct Root {
    dir: Dir,
    path: PathBuf,
    metadata: std::fs::Metadata,
}
pub(crate) struct Lock {
    pub _file: std::fs::File,
    deadline: Instant,
}
impl Lock {
    pub fn check(&self, root: &Root) -> MonitorResult<()> {
        check_deadline(self.deadline)?;
        root.validate()?;
        let opened = self._file.metadata().map_err(|_| path_error())?;
        let current = root
            .dir
            .symlink_metadata("state.lock")
            .map_err(|_| path_error())?;
        if !private_cap_metadata(&current, false) {
            return Err(path_error());
        }
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt as _;
            use std::os::unix::fs::MetadataExt as _;
            if opened.dev() != current.dev() || opened.ino() != current.ino() {
                return Err(path_error());
            }
        }
        Ok(())
    }
}
impl Root {
    pub fn clone_handle(&self) -> std::io::Result<std::fs::File> {
        Ok(self.dir.try_clone()?.into_std_file())
    }

    pub fn open(options: &StoreOptions, create: bool) -> MonitorResult<Self> {
        Self::open_checked(options, create, &|| {})
    }
    fn checked_options(options: &StoreOptions) -> MonitorResult<Instant> {
        options.limits.validate()?;
        let deadline = options
            .deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(60));
        check_deadline(deadline)?;
        if !cfg!(unix) {
            return Err(MonitorError::new("E_MONITOR_STATE_UNSUPPORTED"));
        }
        if !absolute_normal(&options.root) {
            return Err(path_error());
        }
        if !options.allow_in_repository {
            for ancestor in options.root.ancestors() {
                check_deadline(deadline)?;
                if std::fs::symlink_metadata(ancestor.join(".git")).is_ok() {
                    return Err(path_error());
                }
            }
        }
        Ok(deadline)
    }
    fn open_checked(
        options: &StoreOptions,
        create: bool,
        before_create: &dyn Fn(),
    ) -> MonitorResult<Self> {
        let deadline = Self::checked_options(options)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            if create {
                let mut ancestor = options.root.as_path();
                while !ancestor.exists() {
                    check_deadline(deadline)?;
                    ancestor = ancestor.parent().ok_or_else(path_error)?;
                }
                if ancestor.canonicalize().map_err(|_| path_error())? != ancestor {
                    return Err(path_error());
                }
                let expected = std::fs::symlink_metadata(ancestor).map_err(|_| path_error())?;
                before_create();
                check_deadline(deadline)?;
                let parent = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(ancestor)
                    .map_err(|_| path_error())?;
                let actual = parent.metadata().map_err(|_| path_error())?;
                if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
                    return Err(path_error());
                }
                return Self::from_parent_checked(options, ancestor, &parent, before_create);
            }
            if options.root.canonicalize().map_err(|_| path_error())? != options.root {
                return Err(path_error());
            }
            check_deadline(deadline)?;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&options.root)
                .map_err(|_| path_error())?;
            Self::finish_open(
                options,
                Dir::from_std_file(file),
                false,
                false,
                before_create,
                deadline,
            )
        }
        #[cfg(not(unix))]
        {
            let _ = (deadline, create, before_create);
            Err(MonitorError::new("E_MONITOR_STATE_UNSUPPORTED"))
        }
    }
    pub fn from_parent(
        options: &StoreOptions,
        parent_path: &std::path::Path,
        parent: &std::fs::File,
    ) -> MonitorResult<Self> {
        Self::from_parent_checked(options, parent_path, parent, &|| {})
    }
    fn from_parent_checked(
        options: &StoreOptions,
        parent_path: &std::path::Path,
        parent: &std::fs::File,
        before_create: &dyn Fn(),
    ) -> MonitorResult<Self> {
        let deadline = Self::checked_options(options)?;
        #[cfg(unix)]
        {
            use cap_std::fs::{DirBuilder, DirBuilderExt, OpenOptionsExt};
            use std::os::unix::fs::MetadataExt;
            if !absolute_normal(parent_path)
                || parent_path.canonicalize().map_err(|_| path_error())? != parent_path
            {
                return Err(path_error());
            }
            let held = parent.metadata().map_err(|_| path_error())?;
            let current = std::fs::symlink_metadata(parent_path).map_err(|_| path_error())?;
            if !held.is_dir()
                || !current.is_dir()
                || held.dev() != current.dev()
                || held.ino() != current.ino()
            {
                return Err(path_error());
            }
            let suffix = options
                .root
                .strip_prefix(parent_path)
                .map_err(|_| path_error())?;
            let mut dir = Dir::from_std_file(parent.try_clone().map_err(|_| path_error())?);
            let mut created = false;
            for component in suffix.components() {
                let std::path::Component::Normal(name) = component else {
                    return Err(path_error());
                };
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                before_create();
                check_deadline(deadline)?;
                // Exclusive mkdir prevents adopting a root that appeared after the grant.
                dir.create_dir_with(name, &builder)
                    .map_err(|_| path_error())?;
                dir.try_clone()
                    .map_err(|_| path_error())?
                    .into_std_file()
                    .sync_all()
                    .map_err(|_| MonitorError::new("E_MONITOR_PERSISTENCE").indeterminate())?;
                let mut open = OpenOptions::new();
                open.read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
                check_deadline(deadline)?;
                dir = Dir::from_std_file(
                    dir.open_with(name, &open)
                        .map_err(|_| path_error())?
                        .into_std(),
                );
                created = true;
            }
            Self::finish_open(options, dir, true, created, before_create, deadline)
        }
        #[cfg(not(unix))]
        {
            let _ = (parent_path, parent, before_create, deadline);
            Err(MonitorError::new("E_MONITOR_STATE_UNSUPPORTED"))
        }
    }
    #[cfg(unix)]
    fn finish_open(
        options: &StoreOptions,
        dir: Dir,
        create: bool,
        new_root: bool,
        before_create: &dyn Fn(),
        deadline: Instant,
    ) -> MonitorResult<Self> {
        check_deadline(deadline)?;
        let metadata = dir
            .try_clone()
            .map_err(|_| path_error())?
            .into_std_file()
            .metadata()
            .map_err(|_| path_error())?;
        if !private_metadata(&metadata, true) {
            return Err(path_error());
        }
        let root = Self {
            dir,
            path: options.root.clone(),
            metadata,
        };
        root.validate()?;
        if create {
            let exists = root.dir.symlink_metadata("state.lock").is_ok();
            if new_root || !exists {
                if root
                    .dir
                    .entries()
                    .map_err(|_| path_error())?
                    .next()
                    .is_some()
                {
                    return Err(path_error());
                }
                before_create();
                check_deadline(deadline)?;
                let mut open = private_open();
                open.write(true).create_new(true);
                root.dir
                    .open_with("state.lock", &open)
                    .map_err(|_| path_error())?
                    .sync_all()
                    .map_err(|_| path_error())?;
                root.sync()?;
            }
        }
        let lock = root.lock(deadline)?;
        drop(lock);
        Ok(root)
    }
    fn validate(&self) -> MonitorResult<()> {
        if self.path.canonicalize().map_err(|_| path_error())? != self.path {
            return Err(path_error());
        }
        let current = std::fs::symlink_metadata(&self.path).map_err(|_| path_error())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !private_metadata(&current, true)
                || current.dev() != self.metadata.dev()
                || current.ino() != self.metadata.ino()
            {
                return Err(path_error());
            }
        }
        Ok(())
    }
    pub fn lock(&self, deadline: Instant) -> MonitorResult<Lock> {
        check_deadline(deadline)?;
        self.validate()?;
        let mut options = private_open();
        // Unix flock serializes through a read-only descriptor; readers need
        // no file-write authority merely to acquire the existing state lock.
        options.read(true);
        let file = self
            .dir
            .open_with("state.lock", &options)
            .map_err(|_| path_error())?
            .into_std();
        if !private_metadata(&file.metadata().map_err(|_| path_error())?, false) {
            return Err(path_error());
        }
        loop {
            check_deadline(deadline)?;
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::park_timeout(
                        Duration::from_millis(5)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    )
                }
                Err(_) => return Err(MonitorError::new("E_MONITOR_LOCK")),
            }
        }
        let lock = Lock {
            _file: file,
            deadline,
        };
        lock.check(self)?;
        Ok(lock)
    }
    pub fn read<T: DeserializeOwned + Serialize>(
        &self,
        name: &str,
        limit: usize,
        lock: &Lock,
    ) -> MonitorResult<Option<T>> {
        lock.check(self)?;
        let mut options = private_open();
        options.read(true);
        let file = match self.dir.open_with(name, &options) {
            Ok(file) => file.into_std(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(path_error()),
        };
        if !private_metadata(&file.metadata().map_err(|_| path_error())?, false) {
            return Err(path_error());
        }
        let mut bytes = vec![];
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| MonitorError::new("E_MONITOR_STATE_CORRUPT"))?;
        if bytes.len() > limit {
            return Err(MonitorError::new("E_MONITOR_LIMIT"));
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| MonitorError::new("E_MONITOR_STATE_CORRUPT"))?;
        if value
            .get("state_version")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
        {
            return Err(MonitorError::new("E_MONITOR_STATE_VERSION"));
        }
        let envelope: Envelope<T> = serde_json::from_value(value)
            .map_err(|_| MonitorError::new("E_MONITOR_STATE_CORRUPT"))?;
        if envelope.digest != crate::security_assessment::semantic_digest(&envelope.payload) {
            return Err(MonitorError::new("E_MONITOR_STATE_CORRUPT"));
        }
        Ok(Some(envelope.payload))
    }
    pub fn write<T: Serialize>(
        &self,
        name: &str,
        value: &T,
        target: CommitTarget,
        limit: usize,
        observer: &Arc<dyn CommitObserver>,
        lock: &Lock,
    ) -> MonitorResult<()> {
        lock.check(self)?;
        if let Ok(metadata) = self.dir.symlink_metadata(name)
            && !private_cap_metadata(&metadata, false)
        {
            return Err(path_error());
        }
        let bytes = serde_json::to_vec(&Envelope {
            state_version: 1,
            digest: crate::security_assessment::semantic_digest(value),
            payload: value,
        })
        .map_err(|_| MonitorError::new("E_MONITOR_STATE_SERIALIZE"))?;
        if bytes.len() > limit {
            return Err(MonitorError::new("E_MONITOR_LIMIT"));
        }
        let temporary = format!(".tmp-{}", random_id());
        let mut replaced = false;
        let result = (|| -> MonitorResult<()> {
            observer
                .observe(target, CommitStage::BeforeTempWrite)
                .map_err(persistence)?;
            lock.check(self)?;
            let mut options = private_open();
            options.create_new(true).write(true);
            let mut file = self
                .dir
                .open_with(&temporary, &options)
                .map_err(persistence)?;
            file.write_all(&bytes).map_err(persistence)?;
            file.flush().map_err(persistence)?;
            file.sync_all().map_err(persistence)?;
            observer
                .observe(target, CommitStage::AfterTempSync)
                .map_err(persistence)?;
            observer
                .observe(target, CommitStage::BeforeReplace)
                .map_err(persistence)?;
            lock.check(self)?;
            self.dir
                .rename(&temporary, &self.dir, name)
                .map_err(persistence)?;
            replaced = true;
            observer
                .observe(target, CommitStage::AfterReplace)
                .map_err(persistence)?;
            observer
                .observe(target, CommitStage::BeforeDirectorySync)
                .map_err(persistence)?;
            self.dir
                .try_clone()
                .map_err(persistence)?
                .into_std_file()
                .sync_all()
                .map_err(persistence)?;
            observer
                .observe(target, CommitStage::AfterDirectorySync)
                .map_err(persistence)?;
            lock.check(self)?;
            Ok(())
        })();
        if !replaced {
            let _ = self.dir.remove_file(&temporary);
        }
        result.map_err(|error| {
            if replaced {
                error.indeterminate()
            } else {
                error
            }
        })
    }
    pub fn quarantine(&self, name: &str, lock: &Lock) -> MonitorResult<()> {
        lock.check(self)?;
        let mut options = private_open();
        options.read(true);
        let file = self
            .dir
            .open_with(name, &options)
            .map_err(|_| path_error())?;
        if !private_cap_metadata(&file.metadata().map_err(|_| path_error())?, false) {
            return Err(path_error());
        }
        let quarantine = format!("quarantine-{}-{name}", random_id());
        lock.check(self)?;
        self.dir
            .rename(name, &self.dir, &quarantine)
            .map_err(|_| MonitorError::new("E_MONITOR_PERSISTENCE"))?;
        self.sync()?;
        lock.check(self).map_err(MonitorError::indeterminate)
    }
    pub fn has_checkpoints(&self, lock: &Lock) -> MonitorResult<bool> {
        lock.check(self)?;
        for entry in self.dir.entries().map_err(|_| path_error())? {
            let entry = entry.map_err(|_| path_error())?;
            if entry
                .file_name()
                .to_string_lossy()
                .ends_with(".checkpoint.json")
            {
                return Ok(true);
            }
            lock.check(self)?;
        }
        Ok(false)
    }
    pub fn sync(&self) -> MonitorResult<()> {
        self.dir
            .try_clone()
            .map_err(|_| path_error())?
            .into_std_file()
            .sync_all()
            .map_err(|_| MonitorError::new("E_MONITOR_PERSISTENCE").indeterminate())
    }
}
fn private_open() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
}
fn private_cap_metadata(metadata: &cap_std::fs::Metadata, directory: bool) -> bool {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        (if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        }) && metadata.mode() & 0o077 == 0
            && metadata.uid() == effective_uid()
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, directory);
        false
    }
}
#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, dereferences no pointers and has no
    // preconditions. Its scalar result is only used for ownership validation.
    unsafe { libc::geteuid() }
}

fn private_metadata(metadata: &std::fs::Metadata, directory: bool) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = effective_uid();
        (if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        }) && metadata.mode() & 0o077 == 0
            && metadata.uid() == uid
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, directory);
        false
    }
}
fn path_error() -> MonitorError {
    MonitorError::new("E_MONITOR_STATE_PATH")
}

fn check_deadline(deadline: Instant) -> MonitorResult<()> {
    if Instant::now() >= deadline {
        Err(MonitorError::new("E_MONITOR_DEADLINE"))
    } else {
        Ok(())
    }
}
fn persistence(_: std::io::Error) -> MonitorError {
    MonitorError::new("E_MONITOR_PERSISTENCE")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn root_creation_rechecks_deadline_immediately_before_each_mutation() {
        use std::{cell::Cell, os::unix::fs::DirBuilderExt};
        for existing_root in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let base = temp.path().canonicalize().unwrap();
            let path = base.join("state");
            if existing_root {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&path)
                    .unwrap();
            }
            let mut options = StoreOptions::new(path.clone());
            let deadline = Instant::now() + Duration::from_millis(100);
            options.deadline = Some(deadline);
            let called = Cell::new(false);
            let parent_path = if existing_root {
                path.as_path()
            } else {
                base.as_path()
            };
            let held = std::fs::File::open(parent_path).unwrap();
            let result = Root::from_parent_checked(&options, parent_path, &held, &|| {
                called.set(true);
                while Instant::now() < deadline {
                    std::thread::park_timeout(deadline.saturating_duration_since(Instant::now()));
                }
            });
            assert!(called.get());
            assert_eq!(result.err().unwrap().code, "E_MONITOR_DEADLINE");
            assert!(!path.join("state.lock").exists());
            assert_eq!(path.exists(), existing_root);
        }
    }
    #[test]
    fn ancestor_swap_cannot_redirect_creation_outside_held_parent() {
        use std::{
            cell::Cell,
            os::unix::fs::{DirBuilderExt, symlink},
        };
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let parent = base.join("anchor");
        let outside = base.join("outside");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&outside)
            .unwrap();
        let moved = base.join("moved");
        let options = StoreOptions::new(parent.join("state"));
        let swapped = Cell::new(false);
        let result = Root::open_checked(&options, true, &|| {
            if !swapped.replace(true) {
                std::fs::rename(&parent, &moved).unwrap();
                symlink(&outside, &parent).unwrap();
            }
        });
        assert!(swapped.get());
        assert!(result.is_err());
        assert!(
            !outside.join("state").exists(),
            "unapproved target must receive no writes"
        );
    }
    #[test]
    fn held_parent_is_not_reopened_after_path_swaps_during_walk() {
        use std::{
            cell::Cell,
            os::unix::fs::{DirBuilderExt, symlink},
        };
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let parent = base.join("anchor");
        let outside = base.join("outside");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&outside)
            .unwrap();
        let held = std::fs::File::open(&parent).unwrap();
        let moved = base.join("moved");
        let options = StoreOptions::new(parent.join("state"));
        let swapped = Cell::new(false);
        let result = Root::from_parent_checked(&options, &parent, &held, &|| {
            if !swapped.replace(true) {
                std::fs::rename(&parent, &moved).unwrap();
                symlink(&outside, &parent).unwrap();
            }
        });
        assert!(swapped.get());
        assert!(result.is_err());
        assert!(!outside.join("state").exists());
    }
}
