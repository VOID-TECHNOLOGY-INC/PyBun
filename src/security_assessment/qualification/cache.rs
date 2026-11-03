//! Optional approved user cache. All file operations after opening the private
//! root are relative to its pinned directory handle, including atomic replace.
use crate::security_assessment::{
    ObservationDiagnostic, ObservationLimits, http::JsonEvidence, semantic_digest,
};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
};

pub struct ObservationCache {
    directory: Dir,
    max_response_bytes: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedObservation {
    cache_version: u32,
    key: String,
    stored_digest: String,
    evidence: JsonEvidence,
}
impl ObservationCache {
    pub fn open(root: &Path, max_response_bytes: usize) -> Result<Self, ObservationDiagnostic> {
        if max_response_bytes == 0
            || max_response_bytes > ObservationLimits::default().max_response_bytes
        {
            return Err(cache_error());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            if !root.is_absolute() || root.canonicalize().map_err(|_| cache_error())? != root {
                return Err(cache_error());
            }
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(root)
                .map_err(|_| cache_error())?;
            let metadata = file.metadata().map_err(|_| cache_error())?;
            let current = std::fs::symlink_metadata(root).map_err(|_| cache_error())?;
            // SAFETY: geteuid takes no arguments and returns process identity;
            // it dereferences no pointers and has no caller preconditions.
            let uid = unsafe { libc::geteuid() };
            if !metadata.is_dir()
                || metadata.mode() & 0o077 != 0
                || metadata.uid() != uid
                || !current.is_dir()
                || current.file_type().is_symlink()
                || current.dev() != metadata.dev()
                || current.ino() != metadata.ino()
            {
                return Err(cache_error());
            }
            Ok(Self {
                directory: Dir::from_std_file(file),
                max_response_bytes,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = root;
            Err(ObservationDiagnostic::new(
                "E_SECURITY_CACHE_UNSUPPORTED",
                "This platform cannot prove the required private no-follow user-cache profile.",
            ))
        }
    }
    pub(crate) fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
    pub fn read(&self, key: &str, now: u64) -> Result<Option<JsonEvidence>, ObservationDiagnostic> {
        let name = filename(key)?;
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = match self.directory.open_with(&name, &options) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(cache_error()),
        };
        let metadata = file.metadata().map_err(|_| cache_error())?;
        if !metadata.is_file() {
            return Err(cache_error());
        }
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt;
            // SAFETY: geteuid has no arguments or pointer/caller preconditions.
            let uid = unsafe { libc::geteuid() };
            if metadata.mode() & 0o077 != 0 || metadata.uid() != uid {
                return Err(cache_error());
            }
        }
        let mut bytes = vec![];
        file.take(self.max_response_bytes as u64 + 4097)
            .read_to_end(&mut bytes)
            .map_err(|_| cache_error())?;
        if bytes.len() > self.max_response_bytes + 4096 {
            return Err(cache_error());
        }
        let stored: CachedObservation =
            serde_json::from_slice(&bytes).map_err(|_| cache_error())?;
        if stored.cache_version != 1
            || stored.key != key
            || stored.evidence.fetched_at > now
            || !digest_valid(&stored.evidence.payload_digest)
            || stored.stored_digest != semantic_digest(&(key, &stored.evidence))
            || serde_json::to_vec(&stored.evidence.value)
                .map_err(|_| cache_error())?
                .len()
                > self.max_response_bytes
        {
            return Err(cache_error());
        }
        Ok(Some(stored.evidence))
    }
    /// Input is already redacted by the transport. Raw endpoint credentials are
    /// never part of the key, envelope, temporary filename or diagnostics.
    pub fn write(&self, key: &str, evidence: &JsonEvidence) -> Result<(), ObservationDiagnostic> {
        let name = filename(key)?;
        if !evidence.freshness.is_authoritative()
            || !digest_valid(&evidence.payload_digest)
            || serde_json::to_vec(&evidence.value)
                .map_err(|_| cache_error())?
                .len()
                > self.max_response_bytes
        {
            return Err(cache_error());
        }
        let stored = CachedObservation {
            cache_version: 1,
            key: key.into(),
            stored_digest: semantic_digest(&(key, evidence)),
            evidence: evidence.clone(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(|_| cache_error())?;
        if bytes.len() > self.max_response_bytes + 4096 {
            return Err(cache_error());
        }
        let temporary = format!(".tmp-{}", uuid::Uuid::new_v4());
        let result = (|| {
            let mut options = cap_std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let mut file = self
                .directory
                .open_with(&temporary, &options)
                .map_err(|_| cache_error())?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| cache_error())?;
            self.directory
                .rename(&temporary, &self.directory, &name)
                .map_err(|_| cache_error())?;
            self.directory
                .open(".")
                .and_then(|directory| directory.sync_all())
                .map_err(|_| cache_error())
        })();
        if result.is_err() {
            let _ = self.directory.remove_file(&temporary);
        }
        result
    }
}
fn digest_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn filename(key: &str) -> Result<String, ObservationDiagnostic> {
    if !digest_valid(key) {
        return Err(cache_error());
    }
    Ok(format!("v1-{key}.json"))
}
fn cache_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_CACHE",
        "Approved cache is unavailable, unsafe, malformed, unsupported, out of bounds, or does not match this observation partition.",
    )
}
