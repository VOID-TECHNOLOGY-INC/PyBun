use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

const MAGIC: &[u8; 8] = b"PYBUNLK1";
/// Legacy envelope version whose body was serialized with bincode 1.x.
const LEGACY_BINCODE_VERSION: u32 = 1;
/// Current envelope version whose body is serialized with postcard.
const VERSION: u32 = 2;

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("invalid magic header")]
    InvalidMagic,
    #[error("unsupported lockfile version {0}")]
    UnsupportedVersion(u32),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "lockfile uses the legacy bincode format (version 1), which is no longer supported; \
         regenerate it with `pybun install` (or `pybun lock`)"
    )]
    LegacyFormat,
    #[error("encode error: {0}")]
    Encode(#[from] postcard::Error),
}

pub type Result<T> = std::result::Result<T, LockfileError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lockfile {
    pub python_versions: Vec<String>,
    pub platforms: Vec<String>,
    pub packages: BTreeMap<String, Package>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub source: PackageSource,
    pub wheel: String,
    pub hash: String,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageSource {
    Registry { index: String, url: String },
    Url { url: String },
}

impl PackageSource {
    pub fn url(&self) -> Option<&str> {
        match self {
            PackageSource::Registry { url, .. } => Some(url), // This is index URL, NOT file URL!
            PackageSource::Url { url } => Some(url),
        }
    }
}

impl Lockfile {
    pub fn new(python_versions: Vec<String>, platforms: Vec<String>) -> Self {
        Self {
            python_versions,
            platforms,
            packages: BTreeMap::new(),
        }
    }

    pub fn add_package(&mut self, package: Package) {
        self.packages.insert(package.name.clone(), package);
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        let body = postcard::to_allocvec(self)?;
        buf.extend_from_slice(&body);
        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MAGIC.len() + 4 {
            return Err(LockfileError::InvalidMagic);
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(LockfileError::InvalidMagic);
        }
        let version_start = MAGIC.len();
        let version = u32::from_le_bytes([
            bytes[version_start],
            bytes[version_start + 1],
            bytes[version_start + 2],
            bytes[version_start + 3],
        ]);
        if version == LEGACY_BINCODE_VERSION {
            return Err(LockfileError::LegacyFormat);
        }
        if version != VERSION {
            return Err(LockfileError::UnsupportedVersion(version));
        }
        let body = &bytes[version_start + 4..];
        let parsed: Lockfile = postcard::from_bytes(body)?;
        Ok(parsed)
    }

    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let bytes = self.to_bytes()?;
        fs::write(path, bytes)?;
        Ok(())
    }

    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Lockfile {
        let mut lock = Lockfile::new(vec!["3.11".into()], vec!["macos-arm64".into()]);
        lock.add_package(Package {
            name: "requests".into(),
            version: "2.31.0".into(),
            source: PackageSource::Registry {
                index: "pypi".into(),
                url: "https://pypi.org/simple".into(),
            },
            wheel: "requests-2.31.0-py3-none-any.whl".into(),
            hash: "sha256:abc".into(),
            dependencies: vec!["urllib3".into()],
        });
        lock
    }

    #[test]
    fn round_trips_through_postcard_envelope() {
        let lock = sample();
        let bytes = lock.to_bytes().unwrap();
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(&bytes[8..12], &VERSION.to_le_bytes());
        assert_eq!(Lockfile::from_bytes(&bytes).unwrap(), lock);
    }

    #[test]
    fn serialization_is_deterministic() {
        assert_eq!(sample().to_bytes().unwrap(), sample().to_bytes().unwrap());
    }

    #[test]
    fn legacy_bincode_lockfile_is_rejected_with_actionable_error() {
        // Hand-built bincode 1.x payload: header + empty vecs/map (u64 LE lengths).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&4u64.to_le_bytes());
        bytes.extend_from_slice(b"3.11");
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        let err = Lockfile::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, LockfileError::LegacyFormat));
        assert!(err.to_string().contains("pybun install"));
    }

    #[test]
    fn unknown_version_is_unsupported() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            Lockfile::from_bytes(&bytes),
            Err(LockfileError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn truncated_body_is_an_error_not_a_panic() {
        let bytes = sample().to_bytes().unwrap();
        assert!(Lockfile::from_bytes(&bytes[..bytes.len() - 3]).is_err());
    }
}
