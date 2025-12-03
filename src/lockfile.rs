use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

const MAGIC: &[u8; 8] = b"PYBUNLK1";
const VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("invalid magic header")]
    InvalidMagic,
    #[error("unsupported lockfile version {0}")]
    UnsupportedVersion(u32),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encode error: {0}")]
    Encode(#[from] bincode::Error),
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
        let body = bincode::serialize(self)?;
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
        if version != VERSION {
            return Err(LockfileError::UnsupportedVersion(version));
        }
        let body = &bytes[version_start + 4..];
        let parsed: Lockfile = bincode::deserialize(body)?;
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
