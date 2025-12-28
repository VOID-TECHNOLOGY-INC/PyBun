use crate::runtime::Platform;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReleaseManifestError {
    #[error("failed to read manifest from {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse manifest: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("failed to fetch manifest from {url}: {source}")]
    Network { url: String, source: reqwest::Error },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub version: String,
    pub channel: String,
    pub published_at: String,
    pub assets: Vec<ReleaseAsset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_notes: Option<ReleaseAttachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom: Option<ReleaseAttachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ReleaseAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub target: String,
    pub url: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ReleaseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseSignature {
    #[serde(rename = "type")]
    pub signature_type: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAttachment {
    pub name: String,
    pub url: String,
    pub sha256: String,
}

impl ReleaseManifest {
    pub fn from_json_str(json: &str) -> Result<Self, ReleaseManifestError> {
        Ok(serde_json::from_str(json)?)
    }

    pub fn from_path(path: &Path) -> Result<Self, ReleaseManifestError> {
        let contents =
            std::fs::read_to_string(path).map_err(|source| ReleaseManifestError::Read {
                path: path.display().to_string(),
                source,
            })?;
        Self::from_json_str(&contents)
    }

    pub fn from_url(url: &str) -> Result<Self, ReleaseManifestError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|source| ReleaseManifestError::Network {
                url: url.to_string(),
                source,
            })?;
        let response = client
            .get(url)
            .send()
            .and_then(|resp| resp.error_for_status())
            .map_err(|source| ReleaseManifestError::Network {
                url: url.to_string(),
                source,
            })?;
        let body = response
            .text()
            .map_err(|source| ReleaseManifestError::Network {
                url: url.to_string(),
                source,
            })?;
        Self::from_json_str(&body)
    }

    pub fn load(source: &str) -> Result<Self, ReleaseManifestError> {
        if let Some(path) = source.strip_prefix("file://") {
            return Self::from_path(Path::new(path));
        }
        if source.starts_with("http://") || source.starts_with("https://") {
            return Self::from_url(source);
        }
        Self::from_path(Path::new(source))
    }

    pub fn select_asset(&self, target: &str) -> Option<&ReleaseAsset> {
        self.assets.iter().find(|asset| asset.target == target)
    }

    pub fn compare_version(&self, current_version: &str) -> Option<Ordering> {
        let latest = parse_version(&self.version)?;
        let current = parse_version(current_version)?;
        Some(latest.cmp(&current))
    }
}

pub fn current_release_target() -> Option<String> {
    Platform::current().map(|platform| platform.release_target().to_string())
}

fn parse_version(version: &str) -> Option<Version> {
    let trimmed = version.trim_start_matches('v');
    Version::parse(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_manifest_and_select_asset() {
        let manifest = ReleaseManifest::from_json_str(
            r#"{
                "version": "1.2.3",
                "channel": "stable",
                "published_at": "2025-01-01T00:00:00Z",
                "release_notes": {
                    "name": "RELEASE_NOTES.md",
                    "url": "https://example.com/notes",
                    "sha256": "fff"
                },
                "assets": [
                    {
                        "name": "pybun-x86_64-unknown-linux-gnu.tar.gz",
                        "target": "x86_64-unknown-linux-gnu",
                        "url": "https://example.com/pybun.tar.gz",
                        "sha256": "abc123"
                    },
                    {
                        "name": "pybun-aarch64-apple-darwin.tar.gz",
                        "target": "aarch64-apple-darwin",
                        "url": "https://example.com/pybun-macos.tar.gz",
                        "sha256": "def456"
                    }
                ]
            }"#,
        )
        .expect("manifest parses");

        let asset = manifest
            .select_asset("x86_64-unknown-linux-gnu")
            .expect("asset should be selectable");
        assert_eq!(asset.name, "pybun-x86_64-unknown-linux-gnu.tar.gz");
        let notes = manifest
            .release_notes
            .expect("release notes attachment present");
        assert_eq!(notes.name, "RELEASE_NOTES.md");
    }

    #[test]
    fn compare_version_reports_newer_release() {
        let manifest = ReleaseManifest::from_json_str(
            r#"{
                "version": "2.0.0",
                "channel": "stable",
                "published_at": "2025-01-01T00:00:00Z",
                "assets": []
            }"#,
        )
        .expect("manifest parses");

        assert_eq!(manifest.compare_version("1.0.0"), Some(Ordering::Greater));
        assert_eq!(manifest.compare_version("2.0.0"), Some(Ordering::Equal));
    }
}
