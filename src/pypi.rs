use crate::lockfile::PackageSource;
use crate::resolver::{PackageArtifacts, PackageIndex, Requirement, ResolvedPackage, Wheel};
use futures::future::try_join_all;
use reqwest::{StatusCode, Url, header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum PyPiError {
    #[error("invalid PyPI base url {0}")]
    InvalidBaseUrl(String),
    #[error("cache directory unavailable")]
    CacheDirUnavailable,
    #[error("cache miss for {0} in offline mode")]
    OfflineCacheMiss(String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
}

/// Package index backed by the PyPI JSON API with local caching and offline support.
#[derive(Clone)]
pub struct PyPiIndex {
    client: PyPiClient,
    memory: Arc<Mutex<HashMap<String, Vec<ResolvedPackage>>>>,
}

impl PyPiIndex {
    pub fn new(client: PyPiClient) -> Self {
        Self {
            client,
            memory: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl PackageIndex for PyPiIndex {
    fn get(
        &self,
        name: &str,
        version: &str,
    ) -> impl std::future::Future<
        Output = Result<Option<ResolvedPackage>, crate::resolver::ResolveError>,
    > + Send {
        let name = name.to_string();
        let version = version.to_string();
        let this = self.clone();
        async move {
            let packages = this
                .client
                .get_or_fetch(&name, &this.memory)
                .await
                .map_err(|e| crate::resolver::ResolveError::Io(e.to_string()))?;
            Ok(packages.into_iter().find(|p| p.version == version))
        }
    }

    fn all(
        &self,
        name: &str,
    ) -> impl std::future::Future<
        Output = Result<Vec<ResolvedPackage>, crate::resolver::ResolveError>,
    > + Send {
        let name = name.to_string();
        let this = self.clone();
        async move {
            this.client
                .get_or_fetch(&name, &this.memory)
                .await
                .map_err(|e| crate::resolver::ResolveError::Io(e.to_string()))
        }
    }
}

#[derive(Clone)]
pub struct PyPiClient {
    base: Url,
    cache_dir: PathBuf,
    http: reqwest::Client,
    offline: bool,
}

impl PyPiClient {
    pub fn from_env(offline: bool) -> Result<Self, PyPiError> {
        let base =
            std::env::var("PYBUN_PYPI_BASE_URL").unwrap_or_else(|_| "https://pypi.org".to_string());
        let normalized = normalize_base(&base)?;
        let cache_dir = std::env::var("PYBUN_PYPI_CACHE_DIR")
            .map(PathBuf::from)
            .or_else(|_| {
                dirs::cache_dir()
                    .map(|p| p.join("pybun").join("pypi"))
                    .ok_or(PyPiError::CacheDirUnavailable)
            })?;
        Ok(Self {
            base: normalized,
            cache_dir,
            http: reqwest::Client::builder().user_agent("pybun/0.1").build()?,
            offline,
        })
    }

    pub async fn get_or_fetch(
        &self,
        name: &str,
        memory: &Arc<Mutex<HashMap<String, Vec<ResolvedPackage>>>>,
    ) -> Result<Vec<ResolvedPackage>, PyPiError> {
        if let Some(cached) = memory.lock().await.get(name).cloned() {
            return Ok(cached);
        }

        let packages = self.fetch_packages(name).await?;
        memory
            .lock()
            .await
            .insert(name.to_string(), packages.clone());
        Ok(packages)
    }

    pub fn index_url(&self) -> String {
        self.base
            .join("simple")
            .map(|u| u.to_string())
            .unwrap_or_else(|_| "https://pypi.org/simple".into())
    }

    async fn fetch_packages(&self, name: &str) -> Result<Vec<ResolvedPackage>, PyPiError> {
        let cache_path = self.cache_path(name);
        let cached_entry = self.load_cache(&cache_path)?;

        if self.offline {
            let entry =
                cached_entry.ok_or_else(|| PyPiError::OfflineCacheMiss(name.to_string()))?;
            return Ok(self.packages_from_cache(entry));
        }

        let mut req = self.http.get(
            self.base
                .join(&format!("pypi/{name}/json"))
                .map_err(|e| PyPiError::Parse(e.to_string()))?,
        );
        if let Some(entry) = &cached_entry {
            if let Some(etag) = &entry.etag {
                req = req.header(header::IF_NONE_MATCH, etag.as_str());
            }
            if let Some(modified) = &entry.last_modified {
                req = req.header(header::IF_MODIFIED_SINCE, modified.as_str());
            }
        }

        let resp = req.send().await?;

        if resp.status() == StatusCode::NOT_MODIFIED {
            let entry =
                cached_entry.ok_or_else(|| PyPiError::OfflineCacheMiss(name.to_string()))?;
            return Ok(self.packages_from_cache(entry));
        }

        if !resp.status().is_success() {
            return Err(PyPiError::Http(resp.error_for_status().unwrap_err()));
        }

        let etag = resp
            .headers()
            .get(header::ETAG)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let last_modified = resp
            .headers()
            .get(header::LAST_MODIFIED)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);

        let body: ProjectResponse = resp.json().await?;

        // Fetch per-version dependency metadata
        let versions: Vec<String> = body.releases.keys().cloned().collect();
        let deps = self.fetch_requires_map(name, &versions).await?;

        let mut packages = Vec::new();
        for (version, files) in body.releases {
            if files.is_empty() {
                continue;
            }
            let mut wheels = Vec::new();
            let mut sdist = None;
            for file in files {
                if file.yanked.unwrap_or(false) {
                    continue;
                }
                match file.packagetype.as_str() {
                    "bdist_wheel" => {
                        let platforms = wheel_platforms(&file.filename);
                        wheels.push(CachedWheel {
                            file: file.filename.clone(),
                            platforms: if platforms.is_empty() {
                                vec!["any".into()]
                            } else {
                                platforms
                            },
                        });
                    }
                    "sdist" => {
                        sdist = Some(file.filename.clone());
                    }
                    _ => {}
                }
            }

            let dependencies = deps
                .get(&version)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(parse_requires_dist)
                .map(|r| r.to_string())
                .collect::<Vec<_>>();

            packages.push(CachedPackage {
                name: body.info.name.clone(),
                version,
                dependencies,
                wheels,
                sdist,
            });
        }

        let entry = CacheEntry {
            etag,
            last_modified,
            packages,
        };
        self.save_cache(&cache_path, &entry)?;

        Ok(self.packages_from_cache(entry))
    }

    async fn fetch_requires_map(
        &self,
        name: &str,
        versions: &[String],
    ) -> Result<HashMap<String, Vec<String>>, PyPiError> {
        let mut out = HashMap::new();
        let futures = versions.iter().map(|version| {
            let url = self
                .base
                .join(&format!("pypi/{}/{}/json", name, version))
                .map_err(|e| PyPiError::Parse(e.to_string()));
            let client = self.http.clone();
            let version = version.clone();
            async move {
                let url = url?;
                let resp = client.get(url).send().await?;
                if !resp.status().is_success() {
                    return Ok::<(String, Vec<String>), PyPiError>((version, Vec::new()));
                }
                let body: VersionResponse = resp.json().await?;
                Ok::<(String, Vec<String>), PyPiError>((
                    version,
                    body.info.requires_dist.unwrap_or_default(),
                ))
            }
        });

        for result in try_join_all(futures).await? {
            out.insert(result.0, result.1);
        }
        Ok(out)
    }

    fn cache_path(&self, name: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", name.to_lowercase()))
    }

    fn load_cache(&self, path: &Path) -> Result<Option<CacheEntry>, PyPiError> {
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(path)?;
        let entry: CacheEntry = serde_json::from_str(&data)
            .map_err(|e| PyPiError::Parse(format!("cache decode error: {}", e)))?;
        Ok(Some(entry))
    }

    fn save_cache(&self, path: &Path, entry: &CacheEntry) -> Result<(), PyPiError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(entry)
            .map_err(|e| PyPiError::Parse(format!("cache encode error: {}", e)))?;
        fs::write(path, data)?;
        Ok(())
    }

    fn packages_from_cache(&self, entry: CacheEntry) -> Vec<ResolvedPackage> {
        let source = PackageSource::Registry {
            index: "pypi".into(),
            url: self.index_url(),
        };
        entry
            .packages
            .into_iter()
            .map(|pkg| {
                let deps = pkg
                    .dependencies
                    .iter()
                    .filter_map(|d| Requirement::from_str(d).ok())
                    .collect::<Vec<_>>();
                let artifacts = PackageArtifacts {
                    wheels: pkg
                        .wheels
                        .iter()
                        .map(|w| Wheel {
                            file: w.file.clone(),
                            platforms: if w.platforms.is_empty() {
                                vec!["any".into()]
                            } else {
                                w.platforms.clone()
                            },
                        })
                        .collect(),
                    sdist: pkg.sdist.clone(),
                };
                ResolvedPackage {
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    dependencies: deps,
                    source: Some(source.clone()),
                    artifacts,
                }
            })
            .collect()
    }
}

#[derive(Debug, Deserialize)]
struct ProjectResponse {
    info: ProjectInfo,
    releases: HashMap<String, Vec<ReleaseFile>>,
}

#[derive(Debug, Deserialize)]
struct ProjectInfo {
    name: String,
}

#[derive(Debug, Deserialize)]
struct ReleaseFile {
    filename: String,
    packagetype: String,
    #[serde(default)]
    yanked: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct VersionResponse {
    info: VersionInfo,
}

#[derive(Debug, Deserialize)]
struct VersionInfo {
    #[serde(default)]
    requires_dist: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedWheel {
    file: String,
    platforms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedPackage {
    name: String,
    version: String,
    dependencies: Vec<String>,
    wheels: Vec<CachedWheel>,
    #[serde(default)]
    sdist: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    last_modified: Option<String>,
    packages: Vec<CachedPackage>,
}

fn normalize_base(input: &str) -> Result<Url, PyPiError> {
    let trimmed = input.trim_end_matches('/');
    let normalized = if trimmed.ends_with("/simple") {
        trimmed.trim_end_matches("/simple")
    } else {
        trimmed
    };
    Url::parse(normalized).map_err(|_| PyPiError::InvalidBaseUrl(input.to_string()))
}

fn parse_requires_dist(raw: String) -> Option<Requirement> {
    let without_marker = raw.split(';').next()?.trim();
    let without_extras = without_marker.split('[').next().unwrap_or("").trim();

    if let Some((name, rest)) = without_extras.split_once('(') {
        let spec = rest.trim_end_matches(')').trim();
        let first_spec = spec.split(',').next().unwrap_or("").trim();
        let normalized = format!("{}{}", name.trim(), first_spec.replace(' ', ""));
        Requirement::from_str(&normalized).ok()
    } else {
        let normalized = without_extras.replace(' ', "");
        let first = normalized.split(',').next().unwrap_or("").trim();
        Requirement::from_str(first).ok()
    }
}

fn wheel_platforms(filename: &str) -> Vec<String> {
    if !filename.ends_with(".whl") {
        return Vec::new();
    }
    let fname = filename
        .trim_end_matches(".whl")
        .rsplit('/')
        .next()
        .unwrap_or(filename);
    let components: Vec<&str> = fname.split('-').collect();
    if components.len() < 5 {
        return vec!["any".into()];
    }
    let platform = components.last().unwrap_or(&"any").to_string();
    vec![platform]
}
