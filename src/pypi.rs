use crate::lockfile::PackageSource;
use crate::once_map::OnceMap;
use crate::resolver::{PackageArtifacts, PackageIndex, Requirement, ResolvedPackage, Wheel};
use dashmap::DashMap;
use reqwest::{StatusCode, Url, header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, thiserror::Error)]
pub enum PyPiError {
    #[error("invalid PyPI base url {0}")]
    InvalidBaseUrl(String),
    #[error("cache directory unavailable")]
    CacheDirUnavailable,
    #[error("cache miss for {0} in offline mode")]
    OfflineCacheMiss(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
}

impl From<reqwest::Error> for PyPiError {
    fn from(value: reqwest::Error) -> Self {
        Self::Http(value.to_string())
    }
}

impl From<std::io::Error> for PyPiError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

/// Package index backed by the PyPI JSON API with local caching and offline support.
#[derive(Clone)]
pub struct PyPiIndex {
    client: PyPiClient,
    memory: Arc<DashMap<String, Vec<CachedPackage>>>,
}

impl PyPiIndex {
    pub fn new(client: PyPiClient) -> Self {
        Self {
            client,
            memory: Arc::new(DashMap::new()),
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
            let cached = packages.iter().find(|p| p.version == version);
            if cached.is_none() {
                return Ok(None);
            }
            let dependencies = this
                .client
                .ensure_dependencies(&name, &version, &this.memory)
                .await
                .map_err(|e| crate::resolver::ResolveError::Io(e.to_string()))?;
            let source = this.client.package_source();
            Ok(Some(this.client.build_resolved(
                cached.expect("checked"),
                &dependencies,
                &source,
            )))
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
            let cached = this
                .client
                .get_or_fetch(&name, &this.memory)
                .await
                .map_err(|e| crate::resolver::ResolveError::Io(e.to_string()))?;
            let source = this.client.package_source();
            Ok(cached
                .iter()
                .map(|pkg| {
                    this.client.build_resolved(
                        pkg,
                        pkg.dependencies.as_deref().unwrap_or(&[]),
                        &source,
                    )
                })
                .collect())
        }
    }
}

#[derive(Clone)]
pub struct PyPiClient {
    base: Url,
    cache_dir: PathBuf,
    http: reqwest::Client,
    offline: bool,
    package_once: Arc<OnceMap<String, Vec<CachedPackage>>>,
    deps_once: Arc<OnceMap<String, Vec<String>>>,
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
            package_once: Arc::new(OnceMap::new()),
            deps_once: Arc::new(OnceMap::new()),
        })
    }

    async fn get_or_fetch(
        &self,
        name: &str,
        memory: &Arc<DashMap<String, Vec<CachedPackage>>>,
    ) -> Result<Vec<CachedPackage>, PyPiError> {
        if let Some(cached) = memory.get(name).map(|entry| entry.clone()) {
            return Ok(cached);
        }
        let name_owned = name.to_string();
        let memory = Arc::clone(memory);
        let packages = self
            .package_once
            .get_or_try_init(name_owned.clone(), || {
                let client = self.clone();
                let memory = Arc::clone(&memory);
                async move {
                    let packages = client.fetch_packages(&name_owned).await?;
                    memory.insert(name_owned.clone(), packages.clone());
                    Ok::<Vec<CachedPackage>, PyPiError>(packages)
                }
            })
            .await?;
        Ok(packages)
    }

    pub fn index_url(&self) -> String {
        self.base
            .join("simple")
            .map(|u| u.to_string())
            .unwrap_or_else(|_| "https://pypi.org/simple".into())
    }

    async fn fetch_packages(&self, name: &str) -> Result<Vec<CachedPackage>, PyPiError> {
        let cached_entry = self.load_cache(name).await?;

        if self.offline {
            let entry =
                cached_entry.ok_or_else(|| PyPiError::OfflineCacheMiss(name.to_string()))?;
            return Ok(entry.packages);
        }

        if let Some(entry) = &cached_entry
            && entry.policy.is_fresh(now_epoch_seconds())
        {
            return Ok(entry.packages.clone());
        }

        let mut req = self.http.get(
            self.base
                .join(&format!("pypi/{name}/json"))
                .map_err(|e| PyPiError::Parse(e.to_string()))?,
        );
        if let Some(entry) = &cached_entry {
            if let Some(etag) = &entry.policy.etag {
                req = req.header(header::IF_NONE_MATCH, etag.as_str());
            }
            if let Some(modified) = &entry.policy.last_modified {
                req = req.header(header::IF_MODIFIED_SINCE, modified.as_str());
            }
        }

        let resp = req.send().await?;

        if resp.status() == StatusCode::NOT_MODIFIED {
            let entry =
                cached_entry.ok_or_else(|| PyPiError::OfflineCacheMiss(name.to_string()))?;
            return Ok(entry.packages);
        }

        if !resp.status().is_success() {
            return Err(PyPiError::Http(
                resp.error_for_status().unwrap_err().to_string(),
            ));
        }

        let headers = resp.headers().clone();
        let body = resp.bytes().await?;
        let cached_deps = cached_entry
            .as_ref()
            .map(|entry| {
                entry
                    .packages
                    .iter()
                    .map(|pkg| (pkg.version.clone(), pkg.dependencies.clone()))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();

        let body_bytes = body.to_vec();
        let body_bytes_for_parse = body_bytes.clone();
        let packages = tokio::task::spawn_blocking(move || {
            let parsed: ProjectResponse = serde_json::from_slice(&body_bytes_for_parse)
                .map_err(|e| PyPiError::Parse(format!("json decode error: {}", e)))?;
            Ok::<_, PyPiError>(build_cached_packages(parsed, &cached_deps))
        })
        .await
        .map_err(|e| PyPiError::Parse(format!("cache parse join error: {}", e)))??;

        let policy = HttpCachePolicy::from_headers(&headers, now_epoch_seconds());
        let entry = CacheEntry {
            policy: policy.clone(),
            body: body_bytes,
            packages,
        };
        if !policy.no_store {
            self.save_cache(name, entry.clone()).await?;
        }

        Ok(entry.packages)
    }

    async fn fetch_requires_dist(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Vec<String>, PyPiError> {
        let url = self
            .base
            .join(&format!("pypi/{}/{}/json", name, version))
            .map_err(|e| PyPiError::Parse(e.to_string()))?;
        let resp = self.http.get(url).send().await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }
        let body: VersionResponse = resp.json().await?;
        Ok(body.info.requires_dist.unwrap_or_default())
    }

    fn cache_path(&self, name: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.bin", name.to_lowercase()))
    }

    fn legacy_cache_path(&self, name: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", name.to_lowercase()))
    }

    async fn load_cache(&self, name: &str) -> Result<Option<CacheEntry>, PyPiError> {
        let path = self.cache_path(name);
        let legacy_path = self.legacy_cache_path(name);
        let now = now_epoch_seconds();
        tokio::task::spawn_blocking(move || load_cache_from_paths(&path, &legacy_path, now))
            .await
            .map_err(|e| PyPiError::Parse(format!("cache join error: {}", e)))?
    }

    async fn save_cache(&self, name: &str, entry: CacheEntry) -> Result<(), PyPiError> {
        let path = self.cache_path(name);
        tokio::task::spawn_blocking(move || save_cache_to_path(&path, &entry))
            .await
            .map_err(|e| PyPiError::Parse(format!("cache join error: {}", e)))?
    }

    fn package_source(&self) -> PackageSource {
        PackageSource::Registry {
            index: "pypi".into(),
            url: self.index_url(),
        }
    }

    fn build_resolved(
        &self,
        pkg: &CachedPackage,
        dependencies: &[String],
        source: &PackageSource,
    ) -> ResolvedPackage {
        let deps = dependencies
            .iter()
            .filter_map(|d| Requirement::from_str(d).ok())
            .collect::<Vec<_>>();
        let artifacts = PackageArtifacts {
            wheels: pkg
                .wheels
                .iter()
                .map(|w| Wheel {
                    file: w.file.clone(),
                    url: w.url.clone(),
                    platforms: if w.platforms.is_empty() {
                        vec!["any".into()]
                    } else {
                        w.platforms.clone()
                    },
                    hash: w.hash.clone(),
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
    }

    async fn ensure_dependencies(
        &self,
        name: &str,
        version: &str,
        memory: &Arc<DashMap<String, Vec<CachedPackage>>>,
    ) -> Result<Vec<String>, PyPiError> {
        if let Some(deps) = self.cached_dependencies(name, version, memory).await {
            return Ok(deps);
        }

        let key = format!("{}=={}", name, version);
        let memory = Arc::clone(memory);
        let name_owned = name.to_string();
        let version_owned = version.to_string();
        let deps = self
            .deps_once
            .get_or_try_init(key, || {
                let client = self.clone();
                let memory = Arc::clone(&memory);
                async move {
                    if client.offline {
                        return Err(PyPiError::OfflineCacheMiss(format!(
                            "{}=={}",
                            name_owned, version_owned
                        )));
                    }

                    let raw_deps = client
                        .fetch_requires_dist(&name_owned, &version_owned)
                        .await?;
                    let deps = raw_deps
                        .into_iter()
                        .filter_map(parse_requires_dist)
                        .map(|req| req.to_string())
                        .collect::<Vec<_>>();
                    client
                        .update_cached_dependencies(
                            &name_owned,
                            &version_owned,
                            deps.clone(),
                            &memory,
                        )
                        .await?;
                    Ok::<Vec<String>, PyPiError>(deps)
                }
            })
            .await?;
        Ok(deps)
    }

    async fn cached_dependencies(
        &self,
        name: &str,
        version: &str,
        memory: &Arc<DashMap<String, Vec<CachedPackage>>>,
    ) -> Option<Vec<String>> {
        memory.get(name).and_then(|packages| {
            packages
                .iter()
                .find(|pkg| pkg.version == version)
                .and_then(|pkg| pkg.dependencies.clone())
        })
    }

    async fn update_cached_dependencies(
        &self,
        name: &str,
        version: &str,
        deps: Vec<String>,
        memory: &Arc<DashMap<String, Vec<CachedPackage>>>,
    ) -> Result<(), PyPiError> {
        if let Some(mut packages) = memory.get_mut(name)
            && let Some(pkg) = packages.iter_mut().find(|pkg| pkg.version == version)
        {
            pkg.dependencies = Some(deps.clone());
        }

        if let Some(mut entry) = self.load_cache(name).await? {
            if let Some(pkg) = entry.packages.iter_mut().find(|pkg| pkg.version == version) {
                pkg.dependencies = Some(deps);
            }
            if !entry.policy.no_store {
                self.save_cache(name, entry).await?;
            }
        }
        Ok(())
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
    url: String,
    pub packagetype: String,

    #[serde(default)]
    yanked: Option<bool>,
    #[serde(default)]
    digests: Option<HashMap<String, String>>,
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
    pub file: String,
    pub url: Option<String>,
    pub hash: Option<String>,
    platforms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedPackage {
    name: String,
    version: String,
    #[serde(default)]
    dependencies: Option<Vec<String>>,
    wheels: Vec<CachedWheel>,
    #[serde(default)]
    sdist: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HttpCachePolicy {
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    last_modified: Option<String>,
    #[serde(default)]
    max_age: Option<u64>,
    #[serde(default)]
    no_cache: bool,
    #[serde(default)]
    no_store: bool,
    #[serde(default)]
    fetched_at: u64,
}

impl HttpCachePolicy {
    fn from_headers(headers: &header::HeaderMap, fetched_at: u64) -> Self {
        let cache_control = headers
            .get(header::CACHE_CONTROL)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        let directives = parse_cache_control(cache_control);
        Self {
            etag: headers
                .get(header::ETAG)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string),
            last_modified: headers
                .get(header::LAST_MODIFIED)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string),
            max_age: directives.max_age,
            no_cache: directives.no_cache,
            no_store: directives.no_store,
            fetched_at,
        }
    }

    fn is_fresh(&self, now: u64) -> bool {
        if self.no_cache {
            return false;
        }
        match self.max_age {
            Some(max_age) => now.saturating_sub(self.fetched_at) <= max_age,
            None => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    policy: HttpCachePolicy,
    #[serde(default)]
    body: Vec<u8>,
    packages: Vec<CachedPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyCacheEntry {
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    last_modified: Option<String>,
    packages: Vec<CachedPackage>,
}

#[derive(Default)]
struct CacheControlDirectives {
    max_age: Option<u64>,
    no_cache: bool,
    no_store: bool,
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
    let py_version = std::env::var("PYBUN_PYPI_PYTHON_VERSION").unwrap_or_else(|_| "3.11".into());

    // Split marker and requirement
    let mut iter = raw.splitn(2, ';');
    let req_part = iter.next()?.trim();
    if iter
        .next()
        .is_some_and(|marker| !marker_allows(marker, &py_version))
    {
        return None;
    }

    let without_extras = req_part.split('[').next().unwrap_or("").trim();

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

fn marker_allows(marker: &str, py_version: &str) -> bool {
    let marker = marker.to_lowercase();

    // Skip extras we didn't request
    if marker.contains("extra ==") || marker.contains("extra==") || marker.contains("extra===") {
        return false;
    }

    // Handle simple python_version comparisons; if parsing fails, allow by default
    if marker.contains("python_version")
        && matches!(eval_python_version_marker(&marker, py_version), Some(false))
    {
        return false;
    }

    true
}

fn eval_python_version_marker(marker: &str, py_version: &str) -> Option<bool> {
    // Support simple markers like python_version >= "3.10", < "3.14"
    let ops = ["<=", ">=", "==", "!=", "<", ">"];
    for op in ops {
        if let Some(idx) = marker.find(op) {
            if !marker[..idx].contains("python_version") {
                continue;
            }
            let rhs = marker[idx + op.len()..].trim();
            let rhs = rhs.trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace());
            return Some(compare_versions(py_version, rhs, op));
        }
    }
    None
}

fn compare_versions(lhs: &str, rhs: &str, op: &str) -> bool {
    let lhs_parts = version_tuple(lhs);
    let rhs_parts = version_tuple(rhs);
    match op {
        "==" => lhs_parts == rhs_parts,
        "!=" => lhs_parts != rhs_parts,
        ">=" => lhs_parts >= rhs_parts,
        "<=" => lhs_parts <= rhs_parts,
        ">" => lhs_parts > rhs_parts,
        "<" => lhs_parts < rhs_parts,
        _ => true,
    }
}

fn version_tuple(s: &str) -> (u64, u64, u64) {
    let mut parts = s
        .split('.')
        .take(3)
        .map(|p| p.parse().unwrap_or(0))
        .collect::<Vec<_>>();
    while parts.len() < 3 {
        parts.push(0);
    }
    (parts[0], parts[1], parts[2])
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

fn parse_cache_control(raw: &str) -> CacheControlDirectives {
    let mut directives = CacheControlDirectives::default();
    for part in raw.split(',') {
        let part = part.trim().to_lowercase();
        if part == "no-cache" {
            directives.no_cache = true;
        } else if part == "no-store" {
            directives.no_store = true;
        } else if let Some(value) = part.strip_prefix("max-age=")
            && let Ok(seconds) = value.trim().parse::<u64>()
        {
            directives.max_age = Some(seconds);
        }
    }
    directives
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_cache_from_paths(
    path: &Path,
    legacy_path: &Path,
    now: u64,
) -> Result<Option<CacheEntry>, PyPiError> {
    if path.exists() {
        let data = fs::read(path)?;
        let entry: CacheEntry = bincode::deserialize(&data)
            .map_err(|e| PyPiError::Parse(format!("cache decode error: {}", e)))?;
        return Ok(Some(entry));
    }
    if legacy_path.exists() {
        let data = fs::read_to_string(legacy_path)?;
        let entry: LegacyCacheEntry = serde_json::from_str(&data)
            .map_err(|e| PyPiError::Parse(format!("cache decode error: {}", e)))?;
        return Ok(Some(CacheEntry {
            policy: HttpCachePolicy {
                etag: entry.etag,
                last_modified: entry.last_modified,
                max_age: None,
                no_cache: false,
                no_store: false,
                fetched_at: now,
            },
            body: Vec::new(),
            packages: entry.packages,
        }));
    }
    Ok(None)
}

fn save_cache_to_path(path: &Path, entry: &CacheEntry) -> Result<(), PyPiError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = bincode::serialize(entry)
        .map_err(|e| PyPiError::Parse(format!("cache encode error: {}", e)))?;
    fs::write(path, data)?;
    Ok(())
}

fn build_cached_packages(
    body: ProjectResponse,
    cached_deps: &HashMap<String, Option<Vec<String>>>,
) -> Vec<CachedPackage> {
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
                    let hash = file
                        .digests
                        .as_ref()
                        .and_then(|d| d.get("sha256"))
                        .map(|h| format!("sha256:{}", h));

                    wheels.push(CachedWheel {
                        file: file.filename.clone(),
                        url: Some(file.url.clone()),
                        hash,
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

        let dependencies = cached_deps.get(&version).cloned().unwrap_or(None);
        packages.push(CachedPackage {
            name: body.info.name.clone(),
            version,
            dependencies,
            wheels,
            sdist,
        });
    }
    packages
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn marker_rejects_extra() {
        assert!(!marker_allows(r#"extra == "cffi""#, "3.11"));
    }

    #[test]
    fn marker_respects_python_version() {
        assert!(!marker_allows(r#"python_version >= "3.14""#, "3.11"));
        assert!(marker_allows(r#"python_version < "3.14""#, "3.11"));
    }

    #[test]
    fn cache_policy_respects_max_age() {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("max-age=60"),
        );
        let policy = HttpCachePolicy::from_headers(&headers, 100);
        assert!(policy.is_fresh(160));
        assert!(!policy.is_fresh(161));
    }

    #[tokio::test]
    async fn binary_cache_roundtrip() {
        let temp = tempdir().unwrap();
        let client = PyPiClient {
            base: Url::parse("https://pypi.org").unwrap(),
            cache_dir: temp.path().join("cache"),
            http: reqwest::Client::new(),
            offline: false,
            package_once: Arc::new(OnceMap::new()),
            deps_once: Arc::new(OnceMap::new()),
        };
        let entry = CacheEntry {
            policy: HttpCachePolicy {
                etag: Some("\"v1\"".into()),
                last_modified: None,
                max_age: Some(30),
                no_cache: false,
                no_store: false,
                fetched_at: 10,
            },
            body: b"{\"info\":{\"name\":\"demo\"},\"releases\":{}}".to_vec(),
            packages: Vec::new(),
        };
        client.save_cache("demo", entry.clone()).await.unwrap();
        let loaded = client.load_cache("demo").await.unwrap().unwrap();
        assert_eq!(loaded.policy.etag, entry.policy.etag);
        assert_eq!(loaded.policy.max_age, entry.policy.max_age);
        assert_eq!(loaded.body, entry.body);
    }
}
