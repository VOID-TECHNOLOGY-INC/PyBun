//! Bounded, approved-endpoint HTTP observations. No environment credentials,
//! redirects, reference fetching, or filesystem/cache side effects.

use super::{AuthorizedQuery, ObservationDiagnostic, ObservationLimits};
use futures::StreamExt;
use reqwest::{Method, Url, header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub id: String,
    pub url: String,
    pub auth_scope_id: String,
    #[serde(default)]
    pub allow_insecure_loopback: bool,
}

#[derive(Clone)]
pub struct ProviderEndpoint {
    config: ProviderConfig,
    url: Url,
    prefix: String,
    headers: header::HeaderMap,
}

impl std::fmt::Debug for ProviderEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderEndpoint")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl ProviderEndpoint {
    pub fn new(config: ProviderConfig) -> Result<Self, ObservationDiagnostic> {
        if !super::source::opaque_id(&config.id) || !super::source::opaque_id(&config.auth_scope_id)
        {
            return Err(endpoint_error());
        }
        let url = Url::parse(&config.url).map_err(|_| endpoint_error())?;
        let loopback = url
            .host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback());
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !(url.scheme() == "https"
                || (url.scheme() == "http" && config.allow_insecure_loopback && loopback))
        {
            return Err(endpoint_error());
        }
        let path = url.path();
        let prefix = if path.ends_with('/') {
            path.to_owned()
        } else {
            path.rsplit_once('/')
                .map(|(parent, _)| format!("{parent}/"))
                .unwrap_or_else(|| "/".into())
        };
        Ok(Self {
            config,
            url,
            prefix,
            headers: header::HeaderMap::new(),
        })
    }

    pub fn id(&self) -> &str {
        &self.config.id
    }
    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Credentials are ephemeral, sensitive headers scoped to this endpoint.
    /// They are never serialized or included in the source/cache identity.
    pub fn with_bearer_token(mut self, token: &str) -> Result<Self, ObservationDiagnostic> {
        let mut value = header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| endpoint_error())?;
        value.set_sensitive(true);
        self.headers.insert(header::AUTHORIZATION, value);
        Ok(self)
    }

    fn redact_value(&self, value: &Value) -> Value {
        let secrets: Vec<_> = self
            .headers
            .values()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| [value, value.strip_prefix("Bearer ").unwrap_or(value)])
            .collect();
        let mut redacted = crate::support_bundle::redact_protocol_with_secrets(value, &secrets);
        // A redacted protocol cursor cannot be used as a different request.
        // Retain an invalid field so pagination reports incomplete evidence.
        if let (Some(original), Some(results)) = (
            value.get("results").and_then(Value::as_array),
            redacted.get_mut("results").and_then(Value::as_array_mut),
        ) {
            for (original, result) in original.iter().zip(results) {
                if let Some(token) = original.get("next_page_token")
                    && result.get("next_page_token") != Some(token)
                    && let Some(result) = result.as_object_mut()
                {
                    result.insert("next_page_token".into(), Value::Null);
                }
            }
        }
        redacted
    }

    pub fn permits(&self, url: &Url) -> bool {
        url.origin() == self.url.origin()
            && url.path().starts_with(&self.prefix)
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    }

    pub fn detail_url(&self, id: &str) -> Result<Url, ObservationDiagnostic> {
        if id.is_empty()
            || id.len() > 200
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b':' | b'.'))
        {
            return Err(protocol_error());
        }
        let mut url = self.url.clone();
        url.path_segments_mut()
            .map_err(|_| endpoint_error())?
            .pop_if_empty()
            .pop()
            .push("vulns")
            .push(id);
        if !self.permits(&url) {
            return Err(endpoint_error());
        }
        Ok(url)
    }

    pub fn observation_key(
        &self,
        query: &AuthorizedQuery,
        method: &str,
        url: &Url,
        body: &Option<Value>,
    ) -> String {
        super::model::semantic_digest(&(2, &self.config, query, method, url.as_str(), body))
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessKind {
    #[default]
    Fresh,
    OfflineCache,
    StaleCache,
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFreshness {
    pub kind: FreshnessKind,
    pub age_seconds: u64,
}
impl EvidenceFreshness {
    pub fn is_authoritative(&self) -> bool {
        self.kind == FreshnessKind::Fresh
    }
    pub(crate) fn merge(&mut self, other: Self) {
        if other.kind == FreshnessKind::StaleCache
            || (self.kind == FreshnessKind::Fresh && other.kind != FreshnessKind::Fresh)
        {
            self.kind = other.kind;
        }
        self.age_seconds = self.age_seconds.max(other.age_seconds);
    }
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ObservationMode {
    #[default]
    Online,
    Offline,
    OnlineWithCacheFallback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonEvidence {
    pub freshness: EvidenceFreshness,
    pub value: Value,
    pub payload_digest: String,
    pub fetched_at: u64,
}

pub struct HttpSession {
    client: reqwest::Client,
    limits: ObservationLimits,
    started: Instant,
    observed_at: u64,
    requests: AtomicUsize,
    retained_evidence: AtomicUsize,
    admission: Semaphore,
    pages: Mutex<BTreeMap<String, usize>>,
    cache: Option<super::qualification::cache::ObservationCache>,
    mode: ObservationMode,
    cache_diagnostics: Mutex<Vec<ObservationDiagnostic>>,
}

impl HttpSession {
    pub fn new(limits: ObservationLimits, observed_at: u64) -> Result<Self, ObservationDiagnostic> {
        let started = Instant::now();
        limits.validate()?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .no_proxy()
            .build()
            .map_err(|_| endpoint_error())?;
        let admission = Semaphore::new(limits.concurrency);
        Ok(Self {
            client,
            limits,
            started,
            observed_at,
            requests: AtomicUsize::new(0),
            retained_evidence: AtomicUsize::new(0),
            admission,
            pages: Mutex::new(BTreeMap::new()),
            cache: None,
            mode: ObservationMode::Online,
            cache_diagnostics: Mutex::new(vec![]),
        })
    }

    pub fn with_cache(
        mut self,
        cache: super::qualification::cache::ObservationCache,
        mode: ObservationMode,
    ) -> Result<Self, ObservationDiagnostic> {
        if cache.max_response_bytes() > self.limits.max_response_bytes {
            return Err(ObservationDiagnostic::new(
                "E_SECURITY_CACHE_LIMIT",
                "Cache response limit exceeds this assessment's HTTP response budget.",
            ));
        }
        self.cache = Some(cache);
        self.mode = mode;
        Ok(self)
    }
    pub fn cache_diagnostics(&self) -> Vec<ObservationDiagnostic> {
        self.cache_diagnostics
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
    fn cache_diagnostic(&self, error: ObservationDiagnostic) {
        let mut diagnostics = self
            .cache_diagnostics
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !diagnostics
            .iter()
            .any(|existing| existing.code == error.code)
        {
            diagnostics.push(error);
        }
    }
    pub fn limits(&self) -> &ObservationLimits {
        &self.limits
    }
    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }
    pub fn request_count(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }

    pub fn remaining_evidence_bytes(&self) -> usize {
        self.limits
            .max_retained_evidence_bytes
            .saturating_sub(self.retained_evidence.load(Ordering::Relaxed))
    }

    /// All providers and candidate re-queries share retained result capacity.
    /// A failed reservation must not be represented as missing upstream data.
    pub fn reserve_evidence(&self, bytes: usize) -> Result<(), ObservationDiagnostic> {
        let mut retained = self.retained_evidence.load(Ordering::Relaxed);
        loop {
            if bytes
                > self
                    .limits
                    .max_retained_evidence_bytes
                    .saturating_sub(retained)
            {
                return Err(ObservationDiagnostic::new(
                    "E_SECURITY_EVIDENCE_LIMIT",
                    "Aggregate retained evidence exceeded the run's bounded JSON size; remaining evidence is incomplete.",
                ));
            }
            match self.retained_evidence.compare_exchange_weak(
                retained,
                retained + bytes,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => retained = current,
            }
        }
    }

    /// Page budgets belong to the run/provider, including later candidate
    /// re-queries, rather than being reset for each source group or package.
    pub fn reserve_provider_page(&self, provider_id: &str) -> Result<(), ObservationDiagnostic> {
        self.remaining()?;
        let mut pages = self.pages.lock().map_err(|_| deadline_error())?;
        let count = pages.entry(provider_id.into()).or_default();
        if *count >= self.limits.max_pages {
            return Err(ObservationDiagnostic::new(
                "E_SECURITY_PROVIDER_PAGE",
                "The provider page budget was exhausted.",
            ));
        }
        *count += 1;
        Ok(())
    }

    fn reserve_request(&self) -> Result<(), ObservationDiagnostic> {
        let mut count = self.request_count();
        loop {
            if count >= self.limits.max_requests {
                return Err(ObservationDiagnostic::new(
                    "E_SECURITY_REQUEST_LIMIT",
                    "The observation request budget was exhausted.",
                ));
            }
            match self.requests.compare_exchange_weak(
                count,
                count + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => count = current,
            }
        }
    }

    pub fn remaining(&self) -> Result<Duration, ObservationDiagnostic> {
        Duration::from_millis(self.limits.total_timeout_ms)
            .checked_sub(self.started.elapsed())
            .filter(|left| !left.is_zero())
            .ok_or_else(deadline_error)
    }

    pub async fn request_json(
        &self,
        endpoint: &ProviderEndpoint,
        method: Method,
        url: Url,
        body: Option<Value>,
        query: &AuthorizedQuery,
    ) -> Result<JsonEvidence, ObservationDiagnostic> {
        self.request_json_tracked(endpoint, method, url, body, query)
            .await
            .0
    }

    pub(crate) async fn request_json_tracked(
        &self,
        endpoint: &ProviderEndpoint,
        method: Method,
        url: Url,
        body: Option<Value>,
        query: &AuthorizedQuery,
    ) -> (Result<JsonEvidence, ObservationDiagnostic>, bool) {
        let attempted = AtomicBool::new(false);
        let result = self
            .request_json_cached(endpoint, method, url, body, query, &attempted)
            .await;
        (result, attempted.load(Ordering::Relaxed))
    }

    async fn request_json_cached(
        &self,
        endpoint: &ProviderEndpoint,
        method: Method,
        url: Url,
        body: Option<Value>,
        query: &AuthorizedQuery,
        attempted: &AtomicBool,
    ) -> Result<JsonEvidence, ObservationDiagnostic> {
        self.remaining()?;
        if endpoint.id() != query.provider_id
            || !endpoint.permits(&url)
            || !matches!(method, Method::GET | Method::POST)
        {
            return Err(endpoint_error());
        }
        let key = endpoint.observation_key(query, method.as_str(), &url, &body);
        let cached = |kind| -> Result<JsonEvidence, ObservationDiagnostic> {
            self.remaining()?;
            let cache = self.cache.as_ref().ok_or_else(cache_miss)?;
            let mut evidence = cache.read(&key, self.observed_at)?.ok_or_else(cache_miss)?;
            evidence.value = endpoint.redact_value(&evidence.value);
            self.remaining()?;
            evidence.freshness = EvidenceFreshness {
                kind,
                age_seconds: self.observed_at.saturating_sub(evidence.fetched_at),
            };
            Ok(evidence)
        };
        if self.mode == ObservationMode::Offline {
            return cached(FreshnessKind::OfflineCache);
        }
        match self
            .request_json_inner(endpoint, method, url, body, query, attempted)
            .await
        {
            Ok(evidence) => {
                self.remaining()?;
                if let Some(cache) = &self.cache
                    && let Err(error) = cache.write(&key, &evidence)
                {
                    self.cache_diagnostic(error);
                }
                self.remaining()?;
                Ok(evidence)
            }
            Err(error) => {
                if self.mode == ObservationMode::OnlineWithCacheFallback {
                    self.cache_diagnostic(error.clone());
                    match cached(FreshnessKind::StaleCache) {
                        Ok(evidence) => return Ok(evidence),
                        Err(error) => self.cache_diagnostic(error),
                    }
                }
                Err(error)
            }
        }
    }

    async fn request_json_inner(
        &self,
        endpoint: &ProviderEndpoint,
        method: Method,
        url: Url,
        body: Option<Value>,
        query: &AuthorizedQuery,
        attempted: &AtomicBool,
    ) -> Result<JsonEvidence, ObservationDiagnostic> {
        if endpoint.id() != query.provider_id
            || !endpoint.permits(&url)
            || !matches!(method, Method::GET | Method::POST)
        {
            return Err(endpoint_error());
        }
        let _permit = tokio::time::timeout(self.remaining()?, self.admission.acquire())
            .await
            .map_err(|_| deadline_error())?
            .map_err(|_| deadline_error())?;
        for attempt in 0..self.limits.max_attempts {
            self.reserve_request()?;
            let timeout = self
                .remaining()?
                .min(Duration::from_millis(self.limits.http_timeout_ms));
            let mut request = self
                .client
                .request(method.clone(), url.clone())
                .headers(endpoint.headers.clone())
                .header(
                    header::ACCEPT,
                    "application/json, application/vnd.pypi.simple.v1+json",
                )
                .header(header::ACCEPT_ENCODING, "identity")
                .timeout(timeout);
            if let Some(value) = &body {
                request = request.json(value);
            }
            attempted.store(true, Ordering::Relaxed);
            let response = match request.send().await {
                Ok(response) => response,
                Err(_) if attempt + 1 < self.limits.max_attempts => {
                    self.remaining()?;
                    continue;
                }
                Err(_) => {
                    return Err(ObservationDiagnostic::new(
                        "E_SECURITY_PROVIDER_HTTP",
                        "The approved provider request failed or timed out.",
                    ));
                }
            };
            let status = response.status();
            if status.is_redirection() {
                return Err(ObservationDiagnostic::new(
                    "E_SECURITY_PROVIDER_REDIRECT",
                    "Provider redirects are not followed; configure the approved canonical endpoint.",
                ));
            }
            if (status.as_u16() == 429 || status.is_server_error())
                && attempt + 1 < self.limits.max_attempts
            {
                let delay = retry_delay(
                    response.headers().get(header::RETRY_AFTER),
                    self.observed_at
                        .saturating_add(self.started.elapsed().as_secs()),
                )?;
                if delay >= self.remaining()? {
                    return Err(deadline_error());
                }
                tokio::time::sleep(delay).await;
                continue;
            }
            if !status.is_success() {
                return Err(ObservationDiagnostic::new(
                    "E_SECURITY_PROVIDER_HTTP",
                    "The approved provider returned an unsuccessful status.",
                ));
            }
            if response
                .headers()
                .get(header::CONTENT_ENCODING)
                .is_some_and(|value| value != "identity")
            {
                return Err(ObservationDiagnostic::new(
                    "E_SECURITY_PROVIDER_ENCODING",
                    "The provider ignored identity encoding; compressed content is not treated as JSON evidence.",
                ));
            }
            if response
                .content_length()
                .is_some_and(|length| length > self.limits.max_response_bytes as u64)
            {
                return Err(response_limit());
            }
            let mut bytes = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = tokio::time::timeout(self.remaining()?, stream.next())
                .await
                .map_err(|_| deadline_error())?
            {
                let chunk = chunk.map_err(|_| {
                    ObservationDiagnostic::new(
                        "E_SECURITY_PROVIDER_HTTP",
                        "The provider response could not be read completely.",
                    )
                })?;
                if chunk.len() > self.limits.max_response_bytes.saturating_sub(bytes.len()) {
                    return Err(response_limit());
                }
                bytes.extend_from_slice(&chunk);
            }
            let value: Value = serde_json::from_slice(&bytes).map_err(|_| protocol_error())?;
            self.remaining()?;
            return Ok(JsonEvidence {
                freshness: EvidenceFreshness::default(),
                value: endpoint.redact_value(&value),
                payload_digest: crate::security::sha256_bytes(&bytes),
                fetched_at: self.observed_at,
            });
        }
        Err(deadline_error())
    }
}

fn retry_delay(
    value: Option<&header::HeaderValue>,
    now: u64,
) -> Result<Duration, ObservationDiagnostic> {
    let Some(value) = value else {
        return Ok(Duration::from_millis(50));
    };
    let text = value.to_str().map_err(|_| protocol_error())?;
    if let Ok(seconds) = text.parse::<u64>() {
        return Ok(Duration::from_secs(seconds));
    }
    let date = httpdate::parse_http_date(text).map_err(|_| protocol_error())?;
    let now = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(now))
        .ok_or_else(protocol_error)?;
    Ok(date.duration_since(now).unwrap_or_default())
}

fn cache_miss() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_CACHE_MISS",
        "No cached observation is available in the currently authorized source/provider/auth-scope/schema partition.",
    )
}

fn endpoint_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_PROVIDER_POLICY",
        "Provider configuration or derived URL is outside the approved credential-free endpoint scope.",
    )
}
fn protocol_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_PROVIDER_SCHEMA",
        "The provider returned invalid or unsupported JSON evidence.",
    )
}
fn deadline_error() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_DEADLINE",
        "The observation deadline was exhausted.",
    )
}
fn response_limit() -> ObservationDiagnostic {
    ObservationDiagnostic::new(
        "E_SECURITY_RESPONSE_LIMIT",
        "Provider response exceeded the bounded JSON size.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_dates_use_the_observation_clock() {
        let value = header::HeaderValue::from_static("Thu, 01 Jan 1970 00:01:00 GMT");
        assert_eq!(
            retry_delay(Some(&value), 20).unwrap(),
            Duration::from_secs(40)
        );
        assert_eq!(retry_delay(Some(&value), 70).unwrap(), Duration::ZERO);
        let seconds = header::HeaderValue::from_static("2");
        assert_eq!(
            retry_delay(Some(&seconds), 20).unwrap(),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn malformed_retry_after_is_not_silently_ignored() {
        let value = header::HeaderValue::from_static("invalid-date");
        assert!(retry_delay(Some(&value), 20).is_err());
    }
}
