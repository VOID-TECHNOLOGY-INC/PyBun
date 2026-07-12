use crate::once_map::OnceMap;
use crate::security::verify_ed25519_signature;
use futures::StreamExt;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::fs::{self, File};
use tokio::io::{AsyncWriteExt, BufWriter};

/// Upper bound on a server-supplied `Retry-After` value, so a malicious or
/// misconfigured index cannot stall a download indefinitely.
const MAX_RETRY_AFTER_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub struct SignatureSpec {
    pub signature: String,
    pub public_key: String,
}

#[derive(Debug, Clone)]
pub struct DownloadRequest {
    pub url: String,
    pub destination: PathBuf,
    pub checksum: Option<String>,
    pub signature: Option<SignatureSpec>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct DownloadKey {
    url: String,
    destination: PathBuf,
}

impl From<(String, PathBuf, Option<String>)> for DownloadRequest {
    fn from(value: (String, PathBuf, Option<String>)) -> Self {
        let (url, destination, checksum) = value;
        Self {
            url,
            destination,
            checksum,
            signature: None,
        }
    }
}

#[derive(Debug, Clone, Error)]
pub enum DownloadError {
    #[error("network error: {0}")]
    Network(String),
    #[error("io error: {0}")]
    Io(String),
    /// An HTTP response with a non-success status code (e.g. 404, 401, 500).
    ///
    /// `retry_after` carries the parsed `Retry-After` header (in seconds), if
    /// the server sent one on a 429/503 response.
    #[error("http error {status} for {url}: {message}")]
    HttpStatus {
        status: u16,
        url: String,
        message: String,
        retry_after: Option<u64>,
    },
    #[error("missing checksum for {path}: {checksum}")]
    MissingChecksum { path: PathBuf, checksum: String },
    #[error("checksum mismatch for {path}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        expected: String,
        actual: String,
        path: PathBuf,
    },
    #[error("signature verification failed for {path}: {message}")]
    SignatureVerificationFailed { path: PathBuf, message: String },
    #[error("max retries exceeded for {url} after {attempts} attempts: {source}")]
    MaxRetriesExceeded {
        url: String,
        attempts: u32,
        #[source]
        source: Box<DownloadError>,
    },
}

impl DownloadError {
    /// Whether this failure is worth retrying with backoff.
    ///
    /// Transport-level failures (connection refused, DNS, timeout) and
    /// server-side/rate-limit HTTP statuses (408, 429, 5xx) are transient and
    /// retried. Client errors like 404/401/403 are not — retrying them just
    /// burns time waiting for a response that will never change.
    fn is_retryable(&self) -> bool {
        match self {
            DownloadError::Network(_) => true,
            DownloadError::Io(_) => true,
            DownloadError::HttpStatus { status, .. } => {
                matches!(*status, 408 | 429 | 500..=599)
            }
            DownloadError::MissingChecksum { .. }
            | DownloadError::ChecksumMismatch { .. }
            | DownloadError::SignatureVerificationFailed { .. }
            | DownloadError::MaxRetriesExceeded { .. } => false,
        }
    }
}

impl From<reqwest::Error> for DownloadError {
    fn from(value: reqwest::Error) -> Self {
        Self::Network(value.to_string())
    }
}

impl From<std::io::Error> for DownloadError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[derive(Debug)]
pub struct Downloader {
    client: Client,
    inflight: Arc<OnceMap<DownloadKey, PathBuf>>,
}

impl Default for Downloader {
    fn default() -> Self {
        Self::new()
    }
}

impl Downloader {
    pub fn new() -> Self {
        Self {
            // Enhanced HTTP client with connection pooling and keepalive
            // for improved cold start performance
            client: Client::builder()
                .timeout(Duration::from_secs(300))
                // Connection pooling: reuse connections for multiple requests
                .pool_max_idle_per_host(10)
                .pool_idle_timeout(Duration::from_secs(90))
                // TCP keepalive to prevent connection drops
                .tcp_keepalive(Duration::from_secs(30))
                // Connection timeout for faster failure detection
                .connect_timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new()),
            inflight: Arc::new(OnceMap::new()),
        }
    }

    /// Download a single file with retries, checksum, and optional signature verification.
    ///
    /// The `checksum` argument expects a SHA-256 hash string (hex).
    /// If verification fails, the file is deleted.
    pub async fn download_file(
        &self,
        url: &str,
        destination: &Path,
        checksum: Option<&str>,
    ) -> Result<PathBuf, DownloadError> {
        self.download_file_with_signature(url, destination, checksum, None)
            .await
    }

    /// Download a file and verify its checksum and signature.
    pub async fn download_file_with_signature(
        &self,
        url: &str,
        destination: &Path,
        checksum: Option<&str>,
        signature: Option<&SignatureSpec>,
    ) -> Result<PathBuf, DownloadError> {
        if let Some(expected) = checksum
            && crate::security::is_placeholder_hash(expected)
        {
            let _ = tokio::fs::remove_file(destination).await;
            return Err(DownloadError::MissingChecksum {
                path: destination.to_path_buf(),
                checksum: expected.to_string(),
            });
        }

        let max_retries = 3;
        let mut attempt = 0;

        loop {
            // Optimization: check if file exists and matches checksum
            if destination.exists() {
                if let Some(expected) = checksum {
                    match self.verify_checksum(destination, expected).await {
                        Ok(_) => {
                            // Hash matches, skip download
                            if let Some(sig) = signature {
                                self.verify_signature(destination, sig).await?;
                            }
                            return Ok(destination.to_path_buf());
                        }
                        Err(_) => {
                            // Hash mismatch, remove and re-download
                            let _ = tokio::fs::remove_file(destination).await;
                        }
                    }
                } else {
                    // No checksum provided, default to overwrite for safety unless configured otherwise?
                    // For now, let's just overwrite to be safe.
                    // Or we could trust it if we want maximum speed.
                    // But Standard behavior is usually overwrite if no hash.
                }
            }

            match self.download_attempt(url, destination).await {
                Ok(_) => {
                    if let Some(expected) = checksum {
                        self.verify_checksum(destination, expected).await?;
                    }
                    if let Some(sig) = signature {
                        self.verify_signature(destination, sig).await?;
                    }
                    return Ok(destination.to_path_buf());
                }
                Err(e) => {
                    // Fail fast on non-retryable errors (e.g. 404/401/403):
                    // retrying them just burns time waiting for a response
                    // that can never change.
                    if !e.is_retryable() {
                        return Err(e);
                    }

                    attempt += 1;
                    if attempt >= max_retries {
                        return Err(DownloadError::MaxRetriesExceeded {
                            url: url.to_string(),
                            attempts: attempt,
                            source: Box::new(e),
                        });
                    }
                    // Respect Retry-After on 429/503 when the server sends one,
                    // capped to avoid a malicious/misconfigured server stalling
                    // the download indefinitely; otherwise fall back to
                    // exponential backoff: 1s, 2s, 4s.
                    let backoff = match &e {
                        DownloadError::HttpStatus {
                            retry_after: Some(secs),
                            ..
                        } => Duration::from_secs((*secs).min(MAX_RETRY_AFTER_SECS)),
                        _ => Duration::from_secs(1 << (attempt - 1)),
                    };
                    eprintln!("retrying download {} (attempt {}): {}", url, attempt + 1, e);
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    async fn download_attempt(&self, url: &str, destination: &Path) -> Result<(), DownloadError> {
        let response = self.client.get(url).send().await?;

        if let Err(status_err) = response.error_for_status_ref() {
            let status = response.status();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            return Err(DownloadError::HttpStatus {
                status: status.as_u16(),
                url: url.to_string(),
                message: status_err.to_string(),
                retry_after,
            });
        }

        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).await?;
        }

        let file = File::create(destination).await?;
        let mut writer = BufWriter::new(file);
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            writer.write_all(&chunk).await?;
        }

        writer.flush().await?;
        Ok(())
    }

    async fn verify_checksum(&self, path: &Path, expected: &str) -> Result<(), DownloadError> {
        if crate::security::is_placeholder_hash(expected) {
            let _ = fs::remove_file(path).await;
            return Err(DownloadError::MissingChecksum {
                path: path.to_path_buf(),
                checksum: expected.to_string(),
            });
        }
        // Handle "sha256:" prefix
        let expected_clean = expected.strip_prefix("sha256:").unwrap_or(expected);

        let mut file = File::open(path).await?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];

        use tokio::io::AsyncReadExt;
        loop {
            let n = file.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        let result = hasher.finalize();
        let actual = hex::encode(result);

        if actual != expected_clean {
            let _ = fs::remove_file(path).await;
            return Err(DownloadError::ChecksumMismatch {
                expected: expected_clean.to_string(),
                actual,
                path: path.to_path_buf(),
            });
        }

        Ok(())
    }

    async fn verify_signature(
        &self,
        path: &Path,
        signature: &SignatureSpec,
    ) -> Result<(), DownloadError> {
        let bytes = fs::read(path).await?;
        match verify_ed25519_signature(&signature.public_key, &signature.signature, &bytes) {
            Ok(_) => Ok(()),
            Err(source) => {
                let _ = fs::remove_file(path).await;
                Err(DownloadError::SignatureVerificationFailed {
                    path: path.to_path_buf(),
                    message: source.to_string(),
                })
            }
        }
    }

    /// Download multiple files in parallel.
    ///
    /// items: Vec<(url, destination, checksum, signature)>
    /// concurrency: Maximum number of concurrent downloads
    pub async fn download_parallel(
        &self,
        items: Vec<DownloadRequest>,
        concurrency: usize,
    ) -> Vec<Result<PathBuf, DownloadError>> {
        let stream = futures::stream::iter(items.into_iter().map(|req| {
            let client = self;
            async move {
                let key = DownloadKey {
                    url: req.url.clone(),
                    destination: req.destination.clone(),
                };
                client
                    .inflight
                    .get_or_try_init(key, || async move {
                        client
                            .download_file_with_signature(
                                &req.url,
                                &req.destination,
                                req.checksum.as_deref(),
                                req.signature.as_ref(),
                            )
                            .await
                    })
                    .await
            }
        }));

        stream.buffer_unordered(concurrency).collect().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use std::time::Instant;
    use tempfile::tempdir;

    /// A 404 (package/version genuinely missing) must fail immediately,
    /// without burning the 1s/2s exponential backoff (Issue #343, defect 1).
    #[tokio::test]
    async fn not_found_fails_fast_without_backoff() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/missing.whl");
            then.status(404).body("not found");
        });

        let dir = tempdir().unwrap();
        let dest = dir.path().join("missing.whl");
        let downloader = Downloader::new();

        let start = Instant::now();
        let result = downloader
            .download_file(&server.url("/missing.whl"), &dest, None)
            .await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "expected 404 to fail");
        assert!(
            elapsed < Duration::from_millis(500),
            "expected fail-fast (<500ms), took {elapsed:?}"
        );
        // Only a single attempt should have been made — no retries for 404.
        mock.assert_calls(1);
    }

    /// A 401/403 (private index without auth) is also a client error and
    /// must not be retried.
    #[tokio::test]
    async fn unauthorized_fails_fast_without_retry() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/private.whl");
            then.status(401).body("unauthorized");
        });

        let dir = tempdir().unwrap();
        let dest = dir.path().join("private.whl");
        let downloader = Downloader::new();

        let result = downloader
            .download_file(&server.url("/private.whl"), &dest, None)
            .await;

        assert!(result.is_err());
        mock.assert_calls(1);
    }

    /// A 500 is a transient server error and should be retried up to the
    /// configured max_retries (3 attempts total).
    #[tokio::test]
    async fn server_error_is_retried() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/flaky.whl");
            then.status(500).body("internal error");
        });

        let dir = tempdir().unwrap();
        let dest = dir.path().join("flaky.whl");
        let downloader = Downloader::new();

        let result = downloader
            .download_file(&server.url("/flaky.whl"), &dest, None)
            .await;

        assert!(result.is_err());
        mock.assert_calls(3);
    }

    /// A 429 (rate limited) should also be retried like a 5xx.
    #[tokio::test]
    async fn rate_limited_is_retried() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/ratelimited.whl");
            then.status(429).body("slow down");
        });

        let dir = tempdir().unwrap();
        let dest = dir.path().join("ratelimited.whl");
        let downloader = Downloader::new();

        let result = downloader
            .download_file(&server.url("/ratelimited.whl"), &dest, None)
            .await;

        assert!(result.is_err());
        mock.assert_calls(3);
    }

    /// The terminal MaxRetriesExceeded error must carry the underlying
    /// cause in its Display output, not just "max retries exceeded for
    /// {url}" (Issue #343, defect 2).
    #[tokio::test]
    async fn max_retries_exceeded_includes_underlying_cause() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/flaky.whl");
            then.status(503).body("service unavailable");
        });

        let dir = tempdir().unwrap();
        let dest = dir.path().join("flaky.whl");
        let downloader = Downloader::new();

        let result = downloader
            .download_file(&server.url("/flaky.whl"), &dest, None)
            .await;
        mock.assert_calls(3);

        match result {
            Err(err @ DownloadError::MaxRetriesExceeded { .. }) => {
                let message = err.to_string();
                assert!(
                    message.contains("503"),
                    "expected underlying HTTP status in message, got: {message}"
                );
                // Ensure the error chain (source()) also carries the cause,
                // not just the Display string.
                use std::error::Error as _;
                assert!(err.source().is_some(), "expected a wrapped source error");
            }
            other => panic!("expected MaxRetriesExceeded, got {other:?}"),
        }
    }

    /// A server-supplied `Retry-After` must be capped so a malicious or
    /// misconfigured index cannot stall a download indefinitely.
    #[tokio::test]
    async fn retry_after_is_capped() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/slow.whl");
            then.status(429)
                .header("Retry-After", "999999999")
                .body("slow down");
        });

        let dir = tempdir().unwrap();
        let dest = dir.path().join("slow.whl");
        let downloader = Downloader::new();

        let start = Instant::now();
        let result = downloader
            .download_file(&server.url("/slow.whl"), &dest, None)
            .await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        mock.assert_calls(3);
        assert!(
            elapsed < Duration::from_secs(MAX_RETRY_AFTER_SECS * 2 + 5),
            "Retry-After should be capped at {MAX_RETRY_AFTER_SECS}s per attempt, took {elapsed:?}"
        );
    }

    /// A successful download should not be affected by the new classification
    /// logic.
    #[tokio::test]
    async fn successful_download_still_works() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/ok.whl");
            then.status(200).body("wheel-bytes");
        });

        let dir = tempdir().unwrap();
        let dest = dir.path().join("ok.whl");
        let downloader = Downloader::new();

        let result = downloader
            .download_file(&server.url("/ok.whl"), &dest, None)
            .await;

        assert!(result.is_ok());
        mock.assert_calls(1);
        assert_eq!(
            tokio::fs::read_to_string(&dest).await.unwrap(),
            "wheel-bytes"
        );
    }
}
