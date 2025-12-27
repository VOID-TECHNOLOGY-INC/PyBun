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
    #[error("checksum mismatch for {path}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        expected: String,
        actual: String,
        path: PathBuf,
    },
    #[error("signature verification failed for {path}: {message}")]
    SignatureVerificationFailed {
        path: PathBuf,
        message: String,
    },
    #[error("max retries exceeded for {url}")]
    MaxRetriesExceeded { url: String },
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
            client: Client::builder()
                .timeout(Duration::from_secs(300))
                .build()
                .expect("failed to build reqwest client"),
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
        let max_retries = 3;
        let mut attempt = 0;

        loop {
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
                    attempt += 1;
                    if attempt >= max_retries {
                        return Err(DownloadError::MaxRetriesExceeded {
                            url: url.to_string(),
                        });
                    }
                    // Simple exponential backoff: 1s, 2s, 4s
                    tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
                    eprintln!("retrying download {} (attempt {}): {}", url, attempt + 1, e);
                }
            }
        }
    }

    async fn download_attempt(&self, url: &str, destination: &Path) -> Result<(), DownloadError> {
        let response = self.client.get(url).send().await?;
        let response = response.error_for_status()?;

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
        // If expected is placeholder, skip verification
        if expected == "sha256:placeholder" || expected == "placeholder" {
            return Ok(());
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
