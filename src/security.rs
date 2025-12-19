use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("invalid signature bytes")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
}

/// Verify an ed25519 signature encoded as base64 against raw data.
pub fn verify_ed25519_signature(
    public_key_b64: &str,
    signature_b64: &str,
    data: &[u8],
) -> Result<(), SignatureError> {
    let engine = base64::engine::general_purpose::STANDARD;
    let public_key_bytes = engine
        .decode(public_key_b64)
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    let signature_bytes = engine
        .decode(signature_b64)
        .map_err(|_| SignatureError::InvalidSignature)?;

    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignatureError::InvalidPublicKey)?,
    )
    .map_err(|_| SignatureError::InvalidPublicKey)?;

    let signature_bytes: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SignatureError::InvalidSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify_strict(data, &signature)
        .map_err(|_| SignatureError::VerificationFailed)
}

/// Compute SHA-256 hash for an entire file.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Compute SHA-256 hash for raw bytes.
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Rewind a file handle and compute its SHA-256 hash without closing it.
pub fn sha256_and_rewind(file: &mut File) -> std::io::Result<String> {
    file.rewind()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    file.rewind()?;
    Ok(format!("{:x}", hasher.finalize()))
}
