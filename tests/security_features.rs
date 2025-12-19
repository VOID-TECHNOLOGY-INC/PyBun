use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use pybun::downloader::{DownloadError, DownloadRequest, Downloader, SignatureSpec};
use pybun::security::verify_ed25519_signature;
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[test]
fn verify_ed25519_signature_accepts_valid_signature() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let verifier = key.verifying_key();
    let payload = b"pybun secure download";
    let signature = key.sign(payload);

    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(verifier.to_bytes());
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    verify_ed25519_signature(&public_key_b64, &signature_b64, payload)
        .expect("valid signature should verify");
}

#[tokio::test]
async fn download_detects_signature_mismatch_even_when_checksum_matches() {
    // Prepare signing keys and expectations
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let verifier = signing_key.verifying_key();
    let expected_payload = b"expected wheel bytes";
    let signature = signing_key.sign(expected_payload);
    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(verifier.to_bytes());
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    // Serve a tampered payload over a tiny ad-hoc HTTP listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
        let body = b"tampered wheel bytes";
        let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
    });

    let temp = tempdir().unwrap();
    let dest = temp.path().join("artifact.whl");

    // Checksum matches the tampered body so only signature detects mismatch.
    let mut checksum_hasher = Sha256::new();
    checksum_hasher.update(b"tampered wheel bytes");
    let checksum = format!("{:x}", checksum_hasher.finalize());

    let downloader = Downloader::new();
    let request = DownloadRequest {
        url: format!("http://{}", addr),
        destination: dest.clone(),
        checksum: Some(checksum),
        signature: Some(SignatureSpec {
            signature: signature_b64,
            public_key: public_key_b64,
        }),
    };
    let results = downloader.download_parallel(vec![request], 1).await;
    server.await.unwrap();

    let error = results
        .first()
        .expect("one result")
        .as_ref()
        .expect_err("signature mismatch should fail");
    assert!(
        matches!(error, DownloadError::SignatureVerificationFailed { .. }),
        "expected signature verification failure, got {error:?}"
    );
    assert!(
        !dest.exists(),
        "tampered file should be removed after verification failure"
    );
}
