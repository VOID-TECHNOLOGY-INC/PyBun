use httpmock::prelude::*;
use pybun::downloader::{DownloadRequest, Downloader};
use tempfile::tempdir;
use tokio::fs;

#[tokio::test]
async fn simple_download_test() {
    let server = MockServer::start();
    let body = b"hello from mock server";
    let mock = server.mock(|when, then| {
        when.method(GET).path("/robots.txt");
        then.status(200).body(body.as_slice());
    });

    let temp = tempdir().unwrap();
    let dest = temp.path().join("robots.txt");

    let downloader = Downloader::new();
    let result = downloader
        .download_file(&server.url("/robots.txt"), &dest, None)
        .await;

    let path = result.expect("download should succeed against the mock server");
    assert!(path.exists());
    let contents = fs::read(&path).await.unwrap();
    assert_eq!(contents, body);
    mock.assert_calls(1);
}

#[tokio::test]
async fn parallel_download_test() {
    let server = MockServer::start();
    let body1 = b"file one contents";
    let body2 = b"file two contents";
    let mock1 = server.mock(|when, then| {
        when.method(GET).path("/file1.txt");
        then.status(200).body(body1.as_slice());
    });
    let mock2 = server.mock(|when, then| {
        when.method(GET).path("/file2.txt");
        then.status(200).body(body2.as_slice());
    });

    let temp = tempdir().unwrap();
    let downloader = Downloader::new();

    let dest1 = temp.path().join("file1.txt");
    let dest2 = temp.path().join("file2.txt");

    let items: Vec<DownloadRequest> = vec![
        (server.url("/file1.txt"), dest1.clone(), None).into(),
        (server.url("/file2.txt"), dest2.clone(), None).into(),
    ];

    let results = downloader.download_parallel(items, 2).await;

    assert_eq!(results.len(), 2);
    assert!(
        results.iter().all(|r| r.is_ok()),
        "expected both downloads to succeed against the mock server: {results:?}"
    );

    assert_eq!(fs::read(&dest1).await.unwrap(), body1);
    assert_eq!(fs::read(&dest2).await.unwrap(), body2);
    mock1.assert_calls(1);
    mock2.assert_calls(1);
}
