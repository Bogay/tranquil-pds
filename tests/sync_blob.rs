mod common;
use common::*;
use reqwest::StatusCode;
use reqwest::header;
use serde_json::Value;

#[tokio::test]
async fn test_list_blobs_success() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;

    let blob_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header(header::CONTENT_TYPE, "text/plain")
        .bearer_auth(&access_jwt)
        .body("test blob content")
        .send()
        .await
        .expect("Failed to upload blob");

    assert_eq!(blob_res.status(), StatusCode::OK);

    let params = [("did", did.as_str())];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.listBlobs",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["cids"].is_array());
    let cids = body["cids"].as_array().unwrap();
    assert!(!cids.is_empty());
}

#[tokio::test]
async fn test_list_blobs_not_found() {
    let client = client();
    let params = [("did", "did:plc:nonexistent12345")];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.listBlobs",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "RepoNotFound");
}

#[tokio::test]
async fn test_get_blob_success() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;

    let blob_content = "test blob for get_blob";
    let blob_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header(header::CONTENT_TYPE, "text/plain")
        .bearer_auth(&access_jwt)
        .body(blob_content)
        .send()
        .await
        .expect("Failed to upload blob");

    assert_eq!(blob_res.status(), StatusCode::OK);
    let blob_body: Value = blob_res.json().await.expect("Response was not valid JSON");
    let cid = blob_body["blob"]["ref"]["$link"].as_str().expect("No CID");

    let params = [("did", did.as_str()), ("cid", cid)];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlob",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok()),
        Some("text/plain")
    );
    let body = res.text().await.expect("Failed to get body");
    assert_eq!(body, blob_content);
}

#[tokio::test]
async fn test_get_blob_not_found() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    let params = [
        ("did", did.as_str()),
        ("cid", "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"),
    ];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlob",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "BlobNotFound");
}
