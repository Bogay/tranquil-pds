mod common;
use common::*;
use reqwest::{StatusCode, header};
use serde_json::Value;

#[tokio::test]
async fn test_upload_blob_no_auth() {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header(header::CONTENT_TYPE, "text/plain")
        .body("no auth")
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn test_upload_blob_success() {
    let client = client();
    let (token, _) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header(header::CONTENT_TYPE, "text/plain")
        .bearer_auth(token)
        .body("This is our blob data")
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["blob"]["ref"]["$link"].as_str().is_some());
}

#[tokio::test]
async fn test_upload_blob_bad_token() {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header(header::CONTENT_TYPE, "text/plain")
        .bearer_auth(BAD_AUTH_TOKEN)
        .body("This is our blob data")
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "AuthenticationFailed");
}

#[tokio::test]
async fn test_upload_blob_unsupported_mime_type() {
    let client = client();
    let (token, _) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header(header::CONTENT_TYPE, "application/xml")
        .bearer_auth(token)
        .body("<xml>not an image</xml>")
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_missing_blobs() {
    let client = client();
    let (access_jwt, _) = create_account_and_login(&client).await;
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listMissingBlobs",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["blobs"].is_array());
}

#[tokio::test]
async fn test_list_missing_blobs_no_auth() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listMissingBlobs",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
