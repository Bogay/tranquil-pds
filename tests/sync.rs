mod common;
use common::*;
use reqwest::StatusCode;
use reqwest::header;
use serde_json::Value;

#[tokio::test]
async fn test_get_latest_commit_success() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    let params = [("did", did.as_str())];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["cid"].is_string());
    assert!(body["rev"].is_string());
}

#[tokio::test]
async fn test_get_latest_commit_not_found() {
    let client = client();
    let params = [("did", "did:plc:nonexistent12345")];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
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
async fn test_get_latest_commit_missing_param() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_list_repos() {
    let client = client();
    let _ = create_account_and_login(&client).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.listRepos",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["repos"].is_array());
    let repos = body["repos"].as_array().unwrap();
    assert!(!repos.is_empty());

    let repo = &repos[0];
    assert!(repo["did"].is_string());
    assert!(repo["head"].is_string());
    assert!(repo["active"].is_boolean());
}

#[tokio::test]
async fn test_list_repos_with_limit() {
    let client = client();
    let _ = create_account_and_login(&client).await;
    let _ = create_account_and_login(&client).await;
    let _ = create_account_and_login(&client).await;

    let params = [("limit", "2")];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.listRepos",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let repos = body["repos"].as_array().unwrap();
    assert!(repos.len() <= 2);
}

#[tokio::test]
async fn test_list_repos_pagination() {
    let client = client();
    let _ = create_account_and_login(&client).await;
    let _ = create_account_and_login(&client).await;
    let _ = create_account_and_login(&client).await;

    let params = [("limit", "1")];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.listRepos",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let repos = body["repos"].as_array().unwrap();
    assert_eq!(repos.len(), 1);

    if let Some(cursor) = body["cursor"].as_str() {
        let params = [("limit", "1"), ("cursor", cursor)];
        let res = client
            .get(format!(
                "{}/xrpc/com.atproto.sync.listRepos",
                base_url().await
            ))
            .query(&params)
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(res.status(), StatusCode::OK);
        let body: Value = res.json().await.expect("Response was not valid JSON");
        let repos2 = body["repos"].as_array().unwrap();
        assert_eq!(repos2.len(), 1);
        assert_ne!(repos[0]["did"], repos2[0]["did"]);
    }
}

#[tokio::test]
async fn test_get_repo_status_success() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    let params = [("did", did.as_str())];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepoStatus",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["did"], did);
    assert_eq!(body["active"], true);
    assert!(body["rev"].is_string());
}

#[tokio::test]
async fn test_get_repo_status_not_found() {
    let client = client();
    let params = [("did", "did:plc:nonexistent12345")];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepoStatus",
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

#[tokio::test]
async fn test_notify_of_update() {
    let client = client();
    let params = [("hostname", "example.com")];
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.sync.notifyOfUpdate",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_request_crawl() {
    let client = client();
    let payload = serde_json::json!({"hostname": "example.com"});
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.sync.requestCrawl",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}
