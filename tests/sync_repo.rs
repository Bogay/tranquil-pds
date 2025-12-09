mod common;
use common::*;
use reqwest::StatusCode;
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

#[tokio::test]
async fn test_get_repo_success() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;

    let post_payload = serde_json::json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Test post for getRepo",
            "createdAt": chrono::Utc::now().to_rfc3339()
        }
    });
    let _ = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&post_payload)
        .send()
        .await
        .expect("Failed to create record");

    let params = [("did", did.as_str())];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo",
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
        Some("application/vnd.ipld.car")
    );
    let body = res.bytes().await.expect("Failed to get body");
    assert!(!body.is_empty());
}

#[tokio::test]
async fn test_get_repo_not_found() {
    let client = client();
    let params = [("did", "did:plc:nonexistent12345")];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo",
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
async fn test_get_record_sync_success() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;

    let post_payload = serde_json::json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Test post for sync getRecord",
            "createdAt": chrono::Utc::now().to_rfc3339()
        }
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&post_payload)
        .send()
        .await
        .expect("Failed to create record");

    let create_body: Value = create_res.json().await.expect("Invalid JSON");
    let uri = create_body["uri"].as_str().expect("No URI");
    let rkey = uri.split('/').last().expect("Invalid URI");

    let params = [
        ("did", did.as_str()),
        ("collection", "app.bsky.feed.post"),
        ("rkey", rkey),
    ];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRecord",
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
        Some("application/vnd.ipld.car")
    );
    let body = res.bytes().await.expect("Failed to get body");
    assert!(!body.is_empty());
}

#[tokio::test]
async fn test_get_record_sync_not_found() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    let params = [
        ("did", did.as_str()),
        ("collection", "app.bsky.feed.post"),
        ("rkey", "nonexistent12345"),
    ];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRecord",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "RecordNotFound");
}

#[tokio::test]
async fn test_get_blocks_success() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    let params = [("did", did.as_str())];
    let latest_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to get latest commit");

    let latest_body: Value = latest_res.json().await.expect("Invalid JSON");
    let root_cid = latest_body["cid"].as_str().expect("No CID");

    let url = format!(
        "{}/xrpc/com.atproto.sync.getBlocks?did={}&cids={}",
        base_url().await,
        did,
        root_cid
    );
    let res = client
        .get(&url)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok()),
        Some("application/vnd.ipld.car")
    );
}

#[tokio::test]
async fn test_get_blocks_not_found() {
    let client = client();
    let url = format!(
        "{}/xrpc/com.atproto.sync.getBlocks?did=did:plc:nonexistent12345&cids=bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
        base_url().await
    );
    let res = client
        .get(&url)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
