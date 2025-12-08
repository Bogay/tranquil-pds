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
