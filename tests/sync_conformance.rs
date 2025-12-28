mod common;
mod helpers;

use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::Value;

#[tokio::test]
async fn test_get_repo_takendown_returns_error() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    set_account_takedown(&did, Some("test-takedown-ref")).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "RepoTakendown");
}

#[tokio::test]
async fn test_get_repo_deactivated_returns_error() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    set_account_deactivated(&did, true).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "RepoDeactivated");
}

#[tokio::test]
async fn test_get_latest_commit_takendown_returns_error() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    set_account_takedown(&did, Some("test-takedown-ref")).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "RepoTakendown");
}

#[tokio::test]
async fn test_get_blocks_takendown_returns_error() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    let commit_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get commit");
    let commit_body: Value = commit_res.json().await.unwrap();
    let cid = commit_body["cid"].as_str().unwrap();

    set_account_takedown(&did, Some("test-takedown-ref")).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlocks",
            base_url().await
        ))
        .query(&[("did", did.as_str()), ("cids", cid)])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "RepoTakendown");
}

#[tokio::test]
async fn test_get_repo_status_shows_takendown_status() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    set_account_takedown(&did, Some("test-takedown-ref")).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepoStatus",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["active"], false);
    assert_eq!(body["status"], "takendown");
    assert!(body.get("rev").is_none() || body["rev"].is_null());
}

#[tokio::test]
async fn test_get_repo_status_shows_deactivated_status() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    set_account_deactivated(&did, true).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepoStatus",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["active"], false);
    assert_eq!(body["status"], "deactivated");
}

#[tokio::test]
async fn test_list_repos_shows_status_field() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    set_account_takedown(&did, Some("test-takedown-ref")).await;

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
    let repos = body["repos"].as_array().unwrap();

    let takendown_repo = repos.iter().find(|r| r["did"] == did);
    assert!(takendown_repo.is_some(), "Takendown repo should be in list");
    let repo = takendown_repo.unwrap();
    assert_eq!(repo["active"], false);
    assert_eq!(repo["status"], "takendown");
}

#[tokio::test]
async fn test_get_blob_takendown_returns_error() {
    let client = client();
    let (jwt, did) = create_account_and_login(&client).await;

    let blob_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header("Content-Type", "image/png")
        .bearer_auth(&jwt)
        .body(vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        .send()
        .await
        .expect("Failed to upload blob");
    let blob_body: Value = blob_res.json().await.unwrap();
    let cid = blob_body["blob"]["ref"]["$link"].as_str().unwrap();

    set_account_takedown(&did, Some("test-takedown-ref")).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlob",
            base_url().await
        ))
        .query(&[("did", did.as_str()), ("cid", cid)])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "RepoTakendown");
}

#[tokio::test]
async fn test_get_blob_has_security_headers() {
    let client = client();
    let (jwt, did) = create_account_and_login(&client).await;

    let blob_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header("Content-Type", "image/png")
        .bearer_auth(&jwt)
        .body(vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        .send()
        .await
        .expect("Failed to upload blob");
    let blob_body: Value = blob_res.json().await.unwrap();
    let cid = blob_body["blob"]["ref"]["$link"].as_str().unwrap();

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlob",
            base_url().await
        ))
        .query(&[("did", did.as_str()), ("cid", cid)])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);

    let headers = res.headers();
    assert_eq!(
        headers
            .get("x-content-type-options")
            .map(|v| v.to_str().unwrap()),
        Some("nosniff"),
        "Missing x-content-type-options: nosniff header"
    );
    assert_eq!(
        headers
            .get("content-security-policy")
            .map(|v| v.to_str().unwrap()),
        Some("default-src 'none'; sandbox"),
        "Missing content-security-policy header"
    );
    assert!(
        headers.get("content-length").is_some(),
        "Missing content-length header"
    );
}

#[tokio::test]
async fn test_get_blocks_missing_cids_returns_error() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    let fake_cid = "bafyreif2pall7dybz7vecqka3zo24irdwabwdi4wc55jznaq75q7eaavvu";

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlocks",
            base_url().await
        ))
        .query(&[("did", did.as_str()), ("cids", fake_cid)])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "InvalidRequest");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("Could not find blocks"),
        "Error message should mention missing blocks"
    );
}

#[tokio::test]
async fn test_get_blocks_accepts_array_format() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    let commit_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get commit");
    let commit_body: Value = commit_res.json().await.unwrap();
    let cid = commit_body["cid"].as_str().unwrap();

    let url = format!(
        "{}/xrpc/com.atproto.sync.getBlocks?did={}&cids={}&cids={}",
        base_url().await,
        did,
        cid,
        cid
    );
    let res = client
        .get(&url)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let content_type = res.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(
        content_type.contains("application/vnd.ipld.car"),
        "Response should be a CAR file"
    );
}

#[tokio::test]
async fn test_get_repo_since_returns_partial() {
    let client = client();
    let (jwt, did) = create_account_and_login(&client).await;

    let initial_commit_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get initial commit");
    let initial_body: Value = initial_commit_res.json().await.unwrap();
    let initial_rev = initial_body["rev"].as_str().unwrap();

    let full_repo_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get full repo");
    assert_eq!(full_repo_res.status(), StatusCode::OK);
    let full_repo_bytes = full_repo_res.bytes().await.unwrap();
    let full_repo_size = full_repo_bytes.len();

    create_post(&client, &did, &jwt, "Test post for since param").await;

    let partial_repo_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo",
            base_url().await
        ))
        .query(&[("did", did.as_str()), ("since", initial_rev)])
        .send()
        .await
        .expect("Failed to get partial repo");
    assert_eq!(partial_repo_res.status(), StatusCode::OK);
    let partial_repo_bytes = partial_repo_res.bytes().await.unwrap();
    let partial_repo_size = partial_repo_bytes.len();

    assert!(
        partial_repo_size < full_repo_size,
        "Partial export (since={}) should be smaller than full export: {} vs {}",
        initial_rev,
        partial_repo_size,
        full_repo_size
    );
}

#[tokio::test]
async fn test_list_blobs_takendown_returns_error() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    set_account_takedown(&did, Some("test-takedown-ref")).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.listBlobs",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "RepoTakendown");
}

#[tokio::test]
async fn test_get_record_takendown_returns_error() {
    let client = client();
    let (jwt, did) = create_account_and_login(&client).await;

    let (uri, _cid) = create_post(&client, &did, &jwt, "Test post").await;
    let parts: Vec<&str> = uri.split('/').collect();
    let collection = parts[parts.len() - 2];
    let rkey = parts[parts.len() - 1];

    set_account_takedown(&did, Some("test-takedown-ref")).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRecord",
            base_url().await
        ))
        .query(&[
            ("did", did.as_str()),
            ("collection", collection),
            ("rkey", rkey),
        ])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "RepoTakendown");
}
