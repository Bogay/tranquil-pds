mod common;
mod helpers;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use reqwest::header;
use serde_json::{Value, json};

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

#[tokio::test]
async fn test_sync_record_lifecycle() {
    let client = client();
    let (did, jwt) = setup_new_user("sync-record-lifecycle").await;
    let (post_uri, _post_cid) =
        create_post(&client, &did, &jwt, "Post for sync record test").await;
    let post_rkey = post_uri.split('/').last().unwrap();
    let sync_record_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRecord",
            base_url().await
        ))
        .query(&[
            ("did", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", post_rkey),
        ])
        .send()
        .await
        .expect("Failed to get sync record");
    assert_eq!(sync_record_res.status(), StatusCode::OK);
    assert_eq!(
        sync_record_res
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok()),
        Some("application/vnd.ipld.car")
    );
    let car_bytes = sync_record_res.bytes().await.unwrap();
    assert!(!car_bytes.is_empty(), "CAR data should not be empty");
    let latest_before = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get latest commit");
    let latest_before_body: Value = latest_before.json().await.unwrap();
    let rev_before = latest_before_body["rev"].as_str().unwrap().to_string();
    let (post2_uri, _) = create_post(&client, &did, &jwt, "Second post for sync test").await;
    let latest_after = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get latest commit after");
    let latest_after_body: Value = latest_after.json().await.unwrap();
    let rev_after = latest_after_body["rev"].as_str().unwrap().to_string();
    assert_ne!(rev_before, rev_after, "Revision should change after new record");
    let delete_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": post_rkey
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to delete record");
    assert_eq!(delete_res.status(), StatusCode::OK);
    let sync_deleted_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRecord",
            base_url().await
        ))
        .query(&[
            ("did", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", post_rkey),
        ])
        .send()
        .await
        .expect("Failed to check deleted record via sync");
    assert_eq!(
        sync_deleted_res.status(),
        StatusCode::NOT_FOUND,
        "Deleted record should return 404 via sync.getRecord"
    );
    let post2_rkey = post2_uri.split('/').last().unwrap();
    let sync_post2_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRecord",
            base_url().await
        ))
        .query(&[
            ("did", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", post2_rkey),
        ])
        .send()
        .await
        .expect("Failed to get second post via sync");
    assert_eq!(
        sync_post2_res.status(),
        StatusCode::OK,
        "Second post should still be accessible"
    );
}

#[tokio::test]
async fn test_sync_repo_export_lifecycle() {
    let client = client();
    let (did, jwt) = setup_new_user("sync-repo-export").await;
    let profile_payload = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Sync Export User"
        }
    });
    let profile_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&profile_payload)
        .send()
        .await
        .expect("Failed to create profile");
    assert_eq!(profile_res.status(), StatusCode::OK);
    for i in 0..3 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        create_post(&client, &did, &jwt, &format!("Export test post {}", i)).await;
    }
    let blob_data = b"blob data for sync export test";
    let upload_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .bearer_auth(&jwt)
        .body(blob_data.to_vec())
        .send()
        .await
        .expect("Failed to upload blob");
    assert_eq!(upload_res.status(), StatusCode::OK);
    let blob_body: Value = upload_res.json().await.unwrap();
    let blob_cid = blob_body["blob"]["ref"]["$link"].as_str().unwrap().to_string();
    let repo_status_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepoStatus",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get repo status");
    assert_eq!(repo_status_res.status(), StatusCode::OK);
    let status_body: Value = repo_status_res.json().await.unwrap();
    assert_eq!(status_body["did"], did);
    assert_eq!(status_body["active"], true);
    let get_repo_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get full repo");
    assert_eq!(get_repo_res.status(), StatusCode::OK);
    assert_eq!(
        get_repo_res
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok()),
        Some("application/vnd.ipld.car")
    );
    let repo_car = get_repo_res.bytes().await.unwrap();
    assert!(repo_car.len() > 100, "Repo CAR should have substantial data");
    let list_blobs_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.listBlobs",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to list blobs");
    assert_eq!(list_blobs_res.status(), StatusCode::OK);
    let blobs_body: Value = list_blobs_res.json().await.unwrap();
    let cids = blobs_body["cids"].as_array().unwrap();
    assert!(!cids.is_empty(), "Should have at least one blob");
    let get_blob_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlob",
            base_url().await
        ))
        .query(&[("did", did.as_str()), ("cid", &blob_cid)])
        .send()
        .await
        .expect("Failed to get blob");
    assert_eq!(get_blob_res.status(), StatusCode::OK);
    let retrieved_blob = get_blob_res.bytes().await.unwrap();
    assert_eq!(
        retrieved_blob.as_ref(),
        blob_data,
        "Retrieved blob should match uploaded data"
    );
    let latest_commit_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get latest commit");
    assert_eq!(latest_commit_res.status(), StatusCode::OK);
    let commit_body: Value = latest_commit_res.json().await.unwrap();
    let root_cid = commit_body["cid"].as_str().unwrap();
    let get_blocks_url = format!(
        "{}/xrpc/com.atproto.sync.getBlocks?did={}&cids={}",
        base_url().await,
        did,
        root_cid
    );
    let get_blocks_res = client
        .get(&get_blocks_url)
        .send()
        .await
        .expect("Failed to get blocks");
    assert_eq!(get_blocks_res.status(), StatusCode::OK);
    assert_eq!(
        get_blocks_res
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok()),
        Some("application/vnd.ipld.car")
    );
}