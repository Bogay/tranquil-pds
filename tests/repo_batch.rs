mod common;
use chrono::Utc;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_apply_writes_create() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Batch created post 1",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Batch created post 2",
                    "createdAt": now
                }
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["commit"]["cid"].is_string());
    assert!(body["results"].is_array());
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0]["uri"].is_string());
    assert!(results[0]["cid"].is_string());
}

#[tokio::test]
async fn test_apply_writes_update() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("batch_update_{}", Utc::now().timestamp_millis());
    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Original post",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create");
    assert_eq!(res.status(), StatusCode::OK);
    let update_payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Updated post via applyWrites",
                    "createdAt": now
                }
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&update_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0]["uri"].is_string());
}

#[tokio::test]
async fn test_apply_writes_delete() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("batch_delete_{}", Utc::now().timestamp_millis());
    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Post to delete",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create");
    assert_eq!(res.status(), StatusCode::OK);
    let delete_payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": rkey
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to verify");
    assert_eq!(get_res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_apply_writes_mixed_operations() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey_to_delete = format!("mixed_del_{}", Utc::now().timestamp_millis());
    let rkey_to_update = format!("mixed_upd_{}", Utc::now().timestamp_millis());
    let setup_payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_to_delete,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "To be deleted",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_to_update,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "To be updated",
                    "createdAt": now
                }
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&setup_payload)
        .send()
        .await
        .expect("Failed to setup");
    assert_eq!(res.status(), StatusCode::OK);
    let mixed_payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "New post",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_to_update,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Updated text",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_to_delete
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&mixed_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
}

#[tokio::test]
async fn test_apply_writes_no_auth() {
    let client = client();
    let payload = json!({
        "repo": "did:plc:test",
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Test",
                    "createdAt": "2025-01-01T00:00:00Z"
                }
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_apply_writes_empty_writes() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let payload = json!({
        "repo": did,
        "writes": []
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
