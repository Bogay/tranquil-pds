mod common;
use common::*;

use chrono::Utc;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_get_record_not_found() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;

    let params = [
        ("repo", did.as_str()),
        ("collection", "app.bsky.feed.post"),
        ("rkey", "nonexistent"),
    ];

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_put_record_no_auth() {
    let client = client();
    let payload = json!({
        "repo": "did:plc:123",
        "collection": "app.bsky.feed.post",
        "rkey": "fake",
        "record": {}
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn test_put_record_success() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": "e2e_test_post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Hello from the e2e test script!",
            "createdAt": now
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body.get("uri").is_some());
    assert!(body.get("cid").is_some());
}

#[tokio::test]
async fn test_get_record_missing_params() {
    let client = client();
    let params = [("repo", "did:plc:12345")];

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 for missing params"
    );
}

#[tokio::test]
async fn test_put_record_mismatched_repo() {
    let client = client();
    let (token, _) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let payload = json!({
        "repo": "did:plc:OTHER-USER",
        "collection": "app.bsky.feed.post",
        "rkey": "e2e_test_post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Hello from the e2e test script!",
            "createdAt": now
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert!(
        res.status() == StatusCode::FORBIDDEN || res.status() == StatusCode::UNAUTHORIZED,
        "Expected 403 or 401 for mismatched repo and auth, got {}",
        res.status()
    );
}

#[tokio::test]
async fn test_put_record_invalid_schema() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": "e2e_test_invalid",
        "record": {
            "$type": "app.bsky.feed.post",
            "createdAt": now
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 for invalid record schema"
    );
}

#[tokio::test]
async fn test_list_records() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;
    let params = [
        ("repo", did.as_str()),
        ("collection", "app.bsky.feed.post"),
        ("limit", "10"),
    ];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_describe_repo() {
    let client = client();
    let (_, did) = create_account_and_login(&client).await;
    let params = [("repo", did.as_str())];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.describeRepo",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_create_record_success_with_generated_rkey() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Hello, world!",
            "createdAt": "2025-12-02T12:00:00Z"
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .json(&payload)
        .bearer_auth(token)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let uri = body["uri"].as_str().unwrap();
    assert!(uri.starts_with(&format!("at://{}/app.bsky.feed.post/", did)));
    assert!(body.get("cid").is_some());
}

#[tokio::test]
async fn test_create_record_success_with_provided_rkey() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let rkey = format!("custom-rkey-{}", Utc::now().timestamp_millis());
    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Hello, world!",
            "createdAt": "2025-12-02T12:00:00Z"
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .json(&payload)
        .bearer_auth(token)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(
        body["uri"],
        format!("at://{}/app.bsky.feed.post/{}", did, rkey)
    );
    assert!(body.get("cid").is_some());
}

#[tokio::test]
async fn test_delete_record() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let rkey = format!("post_to_delete_{}", Utc::now().timestamp_millis());

    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "This post will be deleted",
            "createdAt": Utc::now().to_rfc3339()
        }
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create record");
    assert_eq!(create_res.status(), StatusCode::OK);

    let delete_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(delete_res.status(), StatusCode::OK);

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
        .expect("Failed to verify deletion");
    assert_eq!(get_res.status(), StatusCode::NOT_FOUND);
}
