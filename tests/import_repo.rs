mod common;
use common::*;

use reqwest::StatusCode;
use serde_json::json;

#[tokio::test]
async fn test_import_repo_requires_auth() {
    let client = client();

    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.importRepo", base_url().await))
        .header("Content-Type", "application/vnd.ipld.car")
        .body(vec![0u8; 100])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_import_repo_invalid_car() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;

    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.importRepo", base_url().await))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(vec![0u8; 100])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_import_repo_empty_body() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;

    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.importRepo", base_url().await))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(vec![])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_import_repo_with_exported_repo() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let post_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Test post for import",
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }
    });

    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&post_payload)
        .send()
        .await
        .expect("Failed to create post");
    assert_eq!(create_res.status(), StatusCode::OK);

    let export_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo?did={}",
            base_url().await,
            did
        ))
        .send()
        .await
        .expect("Failed to export repo");
    assert_eq!(export_res.status(), StatusCode::OK);

    let car_bytes = export_res.bytes().await.expect("Failed to get CAR bytes");

    let import_res = client
        .post(format!("{}/xrpc/com.atproto.repo.importRepo", base_url().await))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes.to_vec())
        .send()
        .await
        .expect("Failed to import repo");

    assert_eq!(import_res.status(), StatusCode::OK);
}

