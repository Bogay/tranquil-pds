mod common;
mod helpers;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::Value;

#[tokio::test]
async fn test_get_head_success() {
    let client = client();
    let (did, _jwt) = setup_new_user("gethead-success").await;
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getHead",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["root"].is_string());
    let root = body["root"].as_str().unwrap();
    assert!(root.starts_with("bafy"), "Root CID should be a CID");
}

#[tokio::test]
async fn test_get_head_not_found() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getHead",
            base_url().await
        ))
        .query(&[("did", "did:plc:nonexistent12345")])
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "HeadNotFound");
    assert!(body["message"].as_str().unwrap().contains("Could not find root"));
}

#[tokio::test]
async fn test_get_head_missing_param() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getHead",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_head_empty_did() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getHead",
            base_url().await
        ))
        .query(&[("did", "")])
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_get_head_whitespace_did() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getHead",
            base_url().await
        ))
        .query(&[("did", "   ")])
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_head_changes_after_record_create() {
    let client = client();
    let (did, jwt) = setup_new_user("gethead-changes").await;
    let res1 = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getHead",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get initial head");
    let body1: Value = res1.json().await.unwrap();
    let head1 = body1["root"].as_str().unwrap().to_string();
    create_post(&client, &did, &jwt, "Post to change head").await;
    let res2 = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getHead",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get head after record");
    let body2: Value = res2.json().await.unwrap();
    let head2 = body2["root"].as_str().unwrap().to_string();
    assert_ne!(head1, head2, "Head CID should change after record creation");
}

#[tokio::test]
async fn test_get_checkout_success() {
    let client = client();
    let (did, jwt) = setup_new_user("getcheckout-success").await;
    create_post(&client, &did, &jwt, "Post for checkout test").await;
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getCheckout",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
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
    assert!(!body.is_empty(), "CAR file should not be empty");
    assert!(body.len() > 50, "CAR file should contain actual data");
}

#[tokio::test]
async fn test_get_checkout_not_found() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getCheckout",
            base_url().await
        ))
        .query(&[("did", "did:plc:nonexistent12345")])
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "RepoNotFound");
}

#[tokio::test]
async fn test_get_checkout_missing_param() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getCheckout",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_checkout_empty_did() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getCheckout",
            base_url().await
        ))
        .query(&[("did", "")])
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_checkout_empty_repo() {
    let client = client();
    let (did, _jwt) = setup_new_user("getcheckout-empty").await;
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getCheckout",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.bytes().await.expect("Failed to get body");
    assert!(!body.is_empty(), "Even empty repo should return CAR header");
}

#[tokio::test]
async fn test_get_checkout_includes_multiple_records() {
    let client = client();
    let (did, jwt) = setup_new_user("getcheckout-multi").await;
    for i in 0..5 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        create_post(&client, &did, &jwt, &format!("Checkout post {}", i)).await;
    }
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getCheckout",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.bytes().await.expect("Failed to get body");
    assert!(body.len() > 500, "CAR file with 5 records should be larger");
}

#[tokio::test]
async fn test_get_head_matches_latest_commit() {
    let client = client();
    let (did, _jwt) = setup_new_user("gethead-matches-latest").await;
    let head_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getHead",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get head");
    let head_body: Value = head_res.json().await.unwrap();
    let head_root = head_body["root"].as_str().unwrap();
    let latest_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get latest commit");
    let latest_body: Value = latest_res.json().await.unwrap();
    let latest_cid = latest_body["cid"].as_str().unwrap();
    assert_eq!(head_root, latest_cid, "getHead root should match getLatestCommit cid");
}

#[tokio::test]
async fn test_get_checkout_car_header_valid() {
    let client = client();
    let (did, _jwt) = setup_new_user("getcheckout-header").await;
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getCheckout",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.bytes().await.expect("Failed to get body");
    assert!(body.len() >= 2, "CAR file should have at least header length");
}
