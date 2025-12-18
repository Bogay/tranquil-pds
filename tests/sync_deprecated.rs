mod common;
mod helpers;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::Value;

#[tokio::test]
async fn test_get_head_comprehensive() {
    let client = client();
    let (did, jwt) = setup_new_user("gethead").await;
    let res = client
        .get(format!("{}/xrpc/com.atproto.sync.getHead", base_url().await))
        .query(&[("did", did.as_str())])
        .send().await.expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["root"].is_string());
    let root1 = body["root"].as_str().unwrap().to_string();
    assert!(root1.starts_with("bafy"), "Root CID should be a CID");
    let latest_res = client
        .get(format!("{}/xrpc/com.atproto.sync.getLatestCommit", base_url().await))
        .query(&[("did", did.as_str())])
        .send().await.expect("Failed to get latest commit");
    let latest_body: Value = latest_res.json().await.unwrap();
    let latest_cid = latest_body["cid"].as_str().unwrap();
    assert_eq!(root1, latest_cid, "getHead root should match getLatestCommit cid");
    create_post(&client, &did, &jwt, "Post to change head").await;
    let res2 = client
        .get(format!("{}/xrpc/com.atproto.sync.getHead", base_url().await))
        .query(&[("did", did.as_str())])
        .send().await.expect("Failed to get head after record");
    let body2: Value = res2.json().await.unwrap();
    let root2 = body2["root"].as_str().unwrap().to_string();
    assert_ne!(root1, root2, "Head CID should change after record creation");
    let not_found_res = client
        .get(format!("{}/xrpc/com.atproto.sync.getHead", base_url().await))
        .query(&[("did", "did:plc:nonexistent12345")])
        .send().await.expect("Failed to send request");
    assert_eq!(not_found_res.status(), StatusCode::BAD_REQUEST);
    let error_body: Value = not_found_res.json().await.unwrap();
    assert_eq!(error_body["error"], "HeadNotFound");
    let missing_res = client
        .get(format!("{}/xrpc/com.atproto.sync.getHead", base_url().await))
        .send().await.expect("Failed to send request");
    assert_eq!(missing_res.status(), StatusCode::BAD_REQUEST);
    let empty_res = client
        .get(format!("{}/xrpc/com.atproto.sync.getHead", base_url().await))
        .query(&[("did", "")])
        .send().await.expect("Failed to send request");
    assert_eq!(empty_res.status(), StatusCode::BAD_REQUEST);
    let whitespace_res = client
        .get(format!("{}/xrpc/com.atproto.sync.getHead", base_url().await))
        .query(&[("did", "   ")])
        .send().await.expect("Failed to send request");
    assert_eq!(whitespace_res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_checkout_comprehensive() {
    let client = client();
    let (did, jwt) = setup_new_user("getcheckout").await;
    let empty_res = client
        .get(format!("{}/xrpc/com.atproto.sync.getCheckout", base_url().await))
        .query(&[("did", did.as_str())])
        .send().await.expect("Failed to send request");
    assert_eq!(empty_res.status(), StatusCode::OK);
    let empty_body = empty_res.bytes().await.expect("Failed to get body");
    assert!(!empty_body.is_empty(), "Even empty repo should return CAR header");
    create_post(&client, &did, &jwt, "Post for checkout test").await;
    let res = client
        .get(format!("{}/xrpc/com.atproto.sync.getCheckout", base_url().await))
        .query(&[("did", did.as_str())])
        .send().await.expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get("content-type").and_then(|h| h.to_str().ok()), Some("application/vnd.ipld.car"));
    let body = res.bytes().await.expect("Failed to get body");
    assert!(!body.is_empty(), "CAR file should not be empty");
    assert!(body.len() > 50, "CAR file should contain actual data");
    assert!(body.len() >= 2, "CAR file should have at least header length");
    for i in 0..4 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        create_post(&client, &did, &jwt, &format!("Checkout post {}", i)).await;
    }
    let multi_res = client
        .get(format!("{}/xrpc/com.atproto.sync.getCheckout", base_url().await))
        .query(&[("did", did.as_str())])
        .send().await.expect("Failed to send request");
    assert_eq!(multi_res.status(), StatusCode::OK);
    let multi_body = multi_res.bytes().await.expect("Failed to get body");
    assert!(multi_body.len() > 500, "CAR file with 5 records should be larger");
    let not_found_res = client
        .get(format!("{}/xrpc/com.atproto.sync.getCheckout", base_url().await))
        .query(&[("did", "did:plc:nonexistent12345")])
        .send().await.expect("Failed to send request");
    assert_eq!(not_found_res.status(), StatusCode::NOT_FOUND);
    let error_body: Value = not_found_res.json().await.unwrap();
    assert_eq!(error_body["error"], "RepoNotFound");
    let missing_res = client
        .get(format!("{}/xrpc/com.atproto.sync.getCheckout", base_url().await))
        .send().await.expect("Failed to send request");
    assert_eq!(missing_res.status(), StatusCode::BAD_REQUEST);
    let empty_did_res = client
        .get(format!("{}/xrpc/com.atproto.sync.getCheckout", base_url().await))
        .query(&[("did", "")])
        .send().await.expect("Failed to send request");
    assert_eq!(empty_did_res.status(), StatusCode::BAD_REQUEST);
}
