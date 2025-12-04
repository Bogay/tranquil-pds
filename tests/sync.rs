mod common;
use common::*;
use reqwest::StatusCode;

#[tokio::test]
async fn test_get_repo() {
    let client = client();
    let params = [
        ("did", AUTH_DID),
    ];
    let res = client.get(format!("{}/xrpc/com.atproto.sync.getRepo", base_url().await))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_blocks() {
    let client = client();
    let params = [
        ("did", AUTH_DID),
        // "cids" would be a list of CIDs
    ];
    let res = client.get(format!("{}/xrpc/com.atproto.sync.getBlocks", base_url().await))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}
