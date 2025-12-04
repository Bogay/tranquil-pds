mod common;
use common::*;
use reqwest::StatusCode;

#[tokio::test]
async fn test_resolve_handle() {
    let client = client();
    let params = [
        ("handle", "bsky.app"),
    ];
    let res = client.get(format!("{}/xrpc/com.atproto.identity.resolveHandle", base_url().await))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}
