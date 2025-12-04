mod common;
use common::*;
use reqwest::StatusCode;

#[tokio::test]
async fn test_get_follows() {
    let client = client();
    let params = [
        ("actor", AUTH_DID),
    ];
    let res = client.get(format!("{}/xrpc/app.bsky.graph.getFollows", base_url().await))
        .query(&params)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_followers() {
    let client = client();
    let params = [
        ("actor", AUTH_DID),
    ];
    let res = client.get(format!("{}/xrpc/app.bsky.graph.getFollowers", base_url().await))
        .query(&params)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_mutes() {
    let client = client();
    let params = [
        ("limit", "25"),
    ];
    let res = client.get(format!("{}/xrpc/app.bsky.graph.getMutes", base_url().await))
        .query(&params)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
// User blocks, ie. not repo blocks ya know
async fn test_get_user_blocks() {
    let client = client();
    let params = [
        ("limit", "25"),
    ];
    let res = client.get(format!("{}/xrpc/app.bsky.graph.getBlocks", base_url().await))
        .query(&params)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}
