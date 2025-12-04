mod common;
use common::*;
use reqwest::StatusCode;

use std::collections::HashMap;

#[tokio::test]
async fn test_get_timeline() {
    let client = client();
    let params = [("limit", "30")];
    let res = client.get(format!("{}/xrpc/app.bsky.feed.getTimeline", base_url().await))
        .query(&params)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_author_feed() {
    let client = client();
    let params = [
        ("actor", AUTH_DID),
        ("limit", "30")
    ];
    let res = client.get(format!("{}/xrpc/app.bsky.feed.getAuthorFeed", base_url().await))
        .query(&params)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_post_thread() {
    let client = client();
    let mut params = HashMap::new();
    params.insert("uri", "at://did:plc:other/app.bsky.feed.post/3k12345");
    params.insert("depth", "5");

    let res = client.get(format!("{}/xrpc/app.bsky.feed.getPostThread", base_url().await))
        .query(&params)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}
