mod common;
use common::*;
use reqwest::StatusCode;

#[tokio::test]
async fn test_get_profile() {
    let client = client();
    let params = [
        ("actor", AUTH_DID),
    ];
    let res = client.get(format!("{}/xrpc/app.bsky.actor.getProfile", base_url().await))
        .query(&params)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_search_actors() {
    let client = client();
    let params = [
        ("q", "test"),
        ("limit", "10"),
    ];
    let res = client.get(format!("{}/xrpc/app.bsky.actor.searchActors", base_url().await))
        .query(&params)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}
