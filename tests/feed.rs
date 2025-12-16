mod common;
use common::{base_url, client, create_account_and_login};
use serde_json::json;

#[tokio::test]
async fn test_get_timeline_requires_auth() {
    let client = client();
    let base = base_url().await;
    let res = client
        .get(format!("{}/xrpc/app.bsky.feed.getTimeline", base))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn test_get_author_feed_requires_actor() {
    let client = client();
    let base = base_url().await;
    let (jwt, _did) = create_account_and_login(&client).await;
    let res = client
        .get(format!("{}/xrpc/app.bsky.feed.getAuthorFeed", base))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn test_get_actor_likes_requires_actor() {
    let client = client();
    let base = base_url().await;
    let (jwt, _did) = create_account_and_login(&client).await;
    let res = client
        .get(format!("{}/xrpc/app.bsky.feed.getActorLikes", base))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn test_get_post_thread_requires_uri() {
    let client = client();
    let base = base_url().await;
    let (jwt, _did) = create_account_and_login(&client).await;
    let res = client
        .get(format!("{}/xrpc/app.bsky.feed.getPostThread", base))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn test_get_feed_requires_auth() {
    let client = client();
    let base = base_url().await;
    let res = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getFeed?feed=at://did:plc:test/app.bsky.feed.generator/test",
            base
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn test_get_feed_requires_feed_param() {
    let client = client();
    let base = base_url().await;
    let (jwt, _did) = create_account_and_login(&client).await;
    let res = client
        .get(format!("{}/xrpc/app.bsky.feed.getFeed", base))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn test_register_push_requires_auth() {
    let client = client();
    let base = base_url().await;
    let res = client
        .post(format!("{}/xrpc/app.bsky.notification.registerPush", base))
        .json(&json!({
            "serviceDid": "did:web:example.com",
            "token": "test-token",
            "platform": "ios",
            "appId": "xyz.bsky.app"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}
