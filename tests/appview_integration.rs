mod common;

use common::{base_url, client, create_account_and_login};
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_get_author_feed_returns_appview_data() {
    let client = client();
    let base = base_url().await;
    let (jwt, did) = create_account_and_login(&client).await;
    let res = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getAuthorFeed?actor={}",
            base, did
        ))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(body["feed"].is_array(), "Response should have feed array");
    let feed = body["feed"].as_array().unwrap();
    assert_eq!(feed.len(), 1, "Feed should have 1 post from appview");
    assert_eq!(
        feed[0]["post"]["record"]["text"].as_str(),
        Some("Author feed post from appview"),
        "Post text should match appview response"
    );
}

#[tokio::test]
async fn test_get_actor_likes_returns_appview_data() {
    let client = client();
    let base = base_url().await;
    let (jwt, did) = create_account_and_login(&client).await;
    let res = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getActorLikes?actor={}",
            base, did
        ))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(body["feed"].is_array(), "Response should have feed array");
    let feed = body["feed"].as_array().unwrap();
    assert_eq!(feed.len(), 1, "Feed should have 1 liked post from appview");
    assert_eq!(
        feed[0]["post"]["record"]["text"].as_str(),
        Some("Liked post from appview"),
        "Post text should match appview response"
    );
}

#[tokio::test]
async fn test_get_post_thread_returns_appview_data() {
    let client = client();
    let base = base_url().await;
    let (jwt, did) = create_account_and_login(&client).await;
    let res = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getPostThread?uri=at://{}/app.bsky.feed.post/test123",
            base, did
        ))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(
        body["thread"].is_object(),
        "Response should have thread object"
    );
    assert_eq!(
        body["thread"]["$type"].as_str(),
        Some("app.bsky.feed.defs#threadViewPost"),
        "Thread should be a threadViewPost"
    );
    assert_eq!(
        body["thread"]["post"]["record"]["text"].as_str(),
        Some("Thread post from appview"),
        "Post text should match appview response"
    );
}

#[tokio::test]
async fn test_get_feed_returns_appview_data() {
    let client = client();
    let base = base_url().await;
    let (jwt, _did) = create_account_and_login(&client).await;
    let res = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getFeed?feed=at://did:plc:test/app.bsky.feed.generator/test",
            base
        ))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(body["feed"].is_array(), "Response should have feed array");
    let feed = body["feed"].as_array().unwrap();
    assert_eq!(feed.len(), 1, "Feed should have 1 post from appview");
    assert_eq!(
        feed[0]["post"]["record"]["text"].as_str(),
        Some("Custom feed post from appview"),
        "Post text should match appview response"
    );
}

#[tokio::test]
async fn test_register_push_proxies_to_appview() {
    let client = client();
    let base = base_url().await;
    let (jwt, _did) = create_account_and_login(&client).await;
    let res = client
        .post(format!("{}/xrpc/app.bsky.notification.registerPush", base))
        .header("Authorization", format!("Bearer {}", jwt))
        .json(&json!({
            "serviceDid": "did:web:example.com",
            "token": "test-push-token",
            "platform": "ios",
            "appId": "xyz.bsky.app"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
