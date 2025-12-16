mod common;
use common::{base_url, client, create_account_and_login};
use serde_json::{Value, json};

#[tokio::test]
async fn test_get_preferences_empty() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("preferences").is_some());
    assert!(body["preferences"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_get_preferences_no_auth() {
    let client = client();
    let base = base_url().await;
    let resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_put_preferences_success() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let prefs = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#adultContentPref",
                "enabled": true
            },
            {
                "$type": "app.bsky.actor.defs#contentLabelPref",
                "label": "nsfw",
                "visibility": "warn"
            }
        ]
    });
    let resp = client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let prefs_arr = body["preferences"].as_array().unwrap();
    assert_eq!(prefs_arr.len(), 2);
    let adult_pref = prefs_arr.iter().find(|p| {
        p.get("$type").and_then(|t| t.as_str()) == Some("app.bsky.actor.defs#adultContentPref")
    });
    assert!(adult_pref.is_some());
    assert_eq!(adult_pref.unwrap()["enabled"], true);
}

#[tokio::test]
async fn test_put_preferences_no_auth() {
    let client = client();
    let base = base_url().await;
    let prefs = json!({
        "preferences": []
    });
    let resp = client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_put_preferences_missing_type() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let prefs = json!({
        "preferences": [
            {
                "enabled": true
            }
        ]
    });
    let resp = client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_put_preferences_invalid_namespace() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let prefs = json!({
        "preferences": [
            {
                "$type": "com.example.somePref",
                "value": "test"
            }
        ]
    });
    let resp = client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_put_preferences_read_only_rejected() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let prefs = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#declaredAgePref",
                "isOverAge18": true
            }
        ]
    });
    let resp = client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_put_preferences_replaces_all() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let prefs1 = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#adultContentPref",
                "enabled": true
            },
            {
                "$type": "app.bsky.actor.defs#contentLabelPref",
                "label": "nsfw",
                "visibility": "warn"
            }
        ]
    });
    client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs1)
        .send()
        .await
        .unwrap();
    let prefs2 = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#threadViewPref",
                "sort": "newest"
            }
        ]
    });
    client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs2)
        .send()
        .await
        .unwrap();
    let resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let prefs_arr = body["preferences"].as_array().unwrap();
    assert_eq!(prefs_arr.len(), 1);
    assert_eq!(prefs_arr[0]["$type"], "app.bsky.actor.defs#threadViewPref");
}

#[tokio::test]
async fn test_put_preferences_saved_feeds() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let prefs = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#savedFeedsPrefV2",
                "items": [
                    {
                        "type": "feed",
                        "value": "at://did:plc:example/app.bsky.feed.generator/my-feed",
                        "pinned": true
                    }
                ]
            }
        ]
    });
    let resp = client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let prefs_arr = body["preferences"].as_array().unwrap();
    assert_eq!(prefs_arr.len(), 1);
    let saved_feeds = &prefs_arr[0];
    assert_eq!(saved_feeds["$type"], "app.bsky.actor.defs#savedFeedsPrefV2");
    assert!(saved_feeds["items"].as_array().unwrap().len() == 1);
}

#[tokio::test]
async fn test_put_preferences_muted_words() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let prefs = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#mutedWordsPref",
                "items": [
                    {
                        "value": "spoiler",
                        "targets": ["content", "tag"],
                        "actorTarget": "all"
                    }
                ]
            }
        ]
    });
    let resp = client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let prefs_arr = body["preferences"].as_array().unwrap();
    assert_eq!(prefs_arr[0]["$type"], "app.bsky.actor.defs#mutedWordsPref");
}

#[tokio::test]
async fn test_preferences_isolation_between_users() {
    let client = client();
    let base = base_url().await;
    let (token1, _did1) = create_account_and_login(&client).await;
    let (token2, _did2) = create_account_and_login(&client).await;
    let prefs1 = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#adultContentPref",
                "enabled": true
            }
        ]
    });
    client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .header("Authorization", format!("Bearer {}", token1))
        .json(&prefs1)
        .send()
        .await
        .unwrap();
    let resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .header("Authorization", format!("Bearer {}", token2))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["preferences"].as_array().unwrap().is_empty());
}
