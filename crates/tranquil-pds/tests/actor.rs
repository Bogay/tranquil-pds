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
async fn test_put_preferences_multiple_same_type() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let prefs = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#adultContentPref",
                "enabled": false
            },
            {
                "$type": "app.bsky.actor.defs#contentLabelPref",
                "label": "dogs",
                "visibility": "show"
            },
            {
                "$type": "app.bsky.actor.defs#contentLabelPref",
                "label": "cats",
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
    assert_eq!(prefs_arr.len(), 3);
    let adult_pref = prefs_arr
        .iter()
        .find(|p| p.get("$type").and_then(|t| t.as_str()) == Some("app.bsky.actor.defs#adultContentPref"));
    assert!(adult_pref.is_some());
    assert_eq!(adult_pref.unwrap()["enabled"], false);
    let content_label_prefs: Vec<&Value> = prefs_arr
        .iter()
        .filter(|p| p.get("$type").and_then(|t| t.as_str()) == Some("app.bsky.actor.defs#contentLabelPref"))
        .collect();
    assert_eq!(content_label_prefs.len(), 2);
    let dogs_pref = content_label_prefs
        .iter()
        .find(|p| p.get("label").and_then(|l| l.as_str()) == Some("dogs"));
    assert!(dogs_pref.is_some());
    assert_eq!(dogs_pref.unwrap()["visibility"], "show");
    let cats_pref = content_label_prefs
        .iter()
        .find(|p| p.get("label").and_then(|l| l.as_str()) == Some("cats"));
    assert!(cats_pref.is_some());
    assert_eq!(cats_pref.unwrap()["visibility"], "warn");
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
async fn test_put_preferences_read_only_silently_filtered() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let prefs = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#declaredAgePref",
                "isOverAge18": true
            },
            {
                "$type": "app.bsky.actor.defs#adultContentPref",
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
    assert_eq!(resp.status(), 200);
    let get_resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 200);
    let body: Value = get_resp.json().await.unwrap();
    let prefs_arr = body["preferences"].as_array().unwrap();
    assert_eq!(prefs_arr.len(), 1);
    assert_eq!(
        prefs_arr[0]["$type"],
        "app.bsky.actor.defs#adultContentPref"
    );
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

#[tokio::test]
async fn test_declared_age_pref_computed_from_birth_date() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let prefs = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#personalDetailsPref",
                "birthDate": "1990-01-15"
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
    let get_resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 200);
    let body: Value = get_resp.json().await.unwrap();
    let prefs_arr = body["preferences"].as_array().unwrap();
    assert_eq!(prefs_arr.len(), 2);
    let personal_details = prefs_arr
        .iter()
        .find(|p| p["$type"] == "app.bsky.actor.defs#personalDetailsPref");
    assert!(personal_details.is_some());
    assert_eq!(personal_details.unwrap()["birthDate"], "1990-01-15");
    let declared_age = prefs_arr
        .iter()
        .find(|p| p["$type"] == "app.bsky.actor.defs#declaredAgePref");
    assert!(declared_age.is_some());
    let declared_age = declared_age.unwrap();
    assert_eq!(declared_age["isOverAge13"], true);
    assert_eq!(declared_age["isOverAge16"], true);
    assert_eq!(declared_age["isOverAge18"], true);
}

#[tokio::test]
async fn test_declared_age_pref_computed_under_18() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;
    let current_year = chrono::Utc::now()
        .format("%Y")
        .to_string()
        .parse::<i32>()
        .unwrap();
    let birth_year = current_year - 15;
    let prefs = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#personalDetailsPref",
                "birthDate": format!("{}-06-15", birth_year)
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
    let get_resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 200);
    let body: Value = get_resp.json().await.unwrap();
    let prefs_arr = body["preferences"].as_array().unwrap();
    let declared_age = prefs_arr
        .iter()
        .find(|p| p["$type"] == "app.bsky.actor.defs#declaredAgePref");
    assert!(declared_age.is_some());
    let declared_age = declared_age.unwrap();
    assert_eq!(declared_age["isOverAge13"], true);
    assert_eq!(declared_age["isOverAge16"], false);
    assert_eq!(declared_age["isOverAge18"], false);
}

#[tokio::test]
async fn test_deactivated_account_can_get_preferences() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;

    let prefs = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#adultContentPref",
                "enabled": true
            }
        ]
    });
    let put_resp = client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), 200);

    let deactivate = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deactivateAccount",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(deactivate.status(), 200);

    let get_resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(
        get_resp.status(),
        200,
        "Deactivated account should still be able to get preferences"
    );
    let body: Value = get_resp.json().await.unwrap();
    let prefs_arr = body["preferences"].as_array().unwrap();
    assert_eq!(prefs_arr.len(), 1);
}

#[tokio::test]
async fn test_deactivated_account_can_put_preferences() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;

    let deactivate = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deactivateAccount",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(deactivate.status(), 200);

    let prefs = json!({
        "preferences": [
            {
                "$type": "app.bsky.actor.defs#adultContentPref",
                "enabled": true
            }
        ]
    });
    let put_resp = client
        .post(format!("{}/xrpc/app.bsky.actor.putPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(
        put_resp.status(),
        200,
        "Deactivated account should still be able to put preferences"
    );

    let get_resp = client
        .get(format!("{}/xrpc/app.bsky.actor.getPreferences", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 200);
    let body: Value = get_resp.json().await.unwrap();
    let prefs_arr = body["preferences"].as_array().unwrap();
    assert_eq!(prefs_arr.len(), 1);
}
