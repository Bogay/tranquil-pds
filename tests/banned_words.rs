/*
  * CONTENT WARNING
  *
  * This file contains explicit slurs and hateful language. We're sorry you have to see them.
  *
  * These words exist here for one reason: to ensure our moderation system correctly blocks them.
  * We can't verify the filter catches the n-word without testing against the actual word.
  * Euphemisms wouldn't prove the protection works.
  *
  * If reading this file has caused you distress, please know:
  * - you are valued and welcome in this community
  * - these words do not reflect the views of this project or its contributors
  * - we maintain this code precisely because we believe everyone deserves an experience on the web that is free from this kinda language
*/

mod common;
mod helpers;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::json;

#[tokio::test]
async fn test_handle_with_slur_rejected() {
    let client = client();
    let timestamp = chrono::Utc::now().timestamp_millis();
    let offensive_handle = format!("nigger{}", timestamp);

    let create_payload = json!({
        "handle": offensive_handle,
        "email": format!("test{}@example.com", timestamp),
        "password": "TestPassword123!"
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_payload)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidHandle");
    assert!(body["message"]
        .as_str()
        .unwrap_or("")
        .contains("Inappropriate language"));
}

#[tokio::test]
async fn test_handle_with_normalized_slur_rejected() {
    let client = client();
    let timestamp = chrono::Utc::now().timestamp_millis();
    let offensive_handle = format!("n-i-g-g-e-r{}", timestamp);

    let create_payload = json!({
        "handle": offensive_handle,
        "email": format!("test{}@example.com", timestamp),
        "password": "TestPassword123!"
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_payload)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidHandle");
}

#[tokio::test]
async fn test_handle_update_with_slur_rejected() {
    let client = client();
    let (_, jwt) = setup_new_user("handleupdate").await;

    let update_payload = json!({
        "handle": "faggots"
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.updateHandle",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&update_payload)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidHandle");
}

#[tokio::test]
async fn test_profile_displayname_with_slur_rejected() {
    let client = client();
    let (did, jwt) = setup_new_user("profileslur").await;

    let profile = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "I am a kike"
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&profile)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRecord");
}

#[tokio::test]
async fn test_profile_description_with_slur_rejected() {
    let client = client();
    let (did, jwt) = setup_new_user("profiledesc").await;

    let profile = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Normal Name",
            "description": "I hate all chinks"
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&profile)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRecord");
}

#[tokio::test]
async fn test_clean_content_allowed() {
    let client = client();
    let (did, jwt) = setup_new_user("cleanpost").await;

    let post = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "This is a perfectly normal post about coding and technology!",
            "createdAt": chrono::Utc::now().to_rfc3339()
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&post)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(res.status(), StatusCode::OK);
}
