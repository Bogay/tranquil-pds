mod common;
mod helpers;
use chrono::Utc;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_like_lifecycle() {
    let client = client();
    let (alice_did, alice_jwt) = setup_new_user("alice-like").await;
    let (bob_did, bob_jwt) = setup_new_user("bob-like").await;
    let (post_uri, post_cid) =
        create_post(&client, &alice_did, &alice_jwt, "Like this post!").await;
    let (like_uri, _) = create_like(&client, &bob_did, &bob_jwt, &post_uri, &post_cid).await;
    let like_rkey = like_uri.split('/').last().unwrap();
    let get_like_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", bob_did.as_str()),
            ("collection", "app.bsky.feed.like"),
            ("rkey", like_rkey),
        ])
        .send()
        .await
        .expect("Failed to get like");
    assert_eq!(get_like_res.status(), StatusCode::OK);
    let like_body: Value = get_like_res.json().await.unwrap();
    assert_eq!(like_body["value"]["subject"]["uri"], post_uri);
    let delete_payload = json!({
        "repo": bob_did,
        "collection": "app.bsky.feed.like",
        "rkey": like_rkey
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to delete like");
    assert_eq!(delete_res.status(), StatusCode::OK, "Failed to delete like");
    let get_deleted_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", bob_did.as_str()),
            ("collection", "app.bsky.feed.like"),
            ("rkey", like_rkey),
        ])
        .send()
        .await
        .expect("Failed to check deleted like");
    assert_eq!(
        get_deleted_res.status(),
        StatusCode::NOT_FOUND,
        "Like should be deleted"
    );
}

#[tokio::test]
async fn test_repost_lifecycle() {
    let client = client();
    let (alice_did, alice_jwt) = setup_new_user("alice-repost").await;
    let (bob_did, bob_jwt) = setup_new_user("bob-repost").await;
    let (post_uri, post_cid) = create_post(&client, &alice_did, &alice_jwt, "Repost this!").await;
    let (repost_uri, _) = create_repost(&client, &bob_did, &bob_jwt, &post_uri, &post_cid).await;
    let repost_rkey = repost_uri.split('/').last().unwrap();
    let get_repost_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", bob_did.as_str()),
            ("collection", "app.bsky.feed.repost"),
            ("rkey", repost_rkey),
        ])
        .send()
        .await
        .expect("Failed to get repost");
    assert_eq!(get_repost_res.status(), StatusCode::OK);
    let repost_body: Value = get_repost_res.json().await.unwrap();
    assert_eq!(repost_body["value"]["subject"]["uri"], post_uri);
    let delete_payload = json!({
        "repo": bob_did,
        "collection": "app.bsky.feed.repost",
        "rkey": repost_rkey
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to delete repost");
    assert_eq!(
        delete_res.status(),
        StatusCode::OK,
        "Failed to delete repost"
    );
}

#[tokio::test]
async fn test_unfollow_lifecycle() {
    let client = client();
    let (alice_did, _alice_jwt) = setup_new_user("alice-unfollow").await;
    let (bob_did, bob_jwt) = setup_new_user("bob-unfollow").await;
    let (follow_uri, _) = create_follow(&client, &bob_did, &bob_jwt, &alice_did).await;
    let follow_rkey = follow_uri.split('/').last().unwrap();
    let get_follow_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", bob_did.as_str()),
            ("collection", "app.bsky.graph.follow"),
            ("rkey", follow_rkey),
        ])
        .send()
        .await
        .expect("Failed to get follow");
    assert_eq!(get_follow_res.status(), StatusCode::OK);
    let unfollow_payload = json!({
        "repo": bob_did,
        "collection": "app.bsky.graph.follow",
        "rkey": follow_rkey
    });
    let unfollow_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .json(&unfollow_payload)
        .send()
        .await
        .expect("Failed to unfollow");
    assert_eq!(unfollow_res.status(), StatusCode::OK, "Failed to unfollow");
    let get_deleted_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", bob_did.as_str()),
            ("collection", "app.bsky.graph.follow"),
            ("rkey", follow_rkey),
        ])
        .send()
        .await
        .expect("Failed to check deleted follow");
    assert_eq!(
        get_deleted_res.status(),
        StatusCode::NOT_FOUND,
        "Follow should be deleted"
    );
}

#[tokio::test]
async fn test_account_to_post_full_lifecycle() {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("fullcycle-{}.test", ts);
    let email = format!("fullcycle-{}@test.com", ts);
    let password = "fullcycle-password";
    let create_account_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(create_account_res.status(), StatusCode::OK);
    let account_body: Value = create_account_res.json().await.unwrap();
    let did = account_body["did"].as_str().unwrap().to_string();
    let handle = account_body["handle"].as_str().unwrap().to_string();
    let access_jwt = verify_new_account(&client, &did).await;
    let get_session_res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getSession",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to get session");
    assert_eq!(get_session_res.status(), StatusCode::OK);
    let session_body: Value = get_session_res.json().await.unwrap();
    assert_eq!(session_body["did"], did);
    let normalized_handle = session_body["handle"].as_str().unwrap().to_string();
    assert!(
        normalized_handle.starts_with(&handle),
        "Session handle should start with the requested handle"
    );
    let profile_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.actor.profile",
            "rkey": "self",
            "record": {
                "$type": "app.bsky.actor.profile",
                "displayName": "Full Cycle User"
            }
        }))
        .send()
        .await
        .expect("Failed to create profile");
    assert_eq!(profile_res.status(), StatusCode::OK);
    let (post_uri, post_cid) = create_post(&client, &did, &access_jwt, "My first post!").await;
    let get_post_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", post_uri.split('/').last().unwrap()),
        ])
        .send()
        .await
        .expect("Failed to get post");
    assert_eq!(get_post_res.status(), StatusCode::OK);
    create_like(&client, &did, &access_jwt, &post_uri, &post_cid).await;
    let describe_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.describeRepo",
            base_url().await
        ))
        .query(&[("repo", did.as_str())])
        .send()
        .await
        .expect("Failed to describe repo");
    assert_eq!(describe_res.status(), StatusCode::OK);
    let describe_body: Value = describe_res.json().await.unwrap();
    assert_eq!(describe_body["did"], did);
    let describe_handle = describe_body["handle"].as_str().unwrap();
    assert!(
        normalized_handle.starts_with(describe_handle) || describe_handle.starts_with(&handle),
        "describeRepo handle should be related to the requested handle"
    );
}
