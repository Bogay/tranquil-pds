mod common;
mod helpers;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::time::Duration;
use chrono::Utc;
#[tokio::test]
async fn test_social_flow_lifecycle() {
    let client = client();
    let (alice_did, alice_jwt) = setup_new_user("alice-social").await;
    let (bob_did, bob_jwt) = setup_new_user("bob-social").await;
    let (post1_uri, _) = create_post(&client, &alice_did, &alice_jwt, "Alice's first post!").await;
    create_follow(&client, &bob_did, &bob_jwt, &alice_did).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let timeline_res_1 = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getTimeline",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .send()
        .await
        .expect("Failed to get timeline (1)");
    assert_eq!(
        timeline_res_1.status(),
        reqwest::StatusCode::OK,
        "Failed to get timeline (1)"
    );
    let timeline_body_1: Value = timeline_res_1.json().await.expect("Timeline (1) not JSON");
    let feed_1 = timeline_body_1["feed"].as_array().unwrap();
    assert_eq!(feed_1.len(), 1, "Timeline should have 1 post");
    assert_eq!(
        feed_1[0]["post"]["uri"], post1_uri,
        "Post URI mismatch in timeline (1)"
    );
    let (post2_uri, _) = create_post(
        &client,
        &alice_did,
        &alice_jwt,
        "Alice's second post, so exciting!",
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let timeline_res_2 = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getTimeline",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .send()
        .await
        .expect("Failed to get timeline (2)");
    assert_eq!(
        timeline_res_2.status(),
        reqwest::StatusCode::OK,
        "Failed to get timeline (2)"
    );
    let timeline_body_2: Value = timeline_res_2.json().await.expect("Timeline (2) not JSON");
    let feed_2 = timeline_body_2["feed"].as_array().unwrap();
    assert_eq!(feed_2.len(), 2, "Timeline should have 2 posts");
    assert_eq!(
        feed_2[0]["post"]["uri"], post2_uri,
        "Post 2 should be first"
    );
    assert_eq!(
        feed_2[1]["post"]["uri"], post1_uri,
        "Post 1 should be second"
    );
    let delete_payload = json!({
        "repo": alice_did,
        "collection": "app.bsky.feed.post",
        "rkey": post1_uri.split('/').last().unwrap()
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(&alice_jwt)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");
    assert_eq!(
        delete_res.status(),
        reqwest::StatusCode::OK,
        "Failed to delete record"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let timeline_res_3 = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getTimeline",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .send()
        .await
        .expect("Failed to get timeline (3)");
    assert_eq!(
        timeline_res_3.status(),
        reqwest::StatusCode::OK,
        "Failed to get timeline (3)"
    );
    let timeline_body_3: Value = timeline_res_3.json().await.expect("Timeline (3) not JSON");
    let feed_3 = timeline_body_3["feed"].as_array().unwrap();
    assert_eq!(feed_3.len(), 1, "Timeline should have 1 post after delete");
    assert_eq!(
        feed_3[0]["post"]["uri"], post2_uri,
        "Only post 2 should remain"
    );
}
#[tokio::test]
async fn test_like_lifecycle() {
    let client = client();
    let (alice_did, alice_jwt) = setup_new_user("alice-like").await;
    let (bob_did, bob_jwt) = setup_new_user("bob-like").await;
    let (post_uri, post_cid) = create_post(&client, &alice_did, &alice_jwt, "Like this post!").await;
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
    assert_eq!(get_deleted_res.status(), StatusCode::NOT_FOUND, "Like should be deleted");
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
    assert_eq!(delete_res.status(), StatusCode::OK, "Failed to delete repost");
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
    assert_eq!(get_deleted_res.status(), StatusCode::NOT_FOUND, "Follow should be deleted");
}
#[tokio::test]
async fn test_timeline_after_unfollow() {
    let client = client();
    let (alice_did, alice_jwt) = setup_new_user("alice-tl-unfollow").await;
    let (bob_did, bob_jwt) = setup_new_user("bob-tl-unfollow").await;
    let (follow_uri, _) = create_follow(&client, &bob_did, &bob_jwt, &alice_did).await;
    create_post(&client, &alice_did, &alice_jwt, "Post while following").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let timeline_res = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getTimeline",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .send()
        .await
        .expect("Failed to get timeline");
    assert_eq!(timeline_res.status(), StatusCode::OK);
    let timeline_body: Value = timeline_res.json().await.unwrap();
    let feed = timeline_body["feed"].as_array().unwrap();
    assert_eq!(feed.len(), 1, "Should see 1 post from Alice");
    let follow_rkey = follow_uri.split('/').last().unwrap();
    let unfollow_payload = json!({
        "repo": bob_did,
        "collection": "app.bsky.graph.follow",
        "rkey": follow_rkey
    });
    client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .json(&unfollow_payload)
        .send()
        .await
        .expect("Failed to unfollow");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let timeline_after_res = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getTimeline",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .send()
        .await
        .expect("Failed to get timeline after unfollow");
    assert_eq!(timeline_after_res.status(), StatusCode::OK);
    let timeline_after: Value = timeline_after_res.json().await.unwrap();
    let feed_after = timeline_after["feed"].as_array().unwrap();
    assert_eq!(feed_after.len(), 0, "Should see 0 posts after unfollowing");
}
#[tokio::test]
async fn test_mutual_follow_lifecycle() {
    let client = client();
    let (alice_did, alice_jwt) = setup_new_user("alice-mutual").await;
    let (bob_did, bob_jwt) = setup_new_user("bob-mutual").await;
    create_follow(&client, &alice_did, &alice_jwt, &bob_did).await;
    create_follow(&client, &bob_did, &bob_jwt, &alice_did).await;
    create_post(&client, &alice_did, &alice_jwt, "Alice's post for mutual").await;
    create_post(&client, &bob_did, &bob_jwt, "Bob's post for mutual").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let alice_timeline_res = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getTimeline",
            base_url().await
        ))
        .bearer_auth(&alice_jwt)
        .send()
        .await
        .expect("Failed to get Alice's timeline");
    assert_eq!(alice_timeline_res.status(), StatusCode::OK);
    let alice_tl: Value = alice_timeline_res.json().await.unwrap();
    let alice_feed = alice_tl["feed"].as_array().unwrap();
    assert_eq!(alice_feed.len(), 1, "Alice should see Bob's 1 post");
    let bob_timeline_res = client
        .get(format!(
            "{}/xrpc/app.bsky.feed.getTimeline",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .send()
        .await
        .expect("Failed to get Bob's timeline");
    assert_eq!(bob_timeline_res.status(), StatusCode::OK);
    let bob_tl: Value = bob_timeline_res.json().await.unwrap();
    let bob_feed = bob_tl["feed"].as_array().unwrap();
    assert_eq!(bob_feed.len(), 1, "Bob should see Alice's 1 post");
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
    assert_eq!(session_body["handle"], handle);
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
    assert_eq!(describe_body["handle"], handle);
}