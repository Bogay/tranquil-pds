mod common;
use common::*;

use chrono::Utc;
use reqwest::{self, StatusCode, header};
use serde_json::{Value, json};
use std::time::Duration;

async fn setup_new_user(handle_prefix: &str) -> (String, String) {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("{}-{}.test", handle_prefix, ts);
    let email = format!("{}-{}@test.com", handle_prefix, ts);
    let password = "e2e-password-123";

    let create_account_payload = json!({
        "handle": handle,
        "email": email,
        "password": password
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_account_payload)
        .send()
        .await
        .expect("setup_new_user: Failed to send createAccount");

    if create_res.status() != reqwest::StatusCode::OK {
        panic!(
            "setup_new_user: Failed to create account: {:?}",
            create_res.text().await
        );
    }

    let create_body: Value = create_res
        .json()
        .await
        .expect("setup_new_user: createAccount response was not JSON");

    let new_did = create_body["did"]
        .as_str()
        .expect("setup_new_user: Response had no DID")
        .to_string();
    let new_jwt = create_body["accessJwt"]
        .as_str()
        .expect("setup_new_user: Response had no accessJwt")
        .to_string();

    (new_did, new_jwt)
}

#[tokio::test]
async fn test_post_crud_lifecycle() {
    let client = client();
    let (did, jwt) = setup_new_user("lifecycle-crud").await;
    let collection = "app.bsky.feed.post";

    let rkey = format!("e2e_lifecycle_{}", Utc::now().timestamp_millis());
    let now = Utc::now().to_rfc3339();

    let original_text = "Hello from the lifecycle test!";
    let create_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "text": original_text,
            "createdAt": now
        }
    });

    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to send create request");

    if create_res.status() != reqwest::StatusCode::OK {
        let status = create_res.status();
        let body = create_res
            .text()
            .await
            .unwrap_or_else(|_| "Could not get body".to_string());
        panic!(
            "Failed to create record. Status: {}, Body: {}",
            status, body
        );
    }

    let create_body: Value = create_res
        .json()
        .await
        .expect("create response was not JSON");
    let uri = create_body["uri"].as_str().unwrap();

    let params = [
        ("repo", did.as_str()),
        ("collection", collection),
        ("rkey", &rkey),
    ];
    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send get request");

    assert_eq!(
        get_res.status(),
        reqwest::StatusCode::OK,
        "Failed to get record after create"
    );
    let get_body: Value = get_res.json().await.expect("get response was not JSON");
    assert_eq!(get_body["uri"], uri);
    assert_eq!(get_body["value"]["text"], original_text);

    let updated_text = "This post has been updated.";
    let update_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "text": updated_text,
            "createdAt": now
        }
    });

    let update_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&update_payload)
        .send()
        .await
        .expect("Failed to send update request");

    assert_eq!(
        update_res.status(),
        reqwest::StatusCode::OK,
        "Failed to update record"
    );

    let get_updated_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send get-after-update request");

    assert_eq!(
        get_updated_res.status(),
        reqwest::StatusCode::OK,
        "Failed to get record after update"
    );
    let get_updated_body: Value = get_updated_res
        .json()
        .await
        .expect("get-updated response was not JSON");
    assert_eq!(
        get_updated_body["value"]["text"], updated_text,
        "Text was not updated"
    );

    let delete_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey
    });

    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");

    assert_eq!(
        delete_res.status(),
        reqwest::StatusCode::OK,
        "Failed to delete record"
    );

    let get_deleted_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send get-after-delete request");

    assert_eq!(
        get_deleted_res.status(),
        reqwest::StatusCode::NOT_FOUND,
        "Record was found, but it should be deleted"
    );
}

#[tokio::test]
async fn test_record_update_conflict_lifecycle() {
    let client = client();
    let (user_did, user_jwt) = setup_new_user("user-conflict").await;

    let profile_payload = json!({
        "repo": user_did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Original Name"
        }
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&user_jwt)
        .json(&profile_payload)
        .send()
        .await
        .expect("create profile failed");

    if create_res.status() != reqwest::StatusCode::OK {
        return;
    }

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", &user_did),
            ("collection", &"app.bsky.actor.profile".to_string()),
            ("rkey", &"self".to_string()),
        ])
        .send()
        .await
        .expect("getRecord failed");
    let get_body: Value = get_res.json().await.expect("getRecord not json");
    let cid_v1 = get_body["cid"]
        .as_str()
        .expect("Profile v1 had no CID")
        .to_string();

    let update_payload_v2 = json!({
        "repo": user_did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Updated Name (v2)"
        },
        "swapRecord": cid_v1
    });
    let update_res_v2 = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&user_jwt)
        .json(&update_payload_v2)
        .send()
        .await
        .expect("putRecord v2 failed");
    assert_eq!(
        update_res_v2.status(),
        reqwest::StatusCode::OK,
        "v2 update failed"
    );
    let update_body_v2: Value = update_res_v2.json().await.expect("v2 body not json");
    let cid_v2 = update_body_v2["cid"]
        .as_str()
        .expect("v2 response had no CID")
        .to_string();

    let update_payload_v3_stale = json!({
        "repo": user_did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Stale Update (v3)"
        },
        "swapRecord": cid_v1
    });
    let update_res_v3_stale = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&user_jwt)
        .json(&update_payload_v3_stale)
        .send()
        .await
        .expect("putRecord v3 (stale) failed");

    assert_eq!(
        update_res_v3_stale.status(),
        reqwest::StatusCode::CONFLICT,
        "Stale update did not cause a 409 Conflict"
    );

    let update_payload_v3_good = json!({
        "repo": user_did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Good Update (v3)"
        },
        "swapRecord": cid_v2
    });
    let update_res_v3_good = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&user_jwt)
        .json(&update_payload_v3_good)
        .send()
        .await
        .expect("putRecord v3 (good) failed");

    assert_eq!(
        update_res_v3_good.status(),
        reqwest::StatusCode::OK,
        "v3 (good) update failed"
    );
}

async fn create_post(
    client: &reqwest::Client,
    did: &str,
    jwt: &str,
    text: &str,
) -> (String, String) {
    let collection = "app.bsky.feed.post";
    let rkey = format!("e2e_social_{}", Utc::now().timestamp_millis());
    let now = Utc::now().to_rfc3339();

    let create_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "text": text,
            "createdAt": now
        }
    });

    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to send create post request");

    assert_eq!(
        create_res.status(),
        reqwest::StatusCode::OK,
        "Failed to create post record"
    );
    let create_body: Value = create_res
        .json()
        .await
        .expect("create post response was not JSON");
    let uri = create_body["uri"].as_str().unwrap().to_string();
    let cid = create_body["cid"].as_str().unwrap().to_string();
    (uri, cid)
}

async fn create_follow(
    client: &reqwest::Client,
    follower_did: &str,
    follower_jwt: &str,
    followee_did: &str,
) -> (String, String) {
    let collection = "app.bsky.graph.follow";
    let rkey = format!("e2e_follow_{}", Utc::now().timestamp_millis());
    let now = Utc::now().to_rfc3339();

    let create_payload = json!({
        "repo": follower_did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "subject": followee_did,
            "createdAt": now
        }
    });

    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(follower_jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to send create follow request");

    assert_eq!(
        create_res.status(),
        reqwest::StatusCode::OK,
        "Failed to create follow record"
    );
    let create_body: Value = create_res
        .json()
        .await
        .expect("create follow response was not JSON");
    let uri = create_body["uri"].as_str().unwrap().to_string();
    let cid = create_body["cid"].as_str().unwrap().to_string();
    (uri, cid)
}

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
async fn test_session_lifecycle_wrong_password() {
    let client = client();
    let (_, _) = setup_new_user("session-wrong-pw").await;

    let login_payload = json!({
        "identifier": format!("session-wrong-pw-{}.test", Utc::now().timestamp_millis()),
        "password": "wrong-password"
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed to send request");

    assert!(
        res.status() == StatusCode::UNAUTHORIZED || res.status() == StatusCode::BAD_REQUEST,
        "Expected 401 or 400 for wrong password, got {}",
        res.status()
    );
}

#[tokio::test]
async fn test_session_lifecycle_multiple_sessions() {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("multi-session-{}.test", ts);
    let email = format!("multi-session-{}@test.com", ts);
    let password = "multi-session-pw";

    let create_payload = json!({
        "handle": handle,
        "email": email,
        "password": password
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(create_res.status(), StatusCode::OK);

    let login_payload = json!({
        "identifier": handle,
        "password": password
    });

    let session1_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed session 1");
    assert_eq!(session1_res.status(), StatusCode::OK);
    let session1: Value = session1_res.json().await.unwrap();
    let jwt1 = session1["accessJwt"].as_str().unwrap();

    let session2_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed session 2");
    assert_eq!(session2_res.status(), StatusCode::OK);
    let session2: Value = session2_res.json().await.unwrap();
    let jwt2 = session2["accessJwt"].as_str().unwrap();

    assert_ne!(jwt1, jwt2, "Sessions should have different tokens");

    let get1 = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getSession",
            base_url().await
        ))
        .bearer_auth(jwt1)
        .send()
        .await
        .expect("Failed getSession 1");
    assert_eq!(get1.status(), StatusCode::OK);

    let get2 = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getSession",
            base_url().await
        ))
        .bearer_auth(jwt2)
        .send()
        .await
        .expect("Failed getSession 2");
    assert_eq!(get2.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_session_lifecycle_refresh_invalidates_old() {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("refresh-inv-{}.test", ts);
    let email = format!("refresh-inv-{}@test.com", ts);
    let password = "refresh-inv-pw";

    let create_payload = json!({
        "handle": handle,
        "email": email,
        "password": password
    });
    client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create account");

    let login_payload = json!({
        "identifier": handle,
        "password": password
    });
    let login_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed login");
    let login_body: Value = login_res.json().await.unwrap();
    let refresh_jwt = login_body["refreshJwt"].as_str().unwrap().to_string();

    let refresh_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.refreshSession",
            base_url().await
        ))
        .bearer_auth(&refresh_jwt)
        .send()
        .await
        .expect("Failed first refresh");
    assert_eq!(refresh_res.status(), StatusCode::OK);
    let refresh_body: Value = refresh_res.json().await.unwrap();
    let new_refresh_jwt = refresh_body["refreshJwt"].as_str().unwrap();

    assert_ne!(refresh_jwt, new_refresh_jwt, "Refresh tokens should differ");

    let reuse_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.refreshSession",
            base_url().await
        ))
        .bearer_auth(&refresh_jwt)
        .send()
        .await
        .expect("Failed reuse attempt");

    assert!(
        reuse_res.status() == StatusCode::UNAUTHORIZED || reuse_res.status() == StatusCode::BAD_REQUEST,
        "Old refresh token should be invalid after use"
    );
}

async fn create_like(
    client: &reqwest::Client,
    liker_did: &str,
    liker_jwt: &str,
    subject_uri: &str,
    subject_cid: &str,
) -> (String, String) {
    let collection = "app.bsky.feed.like";
    let rkey = format!("e2e_like_{}", Utc::now().timestamp_millis());
    let now = Utc::now().to_rfc3339();

    let payload = json!({
        "repo": liker_did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "subject": {
                "uri": subject_uri,
                "cid": subject_cid
            },
            "createdAt": now
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(liker_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create like");

    assert_eq!(res.status(), StatusCode::OK, "Failed to create like");
    let body: Value = res.json().await.expect("Like response not JSON");
    (
        body["uri"].as_str().unwrap().to_string(),
        body["cid"].as_str().unwrap().to_string(),
    )
}

async fn create_repost(
    client: &reqwest::Client,
    reposter_did: &str,
    reposter_jwt: &str,
    subject_uri: &str,
    subject_cid: &str,
) -> (String, String) {
    let collection = "app.bsky.feed.repost";
    let rkey = format!("e2e_repost_{}", Utc::now().timestamp_millis());
    let now = Utc::now().to_rfc3339();

    let payload = json!({
        "repo": reposter_did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "subject": {
                "uri": subject_uri,
                "cid": subject_cid
            },
            "createdAt": now
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(reposter_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create repost");

    assert_eq!(res.status(), StatusCode::OK, "Failed to create repost");
    let body: Value = res.json().await.expect("Repost response not JSON");
    (
        body["uri"].as_str().unwrap().to_string(),
        body["cid"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn test_profile_lifecycle() {
    let client = client();
    let (did, jwt) = setup_new_user("profile-lifecycle").await;

    let profile_payload = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Test User",
            "description": "A test profile for lifecycle testing"
        }
    });

    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&profile_payload)
        .send()
        .await
        .expect("Failed to create profile");

    assert_eq!(create_res.status(), StatusCode::OK, "Failed to create profile");
    let create_body: Value = create_res.json().await.unwrap();
    let initial_cid = create_body["cid"].as_str().unwrap().to_string();

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.actor.profile"),
            ("rkey", "self"),
        ])
        .send()
        .await
        .expect("Failed to get profile");

    assert_eq!(get_res.status(), StatusCode::OK);
    let get_body: Value = get_res.json().await.unwrap();
    assert_eq!(get_body["value"]["displayName"], "Test User");
    assert_eq!(get_body["value"]["description"], "A test profile for lifecycle testing");

    let update_payload = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Updated User",
            "description": "Profile has been updated"
        },
        "swapRecord": initial_cid
    });

    let update_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&update_payload)
        .send()
        .await
        .expect("Failed to update profile");

    assert_eq!(update_res.status(), StatusCode::OK, "Failed to update profile");

    let get_updated_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.actor.profile"),
            ("rkey", "self"),
        ])
        .send()
        .await
        .expect("Failed to get updated profile");

    let updated_body: Value = get_updated_res.json().await.unwrap();
    assert_eq!(updated_body["value"]["displayName"], "Updated User");
}

#[tokio::test]
async fn test_reply_thread_lifecycle() {
    let client = client();

    let (alice_did, alice_jwt) = setup_new_user("alice-thread").await;
    let (bob_did, bob_jwt) = setup_new_user("bob-thread").await;

    let (root_uri, root_cid) = create_post(&client, &alice_did, &alice_jwt, "This is the root post").await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let reply_collection = "app.bsky.feed.post";
    let reply_rkey = format!("e2e_reply_{}", Utc::now().timestamp_millis());
    let now = Utc::now().to_rfc3339();

    let reply_payload = json!({
        "repo": bob_did,
        "collection": reply_collection,
        "rkey": reply_rkey,
        "record": {
            "$type": reply_collection,
            "text": "This is Bob's reply to Alice",
            "createdAt": now,
            "reply": {
                "root": {
                    "uri": root_uri,
                    "cid": root_cid
                },
                "parent": {
                    "uri": root_uri,
                    "cid": root_cid
                }
            }
        }
    });

    let reply_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .json(&reply_payload)
        .send()
        .await
        .expect("Failed to create reply");

    assert_eq!(reply_res.status(), StatusCode::OK, "Failed to create reply");
    let reply_body: Value = reply_res.json().await.unwrap();
    let reply_uri = reply_body["uri"].as_str().unwrap();
    let reply_cid = reply_body["cid"].as_str().unwrap();

    let get_reply_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", bob_did.as_str()),
            ("collection", reply_collection),
            ("rkey", reply_rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to get reply");

    assert_eq!(get_reply_res.status(), StatusCode::OK);
    let reply_record: Value = get_reply_res.json().await.unwrap();
    assert_eq!(reply_record["value"]["reply"]["root"]["uri"], root_uri);
    assert_eq!(reply_record["value"]["reply"]["parent"]["uri"], root_uri);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let nested_reply_rkey = format!("e2e_nested_reply_{}", Utc::now().timestamp_millis());
    let nested_payload = json!({
        "repo": alice_did,
        "collection": reply_collection,
        "rkey": nested_reply_rkey,
        "record": {
            "$type": reply_collection,
            "text": "Alice replies to Bob's reply",
            "createdAt": Utc::now().to_rfc3339(),
            "reply": {
                "root": {
                    "uri": root_uri,
                    "cid": root_cid
                },
                "parent": {
                    "uri": reply_uri,
                    "cid": reply_cid
                }
            }
        }
    });

    let nested_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&alice_jwt)
        .json(&nested_payload)
        .send()
        .await
        .expect("Failed to create nested reply");

    assert_eq!(nested_res.status(), StatusCode::OK, "Failed to create nested reply");
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
async fn test_blob_in_record_lifecycle() {
    let client = client();
    let (did, jwt) = setup_new_user("blob-record").await;

    let blob_data = b"This is test blob data for a profile avatar";
    let upload_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header(header::CONTENT_TYPE, "text/plain")
        .bearer_auth(&jwt)
        .body(blob_data.to_vec())
        .send()
        .await
        .expect("Failed to upload blob");

    assert_eq!(upload_res.status(), StatusCode::OK);
    let upload_body: Value = upload_res.json().await.unwrap();
    let blob_ref = upload_body["blob"].clone();

    let profile_payload = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "User With Avatar",
            "avatar": blob_ref
        }
    });

    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&profile_payload)
        .send()
        .await
        .expect("Failed to create profile with blob");

    assert_eq!(create_res.status(), StatusCode::OK, "Failed to create profile with blob");

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.actor.profile"),
            ("rkey", "self"),
        ])
        .send()
        .await
        .expect("Failed to get profile");

    assert_eq!(get_res.status(), StatusCode::OK);
    let profile: Value = get_res.json().await.unwrap();
    assert!(profile["value"]["avatar"]["ref"]["$link"].is_string());
}

#[tokio::test]
async fn test_authorization_cannot_modify_other_repo() {
    let client = client();

    let (alice_did, _alice_jwt) = setup_new_user("alice-auth").await;
    let (_bob_did, bob_jwt) = setup_new_user("bob-auth").await;

    let post_payload = json!({
        "repo": alice_did,
        "collection": "app.bsky.feed.post",
        "rkey": "unauthorized-post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Bob trying to post as Alice",
            "createdAt": Utc::now().to_rfc3339()
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .json(&post_payload)
        .send()
        .await
        .expect("Failed to send request");

    assert!(
        res.status() == StatusCode::FORBIDDEN || res.status() == StatusCode::UNAUTHORIZED,
        "Expected 403 or 401 when writing to another user's repo, got {}",
        res.status()
    );
}

#[tokio::test]
async fn test_authorization_cannot_delete_other_record() {
    let client = client();

    let (alice_did, alice_jwt) = setup_new_user("alice-del-auth").await;
    let (_bob_did, bob_jwt) = setup_new_user("bob-del-auth").await;

    let (post_uri, _) = create_post(&client, &alice_did, &alice_jwt, "Alice's post").await;
    let post_rkey = post_uri.split('/').last().unwrap();

    let delete_payload = json!({
        "repo": alice_did,
        "collection": "app.bsky.feed.post",
        "rkey": post_rkey
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(&bob_jwt)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send request");

    assert!(
        res.status() == StatusCode::FORBIDDEN || res.status() == StatusCode::UNAUTHORIZED,
        "Expected 403 or 401 when deleting another user's record, got {}",
        res.status()
    );

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", alice_did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", post_rkey),
        ])
        .send()
        .await
        .expect("Failed to verify record exists");

    assert_eq!(get_res.status(), StatusCode::OK, "Record should still exist");
}

#[tokio::test]
async fn test_list_records_pagination() {
    let client = client();
    let (did, jwt) = setup_new_user("list-pagination").await;

    for i in 0..5 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        create_post(&client, &did, &jwt, &format!("Post number {}", i)).await;
    }

    let list_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "2"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body: Value = list_res.json().await.unwrap();
    let records = list_body["records"].as_array().unwrap();
    assert_eq!(records.len(), 2, "Should return 2 records with limit=2");

    if let Some(cursor) = list_body["cursor"].as_str() {
        let list_page2_res = client
            .get(format!(
                "{}/xrpc/com.atproto.repo.listRecords",
                base_url().await
            ))
            .query(&[
                ("repo", did.as_str()),
                ("collection", "app.bsky.feed.post"),
                ("limit", "2"),
                ("cursor", cursor),
            ])
            .send()
            .await
            .expect("Failed to list records page 2");

        assert_eq!(list_page2_res.status(), StatusCode::OK);
        let page2_body: Value = list_page2_res.json().await.unwrap();
        let page2_records = page2_body["records"].as_array().unwrap();
        assert_eq!(page2_records.len(), 2, "Page 2 should have 2 more records");
    }
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
    let access_jwt = account_body["accessJwt"].as_str().unwrap().to_string();

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
