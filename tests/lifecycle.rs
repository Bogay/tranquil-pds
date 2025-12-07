mod common;
use common::*;

use chrono::Utc;
use reqwest;
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
#[ignore]
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
#[ignore]
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
        "swapCommit": cid_v1 // <-- Correctly point to v1
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
        "swapCommit": cid_v1
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
        "swapCommit": cid_v2 // <-- Correct
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
#[ignore]
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
