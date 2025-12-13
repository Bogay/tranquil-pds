mod common;
mod helpers;

use common::*;
use helpers::*;

use chrono::Utc;
use reqwest::{StatusCode, header};
use serde_json::{Value, json};
use std::time::Duration;

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
async fn test_apply_writes_batch_lifecycle() {
    let client = client();
    let (did, jwt) = setup_new_user("apply-writes-batch").await;

    let now = Utc::now().to_rfc3339();
    let writes_payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": "batch-post-1",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "First batch post",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": "batch-post-2",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Second batch post",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.actor.profile",
                "rkey": "self",
                "value": {
                    "$type": "app.bsky.actor.profile",
                    "displayName": "Batch User"
                }
            }
        ]
    });

    let apply_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&writes_payload)
        .send()
        .await
        .expect("Failed to apply writes");

    assert_eq!(apply_res.status(), StatusCode::OK);

    let get_post1 = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", "batch-post-1"),
        ])
        .send()
        .await
        .expect("Failed to get post 1");
    assert_eq!(get_post1.status(), StatusCode::OK);
    let post1_body: Value = get_post1.json().await.unwrap();
    assert_eq!(post1_body["value"]["text"], "First batch post");

    let get_post2 = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", "batch-post-2"),
        ])
        .send()
        .await
        .expect("Failed to get post 2");
    assert_eq!(get_post2.status(), StatusCode::OK);

    let get_profile = client
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
    assert_eq!(get_profile.status(), StatusCode::OK);
    let profile_body: Value = get_profile.json().await.unwrap();
    assert_eq!(profile_body["value"]["displayName"], "Batch User");

    let update_writes = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.actor.profile",
                "rkey": "self",
                "value": {
                    "$type": "app.bsky.actor.profile",
                    "displayName": "Updated Batch User"
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": "batch-post-1"
            }
        ]
    });

    let update_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&update_writes)
        .send()
        .await
        .expect("Failed to apply update writes");
    assert_eq!(update_res.status(), StatusCode::OK);

    let get_updated_profile = client
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
    let updated_profile: Value = get_updated_profile.json().await.unwrap();
    assert_eq!(updated_profile["value"]["displayName"], "Updated Batch User");

    let get_deleted_post = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", "batch-post-1"),
        ])
        .send()
        .await
        .expect("Failed to check deleted post");
    assert_eq!(
        get_deleted_post.status(),
        StatusCode::NOT_FOUND,
        "Batch-deleted post should be gone"
    );
}

async fn create_post_with_rkey(
    client: &reqwest::Client,
    did: &str,
    jwt: &str,
    rkey: &str,
    text: &str,
) -> (String, String) {
    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": text,
            "createdAt": Utc::now().to_rfc3339()
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create record");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    (
        body["uri"].as_str().unwrap().to_string(),
        body["cid"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn test_list_records_default_order() {
    let client = client();
    let (did, jwt) = setup_new_user("list-default-order").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "First post").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    create_post_with_rkey(&client, &did, &jwt, "bbbb", "Second post").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    create_post_with_rkey(&client, &did, &jwt, "cccc", "Third post").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    assert_eq!(records.len(), 3);
    let rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    assert_eq!(rkeys, vec!["cccc", "bbbb", "aaaa"], "Default order should be DESC (newest first)");
}

#[tokio::test]
async fn test_list_records_reverse_true() {
    let client = client();
    let (did, jwt) = setup_new_user("list-reverse").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "First post").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    create_post_with_rkey(&client, &did, &jwt, "bbbb", "Second post").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    create_post_with_rkey(&client, &did, &jwt, "cccc", "Third post").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("reverse", "true"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    let rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    assert_eq!(rkeys, vec!["aaaa", "bbbb", "cccc"], "reverse=true should give ASC order (oldest first)");
}

#[tokio::test]
async fn test_list_records_cursor_pagination() {
    let client = client();
    let (did, jwt) = setup_new_user("list-cursor").await;

    for i in 0..5 {
        create_post_with_rkey(&client, &did, &jwt, &format!("post{:02}", i), &format!("Post {}", i)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let res = client
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

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);

    let cursor = body["cursor"].as_str().expect("Should have cursor with more records");

    let res2 = client
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
        .expect("Failed to list records with cursor");

    assert_eq!(res2.status(), StatusCode::OK);
    let body2: Value = res2.json().await.unwrap();
    let records2 = body2["records"].as_array().unwrap();
    assert_eq!(records2.len(), 2);

    let all_uris: Vec<&str> = records
        .iter()
        .chain(records2.iter())
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    let unique_uris: std::collections::HashSet<&str> = all_uris.iter().copied().collect();
    assert_eq!(all_uris.len(), unique_uris.len(), "Cursor pagination should not repeat records");
}

#[tokio::test]
async fn test_list_records_rkey_start() {
    let client = client();
    let (did, jwt) = setup_new_user("list-rkey-start").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "First").await;
    create_post_with_rkey(&client, &did, &jwt, "bbbb", "Second").await;
    create_post_with_rkey(&client, &did, &jwt, "cccc", "Third").await;
    create_post_with_rkey(&client, &did, &jwt, "dddd", "Fourth").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkeyStart", "bbbb"),
            ("reverse", "true"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    let rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    for rkey in &rkeys {
        assert!(*rkey >= "bbbb", "rkeyStart should filter records >= start");
    }
}

#[tokio::test]
async fn test_list_records_rkey_end() {
    let client = client();
    let (did, jwt) = setup_new_user("list-rkey-end").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "First").await;
    create_post_with_rkey(&client, &did, &jwt, "bbbb", "Second").await;
    create_post_with_rkey(&client, &did, &jwt, "cccc", "Third").await;
    create_post_with_rkey(&client, &did, &jwt, "dddd", "Fourth").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkeyEnd", "cccc"),
            ("reverse", "true"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    let rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    for rkey in &rkeys {
        assert!(*rkey <= "cccc", "rkeyEnd should filter records <= end");
    }
}

#[tokio::test]
async fn test_list_records_rkey_range() {
    let client = client();
    let (did, jwt) = setup_new_user("list-rkey-range").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "First").await;
    create_post_with_rkey(&client, &did, &jwt, "bbbb", "Second").await;
    create_post_with_rkey(&client, &did, &jwt, "cccc", "Third").await;
    create_post_with_rkey(&client, &did, &jwt, "dddd", "Fourth").await;
    create_post_with_rkey(&client, &did, &jwt, "eeee", "Fifth").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkeyStart", "bbbb"),
            ("rkeyEnd", "dddd"),
            ("reverse", "true"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    let rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    for rkey in &rkeys {
        assert!(*rkey >= "bbbb" && *rkey <= "dddd", "Range should be inclusive, got {}", rkey);
    }
    assert!(!rkeys.is_empty(), "Should have at least some records in range");
}

#[tokio::test]
async fn test_list_records_limit_clamping_max() {
    let client = client();
    let (did, jwt) = setup_new_user("list-limit-max").await;

    for i in 0..5 {
        create_post_with_rkey(&client, &did, &jwt, &format!("post{:02}", i), &format!("Post {}", i)).await;
    }

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "1000"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert!(records.len() <= 100, "Limit should be clamped to max 100");
}

#[tokio::test]
async fn test_list_records_limit_clamping_min() {
    let client = client();
    let (did, jwt) = setup_new_user("list-limit-min").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "Post").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "0"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert!(records.len() >= 1, "Limit should be clamped to min 1");
}

#[tokio::test]
async fn test_list_records_empty_collection() {
    let client = client();
    let (did, _jwt) = setup_new_user("list-empty").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert!(records.is_empty(), "Empty collection should return empty array");
    assert!(body["cursor"].is_null(), "Empty collection should have no cursor");
}

#[tokio::test]
async fn test_list_records_exact_limit() {
    let client = client();
    let (did, jwt) = setup_new_user("list-exact-limit").await;

    for i in 0..10 {
        create_post_with_rkey(&client, &did, &jwt, &format!("post{:02}", i), &format!("Post {}", i)).await;
    }

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "5"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 5, "Should return exactly 5 records when limit=5");
}

#[tokio::test]
async fn test_list_records_cursor_exhaustion() {
    let client = client();
    let (did, jwt) = setup_new_user("list-cursor-exhaust").await;

    for i in 0..3 {
        create_post_with_rkey(&client, &did, &jwt, &format!("post{:02}", i), &format!("Post {}", i)).await;
    }

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "10"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 3);
}

#[tokio::test]
async fn test_list_records_repo_not_found() {
    let client = client();

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", "did:plc:nonexistent12345"),
            ("collection", "app.bsky.feed.post"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_list_records_includes_cid() {
    let client = client();
    let (did, jwt) = setup_new_user("list-includes-cid").await;

    create_post_with_rkey(&client, &did, &jwt, "test", "Test post").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    for record in records {
        assert!(record["uri"].is_string(), "Record should have uri");
        assert!(record["cid"].is_string(), "Record should have cid");
        assert!(record["value"].is_object(), "Record should have value");
        let cid = record["cid"].as_str().unwrap();
        assert!(cid.starts_with("bafy"), "CID should be valid");
    }
}

#[tokio::test]
async fn test_list_records_cursor_with_reverse() {
    let client = client();
    let (did, jwt) = setup_new_user("list-cursor-reverse").await;

    for i in 0..5 {
        create_post_with_rkey(&client, &did, &jwt, &format!("post{:02}", i), &format!("Post {}", i)).await;
    }

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "2"),
            ("reverse", "true"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    let first_rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    assert_eq!(first_rkeys, vec!["post00", "post01"], "First page with reverse should start from oldest");

    if let Some(cursor) = body["cursor"].as_str() {
        let res2 = client
            .get(format!(
                "{}/xrpc/com.atproto.repo.listRecords",
                base_url().await
            ))
            .query(&[
                ("repo", did.as_str()),
                ("collection", "app.bsky.feed.post"),
                ("limit", "2"),
                ("reverse", "true"),
                ("cursor", cursor),
            ])
            .send()
            .await
            .expect("Failed to list records with cursor");

        let body2: Value = res2.json().await.unwrap();
        let records2 = body2["records"].as_array().unwrap();
        let second_rkeys: Vec<&str> = records2
            .iter()
            .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
            .collect();

        assert_eq!(second_rkeys, vec!["post02", "post03"], "Second page should continue in ASC order");
    }
}
