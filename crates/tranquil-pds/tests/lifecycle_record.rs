mod common;
mod helpers;
use chrono::Utc;
use common::*;
use helpers::*;
use reqwest::{StatusCode, header};
use serde_json::{Value, json};
use std::time::Duration;

#[tokio::test]
async fn test_record_crud_lifecycle() {
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
    assert_eq!(
        create_res.status(),
        StatusCode::OK,
        "Failed to create record"
    );
    let create_body: Value = create_res
        .json()
        .await
        .expect("create response was not JSON");
    let uri = create_body["uri"].as_str().unwrap();
    let initial_cid = create_body["cid"].as_str().unwrap().to_string();
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
        StatusCode::OK,
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
        "record": { "$type": collection, "text": updated_text, "createdAt": now },
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
        .expect("Failed to send update request");
    assert_eq!(
        update_res.status(),
        StatusCode::OK,
        "Failed to update record"
    );
    let update_body: Value = update_res
        .json()
        .await
        .expect("update response was not JSON");
    let updated_cid = update_body["cid"].as_str().unwrap().to_string();
    let get_updated_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send get-after-update request");
    let get_updated_body: Value = get_updated_res
        .json()
        .await
        .expect("get-updated response was not JSON");
    assert_eq!(
        get_updated_body["value"]["text"], updated_text,
        "Text was not updated"
    );
    let stale_update_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey,
        "record": { "$type": collection, "text": "Stale update", "createdAt": now },
        "swapRecord": initial_cid
    });
    let stale_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&stale_update_payload)
        .send()
        .await
        .expect("Failed to send stale update");
    assert_eq!(
        stale_res.status(),
        StatusCode::BAD_REQUEST,
        "Stale update should cause 400 InvalidSwap"
    );
    let good_update_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey,
        "record": { "$type": collection, "text": "Good update", "createdAt": now },
        "swapRecord": updated_cid
    });
    let good_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&good_update_payload)
        .send()
        .await
        .expect("Failed to send good update");
    assert_eq!(
        good_res.status(),
        StatusCode::OK,
        "Good update should succeed"
    );
    let delete_payload = json!({ "repo": did, "collection": collection, "rkey": rkey });
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
        StatusCode::OK,
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
        StatusCode::NOT_FOUND,
        "Record should be deleted"
    );
}

#[tokio::test]
async fn test_profile_with_blob_lifecycle() {
    let client = client();
    let (did, jwt) = setup_new_user("profile-blob").await;
    let blob_data = b"\x89PNG\r\n\x1a\nfake image data for test";
    let upload_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header(header::CONTENT_TYPE, "image/png")
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
            "displayName": "Test User",
            "description": "A test profile for lifecycle testing",
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
        .expect("Failed to create profile");
    assert_eq!(
        create_res.status(),
        StatusCode::OK,
        "Failed to create profile"
    );
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
    assert!(get_body["value"]["avatar"]["ref"]["$link"].is_string());
    let update_payload = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": { "$type": "app.bsky.actor.profile", "displayName": "Updated User", "description": "Profile updated" },
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
    assert_eq!(
        update_res.status(),
        StatusCode::OK,
        "Failed to update profile"
    );
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
    let (root_uri, root_cid) =
        create_post(&client, &alice_did, &alice_jwt, "This is the root post").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let reply_collection = "app.bsky.feed.post";
    let reply_rkey = format!("e2e_reply_{}", Utc::now().timestamp_millis());
    let reply_payload = json!({
        "repo": bob_did,
        "collection": reply_collection,
        "rkey": reply_rkey,
        "record": {
            "$type": reply_collection,
            "text": "This is Bob's reply to Alice",
            "createdAt": Utc::now().to_rfc3339(),
            "reply": {
                "root": { "uri": root_uri, "cid": root_cid },
                "parent": { "uri": root_uri, "cid": root_cid }
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
                "root": { "uri": root_uri, "cid": root_cid },
                "parent": { "uri": reply_uri, "cid": reply_cid }
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
    assert_eq!(
        nested_res.status(),
        StatusCode::OK,
        "Failed to create nested reply"
    );
}

#[tokio::test]
async fn test_authorization_protects_repos() {
    let client = client();
    let (alice_did, alice_jwt) = setup_new_user("alice-auth").await;
    let (_bob_did, bob_jwt) = setup_new_user("bob-auth").await;
    let (post_uri, _) = create_post(&client, &alice_did, &alice_jwt, "Alice's post").await;
    let post_rkey = post_uri.split('/').next_back().unwrap();
    let post_payload = json!({
        "repo": alice_did,
        "collection": "app.bsky.feed.post",
        "rkey": "unauthorized-post",
        "record": { "$type": "app.bsky.feed.post", "text": "Bob trying to post as Alice", "createdAt": Utc::now().to_rfc3339() }
    });
    let write_res = client
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
        write_res.status() == StatusCode::FORBIDDEN
            || write_res.status() == StatusCode::UNAUTHORIZED,
        "Expected 403/401 for writing to another user's repo, got {}",
        write_res.status()
    );
    let delete_payload =
        json!({ "repo": alice_did, "collection": "app.bsky.feed.post", "rkey": post_rkey });
    let delete_res = client
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
        delete_res.status() == StatusCode::FORBIDDEN
            || delete_res.status() == StatusCode::UNAUTHORIZED,
        "Expected 403/401 for deleting another user's record, got {}",
        delete_res.status()
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
    assert_eq!(
        get_res.status(),
        StatusCode::OK,
        "Record should still exist"
    );
}

#[tokio::test]
async fn test_apply_writes_batch() {
    let client = client();
    let (did, jwt) = setup_new_user("apply-writes-batch").await;
    let now = Utc::now().to_rfc3339();
    let writes_payload = json!({
        "repo": did,
        "writes": [
            { "$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "rkey": "batch-post-1", "value": { "$type": "app.bsky.feed.post", "text": "First batch post", "createdAt": now } },
            { "$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "rkey": "batch-post-2", "value": { "$type": "app.bsky.feed.post", "text": "Second batch post", "createdAt": now } },
            { "$type": "com.atproto.repo.applyWrites#update", "collection": "app.bsky.actor.profile", "rkey": "self", "value": { "$type": "app.bsky.actor.profile", "displayName": "Batch User" } }
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
    let profile_body: Value = get_profile.json().await.unwrap();
    assert_eq!(profile_body["value"]["displayName"], "Batch User");
    let update_writes = json!({
        "repo": did,
        "writes": [
            { "$type": "com.atproto.repo.applyWrites#update", "collection": "app.bsky.actor.profile", "rkey": "self", "value": { "$type": "app.bsky.actor.profile", "displayName": "Updated Batch User" } },
            { "$type": "com.atproto.repo.applyWrites#delete", "collection": "app.bsky.feed.post", "rkey": "batch-post-1" }
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
    assert_eq!(
        updated_profile["value"]["displayName"],
        "Updated Batch User"
    );
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
        "repo": did, "collection": "app.bsky.feed.post", "rkey": rkey,
        "record": { "$type": "app.bsky.feed.post", "text": text, "createdAt": Utc::now().to_rfc3339() }
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
async fn test_list_records_comprehensive() {
    let client = client();
    let (did, jwt) = setup_new_user("list-records-test").await;
    for i in 0..5 {
        create_post_with_rkey(
            &client,
            &did,
            &jwt,
            &format!("post{:02}", i),
            &format!("Post {}", i),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .expect("Failed to list records");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 5);
    let rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').next_back().unwrap())
        .collect();
    assert_eq!(
        rkeys,
        vec!["post04", "post03", "post02", "post01", "post00"],
        "Default order should be DESC"
    );
    for record in records {
        assert!(record["uri"].is_string());
        assert!(record["cid"].is_string());
        assert!(record["cid"].as_str().unwrap().starts_with("bafy"));
        assert!(record["value"].is_object());
    }
    let rev_res = client
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
        .expect("Failed to list records reverse");
    let rev_body: Value = rev_res.json().await.unwrap();
    let rev_rkeys: Vec<&str> = rev_body["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').next_back().unwrap())
        .collect();
    assert_eq!(
        rev_rkeys,
        vec!["post00", "post01", "post02", "post03", "post04"],
        "reverse=true should give ASC"
    );
    let page1 = client
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
        .expect("Failed to list page 1");
    let page1_body: Value = page1.json().await.unwrap();
    let page1_records = page1_body["records"].as_array().unwrap();
    assert_eq!(page1_records.len(), 2);
    let cursor = page1_body["cursor"].as_str().expect("Should have cursor");
    let page2 = client
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
        .expect("Failed to list page 2");
    let page2_body: Value = page2.json().await.unwrap();
    let page2_records = page2_body["records"].as_array().unwrap();
    assert_eq!(page2_records.len(), 2);
    let all_uris: Vec<&str> = page1_records
        .iter()
        .chain(page2_records.iter())
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    let unique_uris: std::collections::HashSet<&str> = all_uris.iter().copied().collect();
    assert_eq!(
        all_uris.len(),
        unique_uris.len(),
        "Cursor pagination should not repeat records"
    );
    let range_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkeyStart", "post01"),
            ("rkeyEnd", "post03"),
            ("reverse", "true"),
        ])
        .send()
        .await
        .expect("Failed to list range");
    let range_body: Value = range_res.json().await.unwrap();
    let range_rkeys: Vec<&str> = range_body["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').next_back().unwrap())
        .collect();
    for rkey in &range_rkeys {
        assert!(
            *rkey >= "post01" && *rkey <= "post03",
            "Range should be inclusive"
        );
    }
    let limit_res = client
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
        .expect("Failed with high limit");
    let limit_body: Value = limit_res.json().await.unwrap();
    assert!(
        limit_body["records"].as_array().unwrap().len() <= 100,
        "Limit should be clamped to max 100"
    );
    let not_found_res = client
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
        .expect("Failed with nonexistent repo");
    assert_eq!(not_found_res.status(), StatusCode::BAD_REQUEST);
}
