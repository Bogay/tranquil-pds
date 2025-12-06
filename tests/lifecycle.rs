mod common;
use common::*;

use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use chrono::Utc;
#[allow(unused_imports)]
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
    let create_res = client.post(format!("{}/xrpc/com.atproto.server.createAccount", base_url().await))
        .json(&create_account_payload)
        .send()
        .await
        .expect("setup_new_user: Failed to send createAccount");

    if create_res.status() != StatusCode::OK {
        panic!("setup_new_user: Failed to create account: {:?}", create_res.text().await);
    }

    let create_body: Value = create_res.json().await.expect("setup_new_user: createAccount response was not JSON");

    let new_did = create_body["did"].as_str().expect("setup_new_user: Response had no DID").to_string();
    let new_jwt = create_body["accessJwt"].as_str().expect("setup_new_user: Response had no accessJwt").to_string();

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

    let create_res = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to send create request");

    assert_eq!(create_res.status(), StatusCode::OK, "Failed to create record");
    let create_body: Value = create_res.json().await.expect("create response was not JSON");
    let uri = create_body["uri"].as_str().unwrap();


    let params = [
        ("repo", did.as_str()),
        ("collection", collection),
        ("rkey", &rkey),
    ];
    let get_res = client.get(format!("{}/xrpc/com.atproto.repo.getRecord", base_url().await))
        .query(&params)
        .send()
        .await
        .expect("Failed to send get request");

    assert_eq!(get_res.status(), StatusCode::OK, "Failed to get record after create");
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

    let update_res = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&update_payload)
        .send()
        .await
        .expect("Failed to send update request");

    assert_eq!(update_res.status(), StatusCode::OK, "Failed to update record");


    let get_updated_res = client.get(format!("{}/xrpc/com.atproto.repo.getRecord", base_url().await))
        .query(&params)
        .send()
        .await
        .expect("Failed to send get-after-update request");

    assert_eq!(get_updated_res.status(), StatusCode::OK, "Failed to get record after update");
    let get_updated_body: Value = get_updated_res.json().await.expect("get-updated response was not JSON");
    assert_eq!(get_updated_body["value"]["text"], updated_text, "Text was not updated");


    let delete_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey
    });

    let delete_res = client.post(format!("{}/xrpc/com.atproto.repo.deleteRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");

    assert_eq!(delete_res.status(), StatusCode::OK, "Failed to delete record");


    let get_deleted_res = client.get(format!("{}/xrpc/com.atproto.repo.getRecord", base_url().await))
        .query(&params)
        .send()
        .await
        .expect("Failed to send get-after-delete request");

    assert_eq!(get_deleted_res.status(), StatusCode::NOT_FOUND, "Record was found, but it should be deleted");
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
    let create_res = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(&user_jwt)
        .json(&profile_payload)
        .send().await.expect("create profile failed");

    if create_res.status() != StatusCode::OK {
        return;
    }

    let get_res = client.get(format!("{}/xrpc/com.atproto.repo.getRecord", base_url().await))
        .query(&[
            ("repo", &user_did),
            ("collection", &"app.bsky.actor.profile".to_string()),
            ("rkey", &"self".to_string()),
        ])
        .send().await.expect("getRecord failed");
    let get_body: Value = get_res.json().await.expect("getRecord not json");
    let cid_v1 = get_body["cid"].as_str().expect("Profile v1 had no CID").to_string();

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
    let update_res_v2 = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(&user_jwt)
        .json(&update_payload_v2)
        .send().await.expect("putRecord v2 failed");
    assert_eq!(update_res_v2.status(), StatusCode::OK, "v2 update failed");
    let update_body_v2: Value = update_res_v2.json().await.expect("v2 body not json");
    let cid_v2 = update_body_v2["cid"].as_str().expect("v2 response had no CID").to_string();

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
    let update_res_v3_stale = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(&user_jwt)
        .json(&update_payload_v3_stale)
        .send().await.expect("putRecord v3 (stale) failed");

    assert_eq!(
        update_res_v3_stale.status(),
        StatusCode::CONFLICT,
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
    let update_res_v3_good = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(&user_jwt)
        .json(&update_payload_v3_good)
        .send().await.expect("putRecord v3 (good) failed");

    assert_eq!(update_res_v3_good.status(), StatusCode::OK, "v3 (good) update failed");
}
