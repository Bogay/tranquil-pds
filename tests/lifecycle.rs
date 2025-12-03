mod common;
use common::*;

use reqwest::StatusCode;
use serde_json::{json, Value};
use chrono::Utc;
use std::time::Duration;

use reqwest::Client;
#[allow(unused_imports)]
use std::collections::HashMap;

#[tokio::test]
async fn test_post_crud_lifecycle() {
    let client = client();
    let collection = "app.bsky.feed.post";

    let rkey = format!("e2e_lifecycle_{}", Utc::now().timestamp_millis());
    let now = Utc::now().to_rfc3339();

    let original_text = "Hello from the lifecycle test!";
    let create_payload = json!({
        "repo": AUTH_DID,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "text": original_text,
            "createdAt": now
        }
    });

    let create_res = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", BASE_URL))
        .bearer_auth(AUTH_TOKEN)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to send create request");

    assert_eq!(create_res.status(), StatusCode::OK, "Failed to create record");
    let create_body: Value = create_res.json().await.expect("create response was not JSON");
    let uri = create_body["uri"].as_str().unwrap();


    let params = [
        ("repo", AUTH_DID),
        ("collection", collection),
        ("rkey", &rkey),
    ];
    let get_res = client.get(format!("{}/xrpc/com.atproto.repo.getRecord", BASE_URL))
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
        "repo": AUTH_DID,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "text": updated_text,
            "createdAt": now
        }
    });

    let update_res = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", BASE_URL))
        .bearer_auth(AUTH_TOKEN)
        .json(&update_payload)
        .send()
        .await
        .expect("Failed to send update request");

    assert_eq!(update_res.status(), StatusCode::OK, "Failed to update record");


    let get_updated_res = client.get(format!("{}/xrpc/com.atproto.repo.getRecord", BASE_URL))
        .query(&params)
        .send()
        .await
        .expect("Failed to send get-after-update request");

    assert_eq!(get_updated_res.status(), StatusCode::OK, "Failed to get record after update");
    let get_updated_body: Value = get_updated_res.json().await.expect("get-updated response was not JSON");
    assert_eq!(get_updated_body["value"]["text"], updated_text, "Text was not updated");


    let delete_payload = json!({
        "repo": AUTH_DID,
        "collection": collection,
        "rkey": rkey
    });

    let delete_res = client.post(format!("{}/xrpc/com.atproto.repo.deleteRecord", BASE_URL))
        .bearer_auth(AUTH_TOKEN)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");

    assert_eq!(delete_res.status(), StatusCode::OK, "Failed to delete record");


    let get_deleted_res = client.get(format!("{}/xrpc/com.atproto.repo.getRecord", BASE_URL))
        .query(&params)
        .send()
        .await
        .expect("Failed to send get-after-delete request");

    assert_eq!(get_deleted_res.status(), StatusCode::NOT_FOUND, "Record was found, but it should be deleted");
}

#[tokio::test]
async fn test_post_with_image_lifecycle() {
    let client = client();

    let now_str = Utc::now().to_rfc3339();
    let fake_image_data = format!("This is a fake PNG for test at {}", now_str);

    let image_blob = upload_test_blob(
        &client,
        Box::leak(fake_image_data.into_boxed_str()),
        "image/png"
    ).await;

    let blob_ref = image_blob["ref"].clone();
    assert!(blob_ref.is_object(), "Blob ref is not an object");


    let collection = "app.bsky.feed.post";
    let rkey = format!("e2e_image_post_{}", Utc::now().timestamp_millis());

    let create_payload = json!({
        "repo": AUTH_DID,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "text": "Check out this image!",
            "createdAt": Utc::now().to_rfc3339(),
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [
                    {
                        "image": image_blob,
                        "alt": "A test image"
                    }
                ]
            }
        }
    });

    let create_res = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", BASE_URL))
        .bearer_auth(AUTH_TOKEN)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create image post");

    assert_eq!(create_res.status(), StatusCode::OK, "Failed to create post with image");


    let params = [
        ("repo", AUTH_DID),
        ("collection", collection),
        ("rkey", &rkey),
    ];
    let get_res = client.get(format!("{}/xrpc/com.atproto.repo.getRecord", BASE_URL))
        .query(&params)
        .send()
        .await
        .expect("Failed to get image post");

    assert_eq!(get_res.status(), StatusCode::OK, "Failed to get image post");
    let get_body: Value = get_res.json().await.expect("get image post was not JSON");

    let embed_image = &get_body["value"]["embed"]["images"][0]["image"];
    assert!(embed_image.is_object(), "Embedded image is missing");
    assert_eq!(embed_image["ref"], blob_ref, "Embedded blob ref does not match uploaded ref");
}

#[tokio::test]
async fn test_graph_lifecycle_follow_unfollow() {
    let client = client();
    let collection = "app.bsky.graph.follow";

    let create_payload = json!({
        "repo": AUTH_DID,
        "collection": collection,
        // "rkey" is omitted, server will generate it right?
        "record": {
            "$type": collection,
            "subject": TARGET_DID,
            "createdAt": Utc::now().to_rfc3339()
        }
    });

    let create_res = client.post(format!("{}/xrpc/com.atproto.repo.createRecord", BASE_URL))
        .bearer_auth(AUTH_TOKEN)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to send follow createRecord");

    assert_eq!(create_res.status(), StatusCode::OK, "Failed to create follow record");
    let create_body: Value = create_res.json().await.expect("create follow response was not JSON");
    let follow_uri = create_body["uri"].as_str().expect("Response had no URI");

    let rkey = follow_uri.split('/').last().expect("URI was malformed");


    let params_get_follows = [
        ("actor", AUTH_DID),
    ];
    let get_follows_res = client.get(format!("{}/xrpc/app.bsky.graph.getFollows", BASE_URL))
        .query(&params_get_follows)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send getFollows");

    assert_eq!(get_follows_res.status(), StatusCode::OK, "getFollows did not return 200");
    let get_follows_body: Value = get_follows_res.json().await.expect("getFollows response was not JSON");

    let follows_list = get_follows_body["follows"].as_array().expect("follows key was not an array");
    let is_following = follows_list.iter().any(|actor| {
        actor["did"].as_str() == Some(TARGET_DID)
    });

    assert!(is_following, "getFollows list did not contain the target DID");


    let delete_payload = json!({
        "repo": AUTH_DID,
        "collection": collection,
        "rkey": rkey
    });

    let delete_res = client.post(format!("{}/xrpc/com.atproto.repo.deleteRecord", BASE_URL))
        .bearer_auth(AUTH_TOKEN)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send unfollow deleteRecord");

    assert_eq!(delete_res.status(), StatusCode::OK, "Failed to delete follow record");


    let get_unfollowed_res = client.get(format!("{}/xrpc/app.bsky.graph.getFollows", BASE_URL))
        .query(&params_get_follows)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send getFollows after delete");

    assert_eq!(get_unfollowed_res.status(), StatusCode::OK, "getFollows (after delete) did not return 200");
    let get_unfollowed_body: Value = get_unfollowed_res.json().await.expect("getFollows (after delete) was not JSON");

    let follows_list_after = get_unfollowed_body["follows"].as_array().expect("follows key was not an array");
    let is_still_following = follows_list_after.iter().any(|actor| {
        actor["did"].as_str() == Some(TARGET_DID)
    });

    assert!(!is_still_following, "getFollows list *still* contains the target DID after unfollow");
}

#[tokio::test]
async fn test_list_records_pagination() {
    let client = client();
    let collection = "app.bsky.feed.post";
    let mut created_rkeys = Vec::new();

    for i in 0..3 {
        let rkey = format!("e2e_pagination_{}", Utc::now().timestamp_millis());
        let payload = json!({
            "repo": AUTH_DID,
            "collection": collection,
            "rkey": rkey,
            "record": {
                "$type": collection,
                "text": format!("Pagination test post #{}", i),
                "createdAt": Utc::now().to_rfc3339()
            }
        });

        let res = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", BASE_URL))
            .bearer_auth(AUTH_TOKEN)
            .json(&payload)
            .send()
            .await
            .expect("Failed to create pagination post");

        assert_eq!(res.status(), StatusCode::OK, "Failed to create post for pagination test");
        created_rkeys.push(rkey);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let params_page1 = [
        ("repo", AUTH_DID),
        ("collection", collection),
        ("limit", "2"),
    ];

    let page1_res = client.get(format!("{}/xrpc/com.atproto.repo.listRecords", BASE_URL))
        .query(&params_page1)
        .send()
        .await
        .expect("Failed to send listRecords (page 1)");

    assert_eq!(page1_res.status(), StatusCode::OK, "listRecords (page 1) failed");
    let page1_body: Value = page1_res.json().await.expect("listRecords (page 1) was not JSON");

    let page1_records = page1_body["records"].as_array().expect("records was not an array");
    assert_eq!(page1_records.len(), 2, "Page 1 did not return 2 records");

    let cursor = page1_body["cursor"].as_str().expect("Page 1 did not have a cursor");


    let params_page2 = [
        ("repo", AUTH_DID),
        ("collection", collection),
        ("limit", "2"),
        ("cursor", cursor),
    ];

    let page2_res = client.get(format!("{}/xrpc/com.atproto.repo.listRecords", BASE_URL))
        .query(&params_page2)
        .send()
        .await
        .expect("Failed to send listRecords (page 2)");

    assert_eq!(page2_res.status(), StatusCode::OK, "listRecords (page 2) failed");
    let page2_body: Value = page2_res.json().await.expect("listRecords (page 2) was not JSON");

    let page2_records = page2_body["records"].as_array().expect("records was not an array");
    assert_eq!(page2_records.len(), 1, "Page 2 did not return 1 record");

    assert!(page2_body["cursor"].is_null() || page2_body["cursor"].as_str().is_none(), "Page 2 should not have a cursor");


    for rkey in created_rkeys {
        let delete_payload = json!({
            "repo": AUTH_DID,
            "collection": collection,
            "rkey": rkey
        });
        client.post(format!("{}/xrpc/com.atproto.repo.deleteRecord", BASE_URL))
            .bearer_auth(AUTH_TOKEN)
            .json(&delete_payload)
            .send()
            .await
            .expect("Failed to cleanup pagination post");
    }
}

#[tokio::test]
async fn test_reply_thread_lifecycle() {
    let client = client();

    let (root_uri, root_cid, root_rkey) = create_test_post(
        &client,
        "This is the root of the thread",
        None
    ).await;


    let reply_ref = json!({
        "root": { "uri": root_uri.clone(), "cid": root_cid.clone() },
        "parent": { "uri": root_uri.clone(), "cid": root_cid.clone() }
    });

    let (reply_uri, _reply_cid, reply_rkey) = create_test_post(
        &client,
        "This is a reply!",
        Some(reply_ref)
    ).await;


    let params = [
        ("uri", &root_uri),
    ];
    let res = client.get(format!("{}/xrpc/app.bsky.feed.getPostThread", BASE_URL))
        .query(&params)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send getPostThread");

    assert_eq!(res.status(), StatusCode::OK, "getPostThread did not return 200");
    let body: Value = res.json().await.expect("getPostThread response was not JSON");

    assert_eq!(body["thread"]["$type"], "app.bsky.feed.defs#threadViewPost");
    assert_eq!(body["thread"]["post"]["uri"], root_uri);

    let replies = body["thread"]["replies"].as_array().expect("replies was not an array");
    assert!(!replies.is_empty(), "Replies array is empty, but should contain the reply");

    let found_reply = replies.iter().find(|r| {
        r["post"]["uri"] == reply_uri
    });

    assert!(found_reply.is_some(), "Our specific reply was not found in the thread's replies");


    let collection = "app.bsky.feed.post";
    client.post(format!("{}/xrpc/com.atproto.repo.deleteRecord", BASE_URL))
        .bearer_auth(AUTH_TOKEN)
        .json(&json!({ "repo": AUTH_DID, "collection": collection, "rkey": reply_rkey }))
        .send().await.expect("Failed to delete reply");

    client.post(format!("{}/xrpc/com.atproto.repo.deleteRecord", BASE_URL))
        .bearer_auth(AUTH_TOKEN)
        .json(&json!({ "repo": AUTH_DID, "collection": collection, "rkey": root_rkey }))
        .send().await.expect("Failed to delete root post");
}

#[tokio::test]
async fn test_account_journey_lifecycle() {
    let client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("e2e-user-{}.test", ts);
    let email = format!("e2e-user-{}@test.com", ts);
    let password = "e2e-password-123";

    let create_account_payload = json!({
        "handle": handle,
        "email": email,
        "password": password
    });

    let create_res = client.post(format!("{}/xrpc/com.atproto.server.createAccount", BASE_URL))
        .json(&create_account_payload)
        .send()
        .await
        .expect("Failed to send createAccount");

    assert_eq!(create_res.status(), StatusCode::OK, "Failed to create account");
    let create_body: Value = create_res.json().await.expect("createAccount response was not JSON");

    let new_did = create_body["did"].as_str().expect("Response had no DID").to_string();
    let _new_jwt = create_body["accessJwt"].as_str().expect("Response had no accessJwt").to_string();
    assert_eq!(create_body["handle"], handle);


    let session_payload = json!({
        "identifier": handle,
        "password": password
    });

    let session_res = client.post(format!("{}/xrpc/com.atproto.server.createSession", BASE_URL))
        .json(&session_payload)
        .send()
        .await
        .expect("Failed to send createSession");

    assert_eq!(session_res.status(), StatusCode::OK, "Failed to create session");
    let session_body: Value = session_res.json().await.expect("createSession response was not JSON");

    let session_jwt = session_body["accessJwt"].as_str().expect("Session response had no accessJwt").to_string();
    assert_eq!(session_body["did"], new_did);


    let profile_payload = json!({
        "repo": new_did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self", // The rkey for a profile is always "self"
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "E2E Test User",
            "description": "A user created by the e2e test suite."
        }
    });

    let profile_res = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", BASE_URL))
        .bearer_auth(&session_jwt)
        .json(&profile_payload)
        .send()
        .await
        .expect("Failed to send putRecord for profile");

    assert_eq!(profile_res.status(), StatusCode::OK, "Failed to create profile");


    let params_get_profile = [
        ("actor", &handle),
    ];
    let get_profile_res = client.get(format!("{}/xrpc/app.bsky.actor.getProfile", BASE_URL))
        .query(&params_get_profile)
        .send()
        .await
        .expect("Failed to send getProfile");

    assert_eq!(get_profile_res.status(), StatusCode::OK, "getProfile did not return 200");
    let profile_body: Value = get_profile_res.json().await.expect("getProfile response was not JSON");

    assert_eq!(profile_body["did"], new_did);
    assert_eq!(profile_body["handle"], handle);
    assert_eq!(profile_body["displayName"], "E2E Test User");


    let logout_res = client.post(format!("{}/xrpc/com.atproto.server.deleteSession", BASE_URL))
        .bearer_auth(&session_jwt)
        .send()
        .await
        .expect("Failed to send deleteSession");

    assert_eq!(logout_res.status(), StatusCode::OK, "Failed to delete session");


    let get_session_res = client.get(format!("{}/xrpc/com.atproto.server.getSession", BASE_URL))
        .bearer_auth(&session_jwt)
        .send()
        .await
        .expect("Failed to send getSession");

    assert_eq!(get_session_res.status(), StatusCode::UNAUTHORIZED, "Session was still valid after logout");
}

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
    let create_res = client.post(format!("{}/xrpc/com.atproto.server.createAccount", BASE_URL))
        .json(&create_account_payload)
        .send()
        .await
        .expect("setup_new_user: Failed to send createAccount");
    assert_eq!(create_res.status(), StatusCode::OK, "setup_new_user: Failed to create account");
    let create_body: Value = create_res.json().await.expect("setup_new_user: createAccount response was not JSON");

    let new_did = create_body["did"].as_str().expect("setup_new_user: Response had no DID").to_string();
    let new_jwt = create_body["accessJwt"].as_str().expect("setup_new_user: Response had no accessJwt").to_string();

    let profile_payload = json!({
        "repo": new_did.clone(),
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": format!("E2E User {}", handle),
            "description": "A user created by the e2e test suite."
        }
    });
    let profile_res = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", BASE_URL))
        .bearer_auth(&new_jwt)
        .json(&profile_payload)
        .send()
        .await
        .expect("setup_new_user: Failed to send putRecord for profile");
    assert_eq!(profile_res.status(), StatusCode::OK, "setup_new_user: Failed to create profile");

    (new_did, new_jwt)
}

async fn create_record_as(
    client: &Client,
    jwt: &str,
    did: &str,
    collection: &str,
    record: Value,
) -> (String, String) {
    let payload = json!({
        "repo": did,
        "collection": collection,
        "record": record
    });

    let res = client.post(format!("{}/xrpc/com.atproto.repo.createRecord", BASE_URL))
        .bearer_auth(jwt)
        .json(&payload)
        .send()
        .await
        .expect("create_record_as: Failed to send createRecord");

    assert_eq!(res.status(), StatusCode::OK, "create_record_as: Failed to create record");
    let body: Value = res.json().await.expect("create_record_as: response was not JSON");

    let uri = body["uri"].as_str().expect("create_record_as: Response had no URI").to_string();
    let cid = body["cid"].as_str().expect("create_record_as: Response had no CID").to_string();
    (uri, cid)
}

async fn delete_record_as(
    client: &Client,
    jwt: &str,
    did: &str,
    collection: &str,
    rkey: &str,
) {
    let payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey
    });

    let res = client.post(format!("{}/xrpc/com.atproto.repo.deleteRecord", BASE_URL))
        .bearer_auth(jwt)
        .json(&payload)
        .send()
        .await
        .expect("delete_record_as: Failed to send deleteRecord");

    assert_eq!(res.status(), StatusCode::OK, "delete_record_as: Failed to delete record");
}


#[tokio::test]
async fn test_notification_lifecycle() {
    let client = client();

    let (user_a_did, user_a_jwt) = setup_new_user("user-a-notif").await;
    let (user_b_did, user_b_jwt) = setup_new_user("user-b-notif").await;

    let (post_uri, post_cid) = create_record_as(
        &client,
        &user_a_jwt,
        &user_a_did,
        "app.bsky.feed.post",
        json!({
            "$type": "app.bsky.feed.post",
            "text": "A post to be notified about",
            "createdAt": Utc::now().to_rfc3339()
        }),
    ).await;
    let post_ref = json!({ "uri": post_uri, "cid": post_cid });

    let count_res_1 = client.get(format!("{}/xrpc/app.bsky.notification.getUnreadCount", BASE_URL))
        .bearer_auth(&user_a_jwt)
        .send().await.expect("getUnreadCount 1 failed");
    let count_body_1: Value = count_res_1.json().await.expect("count 1 not json");
    assert_eq!(count_body_1["count"], 0, "Initial unread count was not 0");

    create_record_as(
        &client, &user_b_jwt, &user_b_did,
        "app.bsky.graph.follow",
        json!({
            "$type": "app.bsky.graph.follow",
            "subject": user_a_did,
            "createdAt": Utc::now().to_rfc3339()
        }),
    ).await;
    create_record_as(
        &client, &user_b_jwt, &user_b_did,
        "app.bsky.feed.like",
        json!({
            "$type": "app.bsky.feed.like",
            "subject": post_ref,
            "createdAt": Utc::now().to_rfc3339()
        }),
    ).await;
    create_record_as(
        &client, &user_b_jwt, &user_b_did,
        "app.bsky.feed.post",
        json!({
            "$type": "app.bsky.feed.post",
            "text": "This is a reply!",
            "reply": { "root": post_ref.clone(), "parent": post_ref.clone() },
            "createdAt": Utc::now().to_rfc3339()
        }),
    ).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let count_res_2 = client.get(format!("{}/xrpc/app.bsky.notification.getUnreadCount", BASE_URL))
        .bearer_auth(&user_a_jwt)
        .send().await.expect("getUnreadCount 2 failed");
    let count_body_2: Value = count_res_2.json().await.expect("count 2 not json");
    assert_eq!(count_body_2["count"], 3, "Unread count was not 3 after actions");

    let list_res = client.get(format!("{}/xrpc/app.bsky.notification.listNotifications", BASE_URL))
        .bearer_auth(&user_a_jwt)
        .send().await.expect("listNotifications failed");
    let list_body: Value = list_res.json().await.expect("list not json");

    let notifs = list_body["notifications"].as_array().expect("notifications not array");
    assert_eq!(notifs.len(), 3, "Notification list did not have 3 items");

    let has_follow = notifs.iter().any(|n| n["reason"] == "follow" && n["author"]["did"] == user_b_did);
    let has_like = notifs.iter().any(|n| n["reason"] == "like" && n["author"]["did"] == user_b_did);
    let has_reply = notifs.iter().any(|n| n["reason"] == "reply" && n["author"]["did"] == user_b_did);

    assert!(has_follow, "Notification list missing 'follow'");
    assert!(has_like, "Notification list missing 'like'");
    assert!(has_reply, "Notification list missing 'reply'");

    let count_res_3 = client.get(format!("{}/xrpc/app.bsky.notification.getUnreadCount", BASE_URL))
        .bearer_auth(&user_a_jwt)
        .send().await.expect("getUnreadCount 3 failed");
    let count_body_3: Value = count_res_3.json().await.expect("count 3 not json");
    assert_eq!(count_body_3["count"], 0, "Unread count was not 0 after list");
}


#[tokio::test]
async fn test_mute_lifecycle_filters_feed() {
    let client = client();

    let (user_a_did, user_a_jwt) = setup_new_user("user-a-mute").await;
    let (user_b_did, user_b_jwt) = setup_new_user("user-b-mute").await;

    let (post_uri, _) = create_record_as(
        &client,
        &user_b_jwt,
        &user_b_did,
        "app.bsky.feed.post",
        json!({
            "$type": "app.bsky.feed.post",
            "text": "A post from User B",
            "createdAt": Utc::now().to_rfc3339()
        }),
    ).await;

    let feed_params_1 = [("actor", &user_b_did)];
    let feed_res_1 = client.get(format!("{}/xrpc/app.bsky.feed.getAuthorFeed", BASE_URL))
        .query(&feed_params_1)
        .bearer_auth(&user_a_jwt)
        .send().await.expect("getAuthorFeed 1 failed");
    let feed_body_1: Value = feed_res_1.json().await.expect("feed 1 not json");

    let feed_1 = feed_body_1["feed"].as_array().expect("feed 1 not array");
    let found_post_1 = feed_1.iter().any(|p| p["post"]["uri"] == post_uri);
    assert!(found_post_1, "User B's post was not in their feed before mute");

    let (mute_uri, _) = create_record_as(
        &client, &user_a_jwt, &user_a_did,
        "app.bsky.graph.mute",
        json!({
            "$type": "app.bsky.graph.mute",
            "subject": user_b_did,
            "createdAt": Utc::now().to_rfc3339()
        }),
    ).await;
    let mute_rkey = mute_uri.split('/').last().unwrap();

    let feed_params_2 = [("actor", &user_b_did)];
    let feed_res_2 = client.get(format!("{}/xrpc/app.bsky.feed.getAuthorFeed", BASE_URL))
        .query(&feed_params_2)
        .bearer_auth(&user_a_jwt)
        .send().await.expect("getAuthorFeed 2 failed");
    let feed_body_2: Value = feed_res_2.json().await.expect("feed 2 not json");

    let feed_2 = feed_body_2["feed"].as_array().expect("feed 2 not array");
    assert!(feed_2.is_empty(), "User B's feed was not empty after mute");

    delete_record_as(
        &client, &user_a_jwt, &user_a_did,
        "app.bsky.graph.mute",
        mute_rkey,
    ).await;

    let feed_params_3 = [("actor", &user_b_did)];
    let feed_res_3 = client.get(format!("{}/xrpc/app.bsky.feed.getAuthorFeed", BASE_URL))
        .query(&feed_params_3)
        .bearer_auth(&user_a_jwt)
        .send().await.expect("getAuthorFeed 3 failed");
    let feed_body_3: Value = feed_res_3.json().await.expect("feed 3 not json");

    let feed_3 = feed_body_3["feed"].as_array().expect("feed 3 not array");
    let found_post_3 = feed_3.iter().any(|p| p["post"]["uri"] == post_uri);
    assert!(found_post_3, "User B's post did not reappear after unmute");
}


#[tokio::test]
async fn test_record_update_conflict_lifecycle() {
    let client = client();

    let (user_did, user_jwt) = setup_new_user("user-conflict").await;

    let get_res = client.get(format!("{}/xrpc/com.atproto.repo.getRecord", BASE_URL))
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
    let update_res_v2 = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", BASE_URL))
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
    let update_res_v3_stale = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", BASE_URL))
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
    let update_res_v3_good = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", BASE_URL))
        .bearer_auth(&user_jwt)
        .json(&update_payload_v3_good)
        .send().await.expect("putRecord v3 (good) failed");

    assert_eq!(update_res_v3_good.status(), StatusCode::OK, "v3 (good) update failed");
}


#[tokio::test]
async fn test_complex_thread_deletion_lifecycle() {
    let client = client();

    let (user_a_did, user_a_jwt) = setup_new_user("user-a-thread").await;
    let (user_b_did, user_b_jwt) = setup_new_user("user-b-thread").await;
    let (user_c_did, user_c_jwt) = setup_new_user("user-c-thread").await;

    let (p1_uri, p1_cid) = create_record_as(
        &client, &user_a_jwt, &user_a_did,
        "app.bsky.feed.post",
        json!({
            "$type": "app.bsky.feed.post",
            "text": "P1 (Root)",
            "createdAt": Utc::now().to_rfc3339()
        }),
    ).await;
    let p1_ref = json!({ "uri": p1_uri.clone(), "cid": p1_cid.clone() });

    let (p2_uri, p2_cid) = create_record_as(
        &client, &user_b_jwt, &user_b_did,
        "app.bsky.feed.post",
        json!({
            "$type": "app.bsky.feed.post",
            "text": "P2 (Reply)",
            "reply": { "root": p1_ref.clone(), "parent": p1_ref.clone() },
            "createdAt": Utc::now().to_rfc3339()
        }),
    ).await;
    let p2_ref = json!({ "uri": p2_uri.clone(), "cid": p2_cid.clone() });
    let p2_rkey = p2_uri.split('/').last().unwrap().to_string();

    let (p3_uri, _) = create_record_as(
        &client, &user_c_jwt, &user_c_did,
        "app.bsky.feed.post",
        json!({
            "$type": "app.bsky.feed.post",
            "text": "P3 (Grandchild)",
            "reply": { "root": p1_ref.clone(), "parent": p2_ref.clone() },
            "createdAt": Utc::now().to_rfc3339()
        }),
    ).await;

    let thread_res_1 = client.get(format!("{}/xrpc/app.bsky.feed.getPostThread", BASE_URL))
        .query(&[("uri", &p1_uri)])
        .bearer_auth(&user_a_jwt)
        .send().await.expect("getThread 1 failed");
    let thread_body_1: Value = thread_res_1.json().await.expect("thread 1 not json");

    let p1_replies = thread_body_1["thread"]["replies"].as_array().unwrap();
    assert_eq!(p1_replies.len(), 1, "P1 should have 1 reply");
    assert_eq!(p1_replies[0]["post"]["uri"], p2_uri, "P1's reply is not P2");

    let p2_replies = p1_replies[0]["replies"].as_array().unwrap();
    assert_eq!(p2_replies.len(), 1, "P2 should have 1 reply");
    assert_eq!(p2_replies[0]["post"]["uri"], p3_uri, "P2's reply is not P3");

    delete_record_as(
        &client, &user_b_jwt, &user_b_did,
        "app.bsky.feed.post",
        &p2_rkey,
    ).await;

    let thread_res_2 = client.get(format!("{}/xrpc/app.bsky.feed.getPostThread", BASE_URL))
        .query(&[("uri", &p1_uri)])
        .bearer_auth(&user_a_jwt)
        .send().await.expect("getThread 2 failed");
    let thread_body_2: Value = thread_res_2.json().await.expect("thread 2 not json");

    let p1_replies_2 = thread_body_2["thread"]["replies"].as_array().unwrap();
    assert_eq!(p1_replies_2.len(), 1, "P1 should still have 1 reply (the deleted one)");

    let deleted_post = &p1_replies_2[0];
    assert_eq!(
        deleted_post["$type"], "app.bsky.feed.defs#notFoundPost",
        "P2 did not appear as a notFoundPost"
    );
    assert_eq!(deleted_post["uri"], p2_uri, "notFoundPost URI does not match P2");

    let p3_reply = deleted_post["replies"].as_array().unwrap();
    assert_eq!(p3_reply.len(), 1, "notFoundPost should still have P3 as a reply");
    assert_eq!(p3_reply[0]["post"]["uri"], p3_uri, "The reply to the deleted post is not P3");
}
