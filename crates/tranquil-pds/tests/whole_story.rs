mod common;
mod helpers;

use chrono::Utc;
use common::*;
use futures::{StreamExt, future::join_all};
use helpers::*;
use k256::ecdsa::SigningKey;
use reqwest::{StatusCode, header};
use serde_json::{Value, json};

#[tokio::test]
async fn test_complete_user_journey_signup_to_deletion() {
    let client = client();
    let base = base_url().await;
    let uid = uuid::Uuid::new_v4().simple().to_string();
    let handle = format!("journey{}", &uid[..8]);
    let email = format!("journey{}@test.com", &uid[..8]);
    let password = "JourneyPass123!";

    let create_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Account creation failed");
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap().to_string();

    let jwt = verify_new_account(&client, &did).await;

    let blob_data = b"This is my avatar image data for the complete journey test";
    let upload_res = client
        .post(format!("{}/xrpc/com.atproto.repo.uploadBlob", base))
        .header(header::CONTENT_TYPE, "image/png")
        .bearer_auth(&jwt)
        .body(blob_data.to_vec())
        .send()
        .await
        .expect("Blob upload failed");
    assert_eq!(upload_res.status(), StatusCode::OK);
    let upload_body: Value = upload_res.json().await.unwrap();
    let avatar_blob = upload_body["blob"].clone();

    let profile_res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.actor.profile",
            "rkey": "self",
            "record": {
                "$type": "app.bsky.actor.profile",
                "displayName": "Journey Test User",
                "description": "Testing the complete user journey",
                "avatar": avatar_blob
            }
        }))
        .send()
        .await
        .expect("Profile creation failed");
    assert_eq!(profile_res.status(), StatusCode::OK);

    let post1_res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "My first post on this journey!",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .expect("First post failed");
    assert_eq!(post1_res.status(), StatusCode::OK);
    let post1_body: Value = post1_res.json().await.unwrap();
    let post1_uri = post1_body["uri"].as_str().unwrap();
    let post1_cid = post1_body["cid"].as_str().unwrap();

    let post2_res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Second post in my journey",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .expect("Second post failed");
    assert_eq!(post2_res.status(), StatusCode::OK);

    let list_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(&jwt)
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .expect("List records failed");
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body: Value = list_res.json().await.unwrap();
    assert_eq!(list_body["records"].as_array().unwrap().len(), 2);

    let post1_rkey = post1_uri.split('/').next_back().unwrap();
    let edit_res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "rkey": post1_rkey,
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "My first post on this journey! (edited)",
                "createdAt": Utc::now().to_rfc3339()
            },
            "swapRecord": post1_cid
        }))
        .send()
        .await
        .expect("Edit post failed");
    assert_eq!(edit_res.status(), StatusCode::OK);

    let backup_res = client
        .post(format!("{}/xrpc/_backup.createBackup", base))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Backup creation failed");
    assert_eq!(backup_res.status(), StatusCode::OK);
    let backup_body: Value = backup_res.json().await.unwrap();
    let backup_id = backup_body["id"].as_str().unwrap();

    let download_res = client
        .get(format!("{}/xrpc/_backup.getBackup?id={}", base, backup_id))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Backup download failed");
    assert_eq!(download_res.status(), StatusCode::OK);
    let backup_bytes = download_res.bytes().await.unwrap();
    assert!(backup_bytes.len() > 100, "Backup should have content");

    let delete_res = client
        .post(format!("{}/xrpc/com.atproto.server.deleteSession", base))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Logout failed");
    assert!(delete_res.status() == StatusCode::OK || delete_res.status() == StatusCode::NO_CONTENT);

    let login_res = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": password
        }))
        .send()
        .await
        .expect("Re-login failed");
    assert_eq!(login_res.status(), StatusCode::OK);
    let login_body: Value = login_res.json().await.unwrap();
    let new_jwt = login_body["accessJwt"].as_str().unwrap();

    let verify_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(new_jwt)
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .expect("Verify after re-login failed");
    assert_eq!(verify_res.status(), StatusCode::OK);
    let verify_body: Value = verify_res.json().await.unwrap();
    assert_eq!(verify_body["records"].as_array().unwrap().len(), 2);

    let request_delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestAccountDelete",
            base
        ))
        .bearer_auth(new_jwt)
        .send()
        .await
        .expect("Request delete failed");
    assert_eq!(request_delete_res.status(), StatusCode::OK);

    let pool = get_test_db_pool().await;
    let row = sqlx::query!(
        "SELECT token FROM account_deletion_requests WHERE did = $1",
        did
    )
    .fetch_one(pool)
    .await
    .expect("Failed to get deletion token");

    let final_delete_res = client
        .post(format!("{}/xrpc/com.atproto.server.deleteAccount", base))
        .json(&json!({
            "did": did,
            "password": password,
            "token": row.token
        }))
        .send()
        .await
        .expect("Final delete failed");
    assert_eq!(final_delete_res.status(), StatusCode::OK);

    let user_gone = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(pool)
        .await
        .expect("Failed to check user");
    assert!(user_gone.is_none(), "User should be deleted");
}

#[tokio::test]
async fn test_multi_user_social_graph_lifecycle() {
    let client = client();
    let base = base_url().await;

    let (alice_did, alice_jwt) = setup_new_user("alice-social").await;
    let (bob_did, bob_jwt) = setup_new_user("bob-social").await;
    let (carol_did, carol_jwt) = setup_new_user("carol-social").await;

    let (alice_post_uri, alice_post_cid) =
        create_post(&client, &alice_did, &alice_jwt, "Hello from Alice!").await;

    let (bob_post_uri, bob_post_cid) =
        create_post(&client, &bob_did, &bob_jwt, "Hello from Bob!").await;

    let (_bob_follows_alice_uri, _) = create_follow(&client, &bob_did, &bob_jwt, &alice_did).await;
    let (_carol_follows_alice_uri, _) =
        create_follow(&client, &carol_did, &carol_jwt, &alice_did).await;
    let (_carol_follows_bob_uri, _) =
        create_follow(&client, &carol_did, &carol_jwt, &bob_did).await;

    let (_bob_likes_alice_uri, _) = create_like(
        &client,
        &bob_did,
        &bob_jwt,
        &alice_post_uri,
        &alice_post_cid,
    )
    .await;
    let (_carol_likes_alice_uri, _) = create_like(
        &client,
        &carol_did,
        &carol_jwt,
        &alice_post_uri,
        &alice_post_cid,
    )
    .await;

    let (_bob_reposts_alice_uri, _) = create_repost(
        &client,
        &bob_did,
        &bob_jwt,
        &alice_post_uri,
        &alice_post_cid,
    )
    .await;

    let reply_res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(&carol_jwt)
        .json(&json!({
            "repo": carol_did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Great post Alice!",
                "createdAt": Utc::now().to_rfc3339(),
                "reply": {
                    "root": { "uri": alice_post_uri, "cid": alice_post_cid },
                    "parent": { "uri": alice_post_uri, "cid": alice_post_cid }
                }
            }
        }))
        .send()
        .await
        .expect("Reply failed");
    assert_eq!(reply_res.status(), StatusCode::OK);
    let reply_body: Value = reply_res.json().await.unwrap();
    let carol_reply_uri = reply_body["uri"].as_str().unwrap();
    let carol_reply_cid = reply_body["cid"].as_str().unwrap();

    let alice_reply_res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(&alice_jwt)
        .json(&json!({
            "repo": alice_did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Thanks Carol!",
                "createdAt": Utc::now().to_rfc3339(),
                "reply": {
                    "root": { "uri": alice_post_uri, "cid": alice_post_cid },
                    "parent": { "uri": carol_reply_uri, "cid": carol_reply_cid }
                }
            }
        }))
        .send()
        .await
        .expect("Alice reply failed");
    assert_eq!(alice_reply_res.status(), StatusCode::OK);

    let alice_follows_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .query(&[
            ("repo", alice_did.as_str()),
            ("collection", "app.bsky.graph.follow"),
        ])
        .send()
        .await
        .unwrap();
    let alice_follows: Value = alice_follows_res.json().await.unwrap();
    assert_eq!(
        alice_follows["records"].as_array().unwrap().len(),
        0,
        "Alice follows nobody"
    );

    let bob_follows_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .query(&[
            ("repo", bob_did.as_str()),
            ("collection", "app.bsky.graph.follow"),
        ])
        .send()
        .await
        .unwrap();
    let bob_follows: Value = bob_follows_res.json().await.unwrap();
    assert_eq!(
        bob_follows["records"].as_array().unwrap().len(),
        1,
        "Bob follows 1 person"
    );

    let carol_follows_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .query(&[
            ("repo", carol_did.as_str()),
            ("collection", "app.bsky.graph.follow"),
        ])
        .send()
        .await
        .unwrap();
    let carol_follows: Value = carol_follows_res.json().await.unwrap();
    assert_eq!(
        carol_follows["records"].as_array().unwrap().len(),
        2,
        "Carol follows 2 people"
    );

    let bob_likes_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .query(&[
            ("repo", bob_did.as_str()),
            ("collection", "app.bsky.feed.like"),
        ])
        .send()
        .await
        .unwrap();
    let bob_likes: Value = bob_likes_res.json().await.unwrap();
    assert_eq!(bob_likes["records"].as_array().unwrap().len(), 1);

    let alice_posts_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .query(&[
            ("repo", alice_did.as_str()),
            ("collection", "app.bsky.feed.post"),
        ])
        .send()
        .await
        .unwrap();
    let alice_posts: Value = alice_posts_res.json().await.unwrap();
    assert_eq!(
        alice_posts["records"].as_array().unwrap().len(),
        2,
        "Alice has 2 posts (original + reply)"
    );

    let bob_likes_rkey = bob_likes["records"][0]["uri"]
        .as_str()
        .unwrap()
        .split('/')
        .next_back()
        .unwrap();
    let unlike_res = client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", base))
        .bearer_auth(&bob_jwt)
        .json(&json!({
            "repo": bob_did,
            "collection": "app.bsky.feed.like",
            "rkey": bob_likes_rkey
        }))
        .send()
        .await
        .expect("Unlike failed");
    assert_eq!(unlike_res.status(), StatusCode::OK);

    let bob_likes_after = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .query(&[
            ("repo", bob_did.as_str()),
            ("collection", "app.bsky.feed.like"),
        ])
        .send()
        .await
        .unwrap();
    let bob_likes_after_body: Value = bob_likes_after.json().await.unwrap();
    assert_eq!(bob_likes_after_body["records"].as_array().unwrap().len(), 0);

    let relike_res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(&bob_jwt)
        .json(&json!({
            "repo": bob_did,
            "collection": "app.bsky.feed.like",
            "record": {
                "$type": "app.bsky.feed.like",
                "subject": { "uri": alice_post_uri, "cid": alice_post_cid },
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .expect("Relike failed");
    assert_eq!(relike_res.status(), StatusCode::OK);

    let (_alice_likes_bob_uri, _) = create_like(
        &client,
        &alice_did,
        &alice_jwt,
        &bob_post_uri,
        &bob_post_cid,
    )
    .await;

    let mutual_follow_res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(&alice_jwt)
        .json(&json!({
            "repo": alice_did,
            "collection": "app.bsky.graph.follow",
            "record": {
                "$type": "app.bsky.graph.follow",
                "subject": bob_did,
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .expect("Mutual follow failed");
    assert_eq!(mutual_follow_res.status(), StatusCode::OK);

    let alice_final_follows = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .query(&[
            ("repo", alice_did.as_str()),
            ("collection", "app.bsky.graph.follow"),
        ])
        .send()
        .await
        .unwrap();
    let alice_final: Value = alice_final_follows.json().await.unwrap();
    assert_eq!(alice_final["records"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_blob_lifecycle_upload_use_remove() {
    let client = client();
    let base = base_url().await;
    let (did, jwt) = setup_new_user("blob-lifecycle").await;

    let blob1_data = b"First blob for testing lifecycle";
    let upload1_res = client
        .post(format!("{}/xrpc/com.atproto.repo.uploadBlob", base))
        .header(header::CONTENT_TYPE, "text/plain")
        .bearer_auth(&jwt)
        .body(blob1_data.to_vec())
        .send()
        .await
        .expect("Upload 1 failed");
    assert_eq!(upload1_res.status(), StatusCode::OK);
    let upload1_body: Value = upload1_res.json().await.unwrap();
    let blob1 = upload1_body["blob"].clone();
    let blob1_cid = blob1["ref"]["$link"].as_str().unwrap();

    let blob2_data = b"Second blob for testing lifecycle";
    let upload2_res = client
        .post(format!("{}/xrpc/com.atproto.repo.uploadBlob", base))
        .header(header::CONTENT_TYPE, "text/plain")
        .bearer_auth(&jwt)
        .body(blob2_data.to_vec())
        .send()
        .await
        .expect("Upload 2 failed");
    assert_eq!(upload2_res.status(), StatusCode::OK);
    let upload2_body: Value = upload2_res.json().await.unwrap();
    let blob2 = upload2_body["blob"].clone();
    let _blob2_cid = blob2["ref"]["$link"].as_str().unwrap();

    let post_res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Post with images",
                "createdAt": Utc::now().to_rfc3339(),
                "embed": {
                    "$type": "app.bsky.embed.images",
                    "images": [
                        { "alt": "First image", "image": blob1 },
                        { "alt": "Second image", "image": blob2 }
                    ]
                }
            }
        }))
        .send()
        .await
        .expect("Post with blobs failed");
    assert_eq!(post_res.status(), StatusCode::OK);
    let post_body: Value = post_res.json().await.unwrap();
    let post_uri = post_body["uri"].as_str().unwrap();
    let post_cid = post_body["cid"].as_str().unwrap();
    let post_rkey = post_uri.split('/').next_back().unwrap();

    let get_blob1 = client
        .get(format!("{}/xrpc/com.atproto.sync.getBlob", base))
        .query(&[("did", did.as_str()), ("cid", blob1_cid)])
        .send()
        .await
        .expect("Get blob 1 failed");
    assert_eq!(get_blob1.status(), StatusCode::OK);
    let blob1_content = get_blob1.bytes().await.unwrap();
    assert_eq!(blob1_content.as_ref(), blob1_data);

    let get_record = client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", base))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", post_rkey),
        ])
        .send()
        .await
        .expect("Get record failed");
    let record_body: Value = get_record.json().await.unwrap();
    let images = record_body["value"]["embed"]["images"].as_array().unwrap();
    assert_eq!(images.len(), 2);

    let edit_res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "rkey": post_rkey,
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Post with single image now",
                "createdAt": Utc::now().to_rfc3339(),
                "embed": {
                    "$type": "app.bsky.embed.images",
                    "images": [
                        { "alt": "Only first image", "image": blob1 }
                    ]
                }
            },
            "swapRecord": post_cid
        }))
        .send()
        .await
        .expect("Edit failed");
    assert_eq!(edit_res.status(), StatusCode::OK);

    let get_edited = client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", base))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", post_rkey),
        ])
        .send()
        .await
        .unwrap();
    let edited_body: Value = get_edited.json().await.unwrap();
    let edited_images = edited_body["value"]["embed"]["images"].as_array().unwrap();
    assert_eq!(edited_images.len(), 1);

    let profile_res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.actor.profile",
            "rkey": "self",
            "record": {
                "$type": "app.bsky.actor.profile",
                "displayName": "Blob Test User",
                "avatar": blob1
            }
        }))
        .send()
        .await
        .expect("Profile failed");
    assert_eq!(profile_res.status(), StatusCode::OK);

    let list_blobs = client
        .get(format!("{}/xrpc/com.atproto.sync.listBlobs", base))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("List blobs failed");
    assert_eq!(list_blobs.status(), StatusCode::OK);
    let blobs_body: Value = list_blobs.json().await.unwrap();
    let cids = blobs_body["cids"].as_array().unwrap();
    assert!(
        cids.iter().any(|c| c.as_str() == Some(blob1_cid)),
        "blob1 should still exist (referenced by profile and post)"
    );
}

#[tokio::test]
async fn test_session_and_record_interaction() {
    let client = client();
    let base = base_url().await;
    let uid = uuid::Uuid::new_v4().simple().to_string();
    let handle = format!("sess{}", &uid[..8]);
    let email = format!("sess{}@test.com", &uid[..8]);
    let password = "SessionTest123!";

    let create_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Account creation failed");
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap().to_string();
    let jwt = verify_new_account(&client, &did).await;

    let (post1_uri, _) = create_post(&client, &did, &jwt, "Post from session 1").await;

    let session2_res = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": password
        }))
        .send()
        .await
        .expect("Session 2 creation failed");
    assert_eq!(session2_res.status(), StatusCode::OK);
    let session2: Value = session2_res.json().await.unwrap();
    let jwt2 = session2["accessJwt"].as_str().unwrap();
    let refresh2 = session2["refreshJwt"].as_str().unwrap();

    let (post2_uri, _) = create_post(&client, &did, jwt2, "Post from session 2").await;

    let list_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(&jwt)
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .unwrap();
    let list_body: Value = list_res.json().await.unwrap();
    assert_eq!(
        list_body["records"].as_array().unwrap().len(),
        2,
        "Both posts visible from session 1"
    );

    let refresh_res = client
        .post(format!("{}/xrpc/com.atproto.server.refreshSession", base))
        .bearer_auth(refresh2)
        .send()
        .await
        .expect("Refresh failed");
    assert_eq!(refresh_res.status(), StatusCode::OK);
    let refresh_body: Value = refresh_res.json().await.unwrap();
    let new_jwt2 = refresh_body["accessJwt"].as_str().unwrap();

    let verify_posts = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(new_jwt2)
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .unwrap();
    let verify_body: Value = verify_posts.json().await.unwrap();
    assert_eq!(
        verify_body["records"].as_array().unwrap().len(),
        2,
        "Posts still visible after token refresh"
    );

    let post1_rkey = post1_uri.split('/').next_back().unwrap();
    let delete_res = client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", base))
        .bearer_auth(new_jwt2)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "rkey": post1_rkey
        }))
        .send()
        .await
        .expect("Delete from session 2 failed");
    assert_eq!(delete_res.status(), StatusCode::OK);

    let final_list = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(&jwt)
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .unwrap();
    let final_body: Value = final_list.json().await.unwrap();
    let remaining_posts = final_body["records"].as_array().unwrap();
    assert_eq!(remaining_posts.len(), 1);
    assert!(
        remaining_posts[0]["uri"]
            .as_str()
            .unwrap()
            .contains(post2_uri.split('/').next_back().unwrap())
    );
}

#[tokio::test]
async fn test_app_password_record_lifecycle() {
    let client = client();
    let base = base_url().await;
    let uid = uuid::Uuid::new_v4().simple().to_string();
    let handle = format!("apprec{}", &uid[..8]);
    let email = format!("apprec{}@test.com", &uid[..8]);
    let password = "AppRecTest123!";

    let create_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Account creation failed");
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap().to_string();
    let main_jwt = verify_new_account(&client, &did).await;

    let create_app_pass = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAppPassword",
            base
        ))
        .bearer_auth(&main_jwt)
        .json(&json!({ "name": "Test App" }))
        .send()
        .await
        .expect("App password creation failed");
    assert_eq!(create_app_pass.status(), StatusCode::OK);
    let app_pass_body: Value = create_app_pass.json().await.unwrap();
    let app_password = app_pass_body["password"].as_str().unwrap();

    let app_login = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": app_password
        }))
        .send()
        .await
        .expect("App password login failed");
    assert_eq!(app_login.status(), StatusCode::OK);
    let app_session: Value = app_login.json().await.unwrap();
    let app_jwt = app_session["accessJwt"].as_str().unwrap();

    create_post(&client, &did, app_jwt, "Post from app password session").await;

    let verify_main = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(&main_jwt)
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .unwrap();
    let verify_body: Value = verify_main.json().await.unwrap();
    assert_eq!(
        verify_body["records"].as_array().unwrap().len(),
        1,
        "Post visible from main session"
    );

    let revoke_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.revokeAppPassword",
            base
        ))
        .bearer_auth(&main_jwt)
        .json(&json!({ "name": "Test App" }))
        .send()
        .await
        .expect("Revoke failed");
    assert_eq!(revoke_res.status(), StatusCode::OK);

    let post_after_revoke = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(app_jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Should fail",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .expect("Post attempt failed");
    assert!(
        post_after_revoke.status() == StatusCode::UNAUTHORIZED
            || post_after_revoke.status() == StatusCode::BAD_REQUEST,
        "Revoked app password should not create posts"
    );

    let final_list = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(&main_jwt)
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .unwrap();
    let final_body: Value = final_list.json().await.unwrap();
    assert_eq!(
        final_body["records"].as_array().unwrap().len(),
        1,
        "Only the valid post should exist"
    );
}

#[tokio::test]
async fn test_handle_change_with_existing_content() {
    let client = client();
    let base = base_url().await;
    let (did, jwt) = setup_new_user("handlechange").await;

    let (post_uri, post_cid) = create_post(&client, &did, &jwt, "Post before handle change").await;

    let profile_res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.actor.profile",
            "rkey": "self",
            "record": {
                "$type": "app.bsky.actor.profile",
                "displayName": "Original Handle User"
            }
        }))
        .send()
        .await
        .expect("Profile creation failed");
    assert_eq!(profile_res.status(), StatusCode::OK);

    let (other_did, other_jwt) = setup_new_user("other-user").await;
    let (_like_uri, _) = create_like(&client, &other_did, &other_jwt, &post_uri, &post_cid).await;
    let (_follow_uri, _) = create_follow(&client, &other_did, &other_jwt, &did).await;

    let new_handle = format!("newh{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let update_res = client
        .post(format!("{}/xrpc/com.atproto.identity.updateHandle", base))
        .bearer_auth(&jwt)
        .json(&json!({ "handle": new_handle }))
        .send()
        .await
        .expect("Handle update failed");
    assert_eq!(update_res.status(), StatusCode::OK);

    let session_res = client
        .get(format!("{}/xrpc/com.atproto.server.getSession", base))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Get session failed");
    let session_body: Value = session_res.json().await.unwrap();
    assert!(
        session_body["handle"]
            .as_str()
            .unwrap()
            .starts_with(&new_handle),
        "Handle should be updated"
    );

    let posts_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(&jwt)
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .unwrap();
    let posts_body: Value = posts_res.json().await.unwrap();
    assert_eq!(
        posts_body["records"].as_array().unwrap().len(),
        1,
        "Post should still exist after handle change"
    );

    let profile_check = client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", base))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.actor.profile"),
            ("rkey", "self"),
        ])
        .send()
        .await
        .unwrap();
    let profile_body: Value = profile_check.json().await.unwrap();
    assert_eq!(
        profile_body["value"]["displayName"], "Original Handle User",
        "Profile should be intact"
    );

    let other_follows = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .query(&[
            ("repo", other_did.as_str()),
            ("collection", "app.bsky.graph.follow"),
        ])
        .send()
        .await
        .unwrap();
    let follows_body: Value = other_follows.json().await.unwrap();
    let follows = follows_body["records"].as_array().unwrap();
    assert_eq!(follows.len(), 1);
    assert_eq!(
        follows[0]["value"]["subject"], did,
        "Follow should still point to the DID"
    );

    let resolve_res = client
        .get(format!("{}/xrpc/com.atproto.identity.resolveHandle", base))
        .query(&[("handle", session_body["handle"].as_str().unwrap())])
        .send()
        .await
        .expect("Resolve failed");
    assert_eq!(resolve_res.status(), StatusCode::OK);
    let resolve_body: Value = resolve_res.json().await.unwrap();
    assert_eq!(
        resolve_body["did"], did,
        "New handle should resolve to same DID"
    );
}

#[tokio::test]
async fn test_deactivation_preserves_data() {
    let client = client();
    let base = base_url().await;
    let (did, jwt) = setup_new_user("deactivate-data").await;

    create_post(&client, &did, &jwt, "Post 1 before deactivation").await;
    create_post(&client, &did, &jwt, "Post 2 before deactivation").await;

    let profile_res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.actor.profile",
            "rkey": "self",
            "record": {
                "$type": "app.bsky.actor.profile",
                "displayName": "Deactivation Test User"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(profile_res.status(), StatusCode::OK);

    let deactivate_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deactivateAccount",
            base
        ))
        .bearer_auth(&jwt)
        .json(&json!({}))
        .send()
        .await
        .expect("Deactivation failed");
    assert_eq!(deactivate_res.status(), StatusCode::OK);

    let posts_while_deactivated = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .unwrap();
    assert_eq!(posts_while_deactivated.status(), StatusCode::OK);
    let posts_body: Value = posts_while_deactivated.json().await.unwrap();
    assert_eq!(
        posts_body["records"].as_array().unwrap().len(),
        2,
        "Posts should still be readable while deactivated"
    );

    let activate_res = client
        .post(format!("{}/xrpc/com.atproto.server.activateAccount", base))
        .bearer_auth(&jwt)
        .json(&json!({}))
        .send()
        .await
        .expect("Activation failed");
    assert_eq!(activate_res.status(), StatusCode::OK);

    create_post(&client, &did, &jwt, "Post 3 after reactivation").await;

    let final_posts = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(&jwt)
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .unwrap();
    let final_body: Value = final_posts.json().await.unwrap();
    assert_eq!(
        final_body["records"].as_array().unwrap().len(),
        3,
        "All three posts should exist"
    );
}

#[tokio::test]
async fn test_password_change_session_behavior() {
    let client = client();
    let base = base_url().await;
    let uid = uuid::Uuid::new_v4().simple().to_string();
    let handle = format!("pwch{}", &uid[..8]);
    let email = format!("pwch{}@test.com", &uid[..8]);
    let old_password = "OldPassword123!";
    let new_password = "NewPassword456!";

    let create_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": old_password
        }))
        .send()
        .await
        .expect("Account creation failed");
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap().to_string();
    let jwt1 = verify_new_account(&client, &did).await;

    create_post(&client, &did, &jwt1, "Post before password change").await;

    let change_pw_res = client
        .post(format!("{}/xrpc/_account.changePassword", base))
        .bearer_auth(&jwt1)
        .json(&json!({
            "currentPassword": old_password,
            "newPassword": new_password
        }))
        .send()
        .await
        .expect("Password change failed");
    assert_eq!(change_pw_res.status(), StatusCode::OK);

    let old_pw_login = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": old_password
        }))
        .send()
        .await
        .unwrap();
    assert!(
        old_pw_login.status() == StatusCode::UNAUTHORIZED
            || old_pw_login.status() == StatusCode::BAD_REQUEST,
        "Old password should not work"
    );

    let new_pw_login = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": new_password
        }))
        .send()
        .await
        .expect("New password login failed");
    assert_eq!(new_pw_login.status(), StatusCode::OK);
    let new_session: Value = new_pw_login.json().await.unwrap();
    let new_jwt = new_session["accessJwt"].as_str().unwrap();

    let posts_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(new_jwt)
        .query(&[("repo", did.as_str()), ("collection", "app.bsky.feed.post")])
        .send()
        .await
        .unwrap();
    let posts_body: Value = posts_res.json().await.unwrap();
    assert_eq!(
        posts_body["records"].as_array().unwrap().len(),
        1,
        "Post should still exist after password change"
    );
}

#[tokio::test]
async fn test_backup_restore_workflow() {
    let client = client();
    let base = base_url().await;
    let (did, jwt) = setup_new_user("backup-restore").await;

    futures::future::join_all((0..3).map(|i| {
        let client = client.clone();
        let did = did.clone();
        let jwt = jwt.clone();
        async move {
            create_post(&client, &did, &jwt, &format!("Post {} for backup test", i)).await;
        }
    }))
    .await;

    let blob_data = b"Blob data for backup test";
    let upload_res = client
        .post(format!("{}/xrpc/com.atproto.repo.uploadBlob", base))
        .header(header::CONTENT_TYPE, "text/plain")
        .bearer_auth(&jwt)
        .body(blob_data.to_vec())
        .send()
        .await
        .expect("Blob upload failed");
    assert_eq!(upload_res.status(), StatusCode::OK);
    let upload_body: Value = upload_res.json().await.unwrap();
    let blob = upload_body["blob"].clone();

    let profile_res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.actor.profile",
            "rkey": "self",
            "record": {
                "$type": "app.bsky.actor.profile",
                "displayName": "Backup Test User",
                "avatar": blob
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(profile_res.status(), StatusCode::OK);

    let backup1_res = client
        .post(format!("{}/xrpc/_backup.createBackup", base))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Backup 1 failed");
    assert_eq!(backup1_res.status(), StatusCode::OK);
    let backup1: Value = backup1_res.json().await.unwrap();
    let backup1_id = backup1["id"].as_str().unwrap();
    let backup1_rev = backup1["repoRev"].as_str().unwrap();

    create_post(&client, &did, &jwt, "Post 4 after first backup").await;
    create_post(&client, &did, &jwt, "Post 5 after first backup").await;

    let backup2_res = client
        .post(format!("{}/xrpc/_backup.createBackup", base))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Backup 2 failed");
    assert_eq!(backup2_res.status(), StatusCode::OK);
    let backup2: Value = backup2_res.json().await.unwrap();
    let backup2_id = backup2["id"].as_str().unwrap();
    let backup2_rev = backup2["repoRev"].as_str().unwrap();

    assert_ne!(
        backup1_rev, backup2_rev,
        "Backups should have different revs"
    );

    let list_res = client
        .get(format!("{}/xrpc/_backup.listBackups", base))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("List backups failed");
    let list_body: Value = list_res.json().await.unwrap();
    let backups = list_body["backups"].as_array().unwrap();
    assert_eq!(backups.len(), 2, "Should have 2 backups");

    let download1 = client
        .get(format!("{}/xrpc/_backup.getBackup?id={}", base, backup1_id))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Download backup 1 failed");
    assert_eq!(download1.status(), StatusCode::OK);
    let backup1_bytes = download1.bytes().await.unwrap();

    let download2 = client
        .get(format!("{}/xrpc/_backup.getBackup?id={}", base, backup2_id))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Download backup 2 failed");
    assert_eq!(download2.status(), StatusCode::OK);
    let backup2_bytes = download2.bytes().await.unwrap();

    assert!(
        backup2_bytes.len() > backup1_bytes.len(),
        "Second backup should be larger (more posts)"
    );

    let delete_old = client
        .post(format!(
            "{}/xrpc/_backup.deleteBackup?id={}",
            base, backup1_id
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Delete backup failed");
    assert_eq!(delete_old.status(), StatusCode::OK);

    let final_list = client
        .get(format!("{}/xrpc/_backup.listBackups", base))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    let final_body: Value = final_list.json().await.unwrap();
    assert_eq!(final_body["backups"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_scale_100_posts_with_pagination() {
    let client = client();
    let base = base_url().await;
    let (did, jwt) = setup_new_user("scale-posts").await;

    let post_count = 1000;
    let post_futures: Vec<_> = (0..post_count)
        .map(|i| {
            let client = client.clone();
            let base = base.to_string();
            let did = did.clone();
            let jwt = jwt.clone();
            async move {
                let res = client
                    .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
                    .bearer_auth(&jwt)
                    .json(&json!({
                        "repo": did,
                        "collection": "app.bsky.feed.post",
                        "record": {
                            "$type": "app.bsky.feed.post",
                            "text": format!("Scale test post number {}", i),
                            "createdAt": Utc::now().to_rfc3339()
                        }
                    }))
                    .send()
                    .await
                    .expect("Post creation failed");
                let status = res.status();
                let body: Value = res.json().await.unwrap_or_default();
                assert_eq!(
                    status,
                    StatusCode::OK,
                    "Failed to create post {}: {:?}",
                    i,
                    body
                );
            }
        })
        .collect();

    join_all(post_futures).await;

    let count_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(&jwt)
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(count_res.status(), StatusCode::OK);

    let all_uris: Vec<String> =
        paginate_records(&client, base, &jwt, &did, "app.bsky.feed.post", 25)
            .await
            .iter()
            .filter_map(|r| r["uri"].as_str().map(String::from))
            .collect();

    assert_eq!(
        all_uris.len(),
        post_count,
        "Should have paginated through all {} posts",
        post_count
    );

    let unique_uris: std::collections::HashSet<_> = all_uris.iter().collect();
    assert_eq!(
        unique_uris.len(),
        post_count,
        "All posts should have unique URIs"
    );

    let delete_futures: Vec<_> = all_uris
        .iter()
        .take(500)
        .map(|uri| {
            let client = client.clone();
            let base = base.to_string();
            let did = did.clone();
            let jwt = jwt.clone();
            let rkey = uri.split('/').next_back().unwrap().to_string();
            async move {
                let res = client
                    .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", base))
                    .bearer_auth(&jwt)
                    .json(&json!({
                        "repo": did,
                        "collection": "app.bsky.feed.post",
                        "rkey": rkey
                    }))
                    .send()
                    .await
                    .expect("Delete failed");
                assert_eq!(res.status(), StatusCode::OK);
            }
        })
        .collect();

    join_all(delete_futures).await;

    let final_count = count_records(&client, base, &jwt, &did, "app.bsky.feed.post").await;
    assert_eq!(
        final_count, 500,
        "Should have 500 posts remaining after deleting 500"
    );
}

#[tokio::test]
async fn test_scale_many_users_social_graph() {
    let client = client();
    let base = base_url().await;

    let user_count = 50;
    let user_futures: Vec<_> = (0..user_count)
        .map(|i| async move { setup_new_user(&format!("graph{}", i)).await })
        .collect();

    let users: Vec<(String, String)> = join_all(user_futures).await;

    let follow_futures: Vec<_> = users
        .iter()
        .enumerate()
        .flat_map(|(i, (follower_did, follower_jwt))| {
            let client = client.clone();
            let base = base.to_string();
            users.iter().enumerate().filter(move |(j, _)| *j != i).map({
                let client = client.clone();
                let base = base.clone();
                let follower_did = follower_did.clone();
                let follower_jwt = follower_jwt.clone();
                move |(_, (followee_did, _))| {
                    let client = client.clone();
                    let base = base.clone();
                    let follower_did = follower_did.clone();
                    let follower_jwt = follower_jwt.clone();
                    let followee_did = followee_did.clone();
                    async move {
                        let rkey = format!(
                            "follow_{}",
                            &uuid::Uuid::new_v4().simple().to_string()[..12]
                        );
                        let res = client
                            .post(format!("{}/xrpc/com.atproto.repo.putRecord", base))
                            .bearer_auth(&follower_jwt)
                            .json(&json!({
                                "repo": follower_did,
                                "collection": "app.bsky.graph.follow",
                                "rkey": rkey,
                                "record": {
                                    "$type": "app.bsky.graph.follow",
                                    "subject": followee_did,
                                    "createdAt": Utc::now().to_rfc3339()
                                }
                            }))
                            .send()
                            .await
                            .expect("Follow failed");
                        let status = res.status();
                        let body: Value = res.json().await.unwrap_or_default();
                        assert_eq!(status, StatusCode::OK, "Follow failed: {:?}", body);
                    }
                }
            })
        })
        .collect();

    join_all(follow_futures).await;

    let expected_follows_per_user = user_count - 1;
    let verify_futures: Vec<_> = users
        .iter()
        .map(|(did, jwt)| {
            let client = client.clone();
            let base = base.to_string();
            let did = did.clone();
            let jwt = jwt.clone();
            async move {
                let res = client
                    .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
                    .bearer_auth(&jwt)
                    .query(&[
                        ("repo", did.as_str()),
                        ("collection", "app.bsky.graph.follow"),
                        ("limit", "100"),
                    ])
                    .send()
                    .await
                    .unwrap();
                let body: Value = res.json().await.unwrap();
                body["records"].as_array().unwrap().len()
            }
        })
        .collect();

    let follow_counts: Vec<usize> = join_all(verify_futures).await;
    let total_follows: usize = follow_counts.iter().sum();

    assert_eq!(
        total_follows,
        user_count * expected_follows_per_user,
        "Each of {} users should follow {} others = {} total follows",
        user_count,
        expected_follows_per_user,
        user_count * expected_follows_per_user
    );

    let (poster_did, poster_jwt) = &users[0];
    let (post_uri, post_cid) = create_post(&client, poster_did, poster_jwt, "Popular post").await;

    let like_futures: Vec<_> = users
        .iter()
        .skip(1)
        .map(|(liker_did, liker_jwt)| {
            let client = client.clone();
            let base = base.to_string();
            let liker_did = liker_did.clone();
            let liker_jwt = liker_jwt.clone();
            let post_uri = post_uri.clone();
            let post_cid = post_cid.clone();
            async move {
                let rkey = format!("like_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
                let res = client
                    .post(format!("{}/xrpc/com.atproto.repo.putRecord", base))
                    .bearer_auth(&liker_jwt)
                    .json(&json!({
                        "repo": liker_did,
                        "collection": "app.bsky.feed.like",
                        "rkey": rkey,
                        "record": {
                            "$type": "app.bsky.feed.like",
                            "subject": { "uri": post_uri, "cid": post_cid },
                            "createdAt": Utc::now().to_rfc3339()
                        }
                    }))
                    .send()
                    .await
                    .expect("Like failed");
                assert_eq!(res.status(), StatusCode::OK);
            }
        })
        .collect();

    join_all(like_futures).await;
}

#[tokio::test]
async fn test_scale_many_blobs_in_repo() {
    let client = client();
    let base = base_url().await;
    let (did, jwt) = setup_new_user("scale-blobs").await;

    let blob_count = 300;
    let blob_futures: Vec<_> = (0..blob_count)
        .map(|i| {
            let client = client.clone();
            let base = base.to_string();
            let jwt = jwt.clone();
            async move {
                let blob_data = format!("Blob data number {} with some padding to make it realistic size for testing purposes", i);
                let res = client
                    .post(format!("{}/xrpc/com.atproto.repo.uploadBlob", base))
                    .header(header::CONTENT_TYPE, "text/plain")
                    .bearer_auth(&jwt)
                    .body(blob_data)
                    .send()
                    .await
                    .expect("Blob upload failed");
                assert_eq!(res.status(), StatusCode::OK, "Failed to upload blob {}", i);
                let body: Value = res.json().await.unwrap();
                body["blob"].clone()
            }
        })
        .collect();

    let blobs: Vec<Value> = join_all(blob_futures).await;

    let post_futures: Vec<_> = blobs
        .chunks(3)
        .enumerate()
        .map(|(i, blob_chunk)| {
            let client = client.clone();
            let base = base.to_string();
            let did = did.clone();
            let jwt = jwt.clone();
            let images: Vec<Value> = blob_chunk
                .iter()
                .enumerate()
                .map(|(j, blob)| {
                    json!({
                        "alt": format!("Image {} in post {}", j, i),
                        "image": blob
                    })
                })
                .collect();
            async move {
                let res = client
                    .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
                    .bearer_auth(&jwt)
                    .json(&json!({
                        "repo": did,
                        "collection": "app.bsky.feed.post",
                        "record": {
                            "$type": "app.bsky.feed.post",
                            "text": format!("Post {} with {} images", i, images.len()),
                            "createdAt": Utc::now().to_rfc3339(),
                            "embed": {
                                "$type": "app.bsky.embed.images",
                                "images": images
                            }
                        }
                    }))
                    .send()
                    .await
                    .expect("Post with blobs failed");
                let status = res.status();
                let body: Value = res.json().await.unwrap_or_default();
                assert_eq!(status, StatusCode::OK, "Post with blobs failed: {:?}", body);
            }
        })
        .collect();

    join_all(post_futures).await;

    let list_blobs_res = client
        .get(format!("{}/xrpc/com.atproto.sync.listBlobs", base))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("List blobs failed");
    assert_eq!(list_blobs_res.status(), StatusCode::OK);
    let blobs_body: Value = list_blobs_res.json().await.unwrap();
    let cids = blobs_body["cids"].as_array().unwrap();
    assert_eq!(
        cids.len(),
        blob_count,
        "Should have {} blobs in repo",
        blob_count
    );

    let verify_futures: Vec<_> = cids
        .iter()
        .take(10)
        .map(|cid| {
            let client = client.clone();
            let base = base.to_string();
            let did = did.clone();
            let cid_str = cid.as_str().unwrap().to_string();
            async move {
                let res = client
                    .get(format!("{}/xrpc/com.atproto.sync.getBlob", base))
                    .query(&[("did", did.as_str()), ("cid", cid_str.as_str())])
                    .send()
                    .await
                    .expect("Get blob failed");
                assert_eq!(
                    res.status(),
                    StatusCode::OK,
                    "Failed to get blob {}",
                    cid_str
                );
                let bytes = res.bytes().await.unwrap();
                assert!(bytes.len() > 50, "Blob should have content");
            }
        })
        .collect();

    join_all(verify_futures).await;
}

#[tokio::test]
async fn test_scale_batch_operations() {
    let client = client();
    let base = base_url().await;
    let (did, jwt) = setup_new_user("scale-batch").await;

    let batch_size = 200;
    let writes: Vec<Value> = (0..batch_size)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": format!("batch_{:03}", i),
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": format!("Batch created post {}", i),
                    "createdAt": Utc::now().to_rfc3339()
                }
            })
        })
        .collect();

    let apply_res = client
        .post(format!("{}/xrpc/com.atproto.repo.applyWrites", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "writes": writes
        }))
        .send()
        .await
        .expect("Batch create failed");
    assert_eq!(
        apply_res.status(),
        StatusCode::OK,
        "Batch create of {} posts should succeed",
        batch_size
    );

    let batch_count = count_records(&client, base, &jwt, &did, "app.bsky.feed.post").await;
    assert_eq!(
        batch_count, batch_size,
        "Should have {} posts after batch create",
        batch_size
    );

    let update_writes: Vec<Value> = (0..batch_size)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": format!("batch_{:03}", i),
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": format!("UPDATED batch post {}", i),
                    "createdAt": Utc::now().to_rfc3339()
                }
            })
        })
        .collect();

    let update_res = client
        .post(format!("{}/xrpc/com.atproto.repo.applyWrites", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "writes": update_writes
        }))
        .send()
        .await
        .expect("Batch update failed");
    assert_eq!(
        update_res.status(),
        StatusCode::OK,
        "Batch update of {} posts should succeed",
        batch_size
    );

    let verify_res = client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", base))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", "batch_000"),
        ])
        .send()
        .await
        .unwrap();
    let verify_body: Value = verify_res.json().await.unwrap();
    assert!(
        verify_body["value"]["text"]
            .as_str()
            .unwrap()
            .starts_with("UPDATED"),
        "Post should be updated"
    );

    let delete_writes: Vec<Value> = (0..batch_size)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": format!("batch_{:03}", i)
            })
        })
        .collect();

    let delete_res = client
        .post(format!("{}/xrpc/com.atproto.repo.applyWrites", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "writes": delete_writes
        }))
        .send()
        .await
        .expect("Batch delete failed");
    assert_eq!(
        delete_res.status(),
        StatusCode::OK,
        "Batch delete of {} posts should succeed",
        batch_size
    );

    let final_res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(&jwt)
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "100"),
        ])
        .send()
        .await
        .unwrap();
    let final_body: Value = final_res.json().await.unwrap();
    assert_eq!(
        final_body["records"].as_array().unwrap().len(),
        0,
        "Should have 0 posts after batch delete"
    );
}

#[tokio::test]
async fn test_scale_reply_thread_depth() {
    let client = client();
    let base = base_url().await;
    let (did, jwt) = setup_new_user("deep-thread").await;

    let root_res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Root post of deep thread",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .expect("Root post failed");
    assert_eq!(root_res.status(), StatusCode::OK);
    let root_body: Value = root_res.json().await.unwrap();
    let root_uri = root_body["uri"].as_str().unwrap().to_string();
    let root_cid = root_body["cid"].as_str().unwrap().to_string();

    let thread_depth = 500;

    struct ReplyState {
        parent_uri: String,
        parent_cid: String,
        depth: usize,
    }

    let initial_state = ReplyState {
        parent_uri: root_uri.clone(),
        parent_cid: root_cid.clone(),
        depth: 1,
    };

    let (parent_uri, reply_count) = futures::stream::unfold(initial_state, |state| {
        let client = client.clone();
        let base = base.to_string();
        let did = did.clone();
        let jwt = jwt.clone();
        let root_uri = root_uri.clone();
        let root_cid = root_cid.clone();
        async move {
            if state.depth > thread_depth {
                return None;
            }

            let res = client
                .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
                .bearer_auth(&jwt)
                .json(&json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "record": {
                        "$type": "app.bsky.feed.post",
                        "text": format!("Reply at depth {}", state.depth),
                        "createdAt": Utc::now().to_rfc3339(),
                        "reply": {
                            "root": { "uri": root_uri, "cid": root_cid },
                            "parent": { "uri": &state.parent_uri, "cid": &state.parent_cid }
                        }
                    }
                }))
                .send()
                .await
                .expect("Reply failed");
            assert_eq!(
                res.status(),
                StatusCode::OK,
                "Reply at depth {} failed",
                state.depth
            );
            let body: Value = res.json().await.unwrap();
            let new_uri = body["uri"].as_str().unwrap().to_string();
            let new_cid = body["cid"].as_str().unwrap().to_string();

            let next_state = ReplyState {
                parent_uri: new_uri.clone(),
                parent_cid: new_cid,
                depth: state.depth + 1,
            };

            Some((new_uri, next_state))
        }
    })
    .fold((String::new(), 0usize), |(_, count), uri| async move {
        (uri, count + 1)
    })
    .await;

    assert_eq!(
        reply_count, thread_depth,
        "Should have created {} replies",
        thread_depth
    );

    let thread_count = count_records(&client, base, &jwt, &did, "app.bsky.feed.post").await;
    assert_eq!(
        thread_count,
        thread_depth + 1,
        "Should have root + {} replies",
        thread_depth
    );

    let deepest_rkey = parent_uri.split('/').next_back().unwrap();
    let deep_res = client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", base))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", deepest_rkey),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(deep_res.status(), StatusCode::OK);
    let deep_body: Value = deep_res.json().await.unwrap();
    assert_eq!(
        deep_body["value"]["reply"]["root"]["uri"], root_uri,
        "Deepest reply should reference root"
    );
}

#[tokio::test]
async fn test_concurrent_import_and_writes() {
    let client = client();
    let base = base_url().await;
    let (did, jwt) = setup_new_user("import-conc").await;

    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");

    let (car_bytes, _root_cid) = build_car_with_signature(&did, &signing_key);

    let write_count = 10;

    let import_future = {
        let client = client.clone();
        let base = base.to_string();
        let jwt = jwt.clone();
        let car_bytes = car_bytes.clone();
        async move {
            let res = client
                .post(format!("{}/xrpc/com.atproto.repo.importRepo", base))
                .bearer_auth(&jwt)
                .header("Content-Type", "application/vnd.ipld.car")
                .body(car_bytes)
                .send()
                .await
                .expect("Import request failed");
            let status = res.status();
            let body: Value = res.json().await.unwrap_or_default();
            assert_eq!(status, StatusCode::OK, "Import should succeed: {:?}", body);
        }
    };

    let write_futures: Vec<_> = (0..write_count)
        .map(|i| {
            let client = client.clone();
            let base = base.to_string();
            let did = did.clone();
            let jwt = jwt.clone();
            async move {
                let res = client
                    .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
                    .bearer_auth(&jwt)
                    .json(&json!({
                        "repo": did,
                        "collection": "app.bsky.feed.post",
                        "record": {
                            "$type": "app.bsky.feed.post",
                            "text": format!("Concurrent post {}", i),
                            "createdAt": Utc::now().to_rfc3339()
                        }
                    }))
                    .send()
                    .await
                    .expect("Write request failed");
                let status = res.status();
                let body: Value = res.json().await.unwrap_or_default();
                assert_eq!(
                    status,
                    StatusCode::OK,
                    "Write {} should succeed: {:?}",
                    i,
                    body
                );
            }
        })
        .collect();

    tokio::join!(import_future, join_all(write_futures));

    let final_posts = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(&jwt)
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "100"),
        ])
        .send()
        .await
        .unwrap();
    let final_body: Value = final_posts.json().await.unwrap();
    let record_count = final_body["records"].as_array().unwrap().len();

    let min_expected = write_count;
    assert!(
        record_count >= min_expected,
        "Expected at least {} records (from writes), got {} (import may also contribute records)",
        min_expected,
        record_count
    );
}
