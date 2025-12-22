use chrono::Utc;
use reqwest::StatusCode;
use serde_json::{Value, json};

pub use crate::common::*;

#[allow(dead_code)]
pub async fn setup_new_user(handle_prefix: &str) -> (String, String) {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("{}-{}.test", handle_prefix, ts);
    let email = format!("{}-{}@test.com", handle_prefix, ts);
    let password = "E2epass123!";
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
    let new_jwt = verify_new_account(&client, &new_did).await;
    (new_did, new_jwt)
}

#[allow(dead_code)]
pub async fn create_post(
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

#[allow(dead_code)]
pub async fn create_follow(
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

#[allow(dead_code)]
pub async fn create_like(
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

#[allow(dead_code)]
pub async fn create_repost(
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
