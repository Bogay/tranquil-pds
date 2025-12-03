use reqwest::{header, Client, StatusCode};
use serde_json::{json, Value};
use chrono::Utc;
#[allow(unused_imports)]
use std::collections::HashMap;
#[allow(unused_imports)]
use std::time::Duration;

pub const BASE_URL: &str = "http://127.0.0.1:3000";
#[allow(dead_code)]
pub const AUTH_TOKEN: &str = "test-token";
#[allow(dead_code)]
pub const BAD_AUTH_TOKEN: &str = "bad-token";
#[allow(dead_code)]
pub const AUTH_DID: &str = "did:plc:fake";
#[allow(dead_code)]
pub const TARGET_DID: &str = "did:plc:target";

pub fn client() -> Client {
    Client::new()
}

#[allow(dead_code)]
pub async fn upload_test_blob(client: &Client, data: &'static str, mime: &'static str) -> Value {
    let res = client.post(format!("{}/xrpc/com.atproto.repo.uploadBlob", BASE_URL))
        .header(header::CONTENT_TYPE, mime)
        .bearer_auth(AUTH_TOKEN)
        .body(data)
        .send()
        .await
        .expect("Failed to send uploadBlob request");

    assert_eq!(res.status(), StatusCode::OK, "Failed to upload blob");
    let body: Value = res.json().await.expect("Blob upload response was not JSON");
    body["blob"].clone()
}


#[allow(dead_code)]
pub async fn create_test_post(
    client: &Client,
    text: &str,
    reply_to: Option<Value>
) -> (String, String, String) {
    let collection = "app.bsky.feed.post";
    let mut record = json!({
        "$type": collection,
        "text": text,
        "createdAt": Utc::now().to_rfc3339()
    });

    if let Some(reply_obj) = reply_to {
        record["reply"] = reply_obj;
    }

    let payload = json!({
        "repo": AUTH_DID,
        "collection": collection,
        "record": record
    });

    let res = client.post(format!("{}/xrpc/com.atproto.repo.createRecord", BASE_URL))
        .bearer_auth(AUTH_TOKEN)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send createRecord");

    assert_eq!(res.status(), StatusCode::OK, "Failed to create post record");
    let body: Value = res.json().await.expect("createRecord response was not JSON");

    let uri = body["uri"].as_str().expect("Response had no URI").to_string();
    let cid = body["cid"].as_str().expect("Response had no CID").to_string();
    let rkey = uri.split('/').last().expect("URI was malformed").to_string();

    (uri, cid, rkey)
}

pub async fn create_account_and_login(client: &Client) -> (String, String) {
    let handle = format!("user_{}", uuid::Uuid::new_v4());
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "password"
    });

    let res = client.post(format!("{}/xrpc/com.atproto.server.createAccount", BASE_URL))
        .json(&payload)
        .send()
        .await
        .expect("Failed to create account");

    if res.status() != StatusCode::OK {
        panic!("Failed to create account: {:?}", res.text().await);
    }

    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt = body["accessJwt"].as_str().expect("No accessJwt").to_string();
    let did = body["did"].as_str().expect("No did").to_string();
    (access_jwt, did)
}
