mod common;
mod helpers;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use common::{base_url, client};
use helpers::verify_new_account;
use reqwest::{StatusCode, redirect};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn generate_pkce() -> (String, String) {
    let verifier_bytes: [u8; 32] = rand::random();
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let code_challenge = URL_SAFE_NO_PAD.encode(&hash);
    (code_verifier, code_challenge)
}

fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(redirect::Policy::none())
        .build()
        .unwrap()
}

async fn setup_mock_client_metadata(redirect_uri: &str) -> MockServer {
    let mock_server = MockServer::start().await;
    let client_id = mock_server.uri();
    let metadata = json!({
        "client_id": client_id,
        "client_name": "Test OAuth Client",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": false
    });
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(&mock_server)
        .await;
    mock_server
}

struct OAuthSession {
    access_token: String,
    refresh_token: String,
    did: String,
    client_id: String,
}

async fn create_user_and_oauth_session(
    handle_prefix: &str,
    redirect_uri: &str,
) -> (OAuthSession, MockServer) {
    let url = base_url().await;
    let http_client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("{}-{}", handle_prefix, ts);
    let email = format!("{}-{}@example.com", handle_prefix, ts);
    let password = format!("{}-password", handle_prefix);
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
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
    let user_did = account["did"].as_str().unwrap().to_string();
    let _ = verify_new_account(&http_client, &user_did).await;
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (code_verifier, code_challenge) = generate_pkce();
    let par_res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", "atproto"),
        ])
        .send()
        .await
        .expect("PAR failed");
    assert!(
        par_res.status() == StatusCode::OK || par_res.status() == StatusCode::CREATED,
        "PAR should succeed with 200 or 201, got {}",
        par_res.status()
    );
    let par_body: Value = par_res.json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();
    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", &password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .expect("Authorize failed");
    let location = auth_res
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let token_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .expect("Token request failed");
    assert_eq!(token_res.status(), StatusCode::OK);
    let token_body: Value = token_res.json().await.unwrap();
    let session = OAuthSession {
        access_token: token_body["access_token"].as_str().unwrap().to_string(),
        refresh_token: token_body["refresh_token"].as_str().unwrap().to_string(),
        did: user_did,
        client_id,
    };
    (session, mock_client)
}

#[tokio::test]
async fn test_oauth_token_can_create_and_read_records() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) =
        create_user_and_oauth_session("oauth-records", "https://example.com/callback").await;
    let collection = "app.bsky.feed.post";
    let post_text = "Hello from OAuth! This post was created with an OAuth access token.";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": post_text,
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .expect("createRecord failed");
    assert_eq!(
        create_res.status(),
        StatusCode::OK,
        "Should create record with OAuth token"
    );
    let create_body: Value = create_res.json().await.unwrap();
    let uri = create_body["uri"].as_str().unwrap();
    let rkey = uri.split('/').last().unwrap();
    let get_res = http_client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", url))
        .bearer_auth(&session.access_token)
        .query(&[
            ("repo", session.did.as_str()),
            ("collection", collection),
            ("rkey", rkey),
        ])
        .send()
        .await
        .expect("getRecord failed");
    assert_eq!(
        get_res.status(),
        StatusCode::OK,
        "Should read record with OAuth token"
    );
    let get_body: Value = get_res.json().await.unwrap();
    assert_eq!(get_body["value"]["text"], post_text);
}

#[tokio::test]
async fn test_oauth_token_can_upload_blob() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) =
        create_user_and_oauth_session("oauth-blob", "https://example.com/callback").await;
    let blob_data = b"This is test blob data uploaded via OAuth";
    let upload_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.uploadBlob", url))
        .bearer_auth(&session.access_token)
        .header("Content-Type", "text/plain")
        .body(blob_data.to_vec())
        .send()
        .await
        .expect("uploadBlob failed");
    assert_eq!(
        upload_res.status(),
        StatusCode::OK,
        "Should upload blob with OAuth token"
    );
    let upload_body: Value = upload_res.json().await.unwrap();
    assert!(upload_body["blob"]["ref"]["$link"].is_string());
    assert_eq!(upload_body["blob"]["mimeType"], "text/plain");
}

#[tokio::test]
async fn test_oauth_token_can_describe_repo() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) =
        create_user_and_oauth_session("oauth-describe", "https://example.com/callback").await;
    let describe_res = http_client
        .get(format!("{}/xrpc/com.atproto.repo.describeRepo", url))
        .bearer_auth(&session.access_token)
        .query(&[("repo", session.did.as_str())])
        .send()
        .await
        .expect("describeRepo failed");
    assert_eq!(
        describe_res.status(),
        StatusCode::OK,
        "Should describe repo with OAuth token"
    );
    let describe_body: Value = describe_res.json().await.unwrap();
    assert_eq!(describe_body["did"], session.did);
    assert!(describe_body["handle"].is_string());
}

#[tokio::test]
async fn test_oauth_full_post_lifecycle_create_edit_delete() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) =
        create_user_and_oauth_session("oauth-lifecycle", "https://example.com/callback").await;
    let collection = "app.bsky.feed.post";
    let original_text = "Original post content";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": original_text,
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.unwrap();
    let uri = create_body["uri"].as_str().unwrap();
    let rkey = uri.split('/').last().unwrap();
    let updated_text = "Updated post content via OAuth putRecord";
    let put_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "rkey": rkey,
            "record": {
                "$type": collection,
                "text": updated_text,
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        put_res.status(),
        StatusCode::OK,
        "Should update record with OAuth token"
    );
    let get_res = http_client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", url))
        .bearer_auth(&session.access_token)
        .query(&[
            ("repo", session.did.as_str()),
            ("collection", collection),
            ("rkey", rkey),
        ])
        .send()
        .await
        .unwrap();
    let get_body: Value = get_res.json().await.unwrap();
    assert_eq!(
        get_body["value"]["text"], updated_text,
        "Record should have updated text"
    );
    let delete_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "rkey": rkey
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        delete_res.status(),
        StatusCode::OK,
        "Should delete record with OAuth token"
    );
    let get_deleted_res = http_client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", url))
        .bearer_auth(&session.access_token)
        .query(&[
            ("repo", session.did.as_str()),
            ("collection", collection),
            ("rkey", rkey),
        ])
        .send()
        .await
        .unwrap();
    assert!(
        get_deleted_res.status() == StatusCode::BAD_REQUEST
            || get_deleted_res.status() == StatusCode::NOT_FOUND,
        "Deleted record should not be found, got {}",
        get_deleted_res.status()
    );
}

#[tokio::test]
async fn test_oauth_batch_operations_apply_writes() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) =
        create_user_and_oauth_session("oauth-batch", "https://example.com/callback").await;
    let collection = "app.bsky.feed.post";
    let now = Utc::now().to_rfc3339();
    let apply_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.applyWrites", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "writes": [
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": collection,
                    "rkey": "batch1",
                    "value": {
                        "$type": collection,
                        "text": "Batch post 1",
                        "createdAt": now
                    }
                },
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": collection,
                    "rkey": "batch2",
                    "value": {
                        "$type": collection,
                        "text": "Batch post 2",
                        "createdAt": now
                    }
                },
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": collection,
                    "rkey": "batch3",
                    "value": {
                        "$type": collection,
                        "text": "Batch post 3",
                        "createdAt": now
                    }
                }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        apply_res.status(),
        StatusCode::OK,
        "Should apply batch writes with OAuth token"
    );
    let list_res = http_client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", url))
        .bearer_auth(&session.access_token)
        .query(&[("repo", session.did.as_str()), ("collection", collection)])
        .send()
        .await
        .unwrap();
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body: Value = list_res.json().await.unwrap();
    let records = list_body["records"].as_array().unwrap();
    assert!(
        records.len() >= 3,
        "Should have at least 3 records from batch"
    );
}

#[tokio::test]
async fn test_oauth_token_refresh_maintains_access() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) =
        create_user_and_oauth_session("oauth-refresh-access", "https://example.com/callback").await;
    let collection = "app.bsky.feed.post";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": "Post before refresh",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        create_res.status(),
        StatusCode::OK,
        "Original token should work"
    );
    let refresh_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &session.refresh_token),
            ("client_id", &session.client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(refresh_res.status(), StatusCode::OK);
    let refresh_body: Value = refresh_res.json().await.unwrap();
    let new_access_token = refresh_body["access_token"].as_str().unwrap();
    assert_ne!(
        new_access_token, session.access_token,
        "New token should be different"
    );
    let create_res2 = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(new_access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": "Post after refresh with new token",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        create_res2.status(),
        StatusCode::OK,
        "New token should work for creating records"
    );
    let list_res = http_client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", url))
        .bearer_auth(new_access_token)
        .query(&[("repo", session.did.as_str()), ("collection", collection)])
        .send()
        .await
        .unwrap();
    assert_eq!(
        list_res.status(),
        StatusCode::OK,
        "New token should work for listing records"
    );
    let list_body: Value = list_res.json().await.unwrap();
    let records = list_body["records"].as_array().unwrap();
    assert_eq!(records.len(), 2, "Should have both posts");
}

#[tokio::test]
async fn test_oauth_revoked_token_cannot_access_resources() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) =
        create_user_and_oauth_session("oauth-revoke-access", "https://example.com/callback").await;
    let collection = "app.bsky.feed.post";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": "Post before revocation",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        create_res.status(),
        StatusCode::OK,
        "Token should work before revocation"
    );
    let revoke_res = http_client
        .post(format!("{}/oauth/revoke", url))
        .form(&[("token", session.refresh_token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(
        revoke_res.status(),
        StatusCode::OK,
        "Revocation should succeed"
    );
    let refresh_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &session.refresh_token),
            ("client_id", &session.client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        refresh_res.status(),
        StatusCode::BAD_REQUEST,
        "Revoked refresh token should not work"
    );
}

#[tokio::test]
async fn test_oauth_multiple_clients_same_user() {
    let url = base_url().await;
    let http_client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("multi-client-{}", ts);
    let email = format!("multi-client-{}@example.com", ts);
    let password = "multi-client-password";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap();
    let _ = verify_new_account(&http_client, user_did).await;
    let mock_client1 = setup_mock_client_metadata("https://client1.example.com/callback").await;
    let client1_id = mock_client1.uri();
    let mock_client2 = setup_mock_client_metadata("https://client2.example.com/callback").await;
    let client2_id = mock_client2.uri();
    let (verifier1, challenge1) = generate_pkce();
    let par_res1 = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client1_id),
            ("redirect_uri", "https://client1.example.com/callback"),
            ("code_challenge", &challenge1),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    let par_body1: Value = par_res1.json().await.unwrap();
    let request_uri1 = par_body1["request_uri"].as_str().unwrap();
    let auth_client = no_redirect_client();
    let auth_res1 = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri1),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();
    let location1 = auth_res1
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code1 = location1
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let token_res1 = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code1),
            ("redirect_uri", "https://client1.example.com/callback"),
            ("code_verifier", &verifier1),
            ("client_id", &client1_id),
        ])
        .send()
        .await
        .unwrap();
    let token_body1: Value = token_res1.json().await.unwrap();
    let token1 = token_body1["access_token"].as_str().unwrap();
    let (verifier2, challenge2) = generate_pkce();
    let par_res2 = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client2_id),
            ("redirect_uri", "https://client2.example.com/callback"),
            ("code_challenge", &challenge2),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    let par_body2: Value = par_res2.json().await.unwrap();
    let request_uri2 = par_body2["request_uri"].as_str().unwrap();
    let auth_res2 = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri2),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();
    let location2 = auth_res2
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code2 = location2
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let token_res2 = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code2),
            ("redirect_uri", "https://client2.example.com/callback"),
            ("code_verifier", &verifier2),
            ("client_id", &client2_id),
        ])
        .send()
        .await
        .unwrap();
    let token_body2: Value = token_res2.json().await.unwrap();
    let token2 = token_body2["access_token"].as_str().unwrap();
    assert_ne!(
        token1, token2,
        "Different clients should get different tokens"
    );
    let collection = "app.bsky.feed.post";
    let create_res1 = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(token1)
        .json(&json!({
            "repo": user_did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": "Post from client 1",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        create_res1.status(),
        StatusCode::OK,
        "Client 1 token should work"
    );
    let create_res2 = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(token2)
        .json(&json!({
            "repo": user_did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": "Post from client 2",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        create_res2.status(),
        StatusCode::OK,
        "Client 2 token should work"
    );
    let list_res = http_client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", url))
        .bearer_auth(token1)
        .query(&[("repo", user_did), ("collection", collection)])
        .send()
        .await
        .unwrap();
    let list_body: Value = list_res.json().await.unwrap();
    let records = list_body["records"].as_array().unwrap();
    assert_eq!(
        records.len(),
        2,
        "Both posts should be visible to either client"
    );
}

#[tokio::test]
async fn test_oauth_social_interactions_follow_like_repost() {
    let url = base_url().await;
    let http_client = client();
    let (alice, _mock_alice) =
        create_user_and_oauth_session("alice-social", "https://alice-app.example.com/callback")
            .await;
    let (bob, _mock_bob) =
        create_user_and_oauth_session("bob-social", "https://bob-app.example.com/callback").await;
    let post_collection = "app.bsky.feed.post";
    let post_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&alice.access_token)
        .json(&json!({
            "repo": alice.did,
            "collection": post_collection,
            "record": {
                "$type": post_collection,
                "text": "Hello from Alice! Looking for friends.",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(post_res.status(), StatusCode::OK);
    let post_body: Value = post_res.json().await.unwrap();
    let post_uri = post_body["uri"].as_str().unwrap();
    let post_cid = post_body["cid"].as_str().unwrap();
    let follow_collection = "app.bsky.graph.follow";
    let follow_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&bob.access_token)
        .json(&json!({
            "repo": bob.did,
            "collection": follow_collection,
            "record": {
                "$type": follow_collection,
                "subject": alice.did,
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        follow_res.status(),
        StatusCode::OK,
        "Bob should be able to follow Alice via OAuth"
    );
    let like_collection = "app.bsky.feed.like";
    let like_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&bob.access_token)
        .json(&json!({
            "repo": bob.did,
            "collection": like_collection,
            "record": {
                "$type": like_collection,
                "subject": {
                    "uri": post_uri,
                    "cid": post_cid
                },
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        like_res.status(),
        StatusCode::OK,
        "Bob should be able to like Alice's post via OAuth"
    );
    let repost_collection = "app.bsky.feed.repost";
    let repost_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&bob.access_token)
        .json(&json!({
            "repo": bob.did,
            "collection": repost_collection,
            "record": {
                "$type": repost_collection,
                "subject": {
                    "uri": post_uri,
                    "cid": post_cid
                },
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        repost_res.status(),
        StatusCode::OK,
        "Bob should be able to repost Alice's post via OAuth"
    );
    let bob_follows = http_client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", url))
        .bearer_auth(&bob.access_token)
        .query(&[
            ("repo", bob.did.as_str()),
            ("collection", follow_collection),
        ])
        .send()
        .await
        .unwrap();
    let follows_body: Value = bob_follows.json().await.unwrap();
    let follows = follows_body["records"].as_array().unwrap();
    assert_eq!(follows.len(), 1, "Bob should have 1 follow");
    assert_eq!(follows[0]["value"]["subject"], alice.did);
    let bob_likes = http_client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", url))
        .bearer_auth(&bob.access_token)
        .query(&[("repo", bob.did.as_str()), ("collection", like_collection)])
        .send()
        .await
        .unwrap();
    let likes_body: Value = bob_likes.json().await.unwrap();
    let likes = likes_body["records"].as_array().unwrap();
    assert_eq!(likes.len(), 1, "Bob should have 1 like");
}

#[tokio::test]
async fn test_oauth_cannot_modify_other_users_repo() {
    let url = base_url().await;
    let http_client = client();
    let (alice, _mock_alice) =
        create_user_and_oauth_session("alice-boundary", "https://alice.example.com/callback").await;
    let (bob, _mock_bob) =
        create_user_and_oauth_session("bob-boundary", "https://bob.example.com/callback").await;
    let collection = "app.bsky.feed.post";
    let malicious_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&bob.access_token)
        .json(&json!({
            "repo": alice.did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": "Bob trying to post as Alice!",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_ne!(
        malicious_res.status(),
        StatusCode::OK,
        "Bob should NOT be able to create records in Alice's repo"
    );
    let alice_posts = http_client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", url))
        .bearer_auth(&alice.access_token)
        .query(&[("repo", alice.did.as_str()), ("collection", collection)])
        .send()
        .await
        .unwrap();
    let posts_body: Value = alice_posts.json().await.unwrap();
    let posts = posts_body["records"].as_array().unwrap();
    assert_eq!(posts.len(), 0, "Alice's repo should have no posts from Bob");
}

#[tokio::test]
async fn test_oauth_session_isolation_between_users() {
    let url = base_url().await;
    let http_client = client();
    let (alice, _mock_alice) =
        create_user_and_oauth_session("alice-isolation", "https://alice.example.com/callback")
            .await;
    let (bob, _mock_bob) =
        create_user_and_oauth_session("bob-isolation", "https://bob.example.com/callback").await;
    let collection = "app.bsky.feed.post";
    let alice_post = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&alice.access_token)
        .json(&json!({
            "repo": alice.did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": "Alice's private thoughts",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(alice_post.status(), StatusCode::OK);
    let bob_post = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&bob.access_token)
        .json(&json!({
            "repo": bob.did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": "Bob's different thoughts",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(bob_post.status(), StatusCode::OK);
    let alice_list = http_client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", url))
        .bearer_auth(&alice.access_token)
        .query(&[("repo", alice.did.as_str()), ("collection", collection)])
        .send()
        .await
        .unwrap();
    let alice_records: Value = alice_list.json().await.unwrap();
    let alice_posts = alice_records["records"].as_array().unwrap();
    assert_eq!(alice_posts.len(), 1);
    assert_eq!(alice_posts[0]["value"]["text"], "Alice's private thoughts");
    let bob_list = http_client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", url))
        .bearer_auth(&bob.access_token)
        .query(&[("repo", bob.did.as_str()), ("collection", collection)])
        .send()
        .await
        .unwrap();
    let bob_records: Value = bob_list.json().await.unwrap();
    let bob_posts = bob_records["records"].as_array().unwrap();
    assert_eq!(bob_posts.len(), 1);
    assert_eq!(bob_posts[0]["value"]["text"], "Bob's different thoughts");
}

#[tokio::test]
async fn test_oauth_token_works_with_sync_endpoints() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) =
        create_user_and_oauth_session("oauth-sync", "https://example.com/callback").await;
    let collection = "app.bsky.feed.post";
    http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": "Post to sync",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    let latest_commit = http_client
        .get(format!("{}/xrpc/com.atproto.sync.getLatestCommit", url))
        .query(&[("did", session.did.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(latest_commit.status(), StatusCode::OK);
    let commit_body: Value = latest_commit.json().await.unwrap();
    assert!(commit_body["cid"].is_string());
    assert!(commit_body["rev"].is_string());
    let repo_status = http_client
        .get(format!("{}/xrpc/com.atproto.sync.getRepoStatus", url))
        .query(&[("did", session.did.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(repo_status.status(), StatusCode::OK);
    let status_body: Value = repo_status.json().await.unwrap();
    assert_eq!(status_body["did"], session.did);
    assert!(status_body["active"].as_bool().unwrap());
}
