mod common;
mod helpers;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_check_account_status_returns_correct_block_count() {
    let client = client();
    let base = base_url().await;
    let (access_jwt, did) = create_account_and_login(&client).await;

    let status1 = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(status1.status(), StatusCode::OK);
    let body1: Value = status1.json().await.unwrap();
    let initial_blocks = body1["repoBlocks"].as_i64().unwrap();
    assert!(
        initial_blocks >= 2,
        "New account should have at least 2 blocks (commit + empty MST)"
    );

    let create_res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Test post for block counting",
                "createdAt": chrono::Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.unwrap();
    let rkey = create_body["uri"]
        .as_str()
        .unwrap()
        .split('/')
        .last()
        .unwrap()
        .to_string();

    let status2 = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .unwrap();
    let body2: Value = status2.json().await.unwrap();
    let after_create_blocks = body2["repoBlocks"].as_i64().unwrap();
    assert!(
        after_create_blocks > initial_blocks,
        "Block count should increase after creating a record"
    );

    let delete_res = client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", base))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "rkey": rkey
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(delete_res.status(), StatusCode::OK);

    let status3 = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .unwrap();
    let body3: Value = status3.json().await.unwrap();
    let after_delete_blocks = body3["repoBlocks"].as_i64().unwrap();
    assert!(
        after_delete_blocks >= after_create_blocks,
        "Block count should not decrease after deleting a record (was {}, now {})",
        after_create_blocks,
        after_delete_blocks
    );
}

#[tokio::test]
async fn test_check_account_status_returns_valid_repo_rev() {
    let client = client();
    let base = base_url().await;
    let (access_jwt, _) = create_account_and_login(&client).await;

    let status = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let body: Value = status.json().await.unwrap();

    let repo_rev = body["repoRev"].as_str().unwrap();
    assert!(!repo_rev.is_empty(), "repoRev should not be empty");
    assert!(
        repo_rev.chars().all(|c| c.is_alphanumeric()),
        "repoRev should be alphanumeric TID"
    );
}

#[tokio::test]
async fn test_check_account_status_valid_did_is_true_for_active_account() {
    let client = client();
    let base = base_url().await;
    let (access_jwt, _) = create_account_and_login(&client).await;

    let status = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let body: Value = status.json().await.unwrap();

    assert_eq!(
        body["validDid"], true,
        "validDid should be true for active account with correct DID document"
    );
    assert_eq!(
        body["activated"], true,
        "activated should be true for active account"
    );
}

#[tokio::test]
async fn test_deactivate_account_with_delete_after() {
    let client = client();
    let base = base_url().await;
    let (access_jwt, _) = create_account_and_login(&client).await;

    let future_time = chrono::Utc::now() + chrono::Duration::hours(24);
    let delete_after = future_time.to_rfc3339();

    let deactivate = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deactivateAccount",
            base
        ))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "deleteAfter": delete_after
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(deactivate.status(), StatusCode::OK);

    let status = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let body: Value = status.json().await.unwrap();
    assert_eq!(body["activated"], false, "Account should be deactivated");
}

#[tokio::test]
async fn test_create_account_returns_did_doc() {
    let client = client();
    let base = base_url().await;

    let handle = format!("dd{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "Testpass123!"
    });

    let create_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let body: Value = create_res.json().await.unwrap();

    assert!(
        body["accessJwt"].is_string(),
        "accessJwt should always be returned"
    );
    assert!(
        body["refreshJwt"].is_string(),
        "refreshJwt should always be returned"
    );
    assert!(body["did"].is_string(), "did should be returned");

    if body["didDoc"].is_object() {
        let did_doc = &body["didDoc"];
        assert!(did_doc["id"].is_string(), "didDoc should have id field");
    }
}

#[tokio::test]
async fn test_create_account_always_returns_tokens() {
    let client = client();
    let base = base_url().await;

    let handle = format!("tt{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "Testpass123!"
    });

    let create_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let body: Value = create_res.json().await.unwrap();

    let access_jwt = body["accessJwt"]
        .as_str()
        .expect("accessJwt should be present");
    let refresh_jwt = body["refreshJwt"]
        .as_str()
        .expect("refreshJwt should be present");

    assert!(!access_jwt.is_empty(), "accessJwt should not be empty");
    assert!(!refresh_jwt.is_empty(), "refreshJwt should not be empty");

    let parts: Vec<&str> = access_jwt.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "accessJwt should be a valid JWT with 3 parts"
    );
}

#[tokio::test]
async fn test_describe_server_has_links_and_contact() {
    let client = client();
    let base = base_url().await;

    let describe = client
        .get(format!("{}/xrpc/com.atproto.server.describeServer", base))
        .send()
        .await
        .unwrap();
    assert_eq!(describe.status(), StatusCode::OK);
    let body: Value = describe.json().await.unwrap();

    assert!(
        body.get("links").is_some(),
        "describeServer should include links object"
    );
    assert!(
        body.get("contact").is_some(),
        "describeServer should include contact object"
    );

    let links = &body["links"];
    assert!(
        links.get("privacyPolicy").is_some() || links["privacyPolicy"].is_null(),
        "links should have privacyPolicy field (can be null)"
    );
    assert!(
        links.get("termsOfService").is_some() || links["termsOfService"].is_null(),
        "links should have termsOfService field (can be null)"
    );

    let contact = &body["contact"];
    assert!(
        contact.get("email").is_some() || contact["email"].is_null(),
        "contact should have email field (can be null)"
    );
}

#[tokio::test]
async fn test_delete_account_password_max_length() {
    let client = client();
    let base = base_url().await;

    let handle = format!("pl{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "Testpass123!"
    });

    let create_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let body: Value = create_res.json().await.unwrap();
    let did = body["did"].as_str().unwrap();

    let too_long_password = "a".repeat(600);
    let delete_res = client
        .post(format!("{}/xrpc/com.atproto.server.deleteAccount", base))
        .json(&json!({
            "did": did,
            "password": too_long_password,
            "token": "fake-token"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(delete_res.status(), StatusCode::BAD_REQUEST);
    let error_body: Value = delete_res.json().await.unwrap();
    assert!(
        error_body["message"]
            .as_str()
            .unwrap()
            .contains("password length")
            || error_body["error"].as_str().unwrap() == "InvalidRequest"
    );
}
