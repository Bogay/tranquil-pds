mod common;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_create_invite_code_success() {
    let client = client();
    let (access_jwt, _did) = create_admin_account_and_login(&client).await;
    let payload = json!({
        "useCount": 5
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["code"].is_string());
    let code = body["code"].as_str().unwrap();
    assert!(!code.is_empty());
    assert!(code.contains('-'), "Code should be in hostname-xxxxx-xxxxx format");
    let parts: Vec<&str> = code.split('-').collect();
    assert!(parts.len() >= 3, "Code should have at least 3 parts (hostname + 2 random parts)");
}

#[tokio::test]
async fn test_create_invite_code_no_auth() {
    let client = client();
    let payload = json!({
        "useCount": 5
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn test_create_invite_code_non_admin() {
    let client = client();
    let (access_jwt, _did) = create_account_and_login(&client).await;
    let payload = json!({
        "useCount": 5
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "AdminRequired");
}

#[tokio::test]
async fn test_create_invite_code_invalid_use_count() {
    let client = client();
    let (access_jwt, _did) = create_admin_account_and_login(&client).await;
    let payload = json!({
        "useCount": 0
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_create_invite_code_for_another_account() {
    let client = client();
    let (access_jwt1, _did1) = create_admin_account_and_login(&client).await;
    let (_access_jwt2, did2) = create_account_and_login(&client).await;
    let payload = json!({
        "useCount": 3,
        "forAccount": did2
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(&access_jwt1)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["code"].is_string());
}

#[tokio::test]
async fn test_create_invite_codes_success() {
    let client = client();
    let (access_jwt, _did) = create_admin_account_and_login(&client).await;
    let payload = json!({
        "useCount": 2,
        "codeCount": 3
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCodes",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["codes"].is_array());
    let codes = body["codes"].as_array().unwrap();
    assert_eq!(codes.len(), 1);
    assert_eq!(codes[0]["account"], "admin");
    assert_eq!(codes[0]["codes"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_create_invite_codes_for_multiple_accounts() {
    let client = client();
    let (access_jwt1, did1) = create_admin_account_and_login(&client).await;
    let (_access_jwt2, did2) = create_account_and_login(&client).await;
    let payload = json!({
        "useCount": 1,
        "codeCount": 2,
        "forAccounts": [did1, did2]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCodes",
            base_url().await
        ))
        .bearer_auth(&access_jwt1)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let codes = body["codes"].as_array().unwrap();
    assert_eq!(codes.len(), 2);
    for code_obj in codes {
        assert!(code_obj["account"].is_string());
        assert_eq!(code_obj["codes"].as_array().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn test_create_invite_codes_no_auth() {
    let client = client();
    let payload = json!({
        "useCount": 2
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCodes",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_invite_codes_non_admin() {
    let client = client();
    let (access_jwt, _did) = create_account_and_login(&client).await;
    let payload = json!({
        "useCount": 2
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCodes",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "AdminRequired");
}

#[tokio::test]
async fn test_get_account_invite_codes_success() {
    let client = client();
    let (admin_jwt, _admin_did) = create_admin_account_and_login(&client).await;
    let (user_jwt, user_did) = create_account_and_login(&client).await;

    let create_payload = json!({
        "useCount": 5,
        "forAccount": user_did
    });
    let _ = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(&admin_jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create invite code");

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getAccountInviteCodes",
            base_url().await
        ))
        .bearer_auth(&user_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["codes"].is_array());
    let codes = body["codes"].as_array().unwrap();
    assert!(!codes.is_empty());
    let code = &codes[0];
    assert!(code["code"].is_string());
    assert!(code["available"].is_number());
    assert!(code["disabled"].is_boolean());
    assert!(code["createdAt"].is_string());
    assert!(code["uses"].is_array());
    assert_eq!(code["forAccount"], user_did);
    assert_eq!(code["createdBy"], "admin");
}

#[tokio::test]
async fn test_get_account_invite_codes_no_auth() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getAccountInviteCodes",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_account_invite_codes_include_used_filter() {
    let client = client();
    let (admin_jwt, _admin_did) = create_admin_account_and_login(&client).await;
    let (user_jwt, user_did) = create_account_and_login(&client).await;

    let create_payload = json!({
        "useCount": 5,
        "forAccount": user_did
    });
    let _ = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(&admin_jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create invite code");

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getAccountInviteCodes",
            base_url().await
        ))
        .bearer_auth(&user_jwt)
        .query(&[("includeUsed", "false")])
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["codes"].is_array());
    for code in body["codes"].as_array().unwrap() {
        assert!(code["available"].as_i64().unwrap() > 0);
    }
}

#[tokio::test]
async fn test_get_account_invite_codes_filters_disabled() {
    let client = client();
    let (admin_jwt, admin_did) = create_admin_account_and_login(&client).await;

    let create_payload = json!({
        "useCount": 5,
        "forAccount": admin_did
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(&admin_jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create invite code");
    let create_body: Value = create_res.json().await.unwrap();
    let code = create_body["code"].as_str().unwrap();

    let disable_payload = json!({
        "codes": [code]
    });
    let _ = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.disableInviteCodes",
            base_url().await
        ))
        .bearer_auth(&admin_jwt)
        .json(&disable_payload)
        .send()
        .await
        .expect("Failed to disable invite code");

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getAccountInviteCodes",
            base_url().await
        ))
        .bearer_auth(&admin_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let codes = body["codes"].as_array().unwrap();
    for c in codes {
        assert_ne!(c["code"].as_str().unwrap(), code, "Disabled code should be filtered out");
    }
}
