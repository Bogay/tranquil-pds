mod common;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
#[tokio::test]
async fn test_admin_get_invite_codes_success() {
    let client = client();
    let (access_jwt, _did) = create_account_and_login(&client).await;
    let create_payload = json!({
        "useCount": 3
    });
    let _ = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create invite code");
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.getInviteCodes",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["codes"].is_array());
}
#[tokio::test]
async fn test_admin_get_invite_codes_with_limit() {
    let client = client();
    let (access_jwt, _did) = create_account_and_login(&client).await;
    for _ in 0..5 {
        let create_payload = json!({
            "useCount": 1
        });
        let _ = client
            .post(format!(
                "{}/xrpc/com.atproto.server.createInviteCode",
                base_url().await
            ))
            .bearer_auth(&access_jwt)
            .json(&create_payload)
            .send()
            .await;
    }
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.getInviteCodes",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .query(&[("limit", "2")])
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let codes = body["codes"].as_array().unwrap();
    assert!(codes.len() <= 2);
}
#[tokio::test]
async fn test_admin_get_invite_codes_no_auth() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.getInviteCodes",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn test_disable_account_invites_success() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;
    let payload = json!({
        "account": did
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.disableAccountInvites",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let create_payload = json!({
        "useCount": 1
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "InvitesDisabled");
}
#[tokio::test]
async fn test_enable_account_invites_success() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;
    let disable_payload = json!({
        "account": did
    });
    let _ = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.disableAccountInvites",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&disable_payload)
        .send()
        .await;
    let enable_payload = json!({
        "account": did
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.enableAccountInvites",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&enable_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let create_payload = json!({
        "useCount": 1
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
}
#[tokio::test]
async fn test_disable_account_invites_no_auth() {
    let client = client();
    let payload = json!({
        "account": "did:plc:test"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.disableAccountInvites",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn test_disable_account_invites_not_found() {
    let client = client();
    let (access_jwt, _did) = create_account_and_login(&client).await;
    let payload = json!({
        "account": "did:plc:nonexistent"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.disableAccountInvites",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn test_disable_invite_codes_by_code() {
    let client = client();
    let (access_jwt, _did) = create_account_and_login(&client).await;
    let create_payload = json!({
        "useCount": 5
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create invite code");
    let create_body: Value = create_res.json().await.unwrap();
    let code = create_body["code"].as_str().unwrap();
    let disable_payload = json!({
        "codes": [code]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.disableInviteCodes",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&disable_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let list_res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getAccountInviteCodes",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to get invite codes");
    let list_body: Value = list_res.json().await.unwrap();
    let codes = list_body["codes"].as_array().unwrap();
    let disabled_code = codes.iter().find(|c| c["code"].as_str().unwrap() == code);
    assert!(disabled_code.is_some());
    assert_eq!(disabled_code.unwrap()["disabled"], true);
}
#[tokio::test]
async fn test_disable_invite_codes_by_account() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;
    for _ in 0..3 {
        let create_payload = json!({
            "useCount": 1
        });
        let _ = client
            .post(format!(
                "{}/xrpc/com.atproto.server.createInviteCode",
                base_url().await
            ))
            .bearer_auth(&access_jwt)
            .json(&create_payload)
            .send()
            .await;
    }
    let disable_payload = json!({
        "accounts": [did]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.disableInviteCodes",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&disable_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let list_res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getAccountInviteCodes",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to get invite codes");
    let list_body: Value = list_res.json().await.unwrap();
    let codes = list_body["codes"].as_array().unwrap();
    for code in codes {
        assert_eq!(code["disabled"], true);
    }
}
#[tokio::test]
async fn test_disable_invite_codes_no_auth() {
    let client = client();
    let payload = json!({
        "codes": ["some-code"]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.disableInviteCodes",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn test_admin_enable_account_invites_not_found() {
    let client = client();
    let (access_jwt, _did) = create_account_and_login(&client).await;
    let payload = json!({
        "account": "did:plc:nonexistent"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.enableAccountInvites",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
