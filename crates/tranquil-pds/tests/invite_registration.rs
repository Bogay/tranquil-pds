mod common;
use common::*;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tranquil_pds::api::error::ApiError;
use tranquil_pds::api::invite::{InviteRegistration, check_registration_invite};
use tranquil_types::InviteCode;

async fn create_invite_code(client: &Client, admin_jwt: &str, use_count: u32) -> InviteCode {
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createInviteCode",
            base_url().await
        ))
        .bearer_auth(admin_jwt)
        .json(&json!({ "useCount": use_count }))
        .send()
        .await
        .expect("failed to create invite code");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("invite code response not json");
    InviteCode::from(body["code"].as_str().expect("missing code").to_string())
}

#[tokio::test]
async fn check_registration_invite_validates_without_consuming() {
    let state = get_test_app_state().await;

    let client = client();
    let (admin_jwt, _did) = create_admin_account_and_login(&client).await;
    let code = create_invite_code(&client, &admin_jwt, 1).await;

    assert_eq!(
        check_registration_invite(state, Some(code.as_str()))
            .await
            .unwrap(),
        InviteRegistration::Standard(Some(code.clone()))
    );
    assert_eq!(
        state
            .repos
            .infra
            .get_invite_code_available_uses(&code)
            .await
            .unwrap(),
        Some(1),
        "validation must not consume the invite"
    );

    assert_eq!(
        check_registration_invite(state, Some(&format!("  {code}  ")))
            .await
            .unwrap(),
        InviteRegistration::Standard(Some(code.clone())),
        "surrounding whitespace must be trimmed into the validated code"
    );

    assert!(matches!(
        check_registration_invite(state, Some("whelk")).await,
        Err(ApiError::InvalidInviteCode)
    ));
}

#[tokio::test]
async fn create_account_consumes_invite_code_exactly_once() {
    let client = client();
    let (admin_jwt, _did) = create_admin_account_and_login(&client).await;
    let code = create_invite_code(&client, &admin_jwt, 2).await;

    let handle = format!("u{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&json!({
            "handle": handle,
            "email": format!("{handle}@nel.pet"),
            "password": "Testpass123!",
            "inviteCode": code,
        }))
        .send()
        .await
        .expect("createAccount request failed");
    let status = res.status();
    let text = res.text().await.unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "createAccount failed: {text}");

    let state = get_test_app_state().await;
    assert_eq!(
        state
            .repos
            .infra
            .get_invite_code_available_uses(&code)
            .await
            .unwrap(),
        Some(1),
        "a single registration must consume exactly one invite use"
    );
}
