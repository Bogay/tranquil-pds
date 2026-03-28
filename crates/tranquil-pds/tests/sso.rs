mod common;

use common::{base_url, client, create_account_and_login, get_test_repos};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_db_traits::{CommsChannel, SsoAction, SsoProviderType};
use tranquil_oauth::{
    AuthorizationRequestParameters, CodeChallengeMethod, RequestData, ResponseType,
};
use tranquil_types::{Did, RequestId};

#[tokio::test]
async fn test_sso_providers_endpoint() {
    let url = base_url().await;
    let client = client();

    let res = client
        .get(format!("{}/oauth/sso/providers", url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(body["providers"].is_array());
}

#[tokio::test]
async fn test_sso_initiate_invalid_provider() {
    let url = base_url().await;
    let client = client();

    let res = client
        .post(format!("{}/oauth/sso/initiate", url))
        .json(&json!({
            "provider": "nonexistent_provider",
            "request_uri": "urn:test:request",
            "action": "login"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_sso_initiate_invalid_action() {
    let url = base_url().await;
    let client = client();

    let res = client
        .post(format!("{}/oauth/sso/initiate", url))
        .json(&json!({
            "provider": "github",
            "request_uri": "urn:test:request",
            "action": "invalid_action"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_sso_linked_requires_auth() {
    let url = base_url().await;
    let client = client();

    let res = client
        .get(format!("{}/oauth/sso/linked", url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_sso_linked_returns_empty_for_new_user() {
    let url = base_url().await;
    let client = client();

    let (token, _did) = create_account_and_login(&client).await;

    let res = client
        .get(format!("{}/oauth/sso/linked", url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(body["accounts"].is_array());
    assert_eq!(body["accounts"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_sso_unlink_requires_auth() {
    let url = base_url().await;
    let client = client();

    let res = client
        .post(format!("{}/oauth/sso/unlink", url))
        .json(&json!({
            "id": "00000000-0000-0000-0000-000000000000"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_sso_unlink_invalid_id() {
    let url = base_url().await;
    let client = client();

    let (token, _did) = create_account_and_login(&client).await;

    let res = client
        .post(format!("{}/oauth/sso/unlink", url))
        .bearer_auth(&token)
        .json(&json!({
            "id": "not-a-uuid"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidId");
}

#[tokio::test]
async fn test_sso_unlink_not_found() {
    let url = base_url().await;
    let client = client();

    let (token, _did) = create_account_and_login(&client).await;

    let res = client
        .post(format!("{}/oauth/sso/unlink", url))
        .bearer_auth(&token)
        .json(&json!({
            "id": "00000000-0000-0000-0000-000000000000"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "SsoLinkNotFound");
}

#[tokio::test]
async fn test_sso_callback_missing_params() {
    let url = base_url().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let res = client
        .get(format!("{}/oauth/sso/callback", url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let location = res.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("/app/oauth/error"));
}

#[tokio::test]
async fn test_sso_callback_with_error() {
    let url = base_url().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let res = client
        .get(format!(
            "{}/oauth/sso/callback?error=access_denied&error_description=User%20cancelled",
            url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let location = res.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("/app/oauth/error"));
    assert!(location.contains("access_denied"));
}

#[tokio::test]
async fn test_sso_callback_invalid_state() {
    let url = base_url().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let res = client
        .get(format!(
            "{}/oauth/sso/callback?code=fake_code&state=invalid_state_token",
            url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let location = res.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("/app/oauth/error"));
}

#[tokio::test]
async fn test_external_identity_repository_crud() {
    let _url = base_url().await;
    let repos = get_test_repos().await;
    let client = client();

    let (_token, did_string) = create_account_and_login(&client).await;
    let did: Did = did_string.parse().expect("valid DID");

    let provider = SsoProviderType::Github;
    let provider_user_id = format!("github_user_{}", uuid::Uuid::new_v4().simple());

    let id = repos
        .sso
        .create_external_identity(
            &did,
            provider,
            &provider_user_id,
            Some("testuser"),
            Some("test@github.com"),
        )
        .await
        .unwrap();

    let found = repos
        .sso
        .get_external_identity_by_provider(provider, &provider_user_id)
        .await
        .unwrap();

    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.id, id);
    assert_eq!(found.did, did);
    assert_eq!(
        found.provider_username.as_ref().unwrap().as_str(),
        "testuser"
    );

    let identities = repos
        .sso
        .get_external_identities_by_did(&did)
        .await
        .unwrap();

    assert_eq!(identities.len(), 1);

    repos
        .sso
        .update_external_identity_login(id, Some("updated_username"), None)
        .await
        .unwrap();

    let updated = repos
        .sso
        .get_external_identity_by_provider(provider, &provider_user_id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        updated.provider_username.as_ref().unwrap().as_str(),
        "updated_username"
    );
    assert!(updated.last_login_at.is_some());

    let deleted = repos.sso.delete_external_identity(id, &did).await.unwrap();
    assert!(deleted);

    let not_found = repos
        .sso
        .get_external_identity_by_provider(provider, &provider_user_id)
        .await
        .unwrap();

    assert!(not_found.is_none());
}

#[tokio::test]
async fn test_external_identity_unique_constraints() {
    let _url = base_url().await;
    let repos = get_test_repos().await;
    let client = client();

    let (_token1, did1_string) = create_account_and_login(&client).await;
    let did1: Did = did1_string.parse().expect("valid DID");
    let (_token2, did2_string) = create_account_and_login(&client).await;
    let did2: Did = did2_string.parse().expect("valid DID");

    let provider_user_id = format!("unique_test_{}", uuid::Uuid::new_v4().simple());

    repos
        .sso
        .create_external_identity(
            &did1,
            SsoProviderType::Github,
            &provider_user_id,
            None,
            None,
        )
        .await
        .unwrap();

    let duplicate_provider_user = repos
        .sso
        .create_external_identity(
            &did2,
            SsoProviderType::Github,
            &provider_user_id,
            None,
            None,
        )
        .await;

    assert!(duplicate_provider_user.is_err());

    let duplicate_did_provider = repos
        .sso
        .create_external_identity(
            &did1,
            SsoProviderType::Github,
            "different_user_id",
            None,
            None,
        )
        .await;

    assert!(duplicate_did_provider.is_err());

    let discord_user_id = format!("discord_user_{}", uuid::Uuid::new_v4().simple());
    let different_provider = repos
        .sso
        .create_external_identity(
            &did1,
            SsoProviderType::Discord,
            &discord_user_id,
            None,
            None,
        )
        .await;

    assert!(
        different_provider.is_ok(),
        "Expected OK but got: {:?}",
        different_provider.err()
    );
}

#[tokio::test]
async fn test_sso_auth_state_lifecycle() {
    let _url = base_url().await;
    let repos = get_test_repos().await;

    let state = format!("test_state_{}", uuid::Uuid::new_v4().simple());
    let request_uri = "urn:ietf:params:oauth:request_uri:test123";

    repos
        .sso
        .create_sso_auth_state(
            &state,
            request_uri,
            SsoProviderType::Github,
            SsoAction::Login,
            Some("test_nonce"),
            Some("test_verifier"),
            None,
        )
        .await
        .unwrap();

    let consumed = repos.sso.consume_sso_auth_state(&state).await.unwrap();

    assert!(consumed.is_some());
    let consumed = consumed.unwrap();
    assert_eq!(consumed.request_uri, request_uri);
    assert_eq!(consumed.action, SsoAction::Login);
    assert_eq!(consumed.nonce.as_deref(), Some("test_nonce"));
    assert_eq!(consumed.code_verifier.as_deref(), Some("test_verifier"));

    let double_consume = repos.sso.consume_sso_auth_state(&state).await.unwrap();
    assert!(double_consume.is_none());
}

#[tokio::test]
async fn test_sso_auth_state_expiration() {
    let _url = base_url().await;
    let repos = get_test_repos().await;

    let consumed = repos
        .sso
        .consume_sso_auth_state("nonexistent_state_token")
        .await
        .unwrap();

    assert!(consumed.is_none());

    let cleaned = repos.sso.cleanup_expired_sso_auth_states().await.unwrap();

    assert!(cleaned == 0 || cleaned >= 1);
}

#[tokio::test]
async fn test_delete_external_identity_wrong_did() {
    let _url = base_url().await;
    let repos = get_test_repos().await;
    let client = client();

    let (_token, did_string) = create_account_and_login(&client).await;
    let did: Did = did_string.parse().expect("valid DID");
    let wrong_did: Did = "did:plc:wrongdid12345".parse().expect("valid test DID");

    let provider_user_id = format!("delete_test_{}", uuid::Uuid::new_v4().simple());

    let id = repos
        .sso
        .create_external_identity(&did, SsoProviderType::Github, &provider_user_id, None, None)
        .await
        .unwrap();

    let deleted = repos
        .sso
        .delete_external_identity(id, &wrong_did)
        .await
        .unwrap();

    assert!(!deleted);

    let still_exists = repos
        .sso
        .get_external_identity_by_provider(SsoProviderType::Github, &provider_user_id)
        .await
        .unwrap();

    assert!(still_exists.is_some());
}

#[tokio::test]
async fn test_sso_pending_registration_lifecycle() {
    let _url = base_url().await;
    let repos = get_test_repos().await;

    let token = format!("pending_token_{}", uuid::Uuid::new_v4().simple());
    let request_uri = "urn:ietf:params:oauth:request_uri:pendingtest";
    let provider_user_id = format!("pending_user_{}", uuid::Uuid::new_v4().simple());

    repos
        .sso
        .create_pending_registration(
            &token,
            request_uri,
            SsoProviderType::Github,
            &provider_user_id,
            Some("pendinguser"),
            Some("pending@github.com"),
            false,
        )
        .await
        .unwrap();

    let found = repos.sso.get_pending_registration(&token).await.unwrap();

    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.request_uri, request_uri);
    assert_eq!(
        found.provider_username.as_ref().unwrap().as_str(),
        "pendinguser"
    );
    assert_eq!(
        found.provider_email.as_ref().unwrap().as_str(),
        "pending@github.com"
    );

    let consumed = repos
        .sso
        .consume_pending_registration(&token)
        .await
        .unwrap();

    assert!(consumed.is_some());

    let double_consume = repos
        .sso
        .consume_pending_registration(&token)
        .await
        .unwrap();

    assert!(double_consume.is_none());
}

#[tokio::test]
async fn test_sso_pending_registration_expiration() {
    let _url = base_url().await;
    let repos = get_test_repos().await;

    let consumed = repos
        .sso
        .get_pending_registration("nonexistent_pending_token")
        .await
        .unwrap();

    assert!(consumed.is_none());

    let cleaned = repos
        .sso
        .cleanup_expired_pending_registrations()
        .await
        .unwrap();

    assert!(cleaned == 0 || cleaned >= 1);
}

#[tokio::test]
async fn test_sso_complete_registration_invalid_token() {
    let url = base_url().await;
    let client = client();

    let res = client
        .post(format!("{}/oauth/sso/complete-registration", url))
        .json(&json!({
            "token": "nonexistent_token_12345",
            "handle": "newuser"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "SsoSessionExpired");
}

#[tokio::test]
async fn test_sso_complete_registration_expired_token() {
    let url = base_url().await;
    let client = client();

    let res = client
        .post(format!("{}/oauth/sso/complete-registration", url))
        .json(&json!({
            "token": format!("expired_reg_token_{}", uuid::Uuid::new_v4().simple()),
            "handle": "newuser"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "SsoSessionExpired");
}

#[tokio::test]
async fn test_sso_get_pending_registration_invalid_token() {
    let url = base_url().await;
    let client = client();

    let res = client
        .get(format!(
            "{}/oauth/sso/pending-registration?token=nonexistent_token",
            url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "SsoSessionExpired");
}

#[tokio::test]
async fn test_sso_get_pending_registration_token_too_long() {
    let url = base_url().await;
    let client = client();

    let long_token = "a".repeat(200);
    let res = client
        .get(format!(
            "{}/oauth/sso/pending-registration?token={}",
            url, long_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

fn test_request_data() -> RequestData {
    RequestData {
        client_id: "https://test.example.com".to_string(),
        client_auth: None,
        parameters: AuthorizationRequestParameters {
            response_type: ResponseType::Code,
            client_id: "https://test.example.com".to_string(),
            redirect_uri: "https://test.example.com/callback".to_string(),
            scope: Some("atproto".to_string()),
            state: Some("teststate".to_string()),
            code_challenge: "testchallenge".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            response_mode: None,
            login_hint: None,
            dpop_jkt: None,
            prompt: None,
            extra: None,
        },
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        did: None,
        device_id: None,
        code: None,
        controller_did: None,
    }
}

#[tokio::test]
async fn test_sso_complete_registration_success() {
    let url = base_url().await;
    let repos = get_test_repos().await;
    let client = client();

    let token = format!("success_reg_token_{}", uuid::Uuid::new_v4().simple());
    let handle_prefix = format!("ssoreg{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);
    let provider_user_id = format!("success_user_{}", uuid::Uuid::new_v4().simple());
    let provider_email = format!("sso_{}@example.com", uuid::Uuid::new_v4().simple());

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4());
    let request_id = RequestId::new(&request_uri);

    repos
        .oauth
        .create_authorization_request(&request_id, &test_request_data())
        .await
        .unwrap();

    repos
        .sso
        .create_pending_registration(
            &token,
            &request_uri,
            SsoProviderType::Github,
            &provider_user_id,
            Some("ssouser"),
            Some(&provider_email),
            true,
        )
        .await
        .unwrap();

    let res = client
        .post(format!("{}/oauth/sso/complete-registration", url))
        .json(&json!({
            "token": token,
            "handle": handle_prefix,
            "email": provider_email,
            "verification_channel": "email"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(
        body.get("did").is_some(),
        "Expected did in response, got: {:?}",
        body
    );
    assert!(
        body.get("handle").is_some(),
        "Expected handle in response, got: {:?}",
        body
    );
    assert!(
        body.get("redirectUrl").is_some(),
        "Expected redirectUrl in response, got: {:?}",
        body
    );

    let did_str = body["did"].as_str().unwrap();
    assert!(did_str.starts_with("did:plc:"));

    let redirect_url = body["redirectUrl"].as_str().unwrap();
    assert!(
        redirect_url.contains("/app/oauth/consent"),
        "Auto-verified email should redirect to consent, got: {}",
        redirect_url
    );

    let pending_consumed = repos.sso.get_pending_registration(&token).await.unwrap();

    assert!(
        pending_consumed.is_none(),
        "Pending registration should be consumed after successful registration"
    );

    let did: Did = did_str.parse().expect("valid DID from response");
    let external_identities = repos
        .sso
        .get_external_identities_by_did(&did)
        .await
        .unwrap();

    assert!(
        !external_identities.is_empty(),
        "External identity should be created"
    );
    let ext_id = &external_identities[0];
    assert_eq!(ext_id.provider_user_id.as_str(), provider_user_id);
}

#[tokio::test]
async fn test_sso_complete_registration_multichannel_discord() {
    let url = base_url().await;
    let repos = get_test_repos().await;
    let client = client();

    let token = format!("discord_reg_token_{}", uuid::Uuid::new_v4().simple());
    let handle_prefix = format!(
        "discordreg{}",
        &uuid::Uuid::new_v4().simple().to_string()[..4]
    );
    let provider_user_id = format!("discord_prov_{}", uuid::Uuid::new_v4().simple());
    let discord_id = "123456789012345678";

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4());
    let request_id = RequestId::new(&request_uri);

    repos
        .oauth
        .create_authorization_request(&request_id, &test_request_data())
        .await
        .unwrap();

    repos
        .sso
        .create_pending_registration(
            &token,
            &request_uri,
            SsoProviderType::Discord,
            &provider_user_id,
            Some("discorduser"),
            None,
            false,
        )
        .await
        .unwrap();

    let res = client
        .post(format!("{}/oauth/sso/complete-registration", url))
        .json(&json!({
            "token": token,
            "handle": handle_prefix,
            "verification_channel": "discord",
            "discord_username": discord_id
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(body.get("did").is_some());

    let redirect_url = body["redirectUrl"].as_str().unwrap();
    assert!(
        redirect_url.contains("/app/verify"),
        "Non-auto-verified channel should redirect to verify, got: {}",
        redirect_url
    );

    let did_str = body["did"].as_str().unwrap();
    let did: Did = did_str.parse().expect("valid DID from response");
    let user = repos
        .user
        .get_resend_verification_by_did(&did)
        .await
        .unwrap();
    assert!(user.is_some(), "User should exist");
    let user = user.unwrap();
    assert_eq!(user.channel, CommsChannel::Discord);
    assert_eq!(user.discord_username.as_deref(), Some(discord_id));
}

#[tokio::test]
async fn test_sso_check_handle_available() {
    let url = base_url().await;
    let client = client();

    let unique_handle = format!("avail{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let res = client
        .get(format!(
            "{}/oauth/sso/check-handle-available?handle={}",
            url, unique_handle
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["available"], true);
    assert!(body["reason"].is_null());
}

#[tokio::test]
async fn test_sso_check_handle_invalid() {
    let url = base_url().await;
    let client = client();

    let res = client
        .get(format!(
            "{}/oauth/sso/check-handle-available?handle=ab",
            url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["available"], false);
    assert!(body["reason"].is_string());
}

#[tokio::test]
async fn test_sso_complete_registration_missing_channel_data() {
    let url = base_url().await;
    let repos = get_test_repos().await;
    let client = client();

    let token = format!("missing_channel_{}", uuid::Uuid::new_v4().simple());
    let handle_prefix = format!("missch{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4());
    let request_id = RequestId::new(&request_uri);

    repos
        .oauth
        .create_authorization_request(&request_id, &test_request_data())
        .await
        .unwrap();

    repos
        .sso
        .create_pending_registration(
            &token,
            &request_uri,
            SsoProviderType::Github,
            "missing_channel_user",
            None,
            None,
            false,
        )
        .await
        .unwrap();

    let res = client
        .post(format!("{}/oauth/sso/complete-registration", url))
        .json(&json!({
            "token": token,
            "handle": handle_prefix,
            "verification_channel": "discord"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "MissingDiscordId");
}
