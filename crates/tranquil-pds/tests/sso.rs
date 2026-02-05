mod common;

use common::{base_url, client, create_account_and_login, get_test_db_pool};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_db_traits::SsoProviderType;
use tranquil_types::Did;

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
    assert_eq!(body["error"], "SsoProviderNotFound");
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
    assert!(
        body["error"] == "SsoInvalidAction" || body["error"] == "SsoProviderNotEnabled",
        "Expected SsoInvalidAction or SsoProviderNotEnabled, got: {}",
        body["error"]
    );
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
    let pool = get_test_db_pool().await;

    let did = unsafe {
        Did::new_unchecked(format!(
            "did:plc:test{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        ))
    };
    let provider = SsoProviderType::Github;
    let provider_user_id = format!("github_user_{}", uuid::Uuid::new_v4().simple());

    sqlx::query!(
        "INSERT INTO users (did, handle, email, password_hash) VALUES ($1, $2, $3, 'hash')",
        did.as_str(),
        format!("test{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
        format!(
            "test{}@example.com",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        )
    )
    .execute(pool)
    .await
    .unwrap();

    let id: uuid::Uuid = sqlx::query_scalar!(
        r#"
        INSERT INTO external_identities (did, provider, provider_user_id, provider_username, provider_email)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        "#,
        did.as_str(),
        provider as SsoProviderType,
        &provider_user_id,
        Some("testuser"),
        Some("test@github.com"),
    )
    .fetch_one(pool)
    .await
    .unwrap();

    let found = sqlx::query!(
        r#"
        SELECT id, did, provider as "provider: SsoProviderType", provider_user_id, provider_username, provider_email
        FROM external_identities
        WHERE provider = $1 AND provider_user_id = $2
        "#,
        provider as SsoProviderType,
        &provider_user_id,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.id, id);
    assert_eq!(found.did, did.as_str());
    assert_eq!(found.provider_username, Some("testuser".to_string()));

    let identities = sqlx::query!(
        r#"
        SELECT id FROM external_identities WHERE did = $1
        "#,
        did.as_str(),
    )
    .fetch_all(pool)
    .await
    .unwrap();

    assert_eq!(identities.len(), 1);

    sqlx::query!(
        r#"
        UPDATE external_identities
        SET provider_username = $2, last_login_at = NOW()
        WHERE id = $1
        "#,
        id,
        "updated_username",
    )
    .execute(pool)
    .await
    .unwrap();

    let updated = sqlx::query!(
        r#"SELECT provider_username, last_login_at FROM external_identities WHERE id = $1"#,
        id,
    )
    .fetch_one(pool)
    .await
    .unwrap();

    assert_eq!(
        updated.provider_username,
        Some("updated_username".to_string())
    );
    assert!(updated.last_login_at.is_some());

    let deleted = sqlx::query!(
        r#"DELETE FROM external_identities WHERE id = $1 AND did = $2"#,
        id,
        did.as_str(),
    )
    .execute(pool)
    .await
    .unwrap();

    assert_eq!(deleted.rows_affected(), 1);

    let not_found = sqlx::query!(r#"SELECT id FROM external_identities WHERE id = $1"#, id,)
        .fetch_optional(pool)
        .await
        .unwrap();

    assert!(not_found.is_none());
}

#[tokio::test]
async fn test_external_identity_unique_constraints() {
    let _url = base_url().await;
    let pool = get_test_db_pool().await;

    let did1 = unsafe {
        Did::new_unchecked(format!(
            "did:plc:uc1{}",
            &uuid::Uuid::new_v4().simple().to_string()[..10]
        ))
    };
    let did2 = unsafe {
        Did::new_unchecked(format!(
            "did:plc:uc2{}",
            &uuid::Uuid::new_v4().simple().to_string()[..10]
        ))
    };
    let provider_user_id = format!("unique_test_{}", uuid::Uuid::new_v4().simple());

    sqlx::query!(
        "INSERT INTO users (did, handle, email, password_hash) VALUES ($1, $2, $3, 'hash')",
        did1.as_str(),
        format!("uc1{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
        format!(
            "uc1{}@example.com",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        )
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query!(
        "INSERT INTO users (did, handle, email, password_hash) VALUES ($1, $2, $3, 'hash')",
        did2.as_str(),
        format!("uc2{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
        format!(
            "uc2{}@example.com",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        )
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query!(
        r#"
        INSERT INTO external_identities (did, provider, provider_user_id)
        VALUES ($1, $2, $3)
        "#,
        did1.as_str(),
        SsoProviderType::Github as SsoProviderType,
        &provider_user_id,
    )
    .execute(pool)
    .await
    .unwrap();

    let duplicate_provider_user = sqlx::query!(
        r#"
        INSERT INTO external_identities (did, provider, provider_user_id)
        VALUES ($1, $2, $3)
        "#,
        did2.as_str(),
        SsoProviderType::Github as SsoProviderType,
        &provider_user_id,
    )
    .execute(pool)
    .await;

    assert!(duplicate_provider_user.is_err());

    let duplicate_did_provider = sqlx::query!(
        r#"
        INSERT INTO external_identities (did, provider, provider_user_id)
        VALUES ($1, $2, $3)
        "#,
        did1.as_str(),
        SsoProviderType::Github as SsoProviderType,
        "different_user_id",
    )
    .execute(pool)
    .await;

    assert!(duplicate_did_provider.is_err());

    let discord_user_id = format!("discord_user_{}", uuid::Uuid::new_v4().simple());
    let different_provider = sqlx::query!(
        r#"
        INSERT INTO external_identities (did, provider, provider_user_id)
        VALUES ($1, $2, $3)
        "#,
        did1.as_str(),
        SsoProviderType::Discord as SsoProviderType,
        &discord_user_id,
    )
    .execute(pool)
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
    let pool = get_test_db_pool().await;

    let state = format!("test_state_{}", uuid::Uuid::new_v4().simple());
    let request_uri = "urn:ietf:params:oauth:request_uri:test123";

    sqlx::query!(
        r#"
        INSERT INTO sso_auth_state (state, request_uri, provider, action, nonce, code_verifier)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        &state,
        request_uri,
        SsoProviderType::Github as SsoProviderType,
        "login",
        Some("test_nonce"),
        Some("test_verifier"),
    )
    .execute(pool)
    .await
    .unwrap();

    let found = sqlx::query!(
        r#"
        SELECT state, request_uri, provider as "provider: SsoProviderType", action, nonce, code_verifier
        FROM sso_auth_state
        WHERE state = $1
        "#,
        &state,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.request_uri, request_uri);
    assert_eq!(found.action, "login");
    assert_eq!(found.nonce, Some("test_nonce".to_string()));
    assert_eq!(found.code_verifier, Some("test_verifier".to_string()));

    let consumed = sqlx::query!(
        r#"
        DELETE FROM sso_auth_state
        WHERE state = $1 AND expires_at > NOW()
        RETURNING state, request_uri
        "#,
        &state,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(consumed.is_some());

    let not_found = sqlx::query!(
        r#"SELECT state FROM sso_auth_state WHERE state = $1"#,
        &state,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(not_found.is_none());

    let double_consume = sqlx::query!(
        r#"
        DELETE FROM sso_auth_state
        WHERE state = $1 AND expires_at > NOW()
        RETURNING state
        "#,
        &state,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(double_consume.is_none());
}

#[tokio::test]
async fn test_sso_auth_state_expiration() {
    let _url = base_url().await;
    let pool = get_test_db_pool().await;

    let state = format!("expired_state_{}", uuid::Uuid::new_v4().simple());

    sqlx::query!(
        r#"
        INSERT INTO sso_auth_state (state, request_uri, provider, action, expires_at)
        VALUES ($1, $2, $3, $4, NOW() - INTERVAL '1 hour')
        "#,
        &state,
        "urn:test:expired",
        SsoProviderType::Github as SsoProviderType,
        "login",
    )
    .execute(pool)
    .await
    .unwrap();

    let consumed = sqlx::query!(
        r#"
        DELETE FROM sso_auth_state
        WHERE state = $1 AND expires_at > NOW()
        RETURNING state
        "#,
        &state,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(consumed.is_none());

    let cleaned = sqlx::query!(r#"DELETE FROM sso_auth_state WHERE expires_at < NOW()"#,)
        .execute(pool)
        .await
        .unwrap();

    assert!(cleaned.rows_affected() >= 1);
}

#[tokio::test]
async fn test_delete_external_identity_wrong_did() {
    let _url = base_url().await;
    let pool = get_test_db_pool().await;

    let did = unsafe {
        Did::new_unchecked(format!(
            "did:plc:del{}",
            &uuid::Uuid::new_v4().simple().to_string()[..10]
        ))
    };
    let wrong_did = unsafe { Did::new_unchecked("did:plc:wrongdid12345") };

    sqlx::query!(
        "INSERT INTO users (did, handle, email, password_hash) VALUES ($1, $2, $3, 'hash')",
        did.as_str(),
        format!("del{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
        format!(
            "del{}@example.com",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        )
    )
    .execute(pool)
    .await
    .unwrap();

    let id: uuid::Uuid = sqlx::query_scalar!(
        r#"
        INSERT INTO external_identities (did, provider, provider_user_id)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
        did.as_str(),
        SsoProviderType::Github as SsoProviderType,
        format!("delete_test_{}", uuid::Uuid::new_v4().simple()),
    )
    .fetch_one(pool)
    .await
    .unwrap();

    let wrong_delete = sqlx::query!(
        r#"DELETE FROM external_identities WHERE id = $1 AND did = $2"#,
        id,
        wrong_did.as_str(),
    )
    .execute(pool)
    .await
    .unwrap();

    assert_eq!(wrong_delete.rows_affected(), 0);

    let still_exists = sqlx::query!(r#"SELECT id FROM external_identities WHERE id = $1"#, id,)
        .fetch_optional(pool)
        .await
        .unwrap();

    assert!(still_exists.is_some());
}

#[tokio::test]
async fn test_sso_pending_registration_lifecycle() {
    let _url = base_url().await;
    let pool = get_test_db_pool().await;

    let token = format!("pending_token_{}", uuid::Uuid::new_v4().simple());
    let request_uri = "urn:ietf:params:oauth:request_uri:pendingtest";
    let provider_user_id = format!("pending_user_{}", uuid::Uuid::new_v4().simple());

    sqlx::query!(
        r#"
        INSERT INTO sso_pending_registration (token, request_uri, provider, provider_user_id, provider_username, provider_email)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        &token,
        request_uri,
        SsoProviderType::Github as SsoProviderType,
        &provider_user_id,
        Some("pendinguser"),
        Some("pending@github.com"),
    )
    .execute(pool)
    .await
    .unwrap();

    let found = sqlx::query!(
        r#"
        SELECT token, request_uri, provider as "provider: SsoProviderType", provider_user_id,
               provider_username, provider_email
        FROM sso_pending_registration
        WHERE token = $1 AND expires_at > NOW()
        "#,
        &token,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.request_uri, request_uri);
    assert_eq!(found.provider_username, Some("pendinguser".to_string()));
    assert_eq!(found.provider_email, Some("pending@github.com".to_string()));

    let consumed = sqlx::query!(
        r#"
        DELETE FROM sso_pending_registration
        WHERE token = $1 AND expires_at > NOW()
        RETURNING token, request_uri
        "#,
        &token,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(consumed.is_some());

    let double_consume = sqlx::query!(
        r#"
        DELETE FROM sso_pending_registration
        WHERE token = $1 AND expires_at > NOW()
        RETURNING token
        "#,
        &token,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(double_consume.is_none());
}

#[tokio::test]
async fn test_sso_pending_registration_expiration() {
    let _url = base_url().await;
    let pool = get_test_db_pool().await;

    let token = format!("expired_pending_{}", uuid::Uuid::new_v4().simple());

    sqlx::query!(
        r#"
        INSERT INTO sso_pending_registration (token, request_uri, provider, provider_user_id, expires_at)
        VALUES ($1, $2, $3, $4, NOW() - INTERVAL '1 hour')
        "#,
        &token,
        "urn:test:expired_pending",
        SsoProviderType::Github as SsoProviderType,
        "expired_provider_user",
    )
    .execute(pool)
    .await
    .unwrap();

    let consumed = sqlx::query!(
        r#"
        SELECT token FROM sso_pending_registration
        WHERE token = $1 AND expires_at > NOW()
        "#,
        &token,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(consumed.is_none());
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
    let _url = base_url().await;
    let pool = get_test_db_pool().await;

    let token = format!("expired_reg_token_{}", uuid::Uuid::new_v4().simple());

    sqlx::query!(
        r#"
        INSERT INTO sso_pending_registration (token, request_uri, provider, provider_user_id, expires_at)
        VALUES ($1, $2, $3, $4, NOW() - INTERVAL '1 hour')
        "#,
        &token,
        "urn:test:expired_registration",
        SsoProviderType::Github as SsoProviderType,
        "expired_user_123",
    )
    .execute(pool)
    .await
    .unwrap();

    let client = client();
    let res = client
        .post(format!("{}/oauth/sso/complete-registration", _url))
        .json(&json!({
            "token": token,
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

#[tokio::test]
async fn test_sso_complete_registration_success() {
    let url = base_url().await;
    let pool = get_test_db_pool().await;
    let client = client();

    let token = format!("success_reg_token_{}", uuid::Uuid::new_v4().simple());
    let handle_prefix = format!("ssoreg{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);
    let provider_user_id = format!("success_user_{}", uuid::Uuid::new_v4().simple());
    let provider_email = format!("sso_{}@example.com", uuid::Uuid::new_v4().simple());

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4());

    sqlx::query!(
        r#"
        INSERT INTO oauth_authorization_request (id, client_id, parameters, expires_at)
        VALUES ($1, 'https://test.example.com', $2, NOW() + INTERVAL '1 hour')
        "#,
        &request_uri,
        serde_json::json!({
            "redirect_uri": "https://test.example.com/callback",
            "scope": "atproto",
            "state": "teststate",
            "code_challenge": "testchallenge",
            "code_challenge_method": "S256"
        }),
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query!(
        r#"
        INSERT INTO sso_pending_registration (token, request_uri, provider, provider_user_id, provider_username, provider_email, provider_email_verified)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
        &token,
        &request_uri,
        SsoProviderType::Github as SsoProviderType,
        &provider_user_id,
        Some("ssouser"),
        Some(&provider_email),
        true,
    )
    .execute(pool)
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

    let pending_consumed = sqlx::query!(
        r#"SELECT token FROM sso_pending_registration WHERE token = $1"#,
        &token,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(
        pending_consumed.is_none(),
        "Pending registration should be consumed after successful registration"
    );

    let user_exists = sqlx::query!(
        r#"SELECT did, email_verified FROM users WHERE did = $1"#,
        did_str,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(user_exists.is_some(), "User should exist in database");
    let user = user_exists.unwrap();
    assert!(
        user.email_verified,
        "Email should be auto-verified when provider verified it"
    );

    let external_identity = sqlx::query!(
        r#"
        SELECT provider_user_id, provider_email_verified
        FROM external_identities
        WHERE did = $1 AND provider = $2
        "#,
        did_str,
        SsoProviderType::Github as SsoProviderType,
    )
    .fetch_optional(pool)
    .await
    .unwrap();

    assert!(
        external_identity.is_some(),
        "External identity should be created"
    );
    let ext_id = external_identity.unwrap();
    assert_eq!(ext_id.provider_user_id, provider_user_id);
    assert!(ext_id.provider_email_verified);
}

#[tokio::test]
async fn test_sso_complete_registration_multichannel_discord() {
    let url = base_url().await;
    let pool = get_test_db_pool().await;
    let client = client();

    let token = format!("discord_reg_token_{}", uuid::Uuid::new_v4().simple());
    let handle_prefix = format!(
        "discordreg{}",
        &uuid::Uuid::new_v4().simple().to_string()[..4]
    );
    let provider_user_id = format!("discord_prov_{}", uuid::Uuid::new_v4().simple());
    let discord_id = "123456789012345678";

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4());

    sqlx::query!(
        r#"
        INSERT INTO oauth_authorization_request (id, client_id, parameters, expires_at)
        VALUES ($1, 'https://test.example.com', $2, NOW() + INTERVAL '1 hour')
        "#,
        &request_uri,
        serde_json::json!({
            "redirect_uri": "https://test.example.com/callback",
            "scope": "atproto",
            "state": "teststate",
            "code_challenge": "testchallenge",
            "code_challenge_method": "S256"
        }),
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query!(
        r#"
        INSERT INTO sso_pending_registration (token, request_uri, provider, provider_user_id, provider_username, provider_email_verified)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        &token,
        &request_uri,
        SsoProviderType::Discord as SsoProviderType,
        &provider_user_id,
        Some("discorduser"),
        false,
    )
    .execute(pool)
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
    let user = sqlx::query!(
        r#"SELECT preferred_comms_channel as "preferred_comms_channel: String", discord_username FROM users WHERE did = $1"#,
        did_str,
    )
    .fetch_one(pool)
    .await
    .unwrap();

    assert_eq!(user.preferred_comms_channel, "discord");
    assert_eq!(user.discord_username, Some(discord_id.to_string()));
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
    let pool = get_test_db_pool().await;
    let client = client();

    let token = format!("missing_channel_{}", uuid::Uuid::new_v4().simple());
    let handle_prefix = format!("missch{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);

    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4());

    sqlx::query!(
        r#"
        INSERT INTO oauth_authorization_request (id, client_id, parameters, expires_at)
        VALUES ($1, 'https://test.example.com', $2, NOW() + INTERVAL '1 hour')
        "#,
        &request_uri,
        serde_json::json!({
            "redirect_uri": "https://test.example.com/callback",
            "scope": "atproto",
            "state": "teststate",
            "code_challenge": "testchallenge",
            "code_challenge_method": "S256"
        }),
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query!(
        r#"
        INSERT INTO sso_pending_registration (token, request_uri, provider, provider_user_id, provider_email_verified)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        &token,
        &request_uri,
        SsoProviderType::Github as SsoProviderType,
        "missing_channel_user",
        false,
    )
    .execute(pool)
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
