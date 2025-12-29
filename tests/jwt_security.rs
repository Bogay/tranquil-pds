#![allow(unused_imports)]
mod common;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use common::{base_url, client, create_account_and_login, get_test_db_pool};
use k256::SecretKey;
use k256::ecdsa::{Signature, SigningKey, signature::Signer};
use rand::rngs::OsRng;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tranquil_pds::auth::{
    self, SCOPE_ACCESS, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED, SCOPE_REFRESH,
    TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH, TOKEN_TYPE_SERVICE, create_access_token,
    create_refresh_token, create_service_token, get_did_from_token, get_jti_from_token,
    verify_access_token, verify_refresh_token, verify_token,
};

fn generate_user_key() -> Vec<u8> {
    let secret_key = SecretKey::random(&mut OsRng);
    secret_key.to_bytes().to_vec()
}

fn create_custom_jwt(header: &Value, claims: &Value, key_bytes: &[u8]) -> String {
    let signing_key = SigningKey::from_slice(key_bytes).expect("valid key");
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(claims).unwrap());
    let message = format!("{}.{}", header_b64, claims_b64);
    let signature: Signature = signing_key.sign(message.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    format!("{}.{}", message, signature_b64)
}

fn create_unsigned_jwt(header: &Value, claims: &Value) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(claims).unwrap());
    format!("{}.{}.", header_b64, claims_b64)
}

#[test]
fn test_signature_attacks() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let token = create_access_token(did, &key_bytes).expect("create token");
    let parts: Vec<&str> = token.split('.').collect();

    let forged_signature = URL_SAFE_NO_PAD.encode(&[0u8; 64]);
    let forged_token = format!("{}.{}.{}", parts[0], parts[1], forged_signature);
    let result = verify_access_token(&forged_token, &key_bytes);
    assert!(result.is_err(), "Forged signature must be rejected");
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .to_lowercase()
            .contains("signature")
    );

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let mut payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["sub"] = json!("did:plc:attacker");
    let modified_payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let modified_token = format!("{}.{}.{}", parts[0], modified_payload, parts[2]);
    assert!(
        verify_access_token(&modified_token, &key_bytes).is_err(),
        "Modified payload must be rejected"
    );

    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    let truncated_sig = URL_SAFE_NO_PAD.encode(&sig_bytes[..32]);
    let truncated_token = format!("{}.{}.{}", parts[0], parts[1], truncated_sig);
    assert!(
        verify_access_token(&truncated_token, &key_bytes).is_err(),
        "Truncated signature must be rejected"
    );

    let mut extended_sig = sig_bytes.clone();
    extended_sig.extend_from_slice(&[0u8; 32]);
    let extended_token = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode(&extended_sig)
    );
    assert!(
        verify_access_token(&extended_token, &key_bytes).is_err(),
        "Extended signature must be rejected"
    );

    let key_bytes_user2 = generate_user_key();
    assert!(
        verify_access_token(&token, &key_bytes_user2).is_err(),
        "Token signed with different key must be rejected"
    );
}

#[test]
fn test_algorithm_substitution_attacks() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";

    let none_header = json!({ "alg": "none", "typ": TOKEN_TYPE_ACCESS });
    let claims = json!({
        "iss": did, "sub": did, "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(), "exp": Utc::now().timestamp() + 3600,
        "jti": "attack-token", "scope": SCOPE_ACCESS
    });
    let none_token = create_unsigned_jwt(&none_header, &claims);
    assert!(
        verify_access_token(&none_token, &key_bytes).is_err(),
        "Algorithm 'none' must be rejected"
    );

    let hs256_header = json!({ "alg": "HS256", "typ": TOKEN_TYPE_ACCESS });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&hs256_header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let message = format!("{}.{}", header_b64, claims_b64);
    let mut mac = HmacSha256::new_from_slice(&key_bytes).unwrap();
    mac.update(message.as_bytes());
    let hmac_sig = mac.finalize().into_bytes();
    let hs256_token = format!("{}.{}", message, URL_SAFE_NO_PAD.encode(&hmac_sig));
    assert!(
        verify_access_token(&hs256_token, &key_bytes).is_err(),
        "HS256 substitution must be rejected"
    );

    for (alg, sig_len) in [("RS256", 256), ("ES256", 64)] {
        let header = json!({ "alg": alg, "typ": TOKEN_TYPE_ACCESS });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
        let fake_sig = URL_SAFE_NO_PAD.encode(&vec![1u8; sig_len]);
        let token = format!("{}.{}.{}", header_b64, claims_b64, fake_sig);
        assert!(
            verify_access_token(&token, &key_bytes).is_err(),
            "{} substitution must be rejected",
            alg
        );
    }
}

#[test]
fn test_token_type_confusion() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";

    let refresh_token = create_refresh_token(did, &key_bytes).expect("create refresh token");
    let result = verify_access_token(&refresh_token, &key_bytes);
    assert!(result.is_err(), "Refresh token as access must be rejected");
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("Invalid token type")
    );

    let access_token = create_access_token(did, &key_bytes).expect("create access token");
    let result = verify_refresh_token(&access_token, &key_bytes);
    assert!(result.is_err(), "Access token as refresh must be rejected");
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("Invalid token type")
    );

    let service_token =
        create_service_token(did, "did:web:target", "com.example.method", &key_bytes).unwrap();
    assert!(
        verify_access_token(&service_token, &key_bytes).is_err(),
        "Service token as access must be rejected"
    );
}

#[test]
fn test_scope_validation() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({ "alg": "ES256K", "typ": TOKEN_TYPE_ACCESS });

    let invalid_scope = json!({
        "iss": did, "sub": did, "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(), "exp": Utc::now().timestamp() + 3600,
        "jti": "test", "scope": "admin.all"
    });
    let result = verify_access_token(
        &create_custom_jwt(&header, &invalid_scope, &key_bytes),
        &key_bytes,
    );
    assert!(
        result.is_err()
            && result
                .err()
                .unwrap()
                .to_string()
                .contains("Invalid token scope")
    );

    let empty_scope = json!({
        "iss": did, "sub": did, "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(), "exp": Utc::now().timestamp() + 3600,
        "jti": "test", "scope": ""
    });
    assert!(
        verify_access_token(
            &create_custom_jwt(&header, &empty_scope, &key_bytes),
            &key_bytes
        )
        .is_err()
    );

    let missing_scope = json!({
        "iss": did, "sub": did, "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(), "exp": Utc::now().timestamp() + 3600,
        "jti": "test"
    });
    assert!(
        verify_access_token(
            &create_custom_jwt(&header, &missing_scope, &key_bytes),
            &key_bytes
        )
        .is_err()
    );

    for scope in [SCOPE_ACCESS, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED] {
        let claims = json!({
            "iss": did, "sub": did, "aud": "did:web:test.pds",
            "iat": Utc::now().timestamp(), "exp": Utc::now().timestamp() + 3600,
            "jti": "test", "scope": scope
        });
        assert!(
            verify_access_token(&create_custom_jwt(&header, &claims, &key_bytes), &key_bytes)
                .is_ok()
        );
    }

    let refresh_scope = json!({
        "iss": did, "sub": did, "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(), "exp": Utc::now().timestamp() + 3600,
        "jti": "test", "scope": SCOPE_REFRESH
    });
    assert!(
        verify_access_token(
            &create_custom_jwt(&header, &refresh_scope, &key_bytes),
            &key_bytes
        )
        .is_err()
    );
}

#[test]
fn test_expiration_and_timing() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({ "alg": "ES256K", "typ": TOKEN_TYPE_ACCESS });
    let now = Utc::now().timestamp();

    let expired = json!({
        "iss": did, "sub": did, "aud": "did:web:test.pds",
        "iat": now - 7200, "exp": now - 3600, "jti": "test", "scope": SCOPE_ACCESS
    });
    let result = verify_access_token(
        &create_custom_jwt(&header, &expired, &key_bytes),
        &key_bytes,
    );
    assert!(result.is_err() && result.err().unwrap().to_string().contains("expired"));

    let future_iat = json!({
        "iss": did, "sub": did, "aud": "did:web:test.pds",
        "iat": now + 60, "exp": now + 7200, "jti": "test", "scope": SCOPE_ACCESS
    });
    assert!(
        verify_access_token(
            &create_custom_jwt(&header, &future_iat, &key_bytes),
            &key_bytes
        )
        .is_ok()
    );

    let just_expired = json!({
        "iss": did, "sub": did, "aud": "did:web:test.pds",
        "iat": now - 10, "exp": now - 1, "jti": "test", "scope": SCOPE_ACCESS
    });
    assert!(
        verify_access_token(
            &create_custom_jwt(&header, &just_expired, &key_bytes),
            &key_bytes
        )
        .is_err()
    );

    let far_future = json!({
        "iss": did, "sub": did, "aud": "did:web:test.pds",
        "iat": now, "exp": i64::MAX, "jti": "test", "scope": SCOPE_ACCESS
    });
    let _ = verify_access_token(
        &create_custom_jwt(&header, &far_future, &key_bytes),
        &key_bytes,
    );

    let negative_iat = json!({
        "iss": did, "sub": did, "aud": "did:web:test.pds",
        "iat": -1000000000i64, "exp": now + 3600, "jti": "test", "scope": SCOPE_ACCESS
    });
    let _ = verify_access_token(
        &create_custom_jwt(&header, &negative_iat, &key_bytes),
        &key_bytes,
    );
}

#[test]
fn test_malformed_tokens() {
    let key_bytes = generate_user_key();

    for token in [
        "",
        "not-a-token",
        "one.two",
        "one.two.three.four",
        "....",
        "eyJhbGciOiJFUzI1NksifQ",
        "eyJhbGciOiJFUzI1NksifQ.",
        "eyJhbGciOiJFUzI1NksifQ..",
        ".eyJzdWIiOiJ0ZXN0In0.",
        "!!invalid-base64!!.eyJzdWIiOiJ0ZXN0In0.sig",
    ] {
        assert!(
            verify_access_token(token, &key_bytes).is_err(),
            "Malformed token must be rejected"
        );
    }

    let invalid_header = URL_SAFE_NO_PAD.encode("{not valid json}");
    let claims_b64 = URL_SAFE_NO_PAD.encode(r#"{"sub":"test"}"#);
    let fake_sig = URL_SAFE_NO_PAD.encode(&[1u8; 64]);
    assert!(
        verify_access_token(
            &format!("{}.{}.{}", invalid_header, claims_b64, fake_sig),
            &key_bytes
        )
        .is_err()
    );

    let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K","typ":"at+jwt"}"#);
    let invalid_claims = URL_SAFE_NO_PAD.encode("{not valid json}");
    assert!(
        verify_access_token(
            &format!("{}.{}.{}", header_b64, invalid_claims, fake_sig),
            &key_bytes
        )
        .is_err()
    );
}

#[test]
fn test_claim_validation() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({ "alg": "ES256K", "typ": TOKEN_TYPE_ACCESS });

    let missing_exp = json!({
        "iss": did, "sub": did, "aud": "did:web:test",
        "iat": Utc::now().timestamp(), "scope": SCOPE_ACCESS
    });
    assert!(
        verify_access_token(
            &create_custom_jwt(&header, &missing_exp, &key_bytes),
            &key_bytes
        )
        .is_err()
    );

    let missing_iat = json!({
        "iss": did, "sub": did, "aud": "did:web:test",
        "exp": Utc::now().timestamp() + 3600, "scope": SCOPE_ACCESS
    });
    assert!(
        verify_access_token(
            &create_custom_jwt(&header, &missing_iat, &key_bytes),
            &key_bytes
        )
        .is_err()
    );

    let missing_sub = json!({
        "iss": did, "aud": "did:web:test",
        "iat": Utc::now().timestamp(), "exp": Utc::now().timestamp() + 3600, "scope": SCOPE_ACCESS
    });
    assert!(
        verify_access_token(
            &create_custom_jwt(&header, &missing_sub, &key_bytes),
            &key_bytes
        )
        .is_err()
    );

    let wrong_types = json!({
        "iss": 12345, "sub": ["did:plc:test"], "aud": {"url": "did:web:test"},
        "iat": "not a number", "exp": "also not a number", "jti": null, "scope": SCOPE_ACCESS
    });
    assert!(
        verify_access_token(
            &create_custom_jwt(&header, &wrong_types, &key_bytes),
            &key_bytes
        )
        .is_err()
    );

    let unicode_injection = json!({
        "iss": "did:plc:test\u{0000}attacker", "sub": "did:plc:test\u{202E}rekatta",
        "aud": "did:web:test.pds", "iat": Utc::now().timestamp(), "exp": Utc::now().timestamp() + 3600,
        "jti": "test", "scope": SCOPE_ACCESS
    });
    if let Ok(data) = verify_access_token(
        &create_custom_jwt(&header, &unicode_injection, &key_bytes),
        &key_bytes,
    ) {
        assert!(!data.claims.sub.contains('\0'));
    }
}

#[test]
fn test_did_and_jti_extraction() {
    let key_bytes = generate_user_key();
    let did = "did:plc:legitimate";
    let token = create_access_token(did, &key_bytes).expect("create token");

    assert_eq!(get_did_from_token(&token).unwrap(), did);
    assert!(get_did_from_token("invalid").is_err());
    assert!(get_did_from_token("a.b").is_err());
    assert!(get_did_from_token("").is_err());

    let jti = get_jti_from_token(&token).unwrap();
    assert!(!jti.is_empty());
    assert!(get_jti_from_token("invalid").is_err());

    let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K"}"#);
    let claims_b64 = URL_SAFE_NO_PAD.encode(r#"{"iss":"did:plc:iss","sub":"did:plc:sub"}"#);
    let fake_sig = URL_SAFE_NO_PAD.encode(&[0u8; 64]);
    let unverified = format!("{}.{}.{}", header_b64, claims_b64, fake_sig);
    assert_eq!(get_did_from_token(&unverified).unwrap(), "did:plc:sub");

    let no_jti_claims = URL_SAFE_NO_PAD.encode(r#"{"iss":"did:plc:test"}"#);
    assert!(get_jti_from_token(&format!("{}.{}.{}", header_b64, no_jti_claims, fake_sig)).is_err());
}

#[test]
fn test_header_injection_and_constant_time() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";

    let header = json!({
        "alg": "ES256K", "typ": TOKEN_TYPE_ACCESS,
        "kid": "../../../../../../etc/passwd", "jku": "https://attacker.com/keys"
    });
    let claims = json!({
        "iss": did, "sub": did, "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(), "exp": Utc::now().timestamp() + 3600,
        "jti": "test", "scope": SCOPE_ACCESS
    });
    assert!(
        verify_access_token(&create_custom_jwt(&header, &claims, &key_bytes), &key_bytes).is_ok()
    );

    let valid_token = create_access_token(did, &key_bytes).expect("create token");
    let parts: Vec<&str> = valid_token.split('.').collect();
    let mut almost_valid = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    almost_valid[0] ^= 1;
    let almost_valid_token = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode(&almost_valid)
    );
    let completely_invalid_token = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode(&[0xFFu8; 64])
    );
    let _ = verify_access_token(&almost_valid_token, &key_bytes);
    let _ = verify_access_token(&completely_invalid_token, &key_bytes);
}

#[tokio::test]
async fn test_server_rejects_invalid_tokens() {
    let url = base_url().await;
    let http_client = client();

    let key_bytes = generate_user_key();
    let forged_token = create_access_token("did:plc:fake-user", &key_bytes).unwrap();
    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", forged_token))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "Forged token must be rejected"
    );

    let (access_jwt, _did) = create_account_and_login(&http_client).await;
    let parts: Vec<&str> = access_jwt.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let mut payload: Value = serde_json::from_slice(&payload_bytes).unwrap();

    payload["exp"] = json!(Utc::now().timestamp() - 3600);
    let expired_token = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap()),
        parts[2]
    );
    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", expired_token))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let mut tampered_payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    tampered_payload["sub"] = json!("did:plc:attacker");
    tampered_payload["iss"] = json!("did:plc:attacker");
    let tampered_token = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(serde_json::to_string(&tampered_payload).unwrap()),
        parts[2]
    );
    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", tampered_token))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_authorization_header_formats() {
    let url = base_url().await;
    let http_client = client();
    let (access_jwt, _did) = create_account_and_login(&http_client).await;

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Basic {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", &access_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", "Bearer ")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_session_lifecycle_security() {
    let url = base_url().await;
    let http_client = client();
    let (access_jwt, _did) = create_account_and_login(&http_client).await;

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let logout = http_client
        .post(format!("{}/xrpc/com.atproto.server.deleteSession", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::OK);

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_deactivated_account_behavior() {
    let url = base_url().await;
    let http_client = client();
    let (access_jwt, _did) = create_account_and_login(&http_client).await;

    let deact = http_client
        .post(format!("{}/xrpc/com.atproto.server.deactivateAccount", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(deact.status(), StatusCode::OK);

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["active"], false);

    let post_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .json(&json!({
            "repo": _did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "test",
                "createdAt": "2024-01-01T00:00:00Z"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(post_res.status(), StatusCode::UNAUTHORIZED);
    let post_body: Value = post_res.json().await.unwrap();
    assert_eq!(post_body["error"], "AccountDeactivated");
}

#[tokio::test]
async fn test_refresh_token_replay_protection() {
    let url = base_url().await;
    let http_client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("rt-replay-jwt-{}", ts);
    let email = format!("rt-replay-jwt-{}@example.com", ts);

    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": "Testpass123!" }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap();

    let pool = get_test_db_pool().await;
    let body_text: String = sqlx::query_scalar!(
        "SELECT body FROM comms_queue WHERE user_id = (SELECT id FROM users WHERE did = $1) AND comms_type = 'email_verification' ORDER BY created_at DESC LIMIT 1",
        did
    ).fetch_one(pool).await.unwrap();
    let lines: Vec<&str> = body_text.lines().collect();
    let code = lines
        .iter()
        .enumerate()
        .find(|(_, line)| line.contains("verification code is:") || line.contains("code is:"))
        .and_then(|(i, _)| lines.get(i + 1).map(|s| s.trim().to_string()))
        .or_else(|| {
            body_text
                .split_whitespace()
                .find(|word| word.contains('-') && word.chars().filter(|c| *c == '-').count() >= 3)
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| body_text.clone());

    let confirm = http_client
        .post(format!("{}/xrpc/com.atproto.server.confirmSignup", url))
        .json(&json!({ "did": did, "verificationCode": code }))
        .send()
        .await
        .unwrap();
    assert_eq!(confirm.status(), StatusCode::OK);
    let confirmed: Value = confirm.json().await.unwrap();
    let refresh_jwt = confirmed["refreshJwt"].as_str().unwrap().to_string();

    let first = http_client
        .post(format!("{}/xrpc/com.atproto.server.refreshSession", url))
        .header("Authorization", format!("Bearer {}", refresh_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let replay = http_client
        .post(format!("{}/xrpc/com.atproto.server.refreshSession", url))
        .header("Authorization", format!("Bearer {}", refresh_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}
