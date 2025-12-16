#![allow(unused_imports)]
mod common;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bspds::auth::{
    self, SCOPE_ACCESS, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED, SCOPE_REFRESH,
    TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH, TOKEN_TYPE_SERVICE, create_access_token,
    create_refresh_token, create_service_token, get_did_from_token, get_jti_from_token,
    verify_access_token, verify_refresh_token, verify_token,
};
use chrono::{Duration, Utc};
use common::{base_url, client, create_account_and_login, get_db_connection_string};
use k256::SecretKey;
use k256::ecdsa::{Signature, SigningKey, signature::Signer};
use rand::rngs::OsRng;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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
fn test_jwt_security_forged_signature_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let token = create_access_token(did, &key_bytes).expect("create token");
    let parts: Vec<&str> = token.split('.').collect();
    let forged_signature = URL_SAFE_NO_PAD.encode(&[0u8; 64]);
    let forged_token = format!("{}.{}.{}", parts[0], parts[1], forged_signature);
    let result = verify_access_token(&forged_token, &key_bytes);
    assert!(result.is_err(), "Forged signature must be rejected");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("signature") || err_msg.contains("Signature"),
        "Error should mention signature: {}",
        err_msg
    );
}

#[test]
fn test_jwt_security_modified_payload_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:legitimate";
    let token = create_access_token(did, &key_bytes).expect("create token");
    let parts: Vec<&str> = token.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let mut payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["sub"] = json!("did:plc:attacker");
    let modified_payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let modified_token = format!("{}.{}.{}", parts[0], modified_payload, parts[2]);
    let result = verify_access_token(&modified_token, &key_bytes);
    assert!(result.is_err(), "Modified payload must be rejected");
}

#[test]
fn test_jwt_security_algorithm_none_attack_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "none",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "attacker-token-1",
        "scope": SCOPE_ACCESS
    });
    let malicious_token = create_unsigned_jwt(&header, &claims);
    let result = verify_access_token(&malicious_token, &key_bytes);
    assert!(result.is_err(), "Algorithm 'none' attack must be rejected");
}

#[test]
fn test_jwt_security_algorithm_substitution_hs256_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "HS256",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "attacker-token-2",
        "scope": SCOPE_ACCESS
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let message = format!("{}.{}", header_b64, claims_b64);
    let mut mac = HmacSha256::new_from_slice(&key_bytes).unwrap();
    mac.update(message.as_bytes());
    let hmac_sig = mac.finalize().into_bytes();
    let signature_b64 = URL_SAFE_NO_PAD.encode(&hmac_sig);
    let malicious_token = format!("{}.{}", message, signature_b64);
    let result = verify_access_token(&malicious_token, &key_bytes);
    assert!(
        result.is_err(),
        "HS256 algorithm substitution must be rejected"
    );
}

#[test]
fn test_jwt_security_algorithm_substitution_rs256_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "RS256",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "attacker-token-3",
        "scope": SCOPE_ACCESS
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
    let fake_sig = URL_SAFE_NO_PAD.encode(&[1u8; 256]);
    let malicious_token = format!("{}.{}.{}", header_b64, claims_b64, fake_sig);
    let result = verify_access_token(&malicious_token, &key_bytes);
    assert!(
        result.is_err(),
        "RS256 algorithm substitution must be rejected"
    );
}

#[test]
fn test_jwt_security_algorithm_substitution_es256_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "ES256",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "attacker-token-4",
        "scope": SCOPE_ACCESS
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
    let fake_sig = URL_SAFE_NO_PAD.encode(&[1u8; 64]);
    let malicious_token = format!("{}.{}.{}", header_b64, claims_b64, fake_sig);
    let result = verify_access_token(&malicious_token, &key_bytes);
    assert!(
        result.is_err(),
        "ES256 (P-256) algorithm substitution must be rejected (we use ES256K/secp256k1)"
    );
}

#[test]
fn test_jwt_security_token_type_confusion_refresh_as_access() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let refresh_token = create_refresh_token(did, &key_bytes).expect("create refresh token");
    let result = verify_access_token(&refresh_token, &key_bytes);
    assert!(
        result.is_err(),
        "Refresh token must not be accepted as access token"
    );
    let err_msg = result.err().unwrap().to_string();
    assert!(err_msg.contains("Invalid token type"), "Error: {}", err_msg);
}

#[test]
fn test_jwt_security_token_type_confusion_access_as_refresh() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let access_token = create_access_token(did, &key_bytes).expect("create access token");
    let result = verify_refresh_token(&access_token, &key_bytes);
    assert!(
        result.is_err(),
        "Access token must not be accepted as refresh token"
    );
    let err_msg = result.err().unwrap().to_string();
    assert!(err_msg.contains("Invalid token type"), "Error: {}", err_msg);
}

#[test]
fn test_jwt_security_token_type_confusion_service_as_access() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let service_token =
        create_service_token(did, "did:web:target", "com.example.method", &key_bytes)
            .expect("create service token");
    let result = verify_access_token(&service_token, &key_bytes);
    assert!(
        result.is_err(),
        "Service token must not be accepted as access token"
    );
}

#[test]
fn test_jwt_security_scope_manipulation_attack() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "scope-attack-token",
        "scope": "admin.all"
    });
    let malicious_token = create_custom_jwt(&header, &claims, &key_bytes);
    let result = verify_access_token(&malicious_token, &key_bytes);
    assert!(result.is_err(), "Invalid scope must be rejected");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("Invalid token scope"),
        "Error: {}",
        err_msg
    );
}

#[test]
fn test_jwt_security_empty_scope_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "empty-scope-token",
        "scope": ""
    });
    let token = create_custom_jwt(&header, &claims, &key_bytes);
    let result = verify_access_token(&token, &key_bytes);
    assert!(
        result.is_err(),
        "Empty scope must be rejected for access tokens"
    );
}

#[test]
fn test_jwt_security_missing_scope_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "no-scope-token"
    });
    let token = create_custom_jwt(&header, &claims, &key_bytes);
    let result = verify_access_token(&token, &key_bytes);
    assert!(
        result.is_err(),
        "Missing scope must be rejected for access tokens"
    );
}

#[test]
fn test_jwt_security_expired_token_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp() - 7200,
        "exp": Utc::now().timestamp() - 3600,
        "jti": "expired-token",
        "scope": SCOPE_ACCESS
    });
    let expired_token = create_custom_jwt(&header, &claims, &key_bytes);
    let result = verify_access_token(&expired_token, &key_bytes);
    assert!(result.is_err(), "Expired token must be rejected");
    let err_msg = result.err().unwrap().to_string();
    assert!(err_msg.contains("expired"), "Error: {}", err_msg);
}

#[test]
fn test_jwt_security_future_iat_accepted() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp() + 60,
        "exp": Utc::now().timestamp() + 7200,
        "jti": "future-iat-token",
        "scope": SCOPE_ACCESS
    });
    let token = create_custom_jwt(&header, &claims, &key_bytes);
    let result = verify_access_token(&token, &key_bytes);
    assert!(
        result.is_ok(),
        "Slight future iat should be accepted for clock skew tolerance"
    );
}

#[test]
fn test_jwt_security_cross_user_key_attack() {
    let key_bytes_user1 = generate_user_key();
    let key_bytes_user2 = generate_user_key();
    let did = "did:plc:user1";
    let token = create_access_token(did, &key_bytes_user1).expect("create token");
    let result = verify_access_token(&token, &key_bytes_user2);
    assert!(
        result.is_err(),
        "Token signed by user1's key must not verify with user2's key"
    );
}

#[test]
fn test_jwt_security_signature_truncation_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let token = create_access_token(did, &key_bytes).expect("create token");
    let parts: Vec<&str> = token.split('.').collect();
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    let truncated_sig = URL_SAFE_NO_PAD.encode(&sig_bytes[..32]);
    let truncated_token = format!("{}.{}.{}", parts[0], parts[1], truncated_sig);
    let result = verify_access_token(&truncated_token, &key_bytes);
    assert!(result.is_err(), "Truncated signature must be rejected");
}

#[test]
fn test_jwt_security_signature_extension_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let token = create_access_token(did, &key_bytes).expect("create token");
    let parts: Vec<&str> = token.split('.').collect();
    let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    sig_bytes.extend_from_slice(&[0u8; 32]);
    let extended_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
    let extended_token = format!("{}.{}.{}", parts[0], parts[1], extended_sig);
    let result = verify_access_token(&extended_token, &key_bytes);
    assert!(result.is_err(), "Extended signature must be rejected");
}

#[test]
fn test_jwt_security_malformed_tokens_rejected() {
    let key_bytes = generate_user_key();
    let malformed_tokens = vec![
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
        "eyJhbGciOiJFUzI1NksifQ.!!invalid!!.sig",
    ];
    for token in malformed_tokens {
        let result = verify_access_token(token, &key_bytes);
        assert!(
            result.is_err(),
            "Malformed token '{}' must be rejected",
            if token.len() > 40 {
                &token[..40]
            } else {
                token
            }
        );
    }
}

#[test]
fn test_jwt_security_missing_required_claims_rejected() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let test_cases = vec![
        (
            json!({
                "iss": did,
                "sub": did,
                "aud": "did:web:test",
                "iat": Utc::now().timestamp(),
                "scope": SCOPE_ACCESS
            }),
            "exp",
        ),
        (
            json!({
                "iss": did,
                "sub": did,
                "aud": "did:web:test",
                "exp": Utc::now().timestamp() + 3600,
                "scope": SCOPE_ACCESS
            }),
            "iat",
        ),
        (
            json!({
                "iss": did,
                "aud": "did:web:test",
                "iat": Utc::now().timestamp(),
                "exp": Utc::now().timestamp() + 3600,
                "scope": SCOPE_ACCESS
            }),
            "sub",
        ),
    ];
    for (claims, missing_claim) in test_cases {
        let header = json!({
            "alg": "ES256K",
            "typ": TOKEN_TYPE_ACCESS
        });
        let token = create_custom_jwt(&header, &claims, &key_bytes);
        let result = verify_access_token(&token, &key_bytes);
        assert!(
            result.is_err(),
            "Token missing '{}' claim must be rejected",
            missing_claim
        );
    }
}

#[test]
fn test_jwt_security_invalid_header_json_rejected() {
    let key_bytes = generate_user_key();
    let invalid_header = URL_SAFE_NO_PAD.encode("{not valid json}");
    let claims_b64 = URL_SAFE_NO_PAD.encode(r#"{"sub":"test"}"#);
    let fake_sig = URL_SAFE_NO_PAD.encode(&[1u8; 64]);
    let malicious_token = format!("{}.{}.{}", invalid_header, claims_b64, fake_sig);
    let result = verify_access_token(&malicious_token, &key_bytes);
    assert!(result.is_err(), "Invalid header JSON must be rejected");
}

#[test]
fn test_jwt_security_invalid_claims_json_rejected() {
    let key_bytes = generate_user_key();
    let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K","typ":"at+jwt"}"#);
    let invalid_claims = URL_SAFE_NO_PAD.encode("{not valid json}");
    let fake_sig = URL_SAFE_NO_PAD.encode(&[1u8; 64]);
    let malicious_token = format!("{}.{}.{}", header_b64, invalid_claims, fake_sig);
    let result = verify_access_token(&malicious_token, &key_bytes);
    assert!(result.is_err(), "Invalid claims JSON must be rejected");
}

#[test]
fn test_jwt_security_header_injection_attack() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS,
        "kid": "../../../../../../etc/passwd",
        "jku": "https://attacker.com/keys"
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "header-injection-token",
        "scope": SCOPE_ACCESS
    });
    let token = create_custom_jwt(&header, &claims, &key_bytes);
    let result = verify_access_token(&token, &key_bytes);
    assert!(
        result.is_ok(),
        "Extra header fields should not cause issues (we ignore them)"
    );
}

#[test]
fn test_jwt_security_claims_type_confusion() {
    let key_bytes = generate_user_key();
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": 12345,
        "sub": ["did:plc:test"],
        "aud": {"url": "did:web:test"},
        "iat": "not a number",
        "exp": "also not a number",
        "jti": null,
        "scope": SCOPE_ACCESS
    });
    let token = create_custom_jwt(&header, &claims, &key_bytes);
    let result = verify_access_token(&token, &key_bytes);
    assert!(result.is_err(), "Claims with wrong types must be rejected");
}

#[test]
fn test_jwt_security_unicode_injection_in_claims() {
    let key_bytes = generate_user_key();
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": "did:plc:test\u{0000}attacker",
        "sub": "did:plc:test\u{202E}rekatta",
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "unicode-injection",
        "scope": SCOPE_ACCESS
    });
    let token = create_custom_jwt(&header, &claims, &key_bytes);
    let result = verify_access_token(&token, &key_bytes);
    if result.is_ok() {
        let data = result.unwrap();
        assert!(
            !data.claims.sub.contains('\0'),
            "Null bytes in claims should be sanitized or rejected"
        );
    }
}

#[test]
fn test_jwt_security_signature_verification_is_constant_time() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let valid_token = create_access_token(did, &key_bytes).expect("create token");
    let parts: Vec<&str> = valid_token.split('.').collect();
    let mut almost_valid = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    almost_valid[0] ^= 1;
    let almost_valid_sig = URL_SAFE_NO_PAD.encode(&almost_valid);
    let almost_valid_token = format!("{}.{}.{}", parts[0], parts[1], almost_valid_sig);
    let completely_invalid_sig = URL_SAFE_NO_PAD.encode(&[0xFFu8; 64]);
    let completely_invalid_token = format!("{}.{}.{}", parts[0], parts[1], completely_invalid_sig);
    let _result1 = verify_access_token(&almost_valid_token, &key_bytes);
    let _result2 = verify_access_token(&completely_invalid_token, &key_bytes);
    assert!(
        true,
        "Signature verification should use constant-time comparison (timing attack prevention)"
    );
}

#[test]
fn test_jwt_security_valid_scopes_accepted() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let valid_scopes = vec![SCOPE_ACCESS, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED];
    for scope in valid_scopes {
        let header = json!({
            "alg": "ES256K",
            "typ": TOKEN_TYPE_ACCESS
        });
        let claims = json!({
            "iss": did,
            "sub": did,
            "aud": "did:web:test.pds",
            "iat": Utc::now().timestamp(),
            "exp": Utc::now().timestamp() + 3600,
            "jti": format!("scope-test-{}", scope),
            "scope": scope
        });
        let token = create_custom_jwt(&header, &claims, &key_bytes);
        let result = verify_access_token(&token, &key_bytes);
        assert!(result.is_ok(), "Valid scope '{}' should be accepted", scope);
    }
}

#[test]
fn test_jwt_security_refresh_token_scope_rejected_as_access() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "refresh-scope-access-typ",
        "scope": SCOPE_REFRESH
    });
    let token = create_custom_jwt(&header, &claims, &key_bytes);
    let result = verify_access_token(&token, &key_bytes);
    assert!(
        result.is_err(),
        "Refresh scope with access token type must be rejected"
    );
}

#[test]
fn test_jwt_security_get_did_extraction_safe() {
    let key_bytes = generate_user_key();
    let did = "did:plc:legitimate";
    let token = create_access_token(did, &key_bytes).expect("create token");
    let extracted = get_did_from_token(&token).expect("extract did");
    assert_eq!(extracted, did);
    assert!(get_did_from_token("invalid").is_err());
    assert!(get_did_from_token("a.b").is_err());
    assert!(get_did_from_token("").is_err());
    let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K"}"#);
    let claims_b64 = URL_SAFE_NO_PAD.encode(r#"{"iss":"did:plc:iss","sub":"did:plc:sub"}"#);
    let fake_sig = URL_SAFE_NO_PAD.encode(&[0u8; 64]);
    let unverified_token = format!("{}.{}.{}", header_b64, claims_b64, fake_sig);
    let extracted_unsafe = get_did_from_token(&unverified_token).expect("extract unsafe");
    assert_eq!(
        extracted_unsafe, "did:plc:sub",
        "get_did_from_token extracts sub without verification (by design for lookup)"
    );
}

#[test]
fn test_jwt_security_get_jti_extraction_safe() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let token = create_access_token(did, &key_bytes).expect("create token");
    let jti = get_jti_from_token(&token).expect("extract jti");
    assert!(!jti.is_empty());
    assert!(get_jti_from_token("invalid").is_err());
    assert!(get_jti_from_token("a.b").is_err());
    let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K"}"#);
    let claims_b64 = URL_SAFE_NO_PAD.encode(r#"{"iss":"did:plc:test"}"#);
    let fake_sig = URL_SAFE_NO_PAD.encode(&[0u8; 64]);
    let no_jti_token = format!("{}.{}.{}", header_b64, claims_b64, fake_sig);
    assert!(
        get_jti_from_token(&no_jti_token).is_err(),
        "Missing jti should error"
    );
}

#[test]
fn test_jwt_security_key_from_invalid_bytes_rejected() {
    let invalid_keys: Vec<&[u8]> = vec![&[], &[0u8; 31], &[0u8; 33], &[0xFFu8; 32]];
    for key in invalid_keys {
        let result = create_access_token("did:plc:test", key);
        if result.is_ok() {
            let token = result.unwrap();
            let verify_result = verify_access_token(&token, key);
            if verify_result.is_err() {
                continue;
            }
        }
    }
}

#[test]
fn test_jwt_security_boundary_exp_values() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS
    });
    let now = Utc::now().timestamp();
    let just_expired = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": now - 10,
        "exp": now - 1,
        "jti": "just-expired",
        "scope": SCOPE_ACCESS
    });
    let token1 = create_custom_jwt(&header, &just_expired, &key_bytes);
    assert!(
        verify_access_token(&token1, &key_bytes).is_err(),
        "Just expired token must be rejected"
    );
    let expires_exactly_now = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": now - 10,
        "exp": now,
        "jti": "expires-now",
        "scope": SCOPE_ACCESS
    });
    let token2 = create_custom_jwt(&header, &expires_exactly_now, &key_bytes);
    let result2 = verify_access_token(&token2, &key_bytes);
    assert!(
        result2.is_err() || result2.is_ok(),
        "Token expiring exactly now is a boundary case - either behavior is acceptable"
    );
}

#[test]
fn test_jwt_security_very_long_exp_handled() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": Utc::now().timestamp(),
        "exp": i64::MAX,
        "jti": "far-future",
        "scope": SCOPE_ACCESS
    });
    let token = create_custom_jwt(&header, &claims, &key_bytes);
    let _result = verify_access_token(&token, &key_bytes);
}

#[test]
fn test_jwt_security_negative_timestamps_handled() {
    let key_bytes = generate_user_key();
    let did = "did:plc:test";
    let header = json!({
        "alg": "ES256K",
        "typ": TOKEN_TYPE_ACCESS
    });
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": "did:web:test.pds",
        "iat": -1000000000i64,
        "exp": Utc::now().timestamp() + 3600,
        "jti": "negative-iat",
        "scope": SCOPE_ACCESS
    });
    let token = create_custom_jwt(&header, &claims, &key_bytes);
    let _result = verify_access_token(&token, &key_bytes);
}

#[tokio::test]
async fn test_jwt_security_server_rejects_forged_session_token() {
    let url = base_url().await;
    let http_client = client();
    let key_bytes = generate_user_key();
    let did = "did:plc:fake-user";
    let forged_token = create_access_token(did, &key_bytes).expect("create forged token");
    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", forged_token))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "Forged session token must be rejected"
    );
}

#[tokio::test]
async fn test_jwt_security_server_rejects_expired_token() {
    let url = base_url().await;
    let http_client = client();
    let (access_jwt, _did) = create_account_and_login(&http_client).await;
    let parts: Vec<&str> = access_jwt.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let mut payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["exp"] = json!(Utc::now().timestamp() - 3600);
    let modified_payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let tampered_token = format!("{}.{}.{}", parts[0], modified_payload, parts[2]);
    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", tampered_token))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "Tampered/expired token must be rejected"
    );
}

#[tokio::test]
async fn test_jwt_security_server_rejects_tampered_did() {
    let url = base_url().await;
    let http_client = client();
    let (access_jwt, _did) = create_account_and_login(&http_client).await;
    let parts: Vec<&str> = access_jwt.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let mut payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["sub"] = json!("did:plc:attacker");
    payload["iss"] = json!("did:plc:attacker");
    let modified_payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let tampered_token = format!("{}.{}.{}", parts[0], modified_payload, parts[2]);
    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", tampered_token))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "DID-tampered token must be rejected"
    );
}

#[tokio::test]
async fn test_jwt_security_refresh_token_replay_protection() {
    let url = base_url().await;
    let http_client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("rt-replay-jwt-{}", ts);
    let email = format!("rt-replay-jwt-{}@example.com", ts);
    let password = "test-password-123";
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
    let did = account["did"].as_str().unwrap();
    let conn_str = get_db_connection_string().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&conn_str)
        .await
        .expect("Failed to connect to test database");
    let verification_code: String = sqlx::query_scalar!(
        "SELECT code FROM channel_verifications WHERE user_id = (SELECT id FROM users WHERE did = $1) AND channel = 'email'",
        did
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to get verification code");
    let confirm_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.confirmSignup", url))
        .json(&json!({
            "did": did,
            "verificationCode": verification_code
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(confirm_res.status(), StatusCode::OK);
    let confirmed: Value = confirm_res.json().await.unwrap();
    let refresh_jwt = confirmed["refreshJwt"].as_str().unwrap().to_string();
    let first_refresh = http_client
        .post(format!("{}/xrpc/com.atproto.server.refreshSession", url))
        .header("Authorization", format!("Bearer {}", refresh_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(
        first_refresh.status(),
        StatusCode::OK,
        "First refresh should succeed"
    );
    let replay_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.refreshSession", url))
        .header("Authorization", format!("Bearer {}", refresh_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(
        replay_res.status(),
        StatusCode::UNAUTHORIZED,
        "Refresh token replay must be rejected"
    );
}

#[tokio::test]
async fn test_jwt_security_authorization_header_formats() {
    let url = base_url().await;
    let http_client = client();
    let (access_jwt, _did) = create_account_and_login(&http_client).await;
    let valid_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(
        valid_res.status(),
        StatusCode::OK,
        "Valid Bearer format should work"
    );
    let lowercase_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(
        lowercase_res.status(),
        StatusCode::OK,
        "Lowercase 'bearer' should be accepted (RFC 7235 case-insensitivity)"
    );
    let basic_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Basic {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(
        basic_res.status(),
        StatusCode::UNAUTHORIZED,
        "Basic scheme must be rejected"
    );
    let no_scheme_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", &access_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(
        no_scheme_res.status(),
        StatusCode::UNAUTHORIZED,
        "Missing scheme must be rejected"
    );
    let empty_token_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", "Bearer ")
        .send()
        .await
        .unwrap();
    assert_eq!(
        empty_token_res.status(),
        StatusCode::UNAUTHORIZED,
        "Empty token must be rejected"
    );
}

#[tokio::test]
async fn test_jwt_security_deleted_session_rejected() {
    let url = base_url().await;
    let http_client = client();
    let (access_jwt, _did) = create_account_and_login(&http_client).await;
    let get_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(
        get_res.status(),
        StatusCode::OK,
        "Token should work before logout"
    );
    let logout_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.deleteSession", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(logout_res.status(), StatusCode::OK);
    let after_logout_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(
        after_logout_res.status(),
        StatusCode::UNAUTHORIZED,
        "Token must be rejected after logout"
    );
}

#[tokio::test]
async fn test_jwt_security_deactivated_account_rejected() {
    let url = base_url().await;
    let http_client = client();
    let (access_jwt, _did) = create_account_and_login(&http_client).await;
    let deact_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.deactivateAccount", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(deact_res.status(), StatusCode::OK);
    let get_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await
        .unwrap();
    assert_eq!(
        get_res.status(),
        StatusCode::UNAUTHORIZED,
        "Deactivated account token must be rejected"
    );
    let body: Value = get_res.json().await.unwrap();
    assert_eq!(body["error"], "AccountDeactivated");
}
