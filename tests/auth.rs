use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bspds::auth;
use chrono::{Duration, Utc};
use k256::SecretKey;
use k256::ecdsa::{SigningKey, signature::Signer};
use rand::rngs::OsRng;
use serde_json::json;

#[test]
fn test_jwt_flow() {
    let secret_key = SecretKey::random(&mut OsRng);
    let key_bytes = secret_key.to_bytes();
    let did = "did:plc:test";

    let token = auth::create_access_token(did, &key_bytes).expect("create token");
    let data = auth::verify_access_token(&token, &key_bytes).expect("verify access token");
    assert_eq!(data.claims.sub, did);
    assert_eq!(data.claims.iss, did);
    assert_eq!(data.claims.scope, Some(auth::SCOPE_ACCESS.to_string()));

    let r_token = auth::create_refresh_token(did, &key_bytes).expect("create refresh token");
    let r_data = auth::verify_refresh_token(&r_token, &key_bytes).expect("verify refresh token");
    assert_eq!(r_data.claims.scope, Some(auth::SCOPE_REFRESH.to_string()));

    let aud = "did:web:service";
    let lxm = "com.example.test";
    let s_token =
        auth::create_service_token(did, aud, lxm, &key_bytes).expect("create service token");
    let s_data = auth::verify_token(&s_token, &key_bytes).expect("verify service token");
    assert_eq!(s_data.claims.aud, aud);
    assert_eq!(s_data.claims.lxm, Some(lxm.to_string()));
}

#[test]
fn test_token_type_confusion_prevented() {
    let secret_key = SecretKey::random(&mut OsRng);
    let key_bytes = secret_key.to_bytes();
    let did = "did:plc:test";

    let access_token = auth::create_access_token(did, &key_bytes).expect("create access token");
    let refresh_token = auth::create_refresh_token(did, &key_bytes).expect("create refresh token");

    assert!(auth::verify_access_token(&access_token, &key_bytes).is_ok());
    assert!(auth::verify_access_token(&refresh_token, &key_bytes).is_err());

    assert!(auth::verify_refresh_token(&refresh_token, &key_bytes).is_ok());
    assert!(auth::verify_refresh_token(&access_token, &key_bytes).is_err());
}

#[test]
fn test_verify_fails_with_wrong_key() {
    let secret_key1 = SecretKey::random(&mut OsRng);
    let key_bytes1 = secret_key1.to_bytes();

    let secret_key2 = SecretKey::random(&mut OsRng);
    let key_bytes2 = secret_key2.to_bytes();

    let did = "did:plc:test";
    let token = auth::create_access_token(did, &key_bytes1).expect("create token");

    let result = auth::verify_token(&token, &key_bytes2);
    assert!(result.is_err());
}

#[test]
fn test_token_expiration() {
    let secret_key = SecretKey::random(&mut OsRng);
    let key_bytes = secret_key.to_bytes();
    let signing_key = SigningKey::from_slice(&key_bytes).expect("key");

    let header = json!({
        "alg": "ES256K",
        "typ": "JWT"
    });
    let claims = json!({
        "iss": "did:plc:test",
        "sub": "did:plc:test",
        "aud": "did:web:test",
        "exp": (Utc::now() - Duration::seconds(10)).timestamp(),
        "iat": (Utc::now() - Duration::minutes(1)).timestamp(),
        "jti": "unique",
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
    let message = format!("{}.{}", header_b64, claims_b64);
    let signature: k256::ecdsa::Signature = signing_key.sign(message.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let token = format!("{}.{}", message, signature_b64);

    let result = auth::verify_token(&token, &key_bytes);
    match result {
        Ok(_) => panic!("Token should be expired"),
        Err(e) => assert_eq!(e.to_string(), "Token expired"),
    }
}

#[test]
fn test_invalid_token_format() {
    let secret_key = SecretKey::random(&mut OsRng);
    let key_bytes = secret_key.to_bytes();

    assert!(auth::verify_token("invalid.token", &key_bytes).is_err());
    assert!(auth::verify_token("too.many.parts.here", &key_bytes).is_err());
    assert!(auth::verify_token("bad_base64.payload.sig", &key_bytes).is_err());
}

#[test]
fn test_tampered_token() {
    let secret_key = SecretKey::random(&mut OsRng);
    let key_bytes = secret_key.to_bytes();
    let did = "did:plc:test";

    let token = auth::create_access_token(did, &key_bytes).expect("create token");
    let parts: Vec<&str> = token.split('.').collect();

    let claims_json = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    let mut claims: serde_json::Value = serde_json::from_str(&claims_json).unwrap();
    claims["sub"] = json!("did:plc:hacker");
    let tampered_claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());

    let tampered_token = format!("{}.{}.{}", parts[0], tampered_claims_b64, parts[2]);

    let result = auth::verify_token(&tampered_token, &key_bytes);
    assert!(result.is_err());
}

#[test]
fn test_get_did_from_token() {
    let secret_key = SecretKey::random(&mut OsRng);
    let key_bytes = secret_key.to_bytes();
    let did = "did:plc:test";

    let token = auth::create_access_token(did, &key_bytes).expect("create token");
    let extracted_did = auth::get_did_from_token(&token).expect("get did");
    assert_eq!(extracted_did, did);

    assert!(auth::get_did_from_token("bad.token").is_err());
}
