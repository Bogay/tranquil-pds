use super::{Claims, Header};
use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use k256::ecdsa::{Signature, SigningKey, signature::Signer};
use uuid;

pub fn create_access_token(did: &str, key_bytes: &[u8]) -> Result<String> {
    create_signed_token(did, "access", key_bytes, Duration::minutes(15))
}

pub fn create_refresh_token(did: &str, key_bytes: &[u8]) -> Result<String> {
    create_signed_token(did, "refresh", key_bytes, Duration::days(7))
}

pub fn create_service_token(did: &str, aud: &str, lxm: &str, key_bytes: &[u8]) -> Result<String> {
    let signing_key = SigningKey::from_slice(key_bytes)?;

    let expiration = Utc::now()
        .checked_add_signed(Duration::seconds(60))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        iss: did.to_owned(),
        sub: did.to_owned(),
        aud: aud.to_owned(),
        exp: expiration as usize,
        iat: Utc::now().timestamp() as usize,
        scope: None,
        lxm: Some(lxm.to_string()),
        jti: uuid::Uuid::new_v4().to_string(),
    };

    sign_claims(claims, &signing_key)
}

fn create_signed_token(
    did: &str,
    scope: &str,
    key_bytes: &[u8],
    duration: Duration,
) -> Result<String> {
    let signing_key = SigningKey::from_slice(key_bytes)?;

    let expiration = Utc::now()
        .checked_add_signed(duration)
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        iss: did.to_owned(),
        sub: did.to_owned(),
        aud: format!(
            "did:web:{}",
            std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
        ),
        exp: expiration as usize,
        iat: Utc::now().timestamp() as usize,
        scope: Some(scope.to_string()),
        lxm: None,
        jti: uuid::Uuid::new_v4().to_string(),
    };

    sign_claims(claims, &signing_key)
}

fn sign_claims(claims: Claims, key: &SigningKey) -> Result<String> {
    let header = Header {
        alg: "ES256K".to_string(),
        typ: "JWT".to_string(),
    };

    let header_json = serde_json::to_string(&header)?;
    let claims_json = serde_json::to_string(&claims)?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json);

    let message = format!("{}.{}", header_b64, claims_b64);
    let signature: Signature = key.sign(message.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}", message, signature_b64))
}
