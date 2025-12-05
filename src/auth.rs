use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use k256::ecdsa::{SigningKey, VerifyingKey, signature::Signer, signature::Verifier, Signature};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use anyhow::{Context, Result, anyhow};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxm: Option<String>,
    pub jti: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UnsafeClaims {
    iss: String,
    sub: Option<String>,
}

// fancy boy TokenData equivalent for compatibility/structure
pub struct TokenData<T> {
    pub claims: T,
}

pub fn get_did_from_token(token: &str) -> Result<String, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".to_string());
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    let claims: UnsafeClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JSON decode failed: {}", e))?;

    Ok(claims.sub.unwrap_or(claims.iss))
}

pub fn create_access_token(did: &str, key_bytes: &[u8]) -> Result<String, anyhow::Error> {
    create_signed_token(did, "access", key_bytes, Duration::minutes(15))
}

pub fn create_refresh_token(did: &str, key_bytes: &[u8]) -> Result<String, anyhow::Error> {
    create_signed_token(did, "refresh", key_bytes, Duration::days(7))
}

pub fn create_service_token(did: &str, aud: &str, lxm: &str, key_bytes: &[u8]) -> Result<String, anyhow::Error> {
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

fn create_signed_token(did: &str, scope: &str, key_bytes: &[u8], duration: Duration) -> Result<String, anyhow::Error> {
    let signing_key = SigningKey::from_slice(key_bytes)?;

    let expiration = Utc::now()
        .checked_add_signed(duration)
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        iss: did.to_owned(),
        sub: did.to_owned(),
        aud: format!("did:web:{}", std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())),
        exp: expiration as usize,
        iat: Utc::now().timestamp() as usize,
        scope: Some(scope.to_string()),
        lxm: None,
        jti: uuid::Uuid::new_v4().to_string(),
    };

    sign_claims(claims, &signing_key)
}

fn sign_claims(claims: Claims, key: &SigningKey) -> Result<String, anyhow::Error> {
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

pub fn verify_token(token: &str, key_bytes: &[u8]) -> Result<TokenData<Claims>, anyhow::Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid token format"));
    }

    let header_b64 = parts[0];
    let claims_b64 = parts[1];
    let signature_b64 = parts[2];

    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64)
        .context("Base64 decode of signature failed")?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| anyhow!("Invalid signature format: {}", e))?;

    let signing_key = SigningKey::from_slice(key_bytes)?;
    let verifying_key = VerifyingKey::from(&signing_key);

    let message = format!("{}.{}", header_b64, claims_b64);
    verifying_key.verify(message.as_bytes(), &signature)
        .map_err(|e| anyhow!("Signature verification failed: {}", e))?;

    let claims_bytes = URL_SAFE_NO_PAD.decode(claims_b64)
        .context("Base64 decode of claims failed")?;
    let claims: Claims = serde_json::from_slice(&claims_bytes)
        .context("JSON decode of claims failed")?;

    let now = Utc::now().timestamp() as usize;
    if claims.exp < now {
        return Err(anyhow!("Token expired"));
    }

    Ok(TokenData { claims })
}
