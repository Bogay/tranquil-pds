use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use hmac::Mac;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::AuthConfig;
use crate::oauth::OAuthError;

const ACCESS_TOKEN_EXPIRY_SECONDS: i64 = 3600;

pub struct TokenClaims {
    pub jti: String,
    pub exp: i64,
    pub iat: i64,
}

pub fn verify_pkce(code_challenge: &str, code_verifier: &str) -> Result<(), OAuthError> {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let computed_challenge = URL_SAFE_NO_PAD.encode(&hash);

    if !bool::from(computed_challenge.as_bytes().ct_eq(code_challenge.as_bytes())) {
        return Err(OAuthError::InvalidGrant("PKCE verification failed".to_string()));
    }

    Ok(())
}

pub fn create_access_token(
    token_id: &str,
    sub: &str,
    dpop_jkt: Option<&str>,
) -> Result<String, OAuthError> {
    use serde_json::json;

    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let issuer = format!("https://{}", pds_hostname);

    let now = Utc::now().timestamp();
    let exp = now + ACCESS_TOKEN_EXPIRY_SECONDS;

    let mut payload = json!({
        "iss": issuer,
        "sub": sub,
        "aud": issuer,
        "iat": now,
        "exp": exp,
        "jti": token_id,
        "scope": "atproto"
    });

    if let Some(jkt) = dpop_jkt {
        payload["cnf"] = json!({ "jkt": jkt });
    }

    let header = json!({
        "alg": "HS256",
        "typ": "at+jwt"
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());

    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let config = AuthConfig::get();

    type HmacSha256 = hmac::Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(config.jwt_secret().as_bytes())
        .map_err(|_| OAuthError::ServerError("HMAC key error".to_string()))?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();

    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(format!("{}.{}", signing_input, signature_b64))
}

pub fn extract_token_claims(token: &str) -> Result<TokenClaims, OAuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(OAuthError::InvalidToken("Invalid token format".to_string()));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| OAuthError::InvalidToken("Invalid token encoding".to_string()))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| OAuthError::InvalidToken("Invalid token header".to_string()))?;

    if header.get("typ").and_then(|t| t.as_str()) != Some("at+jwt") {
        return Err(OAuthError::InvalidToken("Not an OAuth access token".to_string()));
    }
    if header.get("alg").and_then(|a| a.as_str()) != Some("HS256") {
        return Err(OAuthError::InvalidToken("Unsupported algorithm".to_string()));
    }

    let config = AuthConfig::get();
    let secret = config.jwt_secret();

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let provided_sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| OAuthError::InvalidToken("Invalid signature encoding".to_string()))?;

    type HmacSha256 = hmac::Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| OAuthError::ServerError("HMAC initialization failed".to_string()))?;
    mac.update(signing_input.as_bytes());
    let expected_sig = mac.finalize().into_bytes();

    if !bool::from(expected_sig.ct_eq(&provided_sig)) {
        return Err(OAuthError::InvalidToken("Invalid token signature".to_string()));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| OAuthError::InvalidToken("Invalid payload encoding".to_string()))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| OAuthError::InvalidToken("Invalid token payload".to_string()))?;

    let jti = payload
        .get("jti")
        .and_then(|j| j.as_str())
        .ok_or_else(|| OAuthError::InvalidToken("Missing jti claim".to_string()))?
        .to_string();

    let exp = payload
        .get("exp")
        .and_then(|e| e.as_i64())
        .ok_or_else(|| OAuthError::InvalidToken("Missing exp claim".to_string()))?;

    let iat = payload
        .get("iat")
        .and_then(|i| i.as_i64())
        .ok_or_else(|| OAuthError::InvalidToken("Missing iat claim".to_string()))?;

    Ok(TokenClaims { jti, exp, iat })
}
