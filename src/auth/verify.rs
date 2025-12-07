use super::{Claims, TokenData, UnsafeClaims};
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier};

pub fn get_did_from_token(token: &str) -> Result<String, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".to_string());
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    let claims: UnsafeClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("JSON decode failed: {}", e))?;

    Ok(claims.sub.unwrap_or(claims.iss))
}

pub fn verify_token(token: &str, key_bytes: &[u8]) -> Result<TokenData<Claims>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid token format"));
    }

    let header_b64 = parts[0];
    let claims_b64 = parts[1];
    let signature_b64 = parts[2];

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .context("Base64 decode of signature failed")?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| anyhow!("Invalid signature format: {}", e))?;

    let signing_key = SigningKey::from_slice(key_bytes)?;
    let verifying_key = VerifyingKey::from(&signing_key);

    let message = format!("{}.{}", header_b64, claims_b64);
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|e| anyhow!("Signature verification failed: {}", e))?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .context("Base64 decode of claims failed")?;
    let claims: Claims =
        serde_json::from_slice(&claims_bytes).context("JSON decode of claims failed")?;

    let now = Utc::now().timestamp() as usize;
    if claims.exp < now {
        return Err(anyhow!("Token expired"));
    }

    Ok(TokenData { claims })
}
