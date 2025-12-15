use super::{Claims, Header, TokenData, UnsafeClaims};
use super::token::{TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH, SCOPE_ACCESS, SCOPE_REFRESH, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED};
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use hmac::{Hmac, Mac};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

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

pub fn get_jti_from_token(token: &str) -> Result<String, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".to_string());
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    let claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("JSON decode failed: {}", e))?;

    claims.get("jti")
        .and_then(|j| j.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "No jti claim in token".to_string())
}

pub fn verify_token(token: &str, key_bytes: &[u8]) -> Result<TokenData<Claims>> {
    verify_token_internal(token, key_bytes, None, None)
}

pub fn verify_access_token(token: &str, key_bytes: &[u8]) -> Result<TokenData<Claims>> {
    verify_token_internal(
        token,
        key_bytes,
        Some(TOKEN_TYPE_ACCESS),
        Some(&[SCOPE_ACCESS, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED]),
    )
}

pub fn verify_refresh_token(token: &str, key_bytes: &[u8]) -> Result<TokenData<Claims>> {
    verify_token_internal(
        token,
        key_bytes,
        Some(TOKEN_TYPE_REFRESH),
        Some(&[SCOPE_REFRESH]),
    )
}

pub fn verify_access_token_hs256(token: &str, secret: &[u8]) -> Result<TokenData<Claims>> {
    verify_token_hs256_internal(
        token,
        secret,
        Some(TOKEN_TYPE_ACCESS),
        Some(&[SCOPE_ACCESS, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED]),
    )
}

pub fn verify_refresh_token_hs256(token: &str, secret: &[u8]) -> Result<TokenData<Claims>> {
    verify_token_hs256_internal(
        token,
        secret,
        Some(TOKEN_TYPE_REFRESH),
        Some(&[SCOPE_REFRESH]),
    )
}

fn verify_token_internal(
    token: &str,
    key_bytes: &[u8],
    expected_typ: Option<&str>,
    allowed_scopes: Option<&[&str]>,
) -> Result<TokenData<Claims>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid token format"));
    }

    let header_b64 = parts[0];
    let claims_b64 = parts[1];
    let signature_b64 = parts[2];

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .context("Base64 decode of header failed")?;

    let header: Header =
        serde_json::from_slice(&header_bytes).context("JSON decode of header failed")?;

    if let Some(expected) = expected_typ {
        if header.typ != expected {
            return Err(anyhow!("Invalid token type: expected {}, got {}", expected, header.typ));
        }
    }

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

    if let Some(scopes) = allowed_scopes {
        let token_scope = claims.scope.as_deref().unwrap_or("");
        if !scopes.contains(&token_scope) {
            return Err(anyhow!("Invalid token scope: {}", token_scope));
        }
    }

    Ok(TokenData { claims })
}

fn verify_token_hs256_internal(
    token: &str,
    secret: &[u8],
    expected_typ: Option<&str>,
    allowed_scopes: Option<&[&str]>,
) -> Result<TokenData<Claims>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid token format"));
    }

    let header_b64 = parts[0];
    let claims_b64 = parts[1];
    let signature_b64 = parts[2];

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .context("Base64 decode of header failed")?;

    let header: Header =
        serde_json::from_slice(&header_bytes).context("JSON decode of header failed")?;

    if header.alg != "HS256" {
        return Err(anyhow!("Expected HS256 algorithm, got {}", header.alg));
    }

    if let Some(expected) = expected_typ {
        if header.typ != expected {
            return Err(anyhow!("Invalid token type: expected {}, got {}", expected, header.typ));
        }
    }

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .context("Base64 decode of signature failed")?;

    let message = format!("{}.{}", header_b64, claims_b64);

    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| anyhow!("Invalid secret: {}", e))?;
    mac.update(message.as_bytes());

    let expected_signature = mac.finalize().into_bytes();
    let is_valid: bool = signature_bytes.ct_eq(&expected_signature).into();

    if !is_valid {
        return Err(anyhow!("Signature verification failed"));
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .context("Base64 decode of claims failed")?;

    let claims: Claims =
        serde_json::from_slice(&claims_bytes).context("JSON decode of claims failed")?;

    let now = Utc::now().timestamp() as usize;
    if claims.exp < now {
        return Err(anyhow!("Token expired"));
    }

    if let Some(scopes) = allowed_scopes {
        let token_scope = claims.scope.as_deref().unwrap_or("");
        if !scopes.contains(&token_scope) {
            return Err(anyhow!("Invalid token scope: {}", token_scope));
        }
    }

    Ok(TokenData { claims })
}

pub fn get_algorithm_from_token(token: &str) -> Result<String, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".to_string());
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("JSON decode failed: {}", e))?;

    Ok(header.alg)
}
