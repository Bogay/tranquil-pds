use super::types::{ActClaim, Claims, Header, TokenWithMetadata};
use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use k256::ecdsa::{Signature, SigningKey, signature::Signer};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const TOKEN_TYPE_ACCESS: &str = "at+jwt";
pub const TOKEN_TYPE_REFRESH: &str = "refresh+jwt";
pub const TOKEN_TYPE_SERVICE: &str = "jwt";
pub const SCOPE_ACCESS: &str = "com.atproto.access";
pub const SCOPE_REFRESH: &str = "com.atproto.refresh";
pub const SCOPE_APP_PASS: &str = "com.atproto.appPass";
pub const SCOPE_APP_PASS_PRIVILEGED: &str = "com.atproto.appPassPrivileged";

pub fn create_access_token(did: &str, key_bytes: &[u8]) -> Result<String> {
    Ok(create_access_token_with_metadata(did, key_bytes)?.token)
}

pub fn create_refresh_token(did: &str, key_bytes: &[u8]) -> Result<String> {
    Ok(create_refresh_token_with_metadata(did, key_bytes)?.token)
}

pub fn create_access_token_with_metadata(did: &str, key_bytes: &[u8]) -> Result<TokenWithMetadata> {
    create_access_token_with_scope_metadata(did, key_bytes, None, None)
}

pub fn create_access_token_with_scope_metadata(
    did: &str,
    key_bytes: &[u8],
    scopes: Option<&str>,
    hostname: Option<&str>,
) -> Result<TokenWithMetadata> {
    let scope = scopes.unwrap_or(SCOPE_ACCESS);
    create_signed_token_with_metadata(
        did,
        scope,
        TOKEN_TYPE_ACCESS,
        key_bytes,
        Duration::minutes(15),
        hostname,
    )
}

pub fn create_access_token_with_delegation(
    did: &str,
    key_bytes: &[u8],
    scopes: Option<&str>,
    controller_did: Option<&str>,
    hostname: Option<&str>,
) -> Result<TokenWithMetadata> {
    let scope = scopes.unwrap_or(SCOPE_ACCESS);
    let act = controller_did.map(|c| ActClaim { sub: c.to_string() });
    create_signed_token_with_act(
        did,
        scope,
        TOKEN_TYPE_ACCESS,
        key_bytes,
        Duration::minutes(15),
        act,
        hostname,
    )
}

pub fn create_refresh_token_with_metadata(
    did: &str,
    key_bytes: &[u8],
) -> Result<TokenWithMetadata> {
    create_signed_token_with_metadata(
        did,
        SCOPE_REFRESH,
        TOKEN_TYPE_REFRESH,
        key_bytes,
        Duration::days(14),
        None,
    )
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
        act: None,
    };

    sign_claims(claims, &signing_key)
}

fn create_signed_token_with_metadata(
    did: &str,
    scope: &str,
    typ: &str,
    key_bytes: &[u8],
    duration: Duration,
    hostname: Option<&str>,
) -> Result<TokenWithMetadata> {
    create_signed_token_with_act(did, scope, typ, key_bytes, duration, None, hostname)
}

fn create_signed_token_with_act(
    did: &str,
    scope: &str,
    typ: &str,
    key_bytes: &[u8],
    duration: Duration,
    act: Option<ActClaim>,
    hostname: Option<&str>,
) -> Result<TokenWithMetadata> {
    let signing_key = SigningKey::from_slice(key_bytes)?;

    let expires_at = Utc::now()
        .checked_add_signed(duration)
        .expect("valid timestamp");

    let expiration = expires_at.timestamp();
    let jti = uuid::Uuid::new_v4().to_string();

    let aud_hostname = hostname.map(|h| h.to_string()).unwrap_or_else(|| {
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
    });

    let claims = Claims {
        iss: did.to_owned(),
        sub: did.to_owned(),
        aud: format!("did:web:{}", aud_hostname),
        exp: expiration as usize,
        iat: Utc::now().timestamp() as usize,
        scope: Some(scope.to_string()),
        lxm: None,
        jti: jti.clone(),
        act,
    };

    let token = sign_claims_with_type(claims, &signing_key, typ)?;

    Ok(TokenWithMetadata {
        token,
        jti,
        expires_at,
    })
}

fn sign_claims(claims: Claims, key: &SigningKey) -> Result<String> {
    sign_claims_with_type(claims, key, TOKEN_TYPE_SERVICE)
}

fn sign_claims_with_type(claims: Claims, key: &SigningKey, typ: &str) -> Result<String> {
    let header = Header {
        alg: "ES256K".to_string(),
        typ: typ.to_string(),
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

pub fn create_access_token_hs256(did: &str, secret: &[u8]) -> Result<String> {
    Ok(create_access_token_hs256_with_metadata(did, secret)?.token)
}

pub fn create_refresh_token_hs256(did: &str, secret: &[u8]) -> Result<String> {
    Ok(create_refresh_token_hs256_with_metadata(did, secret)?.token)
}

pub fn create_access_token_hs256_with_metadata(
    did: &str,
    secret: &[u8],
) -> Result<TokenWithMetadata> {
    create_hs256_token_with_metadata(
        did,
        SCOPE_ACCESS,
        TOKEN_TYPE_ACCESS,
        secret,
        Duration::minutes(15),
    )
}

pub fn create_refresh_token_hs256_with_metadata(
    did: &str,
    secret: &[u8],
) -> Result<TokenWithMetadata> {
    create_hs256_token_with_metadata(
        did,
        SCOPE_REFRESH,
        TOKEN_TYPE_REFRESH,
        secret,
        Duration::days(14),
    )
}

pub fn create_service_token_hs256(
    did: &str,
    aud: &str,
    lxm: &str,
    secret: &[u8],
) -> Result<String> {
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
        act: None,
    };

    sign_claims_hs256(claims, TOKEN_TYPE_SERVICE, secret)
}

fn create_hs256_token_with_metadata(
    did: &str,
    scope: &str,
    typ: &str,
    secret: &[u8],
    duration: Duration,
) -> Result<TokenWithMetadata> {
    let expires_at = Utc::now()
        .checked_add_signed(duration)
        .expect("valid timestamp");

    let expiration = expires_at.timestamp();
    let jti = uuid::Uuid::new_v4().to_string();

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
        jti: jti.clone(),
        act: None,
    };

    let token = sign_claims_hs256(claims, typ, secret)?;

    Ok(TokenWithMetadata {
        token,
        jti,
        expires_at,
    })
}

fn sign_claims_hs256(claims: Claims, typ: &str, secret: &[u8]) -> Result<String> {
    let header = Header {
        alg: "HS256".to_string(),
        typ: typ.to_string(),
    };

    let header_json = serde_json::to_string(&header)?;
    let claims_json = serde_json::to_string(&claims)?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json);

    let message = format!("{}.{}", header_b64, claims_b64);

    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| anyhow::anyhow!("Invalid secret length: {}", e))?;
    mac.update(message.as_bytes());

    let signature = mac.finalize().into_bytes();
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{}.{}", message, signature_b64))
}
