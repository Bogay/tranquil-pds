use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use hmac::Mac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::AuthConfig;
use crate::state::AppState;
use crate::oauth::{
    ClientAuth, OAuthError, RefreshToken, TokenData, TokenId,
    client::{ClientMetadataCache, verify_client_auth},
    db,
    dpop::DPoPVerifier,
};

const ACCESS_TOKEN_EXPIRY_SECONDS: i64 = 3600;
const REFRESH_TOKEN_EXPIRY_DAYS: i64 = 60;

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_assertion: Option<String>,
    #[serde(default)]
    pub client_assertion_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

pub async fn token_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Result<(HeaderMap, Json<TokenResponse>), OAuthError> {
    let dpop_proof = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match request.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(state, headers, request, dpop_proof).await
        }
        "refresh_token" => {
            handle_refresh_token_grant(state, headers, request, dpop_proof).await
        }
        _ => Err(OAuthError::UnsupportedGrantType(format!(
            "Unsupported grant_type: {}",
            request.grant_type
        ))),
    }
}

async fn handle_authorization_code_grant(
    state: AppState,
    _headers: HeaderMap,
    request: TokenRequest,
    dpop_proof: Option<String>,
) -> Result<(HeaderMap, Json<TokenResponse>), OAuthError> {
    let code = request
        .code
        .ok_or_else(|| OAuthError::InvalidRequest("code is required".to_string()))?;

    let code_verifier = request
        .code_verifier
        .ok_or_else(|| OAuthError::InvalidRequest("code_verifier is required".to_string()))?;

    let auth_request = db::consume_authorization_request_by_code(&state.db, &code)
        .await?
        .ok_or_else(|| OAuthError::InvalidGrant("Invalid or expired code".to_string()))?;

    if auth_request.expires_at < Utc::now() {
        return Err(OAuthError::InvalidGrant("Authorization code has expired".to_string()));
    }

    if let Some(request_client_id) = &request.client_id {
        if request_client_id != &auth_request.client_id {
            return Err(OAuthError::InvalidGrant("client_id mismatch".to_string()));
        }
    }

    let did = auth_request
        .did
        .ok_or_else(|| OAuthError::InvalidGrant("Authorization not completed".to_string()))?;

    let client_metadata_cache = ClientMetadataCache::new(3600);
    let client_metadata = client_metadata_cache
        .get(&auth_request.client_id)
        .await?;
    let client_auth = auth_request.client_auth.clone().unwrap_or(ClientAuth::None);
    verify_client_auth(&client_metadata, &client_auth)?;

    verify_pkce(&auth_request.parameters.code_challenge, &code_verifier)?;

    if let Some(redirect_uri) = &request.redirect_uri {
        if redirect_uri != &auth_request.parameters.redirect_uri {
            return Err(OAuthError::InvalidGrant("redirect_uri mismatch".to_string()));
        }
    }

    let dpop_jkt = if let Some(proof) = &dpop_proof {
        let config = AuthConfig::get();
        let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());

        let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        let token_endpoint = format!("https://{}/oauth/token", pds_hostname);

        let result = verifier.verify_proof(proof, "POST", &token_endpoint, None)?;

        if !db::check_and_record_dpop_jti(&state.db, &result.jti).await? {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP proof has already been used".to_string(),
            ));
        }

        if let Some(expected_jkt) = &auth_request.parameters.dpop_jkt {
            if &result.jkt != expected_jkt {
                return Err(OAuthError::InvalidDpopProof(
                    "DPoP key binding mismatch".to_string(),
                ));
            }
        }

        Some(result.jkt)
    } else if auth_request.parameters.dpop_jkt.is_some() {
        return Err(OAuthError::InvalidRequest(
            "DPoP proof required for this authorization".to_string(),
        ));
    } else {
        None
    };

    let token_id = TokenId::generate();
    let refresh_token = RefreshToken::generate();
    let now = Utc::now();

    let access_token = create_access_token(&token_id.0, &did, dpop_jkt.as_deref())?;

    let token_data = TokenData {
        did: did.clone(),
        token_id: token_id.0.clone(),
        created_at: now,
        updated_at: now,
        expires_at: now + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS),
        client_id: auth_request.client_id.clone(),
        client_auth: auth_request.client_auth.unwrap_or(ClientAuth::None),
        device_id: auth_request.device_id,
        parameters: auth_request.parameters.clone(),
        details: None,
        code: None,
        current_refresh_token: Some(refresh_token.0.clone()),
        scope: auth_request.parameters.scope.clone(),
    };

    db::create_token(&state.db, &token_data).await?;

    tokio::spawn({
        let pool = state.db.clone();
        let did_clone = did.clone();
        async move {
            if let Err(e) = db::enforce_token_limit_for_user(&pool, &did_clone).await {
                tracing::warn!("Failed to enforce token limit for user: {:?}", e);
            }
        }
    });

    let mut response_headers = HeaderMap::new();
    let config = AuthConfig::get();
    let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
    response_headers.insert(
        "DPoP-Nonce",
        verifier.generate_nonce().parse().unwrap(),
    );

    Ok((
        response_headers,
        Json(TokenResponse {
            access_token,
            token_type: if dpop_jkt.is_some() { "DPoP" } else { "Bearer" }.to_string(),
            expires_in: ACCESS_TOKEN_EXPIRY_SECONDS as u64,
            refresh_token: Some(refresh_token.0),
            scope: auth_request.parameters.scope,
            sub: Some(did),
        }),
    ))
}

async fn handle_refresh_token_grant(
    state: AppState,
    _headers: HeaderMap,
    request: TokenRequest,
    dpop_proof: Option<String>,
) -> Result<(HeaderMap, Json<TokenResponse>), OAuthError> {
    let refresh_token_str = request
        .refresh_token
        .ok_or_else(|| OAuthError::InvalidRequest("refresh_token is required".to_string()))?;

    if let Some(token_id) = db::check_refresh_token_used(&state.db, &refresh_token_str).await? {
        db::delete_token_family(&state.db, token_id).await?;
        return Err(OAuthError::InvalidGrant(
            "Refresh token reuse detected, token family revoked".to_string(),
        ));
    }

    let (db_id, token_data) = db::get_token_by_refresh_token(&state.db, &refresh_token_str)
        .await?
        .ok_or_else(|| OAuthError::InvalidGrant("Invalid refresh token".to_string()))?;

    if token_data.expires_at < Utc::now() {
        db::delete_token_family(&state.db, db_id).await?;
        return Err(OAuthError::InvalidGrant("Refresh token has expired".to_string()));
    }

    let dpop_jkt = if let Some(proof) = &dpop_proof {
        let config = AuthConfig::get();
        let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());

        let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        let token_endpoint = format!("https://{}/oauth/token", pds_hostname);

        let result = verifier.verify_proof(proof, "POST", &token_endpoint, None)?;

        if !db::check_and_record_dpop_jti(&state.db, &result.jti).await? {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP proof has already been used".to_string(),
            ));
        }

        if let Some(expected_jkt) = &token_data.parameters.dpop_jkt {
            if &result.jkt != expected_jkt {
                return Err(OAuthError::InvalidDpopProof(
                    "DPoP key binding mismatch".to_string(),
                ));
            }
        }

        Some(result.jkt)
    } else if token_data.parameters.dpop_jkt.is_some() {
        return Err(OAuthError::InvalidRequest(
            "DPoP proof required".to_string(),
        ));
    } else {
        None
    };

    let new_token_id = TokenId::generate();
    let new_refresh_token = RefreshToken::generate();
    let new_expires_at = Utc::now() + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS);

    db::rotate_token(
        &state.db,
        db_id,
        &new_token_id.0,
        &new_refresh_token.0,
        new_expires_at,
    )
    .await?;

    let access_token = create_access_token(&new_token_id.0, &token_data.did, dpop_jkt.as_deref())?;

    let mut response_headers = HeaderMap::new();
    let config = AuthConfig::get();
    let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
    response_headers.insert(
        "DPoP-Nonce",
        verifier.generate_nonce().parse().unwrap(),
    );

    Ok((
        response_headers,
        Json(TokenResponse {
            access_token,
            token_type: if dpop_jkt.is_some() { "DPoP" } else { "Bearer" }.to_string(),
            expires_in: ACCESS_TOKEN_EXPIRY_SECONDS as u64,
            refresh_token: Some(new_refresh_token.0),
            scope: token_data.scope,
            sub: Some(token_data.did),
        }),
    ))
}

fn verify_pkce(code_challenge: &str, code_verifier: &str) -> Result<(), OAuthError> {
    use subtle::ConstantTimeEq;

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let computed_challenge = URL_SAFE_NO_PAD.encode(&hash);

    if !bool::from(computed_challenge.as_bytes().ct_eq(code_challenge.as_bytes())) {
        return Err(OAuthError::InvalidGrant("PKCE verification failed".to_string()));
    }

    Ok(())
}

fn create_access_token(
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

    use sha2::Sha256 as HmacSha256;
    use hmac::{Hmac, Mac};
    type HmacSha256Type = Hmac<HmacSha256>;

    let mut mac = HmacSha256Type::new_from_slice(config.jwt_secret().as_bytes())
        .map_err(|_| OAuthError::ServerError("HMAC key error".to_string()))?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();

    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(format!("{}.{}", signing_input, signature_b64))
}

pub async fn revoke_token(
    State(state): State<AppState>,
    Form(request): Form<RevokeRequest>,
) -> Result<StatusCode, OAuthError> {
    if let Some(token) = &request.token {
        if let Some((db_id, _)) = db::get_token_by_refresh_token(&state.db, token).await? {
            db::delete_token_family(&state.db, db_id).await?;
        } else {
            db::delete_token(&state.db, token).await?;
        }
    }

    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: Option<String>,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

pub async fn introspect_token(
    State(state): State<AppState>,
    Form(request): Form<IntrospectRequest>,
) -> Json<IntrospectResponse> {
    let inactive_response = IntrospectResponse {
        active: false,
        scope: None,
        client_id: None,
        username: None,
        token_type: None,
        exp: None,
        iat: None,
        nbf: None,
        sub: None,
        aud: None,
        iss: None,
        jti: None,
    };

    let token_info = match extract_token_claims(&request.token) {
        Ok(info) => info,
        Err(_) => return Json(inactive_response),
    };

    let token_data = match db::get_token_by_id(&state.db, &token_info.jti).await {
        Ok(Some(data)) => data,
        _ => return Json(inactive_response),
    };

    if token_data.expires_at < Utc::now() {
        return Json(inactive_response);
    }

    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let issuer = format!("https://{}", pds_hostname);

    Json(IntrospectResponse {
        active: true,
        scope: token_data.scope,
        client_id: Some(token_data.client_id),
        username: None,
        token_type: if token_data.parameters.dpop_jkt.is_some() {
            Some("DPoP".to_string())
        } else {
            Some("Bearer".to_string())
        },
        exp: Some(token_info.exp),
        iat: Some(token_info.iat),
        nbf: Some(token_info.iat),
        sub: Some(token_data.did),
        aud: Some(issuer.clone()),
        iss: Some(issuer),
        jti: Some(token_info.jti),
    })
}

struct TokenClaims {
    jti: String,
    exp: i64,
    iat: i64,
}

fn extract_token_claims(token: &str) -> Result<TokenClaims, OAuthError> {
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
