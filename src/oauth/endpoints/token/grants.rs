use axum::http::HeaderMap;
use axum::Json;
use chrono::{Duration, Utc};
use crate::config::AuthConfig;
use crate::state::AppState;
use crate::oauth::{
    ClientAuth, OAuthError, RefreshToken, TokenData, TokenId,
    client::{ClientMetadataCache, verify_client_auth},
    db,
    dpop::DPoPVerifier,
};
use super::types::{TokenRequest, TokenResponse};
use super::helpers::{create_access_token, verify_pkce};
const ACCESS_TOKEN_EXPIRY_SECONDS: i64 = 3600;
const REFRESH_TOKEN_EXPIRY_DAYS: i64 = 60;
pub async fn handle_authorization_code_grant(
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
    verify_client_auth(&client_metadata_cache, &client_metadata, &client_auth).await?;
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
pub async fn handle_refresh_token_grant(
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
