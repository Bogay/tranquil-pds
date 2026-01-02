use super::helpers::{create_access_token_with_delegation, verify_pkce};
use super::types::{TokenRequest, TokenResponse};
use crate::config::AuthConfig;
use crate::delegation;
use crate::oauth::{
    ClientAuth, OAuthError, RefreshToken, TokenData, TokenId,
    client::{ClientMetadataCache, verify_client_auth},
    db,
    dpop::DPoPVerifier,
};
use crate::state::AppState;
use axum::Json;
use axum::http::HeaderMap;
use chrono::{Duration, Utc};

const ACCESS_TOKEN_EXPIRY_SECONDS: i64 = 300;
const REFRESH_TOKEN_EXPIRY_DAYS_CONFIDENTIAL: i64 = 60;
const REFRESH_TOKEN_EXPIRY_DAYS_PUBLIC: i64 = 14;

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
        return Err(OAuthError::InvalidGrant(
            "Authorization code has expired".to_string(),
        ));
    }
    if let Some(request_client_id) = &request.client_id
        && request_client_id != &auth_request.client_id
    {
        return Err(OAuthError::InvalidGrant("client_id mismatch".to_string()));
    }
    let did = auth_request
        .did
        .ok_or_else(|| OAuthError::InvalidGrant("Authorization not completed".to_string()))?;
    let client_metadata_cache = ClientMetadataCache::new(3600);
    let client_metadata = client_metadata_cache.get(&auth_request.client_id).await?;
    let client_auth = if let (Some(assertion), Some(assertion_type)) =
        (&request.client_assertion, &request.client_assertion_type)
    {
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return Err(OAuthError::InvalidClient(
                "Unsupported client_assertion_type".to_string(),
            ));
        }
        ClientAuth::PrivateKeyJwt {
            client_assertion: assertion.clone(),
        }
    } else if let Some(secret) = &request.client_secret {
        ClientAuth::SecretPost {
            client_secret: secret.clone(),
        }
    } else {
        ClientAuth::None
    };
    verify_client_auth(&client_metadata_cache, &client_metadata, &client_auth).await?;
    verify_pkce(&auth_request.parameters.code_challenge, &code_verifier)?;
    if let Some(redirect_uri) = &request.redirect_uri
        && redirect_uri != &auth_request.parameters.redirect_uri
    {
        return Err(OAuthError::InvalidGrant(
            "redirect_uri mismatch".to_string(),
        ));
    }
    let dpop_jkt = if let Some(proof) = &dpop_proof {
        let config = AuthConfig::get();
        let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
        let pds_hostname =
            std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        let token_endpoint = format!("https://{}/oauth/token", pds_hostname);
        let result = verifier.verify_proof(proof, "POST", &token_endpoint, None)?;
        if !db::check_and_record_dpop_jti(&state.db, &result.jti).await? {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP proof has already been used".to_string(),
            ));
        }
        if let Some(expected_jkt) = &auth_request.parameters.dpop_jkt
            && &result.jkt != expected_jkt
        {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP key binding mismatch".to_string(),
            ));
        }
        Some(result.jkt)
    } else if auth_request.parameters.dpop_jkt.is_some() || client_metadata.requires_dpop() {
        return Err(OAuthError::UseDpopNonce(
            crate::oauth::dpop::DPoPVerifier::new(AuthConfig::get().dpop_secret().as_bytes())
                .generate_nonce(),
        ));
    } else {
        None
    };
    if let Err(e) = db::revoke_tokens_for_client(&state.db, &did, &auth_request.client_id).await {
        tracing::warn!("Failed to revoke previous tokens for client: {:?}", e);
    }
    let token_id = TokenId::generate();
    let refresh_token = RefreshToken::generate();
    let now = Utc::now();

    let (final_scope, controller_did) = if let Some(ref controller) = auth_request.controller_did {
        let grant = delegation::get_delegation(&state.db, &did, controller)
            .await
            .ok()
            .flatten();
        let granted_scopes = grant.map(|g| g.granted_scopes).unwrap_or_default();
        let requested = auth_request
            .parameters
            .scope
            .as_deref()
            .unwrap_or("atproto");
        let intersected = delegation::intersect_scopes(requested, &granted_scopes);
        (Some(intersected), Some(controller.clone()))
    } else {
        (auth_request.parameters.scope.clone(), None)
    };

    let access_token = create_access_token_with_delegation(
        &token_id.0,
        &did,
        dpop_jkt.as_deref(),
        final_scope.as_deref(),
        controller_did.as_deref(),
    )?;
    let stored_client_auth = auth_request.client_auth.unwrap_or(ClientAuth::None);
    let refresh_expiry_days = if matches!(stored_client_auth, ClientAuth::None) {
        REFRESH_TOKEN_EXPIRY_DAYS_PUBLIC
    } else {
        REFRESH_TOKEN_EXPIRY_DAYS_CONFIDENTIAL
    };
    let mut stored_parameters = auth_request.parameters.clone();
    stored_parameters.dpop_jkt = dpop_jkt.clone();
    let token_data = TokenData {
        did: did.clone(),
        token_id: token_id.0.clone(),
        created_at: now,
        updated_at: now,
        expires_at: now + Duration::days(refresh_expiry_days),
        client_id: auth_request.client_id.clone(),
        client_auth: stored_client_auth,
        device_id: auth_request.device_id,
        parameters: stored_parameters,
        details: None,
        code: None,
        current_refresh_token: Some(refresh_token.0.clone()),
        scope: final_scope.clone(),
        controller_did: controller_did.clone(),
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
    response_headers.insert("DPoP-Nonce", verifier.generate_nonce().parse().unwrap());
    Ok((
        response_headers,
        Json(TokenResponse {
            access_token,
            token_type: if dpop_jkt.is_some() { "DPoP" } else { "Bearer" }.to_string(),
            expires_in: ACCESS_TOKEN_EXPIRY_SECONDS as u64,
            refresh_token: Some(refresh_token.0),
            scope: final_scope,
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
    tracing::info!(
        refresh_token_prefix = %&refresh_token_str[..std::cmp::min(16, refresh_token_str.len())],
        has_dpop = dpop_proof.is_some(),
        "Refresh token grant requested"
    );
    if let Some(token_id) = db::check_refresh_token_used(&state.db, &refresh_token_str).await? {
        if let Some((_db_id, token_data)) =
            db::get_token_by_previous_refresh_token(&state.db, &refresh_token_str).await?
        {
            tracing::info!(
                refresh_token_prefix = %&refresh_token_str[..std::cmp::min(16, refresh_token_str.len())],
                "Refresh token reuse within grace period, returning existing tokens"
            );
            let dpop_jkt = token_data.parameters.dpop_jkt.as_deref();
            let access_token = create_access_token_with_delegation(
                &token_data.token_id,
                &token_data.did,
                dpop_jkt,
                token_data.scope.as_deref(),
                token_data.controller_did.as_deref(),
            )?;
            let mut response_headers = HeaderMap::new();
            let config = AuthConfig::get();
            let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
            response_headers.insert("DPoP-Nonce", verifier.generate_nonce().parse().unwrap());
            return Ok((
                response_headers,
                Json(TokenResponse {
                    access_token,
                    token_type: if dpop_jkt.is_some() { "DPoP" } else { "Bearer" }.to_string(),
                    expires_in: ACCESS_TOKEN_EXPIRY_SECONDS as u64,
                    refresh_token: token_data.current_refresh_token,
                    scope: token_data.scope,
                    sub: Some(token_data.did),
                }),
            ));
        }
        tracing::warn!(
            refresh_token_prefix = %&refresh_token_str[..std::cmp::min(16, refresh_token_str.len())],
            "Refresh token reuse detected, revoking token family"
        );
        db::delete_token_family(&state.db, token_id).await?;
        return Err(OAuthError::InvalidGrant(
            "Refresh token reuse detected, token family revoked".to_string(),
        ));
    }
    let (db_id, token_data) = db::get_token_by_refresh_token(&state.db, &refresh_token_str)
        .await?
        .ok_or_else(|| {
            tracing::warn!(
                refresh_token_prefix = %&refresh_token_str[..std::cmp::min(16, refresh_token_str.len())],
                "Refresh token not found in database"
            );
            OAuthError::InvalidGrant("Invalid refresh token".to_string())
        })?;
    if token_data.expires_at < Utc::now() {
        tracing::warn!(
            did = %token_data.did,
            expired_at = %token_data.expires_at,
            "Refresh token has expired"
        );
        db::delete_token_family(&state.db, db_id).await?;
        return Err(OAuthError::InvalidGrant(
            "Refresh token has expired".to_string(),
        ));
    }
    let dpop_jkt = if let Some(proof) = &dpop_proof {
        let config = AuthConfig::get();
        let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
        let pds_hostname =
            std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        let token_endpoint = format!("https://{}/oauth/token", pds_hostname);
        let result = verifier.verify_proof(proof, "POST", &token_endpoint, None)?;
        if !db::check_and_record_dpop_jti(&state.db, &result.jti).await? {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP proof has already been used".to_string(),
            ));
        }
        if let Some(expected_jkt) = &token_data.parameters.dpop_jkt
            && &result.jkt != expected_jkt
        {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP key binding mismatch".to_string(),
            ));
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
    let refresh_expiry_days = if matches!(token_data.client_auth, ClientAuth::None) {
        REFRESH_TOKEN_EXPIRY_DAYS_PUBLIC
    } else {
        REFRESH_TOKEN_EXPIRY_DAYS_CONFIDENTIAL
    };
    let new_expires_at = Utc::now() + Duration::days(refresh_expiry_days);
    db::rotate_token(
        &state.db,
        db_id,
        &new_token_id.0,
        &new_refresh_token.0,
        new_expires_at,
    )
    .await?;
    tracing::info!(
        did = %token_data.did,
        new_expires_at = %new_expires_at,
        "Refresh token rotated successfully"
    );
    let access_token = create_access_token_with_delegation(
        &new_token_id.0,
        &token_data.did,
        dpop_jkt.as_deref(),
        token_data.scope.as_deref(),
        token_data.controller_did.as_deref(),
    )?;
    let mut response_headers = HeaderMap::new();
    let config = AuthConfig::get();
    let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
    response_headers.insert("DPoP-Nonce", verifier.generate_nonce().parse().unwrap());
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
