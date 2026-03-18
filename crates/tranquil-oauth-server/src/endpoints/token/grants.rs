use super::helpers::{create_access_token_with_delegation, verify_pkce};
use super::types::{
    RequestClientAuth, TokenGrant, TokenResponse, TokenType, ValidatedTokenRequest,
};
use axum::Json;
use axum::http::{HeaderMap, Method};
use chrono::{Duration, Utc};
use tranquil_db_traits::RefreshTokenLookup;
use tranquil_pds::config::AuthConfig;
use tranquil_pds::delegation::intersect_scopes;
use tranquil_pds::oauth::{
    AuthFlow, ClientAuth, ClientMetadataCache, DPoPVerifier, OAuthError, RefreshToken, TokenData,
    TokenId,
    db::{enforce_token_limit_for_user, lookup_refresh_token},
    scopes::expand_include_scopes,
    verify_client_auth,
};
use tranquil_pds::state::AppState;
use tranquil_types::{AuthorizationCode, Did, RefreshToken as RefreshTokenType};

const ACCESS_TOKEN_EXPIRY_SECONDS: u64 = 300;
const REFRESH_TOKEN_EXPIRY_DAYS_CONFIDENTIAL: i64 = 60;
const REFRESH_TOKEN_EXPIRY_DAYS_PUBLIC: i64 = 14;

pub async fn handle_authorization_code_grant(
    state: AppState,
    _headers: HeaderMap,
    request: ValidatedTokenRequest,
    dpop_proof: Option<String>,
) -> Result<(HeaderMap, Json<TokenResponse>), OAuthError> {
    tracing::info!(
        has_dpop = dpop_proof.is_some(),
        client_id = ?request.client_auth.client_id(),
        "Authorization code grant requested"
    );
    let (code, code_verifier, redirect_uri) = match request.grant {
        TokenGrant::AuthorizationCode {
            code,
            code_verifier,
            redirect_uri,
        } => (code, code_verifier, redirect_uri),
        _ => {
            return Err(OAuthError::InvalidRequest(
                "Expected authorization_code grant".to_string(),
            ));
        }
    };
    let auth_code = AuthorizationCode::from(code);
    let auth_request = state
        .oauth_repo
        .consume_authorization_request_by_code(&auth_code)
        .await
        .map_err(tranquil_pds::oauth::db_err_to_oauth)?
        .ok_or_else(|| OAuthError::InvalidGrant("Invalid or expired code".to_string()))?;

    let flow = AuthFlow::from_request_data(auth_request)
        .map_err(|_| OAuthError::InvalidGrant("Authorization code has expired".to_string()))?;

    let authorized = flow
        .require_authorized()
        .map_err(|_| OAuthError::InvalidGrant("Authorization not completed".to_string()))?;

    if let Some(request_client_id) = request.client_auth.client_id()
        && request_client_id != authorized.client_id
    {
        return Err(OAuthError::InvalidGrant("client_id mismatch".to_string()));
    }
    let did = authorized.did.to_string();
    let client_metadata_cache = ClientMetadataCache::new(3600);
    let client_metadata = client_metadata_cache.get(&authorized.client_id).await?;
    let client_auth = match &request.client_auth {
        RequestClientAuth::PrivateKeyJwt {
            assertion,
            assertion_type,
            ..
        } => {
            if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
                return Err(OAuthError::InvalidClient(
                    "Unsupported client_assertion_type".to_string(),
                ));
            }
            ClientAuth::PrivateKeyJwt {
                client_assertion: assertion.clone(),
            }
        }
        RequestClientAuth::SecretPost { client_secret, .. } => ClientAuth::SecretPost {
            client_secret: client_secret.clone(),
        },
        RequestClientAuth::None { .. } => ClientAuth::None,
    };
    verify_client_auth(&client_metadata_cache, &client_metadata, &client_auth).await?;
    verify_pkce(&authorized.parameters.code_challenge, &code_verifier)?;
    if let Some(req_redirect_uri) = &redirect_uri
        && req_redirect_uri != &authorized.parameters.redirect_uri
    {
        return Err(OAuthError::InvalidGrant(
            "redirect_uri mismatch".to_string(),
        ));
    }
    let dpop_jkt = if let Some(proof) = &dpop_proof {
        let config = AuthConfig::get();
        let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
        let pds_hostname = &tranquil_config::get().server.hostname;
        let token_endpoint = format!("https://{}/oauth/token", pds_hostname);
        let result = verifier.verify_proof(proof, Method::POST.as_str(), &token_endpoint, None)?;
        if !state
            .oauth_repo
            .check_and_record_dpop_jti(&result.jti)
            .await
            .map_err(tranquil_pds::oauth::db_err_to_oauth)?
        {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP proof has already been used".to_string(),
            ));
        }
        if let Some(expected_jkt) = &authorized.parameters.dpop_jkt
            && result.jkt.as_str() != expected_jkt
        {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP key binding mismatch".to_string(),
            ));
        }
        Some(result.jkt.as_str().to_string())
    } else if authorized.parameters.dpop_jkt.is_some() || client_metadata.requires_dpop() {
        return Err(OAuthError::UseDpopNonce(
            DPoPVerifier::new(AuthConfig::get().dpop_secret().as_bytes()).generate_nonce(),
        ));
    } else {
        None
    };
    let token_id = TokenId::generate();
    let refresh_token = RefreshToken::generate();
    let now = Utc::now();

    let (raw_scope, controller_did) = if let Some(ref controller) = authorized.controller_did {
        let did_parsed: Did = did
            .parse()
            .map_err(|_| OAuthError::InvalidRequest("Invalid DID format".to_string()))?;
        let controller_parsed: Did = controller
            .parse()
            .map_err(|_| OAuthError::InvalidRequest("Invalid controller DID format".to_string()))?;
        let grant = state
            .delegation_repo
            .get_delegation(&did_parsed, &controller_parsed)
            .await
            .ok()
            .flatten();
        let granted_scopes = grant.map(|g| g.granted_scopes).unwrap_or_default();
        let requested = authorized.parameters.scope.as_deref().unwrap_or("atproto");
        let intersected = intersect_scopes(requested, granted_scopes.as_str());
        (Some(intersected), Some(controller.clone()))
    } else {
        (authorized.parameters.scope.clone(), None)
    };

    let final_scope = if let Some(ref scope) = raw_scope {
        if scope.contains("include:") {
            Some(expand_include_scopes(scope).await)
        } else {
            raw_scope
        }
    } else {
        raw_scope
    };

    let access_token = create_access_token_with_delegation(
        &token_id.0,
        &did,
        dpop_jkt.as_deref(),
        final_scope.as_deref(),
        controller_did.as_deref(),
    )?;
    let stored_client_auth = authorized.client_auth.unwrap_or(ClientAuth::None);
    let refresh_expiry_days = if matches!(stored_client_auth, ClientAuth::None) {
        REFRESH_TOKEN_EXPIRY_DAYS_PUBLIC
    } else {
        REFRESH_TOKEN_EXPIRY_DAYS_CONFIDENTIAL
    };
    let mut stored_parameters = authorized.parameters.clone();
    stored_parameters.dpop_jkt = dpop_jkt.clone();
    let did_typed: Did = did
        .parse()
        .map_err(|_| OAuthError::InvalidRequest("Invalid DID format".to_string()))?;
    let token_data = TokenData {
        did: did_typed,
        token_id: token_id.clone(),
        created_at: now,
        updated_at: now,
        expires_at: now + Duration::days(refresh_expiry_days),
        client_id: authorized.client_id.clone(),
        client_auth: stored_client_auth,
        device_id: authorized.device_id.clone(),
        parameters: stored_parameters,
        details: None,
        code: None,
        current_refresh_token: Some(refresh_token.clone()),
        scope: final_scope.clone(),
        controller_did: controller_did.clone(),
    };
    state
        .oauth_repo
        .create_token(&token_data)
        .await
        .map_err(tranquil_pds::oauth::db_err_to_oauth)?;
    tracing::info!(
        did = %did,
        token_id = %token_id.0,
        client_id = %authorized.client_id,
        "Authorization code grant completed, token created"
    );
    tokio::spawn({
        let oauth_repo = state.oauth_repo.clone();
        let did_clone = did.clone();
        async move {
            if let Ok(did_typed) = did_clone.parse::<tranquil_types::Did>()
                && let Err(e) = enforce_token_limit_for_user(oauth_repo.as_ref(), &did_typed).await
            {
                tracing::warn!("Failed to enforce token limit for user: {:?}", e);
            }
        }
    });
    let mut response_headers = HeaderMap::new();
    let config = AuthConfig::get();
    let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
    let nonce = verifier.generate_nonce();
    let nonce_header = nonce.parse().map_err(|_| {
        OAuthError::ServerError("Failed to encode DPoP nonce as header value".to_string())
    })?;
    response_headers.insert("DPoP-Nonce", nonce_header);
    Ok((
        response_headers,
        Json(TokenResponse {
            access_token,
            token_type: match dpop_jkt {
                Some(_) => TokenType::DPoP,
                None => TokenType::Bearer,
            },
            expires_in: ACCESS_TOKEN_EXPIRY_SECONDS,
            refresh_token: Some(refresh_token.0),
            scope: final_scope,
            sub: Some(did),
        }),
    ))
}

pub async fn handle_refresh_token_grant(
    state: AppState,
    _headers: HeaderMap,
    request: ValidatedTokenRequest,
    dpop_proof: Option<String>,
) -> Result<(HeaderMap, Json<TokenResponse>), OAuthError> {
    let refresh_token_str = match request.grant {
        TokenGrant::RefreshToken { refresh_token } => refresh_token,
        _ => {
            return Err(OAuthError::InvalidRequest(
                "Expected refresh_token grant".to_string(),
            ));
        }
    };
    let token_prefix = &refresh_token_str[..std::cmp::min(16, refresh_token_str.len())];
    tracing::info!(
        refresh_token_prefix = %token_prefix,
        has_dpop = dpop_proof.is_some(),
        "Refresh token grant requested"
    );

    let refresh_token_typed = RefreshTokenType::from(refresh_token_str.clone());
    let lookup = lookup_refresh_token(state.oauth_repo.as_ref(), &refresh_token_typed).await?;
    let token_state = lookup.state();
    tracing::debug!(state = %token_state, "Refresh token state");

    let (db_id, token_data) = match lookup {
        RefreshTokenLookup::Valid { db_id, token_data } => (db_id, token_data),
        RefreshTokenLookup::InGracePeriod {
            db_id: _,
            token_data,
            rotated_at,
        } => {
            tracing::info!(
                refresh_token_prefix = %token_prefix,
                rotated_at = %rotated_at,
                "Refresh token reuse within grace period, returning existing tokens"
            );
            let dpop_jkt = token_data.parameters.dpop_jkt.as_deref();
            let access_token = create_access_token_with_delegation(
                &token_data.token_id.0,
                token_data.did.as_str(),
                dpop_jkt,
                token_data.scope.as_deref(),
                token_data.controller_did.as_ref().map(|d| d.as_str()),
            )?;
            let mut response_headers = HeaderMap::new();
            let config = AuthConfig::get();
            let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
            let nonce = verifier.generate_nonce();
            let nonce_header = nonce.parse().map_err(|_| {
                OAuthError::ServerError("Failed to encode DPoP nonce as header value".to_string())
            })?;
            response_headers.insert("DPoP-Nonce", nonce_header);
            return Ok((
                response_headers,
                Json(TokenResponse {
                    access_token,
                    token_type: match dpop_jkt {
                        Some(_) => TokenType::DPoP,
                        None => TokenType::Bearer,
                    },
                    expires_in: ACCESS_TOKEN_EXPIRY_SECONDS,
                    refresh_token: token_data.current_refresh_token.map(|r| r.0),
                    scope: token_data.scope,
                    sub: Some(token_data.did.to_string()),
                }),
            ));
        }
        RefreshTokenLookup::Used { original_token_id } => {
            tracing::warn!(
                refresh_token_prefix = %token_prefix,
                "Refresh token reuse detected, revoking token family"
            );
            state
                .oauth_repo
                .delete_token_family(original_token_id)
                .await
                .map_err(tranquil_pds::oauth::db_err_to_oauth)?;
            return Err(OAuthError::InvalidGrant(
                "Refresh token reuse detected, token family revoked".to_string(),
            ));
        }
        RefreshTokenLookup::Expired { db_id } => {
            tracing::warn!(refresh_token_prefix = %token_prefix, "Refresh token has expired");
            state
                .oauth_repo
                .delete_token_family(db_id)
                .await
                .map_err(tranquil_pds::oauth::db_err_to_oauth)?;
            return Err(OAuthError::InvalidGrant(
                "Refresh token has expired".to_string(),
            ));
        }
        RefreshTokenLookup::NotFound => {
            tracing::warn!(refresh_token_prefix = %token_prefix, "Refresh token not found");
            return Err(OAuthError::InvalidGrant(
                "Invalid refresh token".to_string(),
            ));
        }
    };
    let dpop_jkt = if let Some(proof) = &dpop_proof {
        let config = AuthConfig::get();
        let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
        let pds_hostname = &tranquil_config::get().server.hostname;
        let token_endpoint = format!("https://{}/oauth/token", pds_hostname);
        let result = verifier.verify_proof(proof, Method::POST.as_str(), &token_endpoint, None)?;
        if !state
            .oauth_repo
            .check_and_record_dpop_jti(&result.jti)
            .await
            .map_err(tranquil_pds::oauth::db_err_to_oauth)?
        {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP proof has already been used".to_string(),
            ));
        }
        if let Some(expected_jkt) = &token_data.parameters.dpop_jkt
            && result.jkt.as_str() != expected_jkt
        {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP key binding mismatch".to_string(),
            ));
        }
        Some(result.jkt.as_str().to_string())
    } else if token_data.parameters.dpop_jkt.is_some() {
        return Err(OAuthError::InvalidRequest(
            "DPoP proof required".to_string(),
        ));
    } else {
        None
    };
    let new_refresh_token = RefreshToken::generate();
    let refresh_expiry_days = if matches!(token_data.client_auth, ClientAuth::None) {
        REFRESH_TOKEN_EXPIRY_DAYS_PUBLIC
    } else {
        REFRESH_TOKEN_EXPIRY_DAYS_CONFIDENTIAL
    };
    let new_expires_at = Utc::now() + Duration::days(refresh_expiry_days);
    let new_refresh_typed = RefreshTokenType::from(new_refresh_token.0.clone());
    state
        .oauth_repo
        .rotate_token(db_id, &new_refresh_typed, new_expires_at)
        .await
        .map_err(tranquil_pds::oauth::db_err_to_oauth)?;
    tracing::info!(
        did = %token_data.did,
        new_expires_at = %new_expires_at,
        "Refresh token rotated successfully"
    );
    let access_token = create_access_token_with_delegation(
        &token_data.token_id.0,
        token_data.did.as_str(),
        dpop_jkt.as_deref(),
        token_data.scope.as_deref(),
        token_data.controller_did.as_ref().map(|d| d.as_str()),
    )?;
    let mut response_headers = HeaderMap::new();
    let config = AuthConfig::get();
    let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
    let nonce = verifier.generate_nonce();
    let nonce_header = nonce.parse().map_err(|_| {
        OAuthError::ServerError("Failed to encode DPoP nonce as header value".to_string())
    })?;
    response_headers.insert("DPoP-Nonce", nonce_header);
    Ok((
        response_headers,
        Json(TokenResponse {
            access_token,
            token_type: match dpop_jkt {
                Some(_) => TokenType::DPoP,
                None => TokenType::Bearer,
            },
            expires_in: ACCESS_TOKEN_EXPIRY_SECONDS,
            refresh_token: Some(new_refresh_token.0),
            scope: token_data.scope,
            sub: Some(token_data.did.to_string()),
        }),
    ))
}
