use super::helpers::{create_access_token_with_delegation, verify_pkce};
use super::types::{
    RequestClientAuth, TokenGrant, TokenResponse, TokenType, ValidatedTokenRequest,
};
use axum::Json;
use axum::http::{HeaderMap, Method};
use chrono::{Duration, Utc};
use tranquil_db_traits::RefreshTokenLookup;
use tranquil_pds::config::AuthConfig;
use tranquil_pds::oauth::{
    AuthFlow, ClientAuth, ClientMetadataCache, DPoPVerifier, OAuthError, RefreshToken, TokenData,
    TokenId,
    db::{enforce_token_limit_for_user, lookup_refresh_token},
    verify_client_auth,
};
use tranquil_pds::state::AppState;

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
    let (auth_code, code_verifier, redirect_uri) = match request.grant {
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
    let auth_request = state
        .repos
        .oauth
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
    let did = authorized.did.clone();
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
            .repos
            .oauth
            .check_and_record_dpop_jti(&result.jti)
            .await
            .map_err(tranquil_pds::oauth::db_err_to_oauth)?
        {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP proof has already been used".to_string(),
            ));
        }
        if let Some(expected_jkt) = &authorized.parameters.dpop_jkt
            && result.jkt != *expected_jkt
        {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP key binding mismatch".to_string(),
            ));
        }
        Some(result.jkt.clone())
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

    let controller_did = authorized.controller_did.clone();
    let requested_scope = authorized.parameters.scope.clone();

    let granted_scopes: Option<tranquil_db_traits::DbScope> =
        if let Some(ref controller) = controller_did {
            let grant = state
                .repos
                .delegation
                .get_delegation(&did, controller)
                .await
                .ok()
                .flatten()
                .ok_or_else(|| {
                    OAuthError::InvalidGrant("Delegation grant not found or revoked".to_string())
                })?;
            Some(grant.granted_scopes.clone())
        } else {
            None
        };
    let authority = match granted_scopes.as_ref() {
        Some(g) => crate::endpoints::authorize::scope_resolution::Authority::Delegated(g),
        None => crate::endpoints::authorize::scope_resolution::Authority::FullSelf,
    };
    let requested_for_resolve = requested_scope.as_deref().unwrap_or("atproto");
    let effective = crate::endpoints::authorize::scope_resolution::resolve_effective_scopes(
        &*state.cache,
        requested_for_resolve,
        authority,
    )
    .await;
    if !effective.outcome.failures.is_empty() {
        let names: Vec<String> = effective
            .outcome
            .failures
            .iter()
            .map(|f| f.given_nsid.clone())
            .collect();
        return Err(OAuthError::InvalidScope(format!(
            "Could not resolve permission set(s): {}",
            names.join(", ")
        )));
    }
    let resolved_scope = effective.permitted;

    let access_token = create_access_token_with_delegation(
        &token_id,
        &did,
        dpop_jkt.as_ref(),
        Some(resolved_scope.as_str()),
        controller_did.as_ref(),
    )?;
    let stored_client_auth = authorized.client_auth.unwrap_or(ClientAuth::None);
    let refresh_expiry_days = if matches!(stored_client_auth, ClientAuth::None) {
        REFRESH_TOKEN_EXPIRY_DAYS_PUBLIC
    } else {
        REFRESH_TOKEN_EXPIRY_DAYS_CONFIDENTIAL
    };
    let mut stored_parameters = authorized.parameters.clone();
    stored_parameters.dpop_jkt = dpop_jkt.clone();
    let token_data = TokenData {
        did: did.clone(),
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
        scope: requested_scope.clone(),
        controller_did: controller_did.clone(),
    };
    state
        .repos
        .oauth
        .create_token(&token_data)
        .await
        .map_err(tranquil_pds::oauth::db_err_to_oauth)?;
    tracing::info!(
        did = %did,
        token_id = %token_id,
        client_id = %authorized.client_id,
        "Authorization code grant completed, token created"
    );
    tokio::spawn({
        let oauth_repo = state.repos.oauth.clone();
        let did_clone = did.clone();
        async move {
            if let Err(e) = enforce_token_limit_for_user(oauth_repo.as_ref(), &did_clone).await {
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
            refresh_token: Some(refresh_token),
            scope: Some(resolved_scope.clone()),
            sub: Some(did),
        }),
    ))
}

async fn recompute_resolved_scope(
    state: &AppState,
    token_data: &TokenData,
) -> Result<String, OAuthError> {
    let requested = token_data.scope.as_deref().unwrap_or("atproto");
    let granted_scopes: Option<tranquil_db_traits::DbScope> =
        if let Some(ref controller) = token_data.controller_did {
            let grant = state
                .repos
                .delegation
                .get_delegation(&token_data.did, controller)
                .await
                .ok()
                .flatten()
                .ok_or_else(|| {
                    OAuthError::InvalidGrant("Delegation grant not found or revoked".to_string())
                })?;
            Some(grant.granted_scopes.clone())
        } else {
            None
        };
    let authority = match granted_scopes.as_ref() {
        Some(g) => crate::endpoints::authorize::scope_resolution::Authority::Delegated(g),
        None => crate::endpoints::authorize::scope_resolution::Authority::FullSelf,
    };
    let effective = crate::endpoints::authorize::scope_resolution::resolve_effective_scopes(
        &*state.cache,
        requested,
        authority,
    )
    .await;
    if !effective.outcome.failures.is_empty() {
        let names: Vec<String> = effective
            .outcome
            .failures
            .iter()
            .map(|f| f.given_nsid.clone())
            .collect();
        return Err(OAuthError::InvalidScope(format!(
            "Permission set(s) expired and unresolvable: {}",
            names.join(", ")
        )));
    }
    Ok(effective.permitted)
}

pub async fn handle_refresh_token_grant(
    state: AppState,
    _headers: HeaderMap,
    request: ValidatedTokenRequest,
    dpop_proof: Option<String>,
) -> Result<(HeaderMap, Json<TokenResponse>), OAuthError> {
    let refresh_token = match request.grant {
        TokenGrant::RefreshToken { refresh_token } => refresh_token,
        _ => {
            return Err(OAuthError::InvalidRequest(
                "Expected refresh_token grant".to_string(),
            ));
        }
    };
    let refresh_token_str = refresh_token.as_str();
    let token_prefix = &refresh_token_str[..std::cmp::min(16, refresh_token_str.len())];
    tracing::info!(
        refresh_token_prefix = %token_prefix,
        has_dpop = dpop_proof.is_some(),
        "Refresh token grant requested"
    );

    let lookup = lookup_refresh_token(state.repos.oauth.as_ref(), &refresh_token).await?;
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
            let dpop_jkt = token_data.parameters.dpop_jkt.as_ref();
            let resolved = recompute_resolved_scope(&state, &token_data).await?;
            let access_token = create_access_token_with_delegation(
                &token_data.token_id,
                &token_data.did,
                dpop_jkt,
                Some(resolved.as_str()),
                token_data.controller_did.as_ref(),
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
                    refresh_token: token_data.current_refresh_token,
                    scope: Some(resolved),
                    sub: Some(token_data.did),
                }),
            ));
        }
        RefreshTokenLookup::Used { original_token_id } => {
            tracing::warn!(
                refresh_token_prefix = %token_prefix,
                "Refresh token reuse detected, revoking token family"
            );
            state
                .repos
                .oauth
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
                .repos
                .oauth
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
            .repos
            .oauth
            .check_and_record_dpop_jti(&result.jti)
            .await
            .map_err(tranquil_pds::oauth::db_err_to_oauth)?
        {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP proof has already been used".to_string(),
            ));
        }
        if let Some(expected_jkt) = &token_data.parameters.dpop_jkt
            && result.jkt != *expected_jkt
        {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP key binding mismatch".to_string(),
            ));
        }
        Some(result.jkt.clone())
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
    state
        .repos
        .oauth
        .rotate_token(db_id, &new_refresh_token, new_expires_at)
        .await
        .map_err(tranquil_pds::oauth::db_err_to_oauth)?;
    tracing::info!(
        did = %token_data.did,
        new_expires_at = %new_expires_at,
        "Refresh token rotated successfully"
    );
    let resolved = recompute_resolved_scope(&state, &token_data).await?;
    let access_token = create_access_token_with_delegation(
        &token_data.token_id,
        &token_data.did,
        dpop_jkt.as_ref(),
        Some(resolved.as_str()),
        token_data.controller_did.as_ref(),
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
            refresh_token: Some(new_refresh_token),
            scope: Some(resolved),
            sub: Some(token_data.did),
        }),
    ))
}
