use axum::{
    Form, Json,
    extract::State,
    http::HeaderMap,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::state::{AppState, RateLimitKind};
use crate::oauth::{
    AuthorizationRequestParameters, ClientAuth, OAuthError, RequestData, RequestId,
    client::ClientMetadataCache,
    db,
};

const PAR_EXPIRY_SECONDS: i64 = 600;

const SUPPORTED_SCOPES: &[&str] = &["atproto", "transition:generic", "transition:chat.bsky"];

#[derive(Debug, Deserialize)]
pub struct ParRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub login_hint: Option<String>,
    #[serde(default)]
    pub dpop_jkt: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_assertion: Option<String>,
    #[serde(default)]
    pub client_assertion_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ParResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

pub async fn pushed_authorization_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<ParRequest>,
) -> Result<Json<ParResponse>, OAuthError> {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state.check_rate_limit(RateLimitKind::OAuthPar, &client_ip).await {
        tracing::warn!(ip = %client_ip, "OAuth PAR rate limit exceeded");
        return Err(OAuthError::RateLimited);
    }

    if request.response_type != "code" {
        return Err(OAuthError::InvalidRequest(
            "response_type must be 'code'".to_string(),
        ));
    }

    let code_challenge = request.code_challenge.as_ref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OAuthError::InvalidRequest(
            "code_challenge is required".to_string(),
        ))?;

    let code_challenge_method = request.code_challenge_method.as_deref().unwrap_or("");
    if code_challenge_method != "S256" {
        return Err(OAuthError::InvalidRequest(
            "code_challenge_method must be 'S256'".to_string(),
        ));
    }

    let client_cache = ClientMetadataCache::new(3600);
    let client_metadata = client_cache.get(&request.client_id).await?;

    client_cache.validate_redirect_uri(&client_metadata, &request.redirect_uri)?;

    let client_auth = determine_client_auth(&request)?;

    if client_metadata.requires_dpop() && request.dpop_jkt.is_none() {
        return Err(OAuthError::InvalidRequest(
            "dpop_jkt is required for this client".to_string(),
        ));
    }

    let validated_scope = validate_scope(&request.scope, &client_metadata)?;

    let request_id = RequestId::generate();
    let expires_at = Utc::now() + Duration::seconds(PAR_EXPIRY_SECONDS);

    let parameters = AuthorizationRequestParameters {
        response_type: request.response_type,
        client_id: request.client_id.clone(),
        redirect_uri: request.redirect_uri,
        scope: validated_scope,
        state: request.state,
        code_challenge: code_challenge.clone(),
        code_challenge_method: code_challenge_method.to_string(),
        login_hint: request.login_hint,
        dpop_jkt: request.dpop_jkt,
        extra: None,
    };

    let request_data = RequestData {
        client_id: request.client_id,
        client_auth: Some(client_auth),
        parameters,
        expires_at,
        did: None,
        device_id: None,
        code: None,
    };

    db::create_authorization_request(&state.db, &request_id.0, &request_data).await?;

    tokio::spawn({
        let pool = state.db.clone();
        async move {
            if let Err(e) = db::delete_expired_authorization_requests(&pool).await {
                tracing::warn!("Failed to cleanup expired authorization requests: {:?}", e);
            }
        }
    });

    Ok(Json(ParResponse {
        request_uri: request_id.0,
        expires_in: PAR_EXPIRY_SECONDS as u64,
    }))
}

fn determine_client_auth(request: &ParRequest) -> Result<ClientAuth, OAuthError> {
    if let (Some(assertion), Some(assertion_type)) =
        (&request.client_assertion, &request.client_assertion_type)
    {
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return Err(OAuthError::InvalidRequest(
                "Unsupported client_assertion_type".to_string(),
            ));
        }
        return Ok(ClientAuth::PrivateKeyJwt {
            client_assertion: assertion.clone(),
        });
    }

    if let Some(secret) = &request.client_secret {
        return Ok(ClientAuth::SecretPost {
            client_secret: secret.clone(),
        });
    }

    Ok(ClientAuth::None)
}

fn validate_scope(
    requested_scope: &Option<String>,
    client_metadata: &crate::oauth::client::ClientMetadata,
) -> Result<Option<String>, OAuthError> {
    let scope_str = match requested_scope {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(Some("atproto".to_string())),
    };

    let requested_scopes: Vec<&str> = scope_str.split_whitespace().collect();

    if requested_scopes.is_empty() {
        return Ok(Some("atproto".to_string()));
    }

    for scope in &requested_scopes {
        if !SUPPORTED_SCOPES.contains(scope) {
            return Err(OAuthError::InvalidScope(format!(
                "Unsupported scope: {}. Supported scopes: {}",
                scope,
                SUPPORTED_SCOPES.join(", ")
            )));
        }
    }

    if let Some(client_scope) = &client_metadata.scope {
        let client_scopes: Vec<&str> = client_scope.split_whitespace().collect();
        for scope in &requested_scopes {
            if !client_scopes.contains(scope) {
                return Err(OAuthError::InvalidScope(format!(
                    "Scope '{}' not registered for this client",
                    scope
                )));
            }
        }
    }

    Ok(Some(requested_scopes.join(" ")))
}
