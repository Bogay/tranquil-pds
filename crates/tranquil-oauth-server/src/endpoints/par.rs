use axum::body::Bytes;
use axum::{Json, extract::State, http::HeaderMap};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tranquil_pds::oauth::{
    AuthorizationRequestParameters, ClientAuth, ClientMetadataCache, CodeChallengeMethod,
    OAuthError, Prompt, RequestData, RequestId, ResponseMode, ResponseType,
    scopes::{ParsedScope, parse_scope},
};
use tranquil_pds::rate_limit::{OAuthParLimit, OAuthRateLimited};
use tranquil_pds::state::AppState;
use tranquil_types::RequestId as RequestIdType;

const PAR_EXPIRY_SECONDS: i64 = 600;

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
    pub response_mode: Option<String>,
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
    #[serde(default)]
    pub prompt: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ParResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

pub async fn pushed_authorization_request(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthParLimit>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(axum::http::StatusCode, Json<ParResponse>), OAuthError> {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let request: ParRequest = if content_type.starts_with("application/json") {
        serde_json::from_slice(&body)
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid JSON: {}", e)))?
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        let parsed: ParRequest = serde_urlencoded::from_bytes(&body)
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid form data: {}", e)))?;
        tracing::info!(login_hint = ?parsed.login_hint, "PAR request received (form)");
        parsed
    } else {
        return Err(OAuthError::InvalidRequest(
            "Content-Type must be application/json or application/x-www-form-urlencoded"
                .to_string(),
        ));
    };
    let response_type = parse_response_type(&request.response_type)?;
    let code_challenge = request
        .code_challenge
        .as_ref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OAuthError::InvalidRequest("code_challenge is required".to_string()))?;
    let code_challenge_method =
        parse_code_challenge_method(request.code_challenge_method.as_deref())?;
    let client_cache = ClientMetadataCache::new(3600);
    let client_metadata = client_cache.get(&request.client_id).await?;
    client_cache.validate_redirect_uri(&client_metadata, &request.redirect_uri)?;
    let client_auth = determine_client_auth(&request)?;
    let validated_scope = validate_scope(&request.scope, &client_metadata)?;
    let request_id = RequestId::generate();
    let expires_at = Utc::now() + Duration::seconds(PAR_EXPIRY_SECONDS);
    let response_mode = parse_response_mode(request.response_mode.as_deref())?;
    let prompt = parse_prompt(request.prompt.as_deref())?;
    let parameters = AuthorizationRequestParameters {
        response_type,
        client_id: request.client_id.clone(),
        redirect_uri: request.redirect_uri,
        scope: validated_scope,
        state: request.state,
        code_challenge: code_challenge.clone(),
        code_challenge_method,
        response_mode,
        login_hint: request.login_hint,
        dpop_jkt: request.dpop_jkt,
        prompt,
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
        controller_did: None,
    };
    let request_id_typed = RequestIdType::from(request_id.0.clone());
    state
        .repos.oauth
        .create_authorization_request(&request_id_typed, &request_data)
        .await
        .map_err(tranquil_pds::oauth::db_err_to_oauth)?;
    tokio::spawn({
        let oauth_repo = state.repos.oauth.clone();
        async move {
            if let Err(e) = oauth_repo.delete_expired_authorization_requests().await {
                tracing::warn!("Failed to cleanup expired authorization requests: {:?}", e);
            }
        }
    });
    Ok((
        axum::http::StatusCode::CREATED,
        Json(ParResponse {
            request_uri: request_id.0,
            expires_in: u64::try_from(PAR_EXPIRY_SECONDS).unwrap_or(600),
        }),
    ))
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
    client_metadata: &tranquil_pds::oauth::ClientMetadata,
) -> Result<Option<String>, OAuthError> {
    let scope_str = match requested_scope {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(Some("atproto".to_string())),
    };
    let requested_scopes: Vec<&str> = scope_str.split_whitespace().collect();
    if requested_scopes.is_empty() {
        return Ok(Some("atproto".to_string()));
    }
    if let Some(unknown) = requested_scopes
        .iter()
        .find(|s| matches!(parse_scope(s), ParsedScope::Unknown(_)))
    {
        return Err(OAuthError::InvalidScope(format!(
            "Unsupported scope: {}",
            unknown
        )));
    }

    let has_transition = requested_scopes.iter().any(|s| {
        matches!(
            parse_scope(s),
            ParsedScope::TransitionGeneric
                | ParsedScope::TransitionChat
                | ParsedScope::TransitionEmail
        )
    });
    let has_granular = requested_scopes.iter().any(|s| {
        matches!(
            parse_scope(s),
            ParsedScope::Repo(_)
                | ParsedScope::Blob(_)
                | ParsedScope::Rpc(_)
                | ParsedScope::Account(_)
                | ParsedScope::Identity(_)
                | ParsedScope::Include(_)
        )
    });

    if has_transition && has_granular {
        return Err(OAuthError::InvalidScope(
            "Cannot mix transition scopes with granular scopes. Use either transition:* scopes OR granular scopes (repo:*, blob:*, rpc:*, account:*, include:*), not both.".to_string()
        ));
    }

    if let Some(client_scope) = &client_metadata.scope {
        let client_scopes: Vec<&str> = client_scope.split_whitespace().collect();
        if let Some(unregistered) = requested_scopes
            .iter()
            .find(|scope| !client_scopes.iter().any(|cs| scope_matches(cs, scope)))
        {
            return Err(OAuthError::InvalidScope(format!(
                "Scope '{}' not registered for this client",
                unregistered
            )));
        }
    }
    Ok(Some(requested_scopes.join(" ")))
}

fn scope_matches(client_scope: &str, requested_scope: &str) -> bool {
    if client_scope == requested_scope {
        return true;
    }

    fn get_resource_type(scope: &str) -> &str {
        let base = scope.split('?').next().unwrap_or(scope);
        base.split(':').next().unwrap_or(base)
    }

    let client_type = get_resource_type(client_scope);
    let requested_type = get_resource_type(requested_scope);

    if client_type == requested_type {
        let client_base = client_scope.split('?').next().unwrap_or(client_scope);
        if client_base.contains('*') {
            return true;
        }
    }

    false
}

fn parse_response_type(value: &str) -> Result<ResponseType, OAuthError> {
    match value {
        "code" => Ok(ResponseType::Code),
        other => Err(OAuthError::InvalidRequest(format!(
            "response_type must be 'code', got '{}'",
            other
        ))),
    }
}

fn parse_code_challenge_method(value: Option<&str>) -> Result<CodeChallengeMethod, OAuthError> {
    match value {
        Some("S256") | None => Ok(CodeChallengeMethod::S256),
        Some("plain") => Err(OAuthError::InvalidRequest(
            "code_challenge_method 'plain' is not allowed, use 'S256'".to_string(),
        )),
        Some(other) => Err(OAuthError::InvalidRequest(format!(
            "Unsupported code_challenge_method: {}",
            other
        ))),
    }
}

fn parse_response_mode(value: Option<&str>) -> Result<Option<ResponseMode>, OAuthError> {
    match value {
        None | Some("query") => Ok(None),
        Some("fragment") => Ok(Some(ResponseMode::Fragment)),
        Some("form_post") => Ok(Some(ResponseMode::FormPost)),
        Some(other) => Err(OAuthError::InvalidRequest(format!(
            "Unsupported response_mode: {}",
            other
        ))),
    }
}

fn parse_prompt(value: Option<&str>) -> Result<Option<Prompt>, OAuthError> {
    match value {
        None | Some("") => Ok(None),
        Some("none") => Ok(Some(Prompt::None)),
        Some("login") => Ok(Some(Prompt::Login)),
        Some("consent") => Ok(Some(Prompt::Consent)),
        Some("select_account") => Ok(Some(Prompt::SelectAccount)),
        Some("create") => Ok(Some(Prompt::Create)),
        Some(other) => Err(OAuthError::InvalidRequest(format!(
            "Unsupported prompt value: {}",
            other
        ))),
    }
}
