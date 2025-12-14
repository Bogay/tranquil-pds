use axum::{Form, Json};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::state::{AppState, RateLimitKind};
use crate::oauth::{OAuthError, db};
use super::helpers::extract_token_claims;
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: Option<String>,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}
pub async fn revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<RevokeRequest>,
) -> Result<StatusCode, OAuthError> {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state.check_rate_limit(RateLimitKind::OAuthIntrospect, &client_ip).await {
        tracing::warn!(ip = %client_ip, "OAuth revoke rate limit exceeded");
        return Err(OAuthError::RateLimited);
    }
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
    headers: HeaderMap,
    Form(request): Form<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, OAuthError> {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state.check_rate_limit(RateLimitKind::OAuthIntrospect, &client_ip).await {
        tracing::warn!(ip = %client_ip, "OAuth introspect rate limit exceeded");
        return Err(OAuthError::RateLimited);
    }
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
        Err(_) => return Ok(Json(inactive_response)),
    };
    let token_data = match db::get_token_by_id(&state.db, &token_info.jti).await {
        Ok(Some(data)) => data,
        _ => return Ok(Json(inactive_response)),
    };
    if token_data.expires_at < Utc::now() {
        return Ok(Json(inactive_response));
    }
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let issuer = format!("https://{}", pds_hostname);
    Ok(Json(IntrospectResponse {
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
    }))
}
