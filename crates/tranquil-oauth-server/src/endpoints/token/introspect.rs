use super::helpers::extract_token_claims;
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Form, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tranquil_pds::oauth::OAuthError;
use tranquil_pds::rate_limit::{OAuthIntrospectLimit, OAuthRateLimited};
use tranquil_pds::state::AppState;
use tranquil_types::{RefreshToken, TokenId};

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: Option<String>,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

pub async fn revoke_token(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthIntrospectLimit>,
    Form(request): Form<RevokeRequest>,
) -> Result<StatusCode, OAuthError> {
    if let Some(token) = &request.token {
        let refresh_token = RefreshToken::from(token.clone());
        if let Some((db_id, _)) = state
            .repos.oauth
            .get_token_by_refresh_token(&refresh_token)
            .await
            .map_err(tranquil_pds::oauth::db_err_to_oauth)?
        {
            state
                .repos.oauth
                .delete_token_family(db_id)
                .await
                .map_err(tranquil_pds::oauth::db_err_to_oauth)?;
        } else {
            let token_id = TokenId::from(token.clone());
            state
                .repos.oauth
                .delete_token(&token_id)
                .await
                .map_err(tranquil_pds::oauth::db_err_to_oauth)?;
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
    _rate_limit: OAuthRateLimited<OAuthIntrospectLimit>,
    Form(request): Form<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, OAuthError> {
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
    let token_id = TokenId::from(token_info.sid.clone());
    let token_data = match state.repos.oauth.get_token_by_id(&token_id).await {
        Ok(Some(data)) => data,
        _ => return Ok(Json(inactive_response)),
    };
    if token_data.expires_at < Utc::now() {
        return Ok(Json(inactive_response));
    }
    let pds_hostname = &tranquil_config::get().server.hostname;
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
        sub: Some(token_data.did.to_string()),
        aud: Some(issuer.clone()),
        iss: Some(issuer),
        jti: Some(token_info.jti),
    }))
}
