use crate::api::ApiError;
use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;
#[derive(Deserialize)]
pub struct GetServiceAuthParams {
    pub aud: String,
    pub lxm: Option<String>,
    pub exp: Option<i64>,
}
#[derive(Serialize)]
pub struct GetServiceAuthOutput {
    pub token: String,
}
pub async fn get_service_auth(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetServiceAuthParams>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let auth_user = match crate::auth::validate_bearer_token(&state.db, &token).await {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let key_bytes = match auth_user.key_bytes {
        Some(kb) => kb,
        None => return ApiError::AuthenticationFailedMsg("OAuth tokens cannot create service auth".into()).into_response(),
    };
    let lxm = params.lxm.as_deref().unwrap_or("*");
    let service_token = match crate::auth::create_service_token(&auth_user.did, &params.aud, lxm, &key_bytes)
    {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to create service token: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(GetServiceAuthOutput { token: service_token })).into_response()
}
