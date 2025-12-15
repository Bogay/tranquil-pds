use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::json;
use crate::auth::{extract_bearer_token_from_header, validate_bearer_token};
use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSignupQueueOutput {
    pub activated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place_in_queue: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_time_ms: Option<i64>,
}

pub async fn check_signup_queue(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Some(token) = extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        if let Ok(user) = validate_bearer_token(&state.db, &token).await {
            if user.is_oauth {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "Forbidden",
                        "message": "OAuth credentials are not supported for this endpoint"
                    })),
                ).into_response();
            }
        }
    }
    Json(CheckSignupQueueOutput {
        activated: true,
        place_in_queue: None,
        estimated_time_ms: None,
    }).into_response()
}
