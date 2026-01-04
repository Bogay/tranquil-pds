use crate::auth::{extract_bearer_token_from_header, validate_bearer_token};
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

pub async fn get_state(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let created_at = get_account_created_at(&state, &headers).await;
    let now = chrono::Utc::now().to_rfc3339();

    (
        StatusCode::OK,
        Json(json!({
            "state": {
                "status": "assured",
                "access": "full",
                "lastInitiatedAt": now
            },
            "metadata": {
                "accountCreatedAt": created_at
            }
        })),
    )
        .into_response()
}

pub async fn get_age_assurance_state() -> Response {
    (StatusCode::OK, Json(json!({"status": "assured"}))).into_response()
}

async fn get_account_created_at(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
    tracing::debug!(?auth_header, "age assurance: extracting token");

    let token = extract_bearer_token_from_header(auth_header)?;
    tracing::debug!("age assurance: got token, validating");

    let auth_user = match validate_bearer_token(&state.db, &token).await {
        Ok(user) => {
            tracing::debug!(did = %user.did, "age assurance: validated user");
            user
        }
        Err(e) => {
            tracing::warn!(?e, "age assurance: token validation failed");
            return None;
        }
    };

    let row = match sqlx::query!(
        "SELECT created_at FROM users WHERE did = $1",
        &auth_user.did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(r) => {
            tracing::debug!(?r, "age assurance: query result");
            r
        }
        Err(e) => {
            tracing::warn!(?e, "age assurance: query failed");
            return None;
        }
    };

    row.map(|r| r.created_at.to_rfc3339())
}
