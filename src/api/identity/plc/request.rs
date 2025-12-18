use crate::api::ApiError;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use serde_json::json;
use tracing::{error, info, warn};

fn generate_plc_token() -> String {
    crate::util::generate_token_code()
}

pub async fn request_plc_operation_signature(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let auth_user = match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &token).await {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let user = match sqlx::query!("SELECT id FROM users WHERE did = $1", auth_user.did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    let _ = sqlx::query!(
        "DELETE FROM plc_operation_tokens WHERE user_id = $1 OR expires_at < NOW()",
        user.id
    )
    .execute(&state.db)
    .await;
    let plc_token = generate_plc_token();
    let expires_at = Utc::now() + Duration::minutes(10);
    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO plc_operation_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)
        "#,
        user.id,
        plc_token,
        expires_at
    )
    .execute(&state.db)
    .await
    {
        error!("Failed to create PLC token: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) =
        crate::comms::enqueue_plc_operation(&state.db, user.id, &plc_token, &hostname).await
    {
        warn!("Failed to enqueue PLC operation notification: {:?}", e);
    }
    info!(
        "PLC operation signature requested for user {}",
        auth_user.did
    );
    (StatusCode::OK, Json(json!({}))).into_response()
}
