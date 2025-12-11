use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, warn};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailInput {
    pub recipient_did: String,
    pub sender_did: String,
    pub content: String,
    pub subject: Option<String>,
    pub comment: Option<String>,
}

#[derive(Serialize)]
pub struct SendEmailOutput {
    pub sent: bool,
}

pub async fn send_email(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<SendEmailInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let recipient_did = input.recipient_did.trim();
    let content = input.content.trim();

    if recipient_did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "recipientDid is required"})),
        )
            .into_response();
    }

    if content.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "content is required"})),
        )
            .into_response();
    }

    let user = sqlx::query!(
        "SELECT id, email, handle FROM users WHERE did = $1",
        recipient_did
    )
    .fetch_optional(&state.db)
    .await;

    let (user_id, email, handle) = match user {
        Ok(Some(row)) => (row.id, row.email, row.handle),
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound", "message": "Recipient account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in send_email: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let subject = input
        .subject
        .clone()
        .unwrap_or_else(|| format!("Message from {}", hostname));

    let notification = crate::notifications::NewNotification::email(
        user_id,
        crate::notifications::NotificationType::AdminEmail,
        email,
        subject,
        content.to_string(),
    );

    let result = crate::notifications::enqueue_notification(&state.db, notification).await;

    match result {
        Ok(_) => {
            tracing::info!(
                "Admin email queued for {} ({})",
                handle,
                recipient_did
            );
            (StatusCode::OK, Json(SendEmailOutput { sent: true })).into_response()
        }
        Err(e) => {
            warn!("Failed to enqueue admin email: {:?}", e);
            (StatusCode::OK, Json(SendEmailOutput { sent: false })).into_response()
        }
    }
}
