use crate::api::error::{ApiError, AtpJson};
use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use crate::types::Did;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailInput {
    pub recipient_did: Did,
    pub sender_did: Did,
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
    _auth: BearerAuthAdmin,
    AtpJson(input): AtpJson<SendEmailInput>,
) -> Response {
    let content = input.content.trim();
    if content.is_empty() {
        return ApiError::InvalidRequest("content is required".into()).into_response();
    }
    let user = sqlx::query!(
        "SELECT id, email, handle FROM users WHERE did = $1",
        input.recipient_did.as_str()
    )
    .fetch_optional(&state.db)
    .await;
    let (user_id, email, handle) = match user {
        Ok(Some(row)) => {
            let email = match row.email {
                Some(e) => e,
                None => {
                    return ApiError::NoEmail.into_response();
                }
            };
            (row.id, email, row.handle)
        }
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error in send_email: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let subject = input
        .subject
        .clone()
        .unwrap_or_else(|| format!("Message from {}", hostname));
    let item = crate::comms::NewComms::email(
        user_id,
        crate::comms::CommsType::AdminEmail,
        email,
        subject,
        content.to_string(),
    );
    let result = crate::comms::enqueue_comms(&state.db, item).await;
    match result {
        Ok(_) => {
            tracing::info!(
                "Admin email queued for {} ({})",
                handle,
                input.recipient_did
            );
            (StatusCode::OK, Json(SendEmailOutput { sent: true })).into_response()
        }
        Err(e) => {
            warn!("Failed to enqueue admin email: {:?}", e);
            (StatusCode::OK, Json(SendEmailOutput { sent: false })).into_response()
        }
    }
}
