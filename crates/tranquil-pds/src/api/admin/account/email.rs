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
    let user = match state.user_repo.get_by_did(&input.recipient_did).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error in send_email: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let email = match user.email {
        Some(e) => e,
        None => {
            return ApiError::NoEmail.into_response();
        }
    };
    let (user_id, handle) = (user.id, user.handle);
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let subject = input
        .subject
        .clone()
        .unwrap_or_else(|| format!("Message from {}", hostname));
    let result = state
        .infra_repo
        .enqueue_comms(
            Some(user_id),
            tranquil_db_traits::CommsChannel::Email,
            tranquil_db_traits::CommsType::AdminEmail,
            &email,
            Some(&subject),
            content,
            None,
        )
        .await;
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
