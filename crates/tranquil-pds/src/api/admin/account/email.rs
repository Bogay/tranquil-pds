use crate::api::error::{ApiError, AtpJson, DbResultExt};
use crate::auth::{Admin, Auth};
use crate::state::AppState;
use crate::types::Did;
use crate::util::pds_hostname;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::warn;

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
    _auth: Auth<Admin>,
    AtpJson(input): AtpJson<SendEmailInput>,
) -> Result<Response, ApiError> {
    let content = input.content.trim();
    if content.is_empty() {
        return Err(ApiError::InvalidRequest("content is required".into()));
    }
    let user = state
        .user_repo
        .get_by_did(&input.recipient_did)
        .await
        .log_db_err("in send_email")?
        .ok_or(ApiError::AccountNotFound)?;

    let email = user.email.ok_or(ApiError::NoEmail)?;
    let (user_id, handle) = (user.id, user.handle);
    let hostname = pds_hostname();
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
            Ok((StatusCode::OK, Json(SendEmailOutput { sent: true })).into_response())
        }
        Err(e) => {
            warn!("Failed to enqueue admin email: {:?}", e);
            Ok((StatusCode::OK, Json(SendEmailOutput { sent: false })).into_response())
        }
    }
}
