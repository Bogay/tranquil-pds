use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing::warn;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::auth::{Admin, Auth};
use tranquil_pds::state::AppState;
use tranquil_pds::types::Did;

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
    Json(input): Json<SendEmailInput>,
) -> Result<Json<SendEmailOutput>, ApiError> {
    let content = input.content.trim();
    if content.is_empty() {
        return Err(ApiError::InvalidRequest("content is required".into()));
    }
    let user = state
        .repos
        .user
        .get_by_did(&input.recipient_did)
        .await
        .log_db_err("in send_email")?
        .ok_or(ApiError::AccountNotFound)?;

    let email = user.email.ok_or(ApiError::NoEmail)?;
    let (user_id, handle) = (user.id, user.handle);
    let hostname = &tranquil_config::get().server.hostname;
    let subject = input
        .subject
        .clone()
        .unwrap_or_else(|| format!("Message from {}", hostname));
    let result = state
        .repos
        .infra
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
            Ok(Json(SendEmailOutput { sent: true }))
        }
        Err(e) => {
            warn!("Failed to enqueue admin email: {:?}", e);
            Ok(Json(SendEmailOutput { sent: false }))
        }
    }
}
