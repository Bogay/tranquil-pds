use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use tranquil_pds::api::error::ApiError;
use tranquil_pds::types::Did;

use tranquil_pds::state::AppState;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyMigrationEmailInput {
    pub token: String,
    pub email: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyMigrationEmailOutput {
    pub success: bool,
    pub did: Did,
}

pub async fn verify_migration_email(
    State(state): State<AppState>,
    Json(input): Json<VerifyMigrationEmailInput>,
) -> Result<Json<VerifyMigrationEmailOutput>, ApiError> {
    let token_input = super::verify_token::VerifyTokenInput {
        token: input.token,
        identifier: input.email,
    };

    let result = super::verify_token::verify_token_internal(&state, token_input).await?;

    Ok(Json(VerifyMigrationEmailOutput {
        success: result.success,
        did: result.did.clone(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendMigrationVerificationInput {
    pub channel: Option<tranquil_db_traits::CommsChannel>,
    pub identifier: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendMigrationVerificationOutput {
    pub sent: bool,
}

pub async fn resend_migration_verification(
    State(state): State<AppState>,
    Json(input): Json<ResendMigrationVerificationInput>,
) -> Result<Json<ResendMigrationVerificationOutput>, ApiError> {
    let channel = input
        .channel
        .unwrap_or(tranquil_db_traits::CommsChannel::Email);
    let identifier = input.identifier.trim().to_lowercase();

    let user = match state.user_repo.get_by_email(&identifier).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Ok(Json(ResendMigrationVerificationOutput { sent: true }));
        }
        Err(e) => {
            warn!(error = ?e, "Database error during resend verification");
            return Err(ApiError::InternalError(None));
        }
    };

    if user.email_verified {
        return Ok(Json(ResendMigrationVerificationOutput { sent: true }));
    }

    crate::identity::provision::enqueue_migration_verification(
        &state,
        user.id,
        &user.did,
        channel,
        &identifier,
    )
    .await;

    info!(did = %user.did, channel = ?channel, "Resent migration verification");

    Ok(Json(ResendMigrationVerificationOutput { sent: true }))
}
