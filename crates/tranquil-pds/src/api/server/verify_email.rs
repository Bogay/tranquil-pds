use crate::api::error::ApiError;
use crate::types::Did;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::state::AppState;

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
    pub email: String,
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
    let email = input.email.trim().to_lowercase();

    let user = match state.user_repo.get_by_email(&email).await {
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

    let hostname = &tranquil_config::get().server.hostname;
    let token = crate::auth::verification_token::generate_migration_token(&user.did, &email);
    let formatted_token = crate::auth::verification_token::format_token_for_display(&token);

    if let Err(e) = crate::comms::comms_repo::enqueue_migration_verification(
        state.user_repo.as_ref(),
        state.infra_repo.as_ref(),
        user.id,
        &email,
        &formatted_token,
        hostname,
    )
    .await
    {
        warn!(error = ?e, "Failed to enqueue migration verification email");
    }

    info!(did = %user.did, "Resent migration verification email");

    Ok(Json(ResendMigrationVerificationOutput { sent: true }))
}
