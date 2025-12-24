use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
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
    pub did: String,
}

pub async fn verify_migration_email(
    State(state): State<AppState>,
    Json(input): Json<VerifyMigrationEmailInput>,
) -> Result<Json<VerifyMigrationEmailOutput>, (StatusCode, Json<serde_json::Value>)> {
    let token_input = super::verify_token::VerifyTokenInput {
        token: input.token,
        identifier: input.email,
    };

    let result = super::verify_token::verify_token_internal(&state, None, token_input).await?;

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
) -> Result<Json<ResendMigrationVerificationOutput>, (StatusCode, Json<serde_json::Value>)> {
    let email = input.email.trim().to_lowercase();

    let user = sqlx::query!(
        "SELECT id, did, email, email_verified, handle FROM users WHERE LOWER(email) = $1",
        email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        warn!(error = %e, "Database error during resend verification");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "InternalError", "message": "Database error" })),
        )
    })?;

    let user = match user {
        Some(u) => u,
        None => {
            return Ok(Json(ResendMigrationVerificationOutput { sent: true }));
        }
    };

    if user.email_verified {
        return Ok(Json(ResendMigrationVerificationOutput { sent: true }));
    }

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let token = crate::auth::verification_token::generate_migration_token(&user.did, &email);
    let formatted_token = crate::auth::verification_token::format_token_for_display(&token);

    if let Err(e) = crate::comms::enqueue_migration_verification(
        &state.db,
        user.id,
        &email,
        &formatted_token,
        &hostname,
    )
    .await
    {
        warn!(error = %e, "Failed to enqueue migration verification email");
    }

    info!(did = %user.did, "Resent migration verification email");

    Ok(Json(ResendMigrationVerificationOutput { sent: true }))
}
