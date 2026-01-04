use crate::api::error::ApiError;
use crate::types::Did;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::auth::verification_token::{
    VerificationPurpose, normalize_token_input, verify_token_signature,
};
use crate::state::AppState;

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifyTokenInput {
    pub token: String,
    pub identifier: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifyTokenOutput {
    pub success: bool,
    pub did: Did,
    pub purpose: String,
    pub channel: String,
}

pub async fn verify_token(
    State(state): State<AppState>,
    Json(input): Json<VerifyTokenInput>,
) -> Result<Json<VerifyTokenOutput>, ApiError> {
    verify_token_internal(&state, input).await
}

pub async fn verify_token_internal(
    state: &AppState,
    input: VerifyTokenInput,
) -> Result<Json<VerifyTokenOutput>, ApiError> {
    let normalized_token = normalize_token_input(&input.token);
    let identifier = input.identifier.trim().to_lowercase();

    let token_data = verify_token_signature(&normalized_token).map_err(|e| {
        warn!(error = ?e, "Token verification failed");
        ApiError::from(e)
    })?;

    let expected_hash = crate::auth::verification_token::hash_identifier(&identifier);
    if token_data.identifier_hash != expected_hash {
        return Err(ApiError::IdentifierMismatch);
    }

    match token_data.purpose {
        VerificationPurpose::Migration => {
            handle_migration_verification(state, &token_data.did, &token_data.channel, &identifier)
                .await
        }
        VerificationPurpose::ChannelUpdate => {
            handle_channel_update(state, &token_data.did, &token_data.channel, &identifier).await
        }
        VerificationPurpose::Signup => {
            handle_signup_verification(state, &token_data.did, &token_data.channel, &identifier)
                .await
        }
    }
}

async fn handle_migration_verification(
    state: &AppState,
    did: &str,
    channel: &str,
    identifier: &str,
) -> Result<Json<VerifyTokenOutput>, ApiError> {
    if channel != "email" {
        return Err(ApiError::InvalidChannel);
    }

    let user = sqlx::query!(
        "SELECT id, email, email_verified FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        warn!(error = %e, "Database error during migration verification");
        ApiError::InternalError(None)
    })?;

    let user = user.ok_or(ApiError::AccountNotFound)?;

    if user.email.as_ref().map(|e| e.to_lowercase()) != Some(identifier.to_string()) {
        return Err(ApiError::IdentifierMismatch);
    }

    if !user.email_verified {
        sqlx::query!(
            "UPDATE users SET email_verified = true WHERE id = $1",
            user.id
        )
        .execute(&state.db)
        .await
        .map_err(|e| {
            warn!(error = %e, "Failed to update email_verified status");
            ApiError::InternalError(None)
        })?;
    }

    info!(did = %did, "Migration email verified successfully");

    Ok(Json(VerifyTokenOutput {
        success: true,
        did: did.to_string().into(),
        purpose: "migration".to_string(),
        channel: channel.to_string(),
    }))
}

async fn handle_channel_update(
    state: &AppState,
    did: &str,
    channel: &str,
    identifier: &str,
) -> Result<Json<VerifyTokenOutput>, ApiError> {
    let user_id = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(&state.db)
        .await
        .map_err(|_| ApiError::InternalError(None))?;

    let update_result = match channel {
        "email" => sqlx::query!(
            "UPDATE users SET email = $1, email_verified = TRUE, updated_at = NOW() WHERE id = $2",
            identifier,
            user_id
        ).execute(&state.db).await,
        "discord" => sqlx::query!(
            "UPDATE users SET discord_id = $1, discord_verified = TRUE, updated_at = NOW() WHERE id = $2",
            identifier,
            user_id
        ).execute(&state.db).await,
        "telegram" => sqlx::query!(
            "UPDATE users SET telegram_username = $1, telegram_verified = TRUE, updated_at = NOW() WHERE id = $2",
            identifier,
            user_id
        ).execute(&state.db).await,
        "signal" => sqlx::query!(
            "UPDATE users SET signal_number = $1, signal_verified = TRUE, updated_at = NOW() WHERE id = $2",
            identifier,
            user_id
        ).execute(&state.db).await,
        _ => {
            return Err(ApiError::InvalidChannel);
        }
    };

    if let Err(e) = update_result {
        error!("Failed to update user channel: {:?}", e);
        if channel == "email"
            && e.as_database_error()
                .map(|db| db.is_unique_violation())
                .unwrap_or(false)
        {
            return Err(ApiError::EmailTaken);
        }
        return Err(ApiError::InternalError(None));
    }

    info!(did = %did, channel = %channel, "Channel verified successfully");

    Ok(Json(VerifyTokenOutput {
        success: true,
        did: did.to_string().into(),
        purpose: "channel_update".to_string(),
        channel: channel.to_string(),
    }))
}

async fn handle_signup_verification(
    state: &AppState,
    did: &str,
    channel: &str,
    _identifier: &str,
) -> Result<Json<VerifyTokenOutput>, ApiError> {
    let user = sqlx::query!(
        "SELECT id, handle, email, email_verified, discord_verified, telegram_verified, signal_verified FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        warn!(error = %e, "Database error during signup verification");
        ApiError::InternalError(None)
    })?;

    let user = user.ok_or(ApiError::AccountNotFound)?;

    let is_verified = user.email_verified
        || user.discord_verified
        || user.telegram_verified
        || user.signal_verified;
    if is_verified {
        info!(did = %did, "Account already verified");
        return Ok(Json(VerifyTokenOutput {
            success: true,
            did: did.to_string().into(),
            purpose: "signup".to_string(),
            channel: channel.to_string(),
        }));
    }

    let update_result = match channel {
        "email" => {
            sqlx::query!(
                "UPDATE users SET email_verified = TRUE WHERE id = $1",
                user.id
            )
            .execute(&state.db)
            .await
        }
        "discord" => {
            sqlx::query!(
                "UPDATE users SET discord_verified = TRUE WHERE id = $1",
                user.id
            )
            .execute(&state.db)
            .await
        }
        "telegram" => {
            sqlx::query!(
                "UPDATE users SET telegram_verified = TRUE WHERE id = $1",
                user.id
            )
            .execute(&state.db)
            .await
        }
        "signal" => {
            sqlx::query!(
                "UPDATE users SET signal_verified = TRUE WHERE id = $1",
                user.id
            )
            .execute(&state.db)
            .await
        }
        _ => {
            return Err(ApiError::InvalidChannel);
        }
    };

    update_result.map_err(|e| {
        warn!(error = %e, "Failed to update channel verified status");
        ApiError::InternalError(None)
    })?;

    info!(did = %did, channel = %channel, "Signup verified successfully");

    Ok(Json(VerifyTokenOutput {
        success: true,
        did: did.to_string().into(),
        purpose: "signup".to_string(),
        channel: channel.to_string(),
    }))
}
