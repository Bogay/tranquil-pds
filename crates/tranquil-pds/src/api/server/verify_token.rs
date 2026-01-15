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

    let did_typed: Did = did
        .parse()
        .map_err(|_| ApiError::InvalidDid("Invalid DID format".into()))?;
    let user = state
        .user_repo
        .get_verification_info(&did_typed)
        .await
        .map_err(|e| {
            warn!(error = ?e, "Database error during migration verification");
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::AccountNotFound)?;

    if user.email.as_ref().map(|e| e.to_lowercase()) != Some(identifier.to_string()) {
        return Err(ApiError::IdentifierMismatch);
    }

    if !user.email_verified {
        state
            .user_repo
            .set_email_verified_flag(user.id)
            .await
            .map_err(|e| {
                warn!(error = ?e, "Failed to update email_verified status");
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
    let did_typed: Did = did
        .parse()
        .map_err(|_| ApiError::InvalidDid("Invalid DID format".into()))?;
    let user_id = state
        .user_repo
        .get_id_by_did(&did_typed)
        .await
        .map_err(|_| ApiError::InternalError(None))?
        .ok_or(ApiError::AccountNotFound)?;

    match channel {
        "email" => {
            let success = state
                .user_repo
                .verify_email_channel(user_id, identifier)
                .await
                .map_err(|e| {
                    error!("Failed to update email channel: {:?}", e);
                    ApiError::InternalError(None)
                })?;
            if !success {
                return Err(ApiError::EmailTaken);
            }
        }
        "discord" => {
            state
                .user_repo
                .verify_discord_channel(user_id, identifier)
                .await
                .map_err(|e| {
                    error!("Failed to update discord channel: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        }
        "telegram" => {
            state
                .user_repo
                .verify_telegram_channel(user_id, identifier)
                .await
                .map_err(|e| {
                    error!("Failed to update telegram channel: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        }
        "signal" => {
            state
                .user_repo
                .verify_signal_channel(user_id, identifier)
                .await
                .map_err(|e| {
                    error!("Failed to update signal channel: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        }
        _ => {
            return Err(ApiError::InvalidChannel);
        }
    };

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
    let did_typed: Did = did
        .parse()
        .map_err(|_| ApiError::InvalidDid("Invalid DID format".into()))?;
    let user = state
        .user_repo
        .get_verification_info(&did_typed)
        .await
        .map_err(|e| {
            warn!(error = ?e, "Database error during signup verification");
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::AccountNotFound)?;

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

    match channel {
        "email" => {
            state
                .user_repo
                .set_email_verified_flag(user.id)
                .await
                .map_err(|e| {
                    warn!(error = ?e, "Failed to update email verified status");
                    ApiError::InternalError(None)
                })?;
        }
        "discord" => {
            state
                .user_repo
                .set_discord_verified_flag(user.id)
                .await
                .map_err(|e| {
                    warn!(error = ?e, "Failed to update discord verified status");
                    ApiError::InternalError(None)
                })?;
        }
        "telegram" => {
            state
                .user_repo
                .set_telegram_verified_flag(user.id)
                .await
                .map_err(|e| {
                    warn!(error = ?e, "Failed to update telegram verified status");
                    ApiError::InternalError(None)
                })?;
        }
        "signal" => {
            state
                .user_repo
                .set_signal_verified_flag(user.id)
                .await
                .map_err(|e| {
                    warn!(error = ?e, "Failed to update signal verified status");
                    ApiError::InternalError(None)
                })?;
        }
        _ => {
            return Err(ApiError::InvalidChannel);
        }
    };

    info!(did = %did, channel = %channel, "Signup verified successfully");

    Ok(Json(VerifyTokenOutput {
        success: true,
        did: did.to_string().into(),
        purpose: "signup".to_string(),
        channel: channel.to_string(),
    }))
}
