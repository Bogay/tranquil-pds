use crate::common;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use tranquil_pds::api::SuccessResponse;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::comms::comms_repo;
use tranquil_pds::types::Did;

use tranquil_db_traits::CommsChannel;
use tranquil_pds::auth::verification_token::{
    VerificationPurpose, normalize_token_input, verify_token_signature,
};
use tranquil_pds::state::AppState;

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
    pub purpose: VerificationPurpose,
    pub channel: CommsChannel,
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

    let expected_hash = tranquil_pds::auth::verification_token::hash_identifier(&identifier);
    if token_data.identifier_hash != expected_hash {
        return Err(ApiError::IdentifierMismatch);
    }

    match token_data.purpose {
        VerificationPurpose::Migration => {
            handle_migration_verification(state, &token_data.did, token_data.channel, &identifier)
                .await
        }
        VerificationPurpose::ChannelUpdate => {
            handle_channel_update(state, &token_data.did, token_data.channel, &identifier).await
        }
        VerificationPurpose::Signup => {
            handle_signup_verification(state, &token_data.did, token_data.channel, &identifier)
                .await
        }
    }
}

async fn handle_migration_verification(
    state: &AppState,
    did: &Did,
    channel: CommsChannel,
    identifier: &str,
) -> Result<Json<VerifyTokenOutput>, ApiError> {
    let user = state
        .repos.user
        .get_verification_info(did)
        .await
        .log_db_err("during migration verification")?
        .ok_or(ApiError::AccountNotFound)?;

    match channel {
        CommsChannel::Email => {
            if user.email.as_ref().map(|e| e.to_lowercase()) != Some(identifier.to_string()) {
                return Err(ApiError::IdentifierMismatch);
            }
            if !user.channel_verification.email {
                state
                    .repos.user
                    .set_email_verified_flag(user.id)
                    .await
                    .log_db_err("updating email_verified status")?;
            }
        }
        _ => common::set_channel_verified_flag(state.repos.user.as_ref(), user.id, channel).await?,
    };

    info!(did = %did, channel = ?channel, "Migration verification completed successfully");

    Ok(Json(VerifyTokenOutput {
        success: true,
        did: did.clone(),
        purpose: VerificationPurpose::Migration,
        channel,
    }))
}

async fn handle_channel_update(
    state: &AppState,
    did: &Did,
    channel: CommsChannel,
    identifier: &str,
) -> Result<Json<VerifyTokenOutput>, ApiError> {
    let user_id = state
        .repos.user
        .get_id_by_did(did)
        .await
        .log_db_err("fetching user id")?
        .ok_or(ApiError::AccountNotFound)?;

    match channel {
        CommsChannel::Email => {
            let success = state
                .repos.user
                .verify_email_channel(user_id, identifier)
                .await
                .log_db_err("updating email channel")?;
            if !success {
                return Err(ApiError::EmailTaken);
            }
        }
        CommsChannel::Discord => {
            state
                .repos.user
                .verify_discord_channel(user_id, identifier)
                .await
                .log_db_err("updating discord channel")?;
        }
        CommsChannel::Telegram => {
            state
                .repos.user
                .verify_telegram_channel(user_id, identifier)
                .await
                .log_db_err("updating telegram channel")?;
        }
        CommsChannel::Signal => {
            state
                .repos.user
                .verify_signal_channel(user_id, identifier)
                .await
                .log_db_err("updating signal channel")?;
        }
    };

    info!(did = %did, channel = ?channel, "Channel verified successfully");

    notify_channel_verified(state, user_id, channel, identifier).await;

    Ok(Json(VerifyTokenOutput {
        success: true,
        did: did.clone(),
        purpose: VerificationPurpose::ChannelUpdate,
        channel,
    }))
}

async fn notify_channel_verified(
    state: &AppState,
    user_id: uuid::Uuid,
    channel: CommsChannel,
    identifier: &str,
) {
    let recipient = match channel {
        CommsChannel::Telegram => state
            .repos.user
            .get_telegram_chat_id(user_id)
            .await
            .ok()
            .flatten()
            .map(|id| id.to_string())
            .unwrap_or_else(|| identifier.to_string()),
        _ => identifier.to_string(),
    };
    if let Err(e) = comms_repo::enqueue_channel_verified(
        state.repos.user.as_ref(),
        state.repos.infra.as_ref(),
        user_id,
        channel,
        &recipient,
        &tranquil_config::get().server.hostname,
    )
    .await
    {
        warn!(error = %e, "Failed to enqueue channel verified notification");
    }
}

async fn handle_signup_verification(
    state: &AppState,
    did: &Did,
    channel: CommsChannel,
    identifier: &str,
) -> Result<Json<VerifyTokenOutput>, ApiError> {
    let user = state
        .repos.user
        .get_verification_info(did)
        .await
        .log_db_err("during signup verification")?
        .ok_or(ApiError::AccountNotFound)?;

    let is_verified = user.channel_verification.has_any_verified();
    if is_verified {
        info!(did = %did, "Account already verified");
        return Ok(Json(VerifyTokenOutput {
            success: true,
            did: did.clone(),
            purpose: VerificationPurpose::Signup,
            channel,
        }));
    }

    common::set_channel_verified_flag(state.repos.user.as_ref(), user.id, channel).await?;

    info!(did = %did, channel = ?channel, "Signup verified successfully");

    notify_channel_verified(state, user.id, channel, identifier).await;

    Ok(Json(VerifyTokenOutput {
        success: true,
        did: did.clone(),
        purpose: VerificationPurpose::Signup,
        channel,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmChannelVerificationInput {
    pub channel: CommsChannel,
    pub identifier: String,
    pub code: String,
}

pub async fn confirm_channel_verification(
    State(state): State<AppState>,
    Json(input): Json<ConfirmChannelVerificationInput>,
) -> Response {
    let token_input = VerifyTokenInput {
        token: input.code,
        identifier: input.identifier,
    };

    match verify_token_internal(&state, token_input).await {
        Ok(_output) => SuccessResponse::ok().into_response(),
        Err(e) => e.into_response(),
    }
}
