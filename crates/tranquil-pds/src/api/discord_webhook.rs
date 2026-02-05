use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info, warn};
use tranquil_types::Handle;

use crate::comms::comms_repo;
use crate::state::AppState;
use crate::util::{discord_public_key, pds_hostname};

#[derive(Deserialize)]
struct Interaction {
    #[serde(rename = "type")]
    interaction_type: u8,
    data: Option<InteractionData>,
    member: Option<InteractionMember>,
    user: Option<InteractionUser>,
}

#[derive(Deserialize)]
struct InteractionData {
    name: Option<String>,
    options: Option<Vec<InteractionOption>>,
}

#[derive(Deserialize)]
struct InteractionOption {
    name: String,
    value: serde_json::Value,
}

#[derive(Deserialize)]
struct InteractionMember {
    user: Option<InteractionUser>,
}

#[derive(Deserialize)]
struct InteractionUser {
    id: String,
    username: Option<String>,
}

fn verify_signature(
    public_key: &VerifyingKey,
    timestamp: &str,
    body: &str,
    signature: &str,
) -> bool {
    let sig_bytes = match hex::decode(signature) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let message = format!("{}{}", timestamp, body);
    public_key.verify(message.as_bytes(), &signature).is_ok()
}

fn parse_start_handle(options: Option<&[InteractionOption]>) -> Option<String> {
    options
        .and_then(|opts| opts.iter().find(|o| o.name == "handle"))
        .and_then(|o| o.value.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

pub async fn handle_discord_webhook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let public_key = match discord_public_key() {
        Some(pk) => pk,
        None => {
            warn!("Discord webhook called but public key is not configured");
            return StatusCode::FORBIDDEN.into_response();
        }
    };

    let signature = headers
        .get("x-signature-ed25519")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let timestamp = headers
        .get("x-signature-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if !verify_signature(public_key, timestamp, &body, signature) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let interaction: Interaction = match serde_json::from_str(&body) {
        Ok(i) => i,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match interaction.interaction_type {
        1 => Json(json!({"type": 1})).into_response(),
        2 => handle_command(state, interaction).await,
        other => {
            debug!(interaction_type = other, "Received unknown Discord interaction type");
            StatusCode::OK.into_response()
        }
    }
}

async fn handle_command(state: AppState, interaction: Interaction) -> Response {
    let command_name = interaction
        .data
        .as_ref()
        .and_then(|d| d.name.as_deref())
        .unwrap_or_default();

    if command_name != "start" {
        return Json(json!({
            "type": 4,
            "data": {"content": "Unknown command", "flags": 64}
        }))
        .into_response();
    }

    let user = interaction
        .member
        .as_ref()
        .and_then(|m| m.user.as_ref())
        .or(interaction.user.as_ref());

    let (discord_user_id, discord_username) = match user {
        Some(u) => (u.id.clone(), u.username.clone().unwrap_or_default()),
        None => {
            return Json(json!({
                "type": 4,
                "data": {"content": "Could not identify user", "flags": 64}
            }))
            .into_response();
        }
    };

    let handle = parse_start_handle(interaction.data.as_ref().and_then(|d| d.options.as_deref()));

    if let Some(ref h) = handle {
        if Handle::new(h).is_err() {
            return Json(json!({
                "type": 4,
                "data": {"content": "Invalid handle format. Handle should look like: alice.example.com", "flags": 64}
            }))
            .into_response();
        }
    }

    debug!(
        discord_username = %discord_username,
        discord_user_id = %discord_user_id,
        handle = ?handle,
        "Received /start from Discord user"
    );

    match state
        .user_repo
        .store_discord_user_id(&discord_username, &discord_user_id, handle.as_deref())
        .await
    {
        Ok(Some(user_id)) => {
            info!(
                discord_username = %discord_username,
                discord_user_id = %discord_user_id,
                "Verified Discord user and stored user ID"
            );
            if let Err(e) = comms_repo::enqueue_channel_verified(
                state.user_repo.as_ref(),
                state.infra_repo.as_ref(),
                user_id,
                "discord",
                &discord_user_id,
                pds_hostname(),
            )
            .await
            {
                warn!(error = %e, "Failed to enqueue channel verified notification");
            }
            Json(json!({
                "type": 4,
                "data": {"content": "Verified", "flags": 64}
            }))
            .into_response()
        }
        Ok(None) => {
            debug!(
                discord_username = %discord_username,
                "No matching user found for Discord username"
            );
            Json(json!({
                "type": 4,
                "data": {"content": "No account found with this Discord username. Set your Discord username in your PDS settings first.", "flags": 64}
            }))
            .into_response()
        }
        Err(tranquil_db_traits::DbError::Ambiguous(msg)) => {
            debug!(
                discord_username = %discord_username,
                "Ambiguous Discord username match"
            );
            Json(json!({
                "type": 4,
                "data": {"content": msg, "flags": 64}
            }))
            .into_response()
        }
        Err(tranquil_db_traits::DbError::LockContention) => {
            debug!(
                discord_username = %discord_username,
                "Lock contention during Discord verification"
            );
            Json(json!({
                "type": 4,
                "data": {"content": "Server busy, please try again in a moment.", "flags": 64}
            }))
            .into_response()
        }
        Err(e) => {
            warn!(
                discord_username = %discord_username,
                error = %e,
                "Failed to store Discord user ID"
            );
            Json(json!({
                "type": 4,
                "data": {"content": "Verification failed. Try again later.", "flags": 64}
            }))
            .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_handle_from_options() {
        let options = vec![InteractionOption {
            name: "handle".to_string(),
            value: serde_json::json!("lewis.buttercup.wizardry.systems"),
        }];
        assert_eq!(
            parse_start_handle(Some(&options)),
            Some("lewis.buttercup.wizardry.systems".to_string()),
        );
    }

    #[test]
    fn parse_handle_no_options() {
        assert_eq!(parse_start_handle(None), None);
    }

    #[test]
    fn parse_handle_empty_options() {
        let options: Vec<InteractionOption> = vec![];
        assert_eq!(parse_start_handle(Some(&options)), None);
    }

    #[test]
    fn parse_handle_wrong_option_name() {
        let options = vec![InteractionOption {
            name: "other".to_string(),
            value: serde_json::json!("test"),
        }];
        assert_eq!(parse_start_handle(Some(&options)), None);
    }

    #[test]
    fn parse_handle_empty_string() {
        let options = vec![InteractionOption {
            name: "handle".to_string(),
            value: serde_json::json!(""),
        }];
        assert_eq!(parse_start_handle(Some(&options)), None);
    }

    #[test]
    fn parse_handle_whitespace_trimmed() {
        let options = vec![InteractionOption {
            name: "handle".to_string(),
            value: serde_json::json!("  alice.example.com  "),
        }];
        assert_eq!(
            parse_start_handle(Some(&options)),
            Some("alice.example.com".to_string()),
        );
    }
}
