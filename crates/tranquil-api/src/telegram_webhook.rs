use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use tracing::{debug, info, warn};

use tranquil_pds::comms::comms_repo;
use tranquil_pds::state::AppState;

#[derive(Deserialize)]
struct TelegramUpdate {
    message: Option<TelegramMessage>,
}

#[derive(Deserialize)]
struct TelegramMessage {
    text: Option<String>,
    from: Option<TelegramUser>,
}

#[derive(Deserialize)]
struct TelegramUser {
    id: i64,
    username: Option<String>,
}

pub async fn handle_telegram_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let expected_secret = match &tranquil_config::get().telegram.webhook_secret {
        Some(s) => s.clone(),
        None => {
            warn!("Telegram webhook called but TELEGRAM_WEBHOOK_SECRET is not configured");
            return StatusCode::FORBIDDEN;
        }
    };
    let provided = headers
        .get("x-telegram-bot-api-secret-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if provided != expected_secret {
        warn!("Telegram webhook received with invalid secret token");
        return StatusCode::UNAUTHORIZED;
    }

    let update: TelegramUpdate = match serde_json::from_str(&body) {
        Ok(u) => u,
        Err(_) => return StatusCode::OK,
    };

    if let Some(message) = update.message {
        let is_start = message
            .text
            .as_deref()
            .is_some_and(|t| t.starts_with("/start"));

        if is_start
            && let Some(from) = message.from
            && let Some(username) = from.username
        {
            let handle = parse_start_handle(message.text.as_deref());

            debug!(
                telegram_username = %username,
                chat_id = from.id,
                handle = ?handle,
                "Received /start from Telegram user"
            );
            match state
                .repos
                .user
                .store_telegram_chat_id(&username, from.id, handle.as_deref())
                .await
            {
                Ok(Some(user_id)) => {
                    info!(
                        telegram_username = %username,
                        chat_id = from.id,
                        "Verified Telegram user and stored chat_id"
                    );
                    if let Err(e) = comms_repo::enqueue_channel_verified(
                        state.repos.user.as_ref(),
                        state.repos.infra.as_ref(),
                        user_id,
                        tranquil_db_traits::CommsChannel::Telegram,
                        &from.id.to_string(),
                        &tranquil_config::get().server.hostname,
                    )
                    .await
                    {
                        warn!(error = %e, "Failed to enqueue channel verified notification");
                    }
                }
                Ok(None) => {
                    debug!(
                        telegram_username = %username,
                        "No matching user found for Telegram username"
                    );
                }
                Err(e) => {
                    warn!(
                        telegram_username = %username,
                        error = %e,
                        "Failed to store Telegram chat_id"
                    );
                }
            }
        }
    }

    StatusCode::OK
}

fn parse_start_handle(text: Option<&str>) -> Option<String> {
    text.and_then(|t| t.strip_prefix("/start "))
        .map(|payload| payload.trim())
        .filter(|p| !p.is_empty())
        .map(|payload| payload.replace('_', "."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_link_underscores_decoded_to_dots() {
        assert_eq!(
            parse_start_handle(Some("/start lewis_buttercup_wizardry_systems")),
            Some("lewis.buttercup.wizardry.systems".to_string()),
        );
    }

    #[test]
    fn manual_handle_with_dots_passes_through() {
        assert_eq!(
            parse_start_handle(Some("/start lewis.buttercup.wizardry.systems")),
            Some("lewis.buttercup.wizardry.systems".to_string()),
        );
    }

    #[test]
    fn bare_start_returns_none() {
        assert_eq!(parse_start_handle(Some("/start")), None);
    }

    #[test]
    fn start_with_trailing_space_returns_none() {
        assert_eq!(parse_start_handle(Some("/start ")), None);
    }

    #[test]
    fn none_text_returns_none() {
        assert_eq!(parse_start_handle(None), None);
    }

    #[test]
    fn non_start_command_returns_none() {
        assert_eq!(parse_start_handle(Some("/help")), None);
    }

    #[test]
    fn payload_with_extra_whitespace_trimmed() {
        assert_eq!(
            parse_start_handle(Some("/start  alice_example_com  ")),
            Some("alice.example.com".to_string()),
        );
    }
}
