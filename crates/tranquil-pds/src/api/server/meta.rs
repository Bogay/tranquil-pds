use crate::BUILD_VERSION;
use crate::state::AppState;
use crate::util::{discord_app_id, discord_bot_username, telegram_bot_username};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;

fn get_available_comms_channels() -> Vec<tranquil_db_traits::CommsChannel> {
    use tranquil_db_traits::CommsChannel;
    let cfg = tranquil_config::get();
    let mut channels = vec![CommsChannel::Email];
    if cfg.discord.bot_token.is_some() {
        channels.push(CommsChannel::Discord);
    }
    if cfg.telegram.bot_token.is_some() {
        channels.push(CommsChannel::Telegram);
    }
    if cfg.signal.sender_number.is_some() {
        channels.push(CommsChannel::Signal);
    }
    channels
}

pub async fn robots_txt() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain")],
        "# Hello!\n\n# Crawling the public API is allowed\nUser-agent: *\nAllow: /\n",
    )
}
pub fn is_self_hosted_did_web_enabled() -> bool {
    tranquil_config::get().server.enable_pds_hosted_did_web
}

pub async fn describe_server() -> impl IntoResponse {
    let cfg = tranquil_config::get();
    let pds_hostname = &cfg.server.hostname;
    let domains = cfg.server.available_user_domain_list();
    let invite_code_required = cfg.server.invite_code_required;
    let privacy_policy = cfg.server.privacy_policy_url.clone();
    let terms_of_service = cfg.server.terms_of_service_url.clone();
    let contact_email = cfg.server.contact_email.clone();
    let mut links = serde_json::Map::new();
    if let Some(pp) = privacy_policy {
        links.insert("privacyPolicy".to_string(), json!(pp));
    }
    if let Some(tos) = terms_of_service {
        links.insert("termsOfService".to_string(), json!(tos));
    }
    let mut contact = serde_json::Map::new();
    if let Some(email) = contact_email {
        contact.insert("email".to_string(), json!(email));
    }
    let mut response = json!({
        "availableUserDomains": domains,
        "inviteCodeRequired": invite_code_required,
        "did": format!("did:web:{}", pds_hostname),
        "links": links,
        "contact": contact,
        "version": BUILD_VERSION,
        "availableCommsChannels": get_available_comms_channels(),
        "selfHostedDidWebEnabled": is_self_hosted_did_web_enabled()
    });
    if let Some(bot_username) = discord_bot_username() {
        response["discordBotUsername"] = json!(bot_username);
    }
    if let Some(app_id) = discord_app_id() {
        response["discordAppId"] = json!(app_id);
    }
    if let Some(bot_username) = telegram_bot_username() {
        response["telegramBotUsername"] = json!(bot_username);
    }
    Json(response)
}
pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    match state.infra_repo.health_check().await {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({
                "version": format!("tranquil {}", BUILD_VERSION)
            })),
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "Service Unavailable"
            })),
        ),
    }
}
