use crate::state::AppState;
use crate::util::{discord_app_id, discord_bot_username, pds_hostname, telegram_bot_username};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;

fn get_available_comms_channels() -> Vec<tranquil_db_traits::CommsChannel> {
    use tranquil_db_traits::CommsChannel;
    let mut channels = vec![CommsChannel::Email];
    if std::env::var("DISCORD_BOT_TOKEN").is_ok() {
        channels.push(CommsChannel::Discord);
    }
    if std::env::var("TELEGRAM_BOT_TOKEN").is_ok() {
        channels.push(CommsChannel::Telegram);
    }
    if std::env::var("SIGNAL_CLI_PATH").is_ok() && std::env::var("SIGNAL_SENDER_NUMBER").is_ok() {
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
    std::env::var("ENABLE_SELF_HOSTED_DID_WEB")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true)
}

pub async fn describe_server() -> impl IntoResponse {
    let pds_hostname = pds_hostname();
    let domains_str =
        std::env::var("AVAILABLE_USER_DOMAINS").unwrap_or_else(|_| pds_hostname.to_string());
    let domains: Vec<&str> = domains_str.split(',').map(|s| s.trim()).collect();
    let invite_code_required = crate::util::parse_env_bool("INVITE_CODE_REQUIRED");
    let privacy_policy = std::env::var("PRIVACY_POLICY_URL").ok();
    let terms_of_service = std::env::var("TERMS_OF_SERVICE_URL").ok();
    let contact_email = std::env::var("CONTACT_EMAIL").ok();
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
        "version": env!("CARGO_PKG_VERSION"),
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
        Ok(true) => (StatusCode::OK, "OK"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable"),
    }
}
