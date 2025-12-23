use crate::state::AppState;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use tracing::error;

fn get_available_comms_channels() -> Vec<&'static str> {
    let mut channels = vec!["email"];
    if std::env::var("DISCORD_WEBHOOK_URL").is_ok() {
        channels.push("discord");
    }
    if std::env::var("TELEGRAM_BOT_TOKEN").is_ok() {
        channels.push("telegram");
    }
    if std::env::var("SIGNAL_CLI_PATH").is_ok() && std::env::var("SIGNAL_SENDER_NUMBER").is_ok() {
        channels.push("signal");
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
pub async fn describe_server() -> impl IntoResponse {
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let domains_str =
        std::env::var("AVAILABLE_USER_DOMAINS").unwrap_or_else(|_| pds_hostname.clone());
    let domains: Vec<&str> = domains_str.split(',').map(|s| s.trim()).collect();
    let invite_code_required = std::env::var("INVITE_CODE_REQUIRED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    Json(json!({
        "availableUserDomains": domains,
        "inviteCodeRequired": invite_code_required,
        "did": format!("did:web:{}", pds_hostname),
        "version": env!("CARGO_PKG_VERSION"),
        "availableCommsChannels": get_available_comms_channels()
    }))
}
pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query!("SELECT 1 as one").fetch_one(&state.db).await {
        Ok(_) => (StatusCode::OK, "OK"),
        Err(e) => {
            error!("Health check failed: {:?}", e);
            (StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
        }
    }
}
