use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use tranquil_db_traits::CommsChannel;
use tranquil_pds::BUILD_VERSION;
use tranquil_pds::state::AppState;
use tranquil_pds::util::{discord_app_id, discord_bot_username, telegram_bot_username};

fn get_available_comms_channels() -> Vec<CommsChannel> {
    let cfg = tranquil_config::get();
    let mut channels = vec![CommsChannel::Email];
    if cfg.discord.bot_token.is_some() {
        channels.push(CommsChannel::Discord);
    }
    if cfg.telegram.bot_token.is_some() {
        channels.push(CommsChannel::Telegram);
    }
    if cfg.signal.enabled {
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeServerLinks {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeServerContact {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeServerOutput {
    pub available_user_domains: Vec<String>,
    pub invite_code_required: bool,
    pub did: String,
    pub links: DescribeServerLinks,
    pub contact: DescribeServerContact,
    pub version: &'static str,
    pub available_comms_channels: Vec<CommsChannel>,
    pub self_hosted_did_web_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discord_bot_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discord_app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telegram_bot_username: Option<String>,
}

pub async fn describe_server() -> Json<DescribeServerOutput> {
    let cfg = tranquil_config::get();
    let pds_hostname = &cfg.server.hostname;

    Json(DescribeServerOutput {
        available_user_domains: cfg.server.user_handle_domain_list(),
        invite_code_required: cfg.server.invite_code_required,
        did: format!("did:web:{}", pds_hostname),
        links: DescribeServerLinks {
            privacy_policy: cfg.server.privacy_policy_url.clone(),
            terms_of_service: cfg.server.terms_of_service_url.clone(),
        },
        contact: DescribeServerContact {
            email: cfg.server.contact_email.clone(),
        },
        version: BUILD_VERSION,
        available_comms_channels: get_available_comms_channels(),
        self_hosted_did_web_enabled: is_self_hosted_did_web_enabled(),
        discord_bot_username: discord_bot_username().map(String::from),
        discord_app_id: discord_app_id().map(String::from),
        telegram_bot_username: telegram_bot_username().map(String::from),
    })
}
#[derive(Serialize)]
pub struct HealthOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
}

pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    match state.infra_repo.health_check().await {
        Ok(true) => (
            StatusCode::OK,
            Json(HealthOutput {
                version: Some(format!("tranquil {}", BUILD_VERSION)),
                error: None,
            }),
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthOutput {
                version: None,
                error: Some("Service Unavailable"),
            }),
        ),
    }
}
