use bcrypt::DEFAULT_COST;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tracing::error;
use tranquil_db_traits::{CommsChannel, DidWebOverrides, SessionRepository, UserRepository};
use tranquil_pds::api::error::ApiError;
use tranquil_pds::api::error::DbResultExt;
use tranquil_pds::types::{AtIdentifier, Did, Handle};

pub struct ResolvedRepo {
    pub user_id: uuid::Uuid,
    pub did: Did,
    pub handle: Handle,
}

fn qualify_handle(handle: &Handle) -> Result<Handle, ApiError> {
    let raw = handle.as_str();
    let qualified = match raw.contains('.') {
        true => return Ok(handle.clone()),
        false => format!(
            "{}.{}",
            raw,
            tranquil_config::get().server.hostname_without_port()
        ),
    };
    qualified
        .parse()
        .map_err(|_| ApiError::InvalidRequest("Invalid handle format".into()))
}

pub async fn resolve_repo(
    user_repo: &dyn UserRepository,
    repo: &AtIdentifier,
) -> Result<ResolvedRepo, ApiError> {
    let row = match repo {
        AtIdentifier::Did(did) => user_repo
            .get_by_did(did)
            .await
            .log_db_err("resolving repo by DID")?,
        AtIdentifier::Handle(handle) => {
            let qualified = qualify_handle(handle)?;
            user_repo
                .get_by_handle(&qualified)
                .await
                .log_db_err("resolving repo by handle")?
        }
    };
    row.map(|r| ResolvedRepo {
        user_id: r.id,
        did: r.did,
        handle: r.handle,
    })
    .ok_or(ApiError::RepoNotFound(Some("Repo not found".into())))
}

pub async fn resolve_repo_user_id(
    user_repo: &dyn UserRepository,
    repo: &AtIdentifier,
) -> Result<uuid::Uuid, ApiError> {
    let id = match repo {
        AtIdentifier::Did(did) => user_repo
            .get_id_by_did(did)
            .await
            .log_db_err("resolving repo user ID by DID")?,
        AtIdentifier::Handle(handle) => {
            let qualified = qualify_handle(handle)?;
            user_repo
                .get_id_by_handle(&qualified)
                .await
                .log_db_err("resolving repo user ID by handle")?
        }
    };
    id.ok_or(ApiError::RepoNotFound(Some("Repo not found".into())))
}

pub fn group_invite_uses_by_code<U, F>(
    uses: Vec<tranquil_db_traits::InviteCodeUse>,
    map_use: F,
) -> HashMap<String, Vec<U>>
where
    F: Fn(tranquil_db_traits::InviteCodeUse) -> U,
{
    uses.into_iter().fold(HashMap::new(), |mut acc, u| {
        let code = u.code.clone();
        acc.entry(code).or_default().push(map_use(u));
        acc
    })
}

pub fn resolve_also_known_as(
    overrides: Option<&DidWebOverrides>,
    current_handle: &str,
) -> Vec<String> {
    overrides
        .filter(|ovr| !ovr.also_known_as.is_empty())
        .map(|ovr| ovr.also_known_as.clone())
        .unwrap_or_else(|| vec![format!("at://{}", current_handle)])
}

pub fn build_did_document(
    did: &str,
    also_known_as: Vec<String>,
    verification_methods: Vec<serde_json::Value>,
    service_endpoint: &str,
) -> serde_json::Value {
    serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "alsoKnownAs": also_known_as,
        "verificationMethod": verification_methods,
        "service": [{
            "id": "#atproto_pds",
            "type": tranquil_pds::plc::ServiceType::Pds.as_str(),
            "serviceEndpoint": service_endpoint
        }]
    })
}

pub async fn set_channel_verified_flag(
    user_repo: &dyn UserRepository,
    user_id: uuid::Uuid,
    channel: CommsChannel,
) -> Result<(), ApiError> {
    match channel {
        CommsChannel::Email => user_repo
            .set_email_verified_flag(user_id)
            .await
            .log_db_err("updating email verified status")?,
        CommsChannel::Discord => user_repo
            .set_discord_verified_flag(user_id)
            .await
            .log_db_err("updating discord verified status")?,
        CommsChannel::Telegram => user_repo
            .set_telegram_verified_flag(user_id)
            .await
            .log_db_err("updating telegram verified status")?,
        CommsChannel::Signal => user_repo
            .set_signal_verified_flag(user_id)
            .await
            .log_db_err("updating signal verified status")?,
    };
    Ok(())
}

pub struct ChannelInput<'a> {
    pub email: Option<&'a str>,
    pub discord_username: Option<&'a str>,
    pub telegram_username: Option<&'a str>,
    pub signal_username: Option<&'a str>,
}

pub fn extract_verification_recipient(
    channel: CommsChannel,
    input: &ChannelInput<'_>,
) -> Result<String, ApiError> {
    match channel {
        CommsChannel::Email => match input.email {
            Some(e) if !e.trim().is_empty() => Ok(e.trim().to_string()),
            _ => Err(ApiError::MissingEmail),
        },
        CommsChannel::Discord => match input.discord_username {
            Some(username) if !username.trim().is_empty() => {
                let clean = username.trim().to_lowercase();
                if !tranquil_pds::api::validation::is_valid_discord_username(&clean) {
                    return Err(ApiError::InvalidRequest(
                        "Invalid Discord username. Must be 2-32 lowercase characters (letters, numbers, underscores, periods)".into(),
                    ));
                }
                Ok(clean)
            }
            _ => Err(ApiError::MissingDiscordId),
        },
        CommsChannel::Telegram => match input.telegram_username {
            Some(username) if !username.trim().is_empty() => {
                let clean = username.trim().trim_start_matches('@');
                if !tranquil_pds::api::validation::is_valid_telegram_username(clean) {
                    return Err(ApiError::InvalidRequest(
                        "Invalid Telegram username. Must be 5-32 characters, alphanumeric or underscore".into(),
                    ));
                }
                Ok(clean.to_string())
            }
            _ => Err(ApiError::MissingTelegramUsername),
        },
        CommsChannel::Signal => match input.signal_username {
            Some(username) if !username.trim().is_empty() => {
                Ok(username.trim().trim_start_matches('@').to_lowercase())
            }
            _ => Err(ApiError::MissingSignalNumber),
        },
    }
}

pub fn create_self_hosted_did_web(handle: &str) -> Result<String, ApiError> {
    if !tranquil_pds::util::is_self_hosted_did_web_enabled() {
        return Err(ApiError::SelfHostedDidWebDisabled);
    }
    let encoded_handle = handle.replace(':', "%3A");
    Ok(format!("did:web:{}", encoded_handle))
}

pub enum CredentialMatch {
    MainPassword,
    AppPassword {
        name: String,
        scopes: Option<String>,
        controller_did: Option<Did>,
    },
}

pub async fn verify_credential(
    session_repo: &dyn SessionRepository,
    user_id: uuid::Uuid,
    password: &str,
    password_hash: Option<&str>,
) -> Option<CredentialMatch> {
    let main_valid = password_hash
        .map(|h| bcrypt::verify(password, h).unwrap_or(false))
        .unwrap_or(false);
    if main_valid {
        return Some(CredentialMatch::MainPassword);
    }
    let app_passwords = session_repo
        .get_app_passwords_for_login(user_id)
        .await
        .unwrap_or_default();
    app_passwords
        .into_iter()
        .find(|app| bcrypt::verify(password, &app.password_hash).unwrap_or(false))
        .map(|app| CredentialMatch::AppPassword {
            name: app.name,
            scopes: app.scopes,
            controller_did: app.created_by_controller_did,
        })
}

pub fn hash_or_internal_error(value: &str) -> Result<String, ApiError> {
    bcrypt::hash(value, DEFAULT_COST).map_err(|e| {
        error!("Bcrypt hash error: {:?}", e);
        ApiError::InternalError(None)
    })
}

pub fn validate_token_hash(
    expires_at: Option<DateTime<Utc>>,
    stored_hash: &str,
    input_token: &str,
    expired_err: ApiError,
    invalid_err: ApiError,
) -> Result<(), ApiError> {
    match expires_at {
        Some(exp) if exp < Utc::now() => Err(expired_err),
        _ => match bcrypt::verify(input_token, stored_hash).unwrap_or(false) {
            true => Ok(()),
            false => Err(invalid_err),
        },
    }
}
