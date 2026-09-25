use bcrypt::hash;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tracing::{error, warn};
use tranquil_db_traits::{CommsChannel, DidWebOverrides, SessionRepository, UserRepository};
use tranquil_pds::api::error::ApiError;
use tranquil_pds::api::error::DbResultExt;
use tranquil_pds::types::{AtIdentifier, Did, Handle, PasswordHash};
use tranquil_types::{DiscordUsername, SignalUsername, TelegramUsername};

#[cfg(not(feature = "low-bcrypt-cost"))]
const PASSWORD_HASH_COST: u32 = bcrypt::DEFAULT_COST;
// Use a lower bcrypt cost in tests.
#[cfg(feature = "low-bcrypt-cost")]
const PASSWORD_HASH_COST: u32 = 4;

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
) -> HashMap<tranquil_types::InviteCode, Vec<U>>
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
) -> Result<tranquil_pds::comms::VerificationTarget, ApiError> {
    match channel {
        CommsChannel::Email => {
            let raw = trimmed(input.email).ok_or(ApiError::MissingEmail)?;
            let address = tranquil_types::EmailAddress::new(raw)?;
            Ok(tranquil_pds::comms::VerificationTarget::direct(
                tranquil_db_traits::Recipient::Email(address),
            ))
        }
        CommsChannel::Signal => {
            let raw = trimmed(input.signal_username).ok_or(ApiError::MissingSignalNumber)?;
            let username = SignalUsername::new(raw)?;
            Ok(tranquil_pds::comms::VerificationTarget::direct(
                tranquil_db_traits::Recipient::Signal(username),
            ))
        }
        CommsChannel::Telegram => {
            let raw = trimmed(input.telegram_username).ok_or(ApiError::MissingTelegramUsername)?;
            let username = TelegramUsername::new(raw)?;
            tranquil_pds::comms::VerificationTarget::resolve(
                channel,
                username.as_str(),
                input.email,
            )
        }
        CommsChannel::Discord => {
            let raw = trimmed(input.discord_username).ok_or(ApiError::MissingDiscordId)?;
            let username = DiscordUsername::new(raw)?;
            tranquil_pds::comms::VerificationTarget::resolve(
                channel,
                username.as_str(),
                input.email,
            )
        }
    }
}

fn trimmed(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|value| !value.is_empty())
}

pub async fn implicitly_verify_channel(
    user_repo: &dyn UserRepository,
    did: &Did,
    user_id: uuid::Uuid,
    preferred_channel: CommsChannel,
    context: &'static str,
) {
    let Ok(Some(prefs)) = user_repo.get_comms_prefs(user_id).await else {
        return;
    };
    let Some(recipient) = tranquil_pds::comms::recipient_for(&prefs, preferred_channel) else {
        warn!(
            did = %did,
            preferred = ?preferred_channel,
            "We skipped implicit verification on {context} because the account doesn't have a valid recipient"
        );
        return;
    };
    if let Err(e) = user_repo
        .set_channel_verified(did, recipient.channel())
        .await
    {
        warn!("Implicit verification on {context} failed: {:?}", e);
    }
}

pub fn create_self_hosted_did_web(handle: &str) -> Result<Did, ApiError> {
    if !tranquil_pds::util::is_self_hosted_did_web_enabled() {
        return Err(ApiError::SelfHostedDidWebDisabled);
    }
    let encoded_handle = handle.replace(':', "%3A");
    Did::new(format!("did:web:{}", encoded_handle))
        .map_err(|_| ApiError::InvalidHandle(Some("Handle is not a valid did:web".into())))
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
    password_hash: Option<&PasswordHash>,
) -> Option<CredentialMatch> {
    let main_valid = password_hash
        .map(|h| bcrypt::verify(password, h.as_str()).unwrap_or(false))
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
        .find(|app| bcrypt::verify(password, app.password_hash.as_str()).unwrap_or(false))
        .map(|app| {
            let scopes = app.scopes.unwrap_or_else(|| {
                if app.privilege.is_privileged() {
                    "transition:generic transition:chat.bsky".to_string()
                } else {
                    "transition:generic".to_string()
                }
            });
            CredentialMatch::AppPassword {
                name: app.name,
                scopes: Some(scopes),
                controller_did: app.created_by_controller_did,
            }
        })
}

pub fn hash_or_internal_error(value: &str) -> Result<PasswordHash, ApiError> {
    bcrypt::hash(value, PASSWORD_HASH_COST)
        .map(PasswordHash::new)
        .map_err(|e| {
            error!("Bcrypt hash error: {:?}", e);
            ApiError::InternalError(None)
        })
}

pub async fn hash_password_async(password: &str) -> Result<PasswordHash, ApiError> {
    let password = password.to_string();
    tokio::task::spawn_blocking(move || hash(password, PASSWORD_HASH_COST))
        .await
        .map_err(|e| {
            error!("Failed to spawn blocking task: {:?}", e);
            ApiError::InternalError(None)
        })?
        .map(PasswordHash::new)
        .map_err(|e| {
            error!("Failed to hash password: {:?}", e);
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
