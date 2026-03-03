use super::did::verify_did_web;
use crate::api::error::ApiError;
use crate::api::repo::record::utils::create_signed_commit;
use crate::auth::{ServiceTokenVerifier, extract_auth_token_from_header, is_service_token};
use crate::plc::{PlcClient, create_genesis_operation, signing_key_to_did_key};
use crate::rate_limit::{AccountCreationLimit, RateLimited};
use crate::state::AppState;
use crate::types::{Did, Handle, PlainPassword};
use crate::validation::validate_password;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bcrypt::{DEFAULT_COST, hash};
use jacquard_common::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::{mst::Mst, storage::BlockStore};
use k256::{SecretKey, ecdsa::SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountInput {
    pub handle: String,
    pub email: Option<String>,
    pub password: PlainPassword,
    pub invite_code: Option<String>,
    pub did: Option<String>,
    pub did_type: Option<String>,
    pub signing_key: Option<String>,
    pub verification_channel: Option<tranquil_db_traits::CommsChannel>,
    pub discord_username: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_username: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountOutput {
    pub handle: Handle,
    pub did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_doc: Option<serde_json::Value>,
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub verification_required: bool,
    pub verification_channel: tranquil_db_traits::CommsChannel,
}

pub async fn create_account(
    State(state): State<AppState>,
    _rate_limit: RateLimited<AccountCreationLimit>,
    headers: HeaderMap,
    Json(input): Json<CreateAccountInput>,
) -> Response {
    let is_potential_migration = input
        .did
        .as_ref()
        .map(|d| d.starts_with("did:plc:"))
        .unwrap_or(false);
    if is_potential_migration {
        info!(
            "[MIGRATION] createAccount called for potential migration did={:?} handle={}",
            input.did, input.handle
        );
    } else {
        info!("create_account called");
    }

    let migration_auth = if let Some(extracted) = extract_auth_token_from_header(
        crate::util::get_header_str(&headers, http::header::AUTHORIZATION),
    ) {
        let token = extracted.token;
        if is_service_token(&token) {
            let verifier = ServiceTokenVerifier::new();
            match verifier
                .verify_service_token(&token, Some("com.atproto.server.createAccount"))
                .await
            {
                Ok(claims) => {
                    debug!("Service token verified for migration: iss={}", claims.iss);
                    Some(claims.iss)
                }
                Err(e) => {
                    error!("Service token verification failed: {:?}", e);
                    return ApiError::AuthenticationFailed(Some(format!(
                        "Service token verification failed: {}",
                        e
                    )))
                    .into_response();
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let is_did_web_byod = migration_auth.is_some()
        && input
            .did
            .as_ref()
            .map(|d| d.starts_with("did:web:"))
            .unwrap_or(false);

    let is_migration = migration_auth.is_some()
        && input
            .did
            .as_ref()
            .map(|d| d.starts_with("did:plc:"))
            .unwrap_or(false);

    if (is_migration || is_did_web_byod)
        && let (Some(provided_did), Some(auth_did)) = (input.did.as_ref(), migration_auth.as_ref())
    {
        if provided_did != auth_did.as_str() {
            info!(
                "[MIGRATION] createAccount: Service token mismatch - token_did={} provided_did={}",
                auth_did, provided_did
            );
            return ApiError::AuthorizationError(format!(
                "Service token issuer {} does not match DID {}",
                auth_did, provided_did
            ))
            .into_response();
        }
        if is_did_web_byod {
            info!(did = %provided_did, "Processing did:web BYOD account creation");
        } else {
            info!(
                "[MIGRATION] createAccount: Service token verified, processing migration for did={}",
                provided_did
            );
        }
    }

    let hostname_for_validation = tranquil_config::get().server.hostname_without_port();
    let pds_suffix = format!(".{}", hostname_for_validation);

    let validated_short_handle = if !input.handle.contains('.')
        || input.handle.ends_with(&pds_suffix)
    {
        let handle_to_validate = if input.handle.ends_with(&pds_suffix) {
            input
                .handle
                .strip_suffix(&pds_suffix)
                .unwrap_or(&input.handle)
        } else {
            &input.handle
        };
        match crate::api::validation::validate_short_handle(handle_to_validate) {
            Ok(h) => h,
            Err(e) => {
                return ApiError::from(e).into_response();
            }
        }
    } else {
        if input.handle.contains(' ') || input.handle.contains('\t') {
            return ApiError::InvalidRequest("Handle cannot contain spaces".into()).into_response();
        }
        if let Some(c) = input
            .handle
            .chars()
            .find(|c| !c.is_ascii_alphanumeric() && *c != '.' && *c != '-')
        {
            return ApiError::InvalidRequest(format!("Handle contains invalid character: {}", c))
                .into_response();
        }
        let handle_lower = input.handle.to_lowercase();
        if crate::moderation::has_explicit_slur(&handle_lower) {
            return ApiError::InvalidRequest("Inappropriate language in handle".into())
                .into_response();
        }
        handle_lower
    };
    let email: Option<String> = input
        .email
        .as_ref()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(ref email) = email
        && !crate::api::validation::is_valid_email(email)
    {
        return ApiError::InvalidEmail.into_response();
    }
    let verification_channel = input
        .verification_channel
        .unwrap_or(tranquil_db_traits::CommsChannel::Email);
    let verification_recipient = if is_migration {
        None
    } else {
        Some(match verification_channel {
            tranquil_db_traits::CommsChannel::Email => match &input.email {
                Some(email) if !email.trim().is_empty() => email.trim().to_string(),
                _ => return ApiError::MissingEmail.into_response(),
            },
            tranquil_db_traits::CommsChannel::Discord => match &input.discord_username {
                Some(username) if !username.trim().is_empty() => {
                    let clean = username.trim().to_lowercase();
                    if !crate::api::validation::is_valid_discord_username(&clean) {
                        return ApiError::InvalidRequest(
                            "Invalid Discord username. Must be 2-32 lowercase characters (letters, numbers, underscores, periods)".into(),
                        ).into_response();
                    }
                    clean
                }
                _ => return ApiError::MissingDiscordId.into_response(),
            },
            tranquil_db_traits::CommsChannel::Telegram => match &input.telegram_username {
                Some(username) if !username.trim().is_empty() => {
                    let clean = username.trim().trim_start_matches('@');
                    if !crate::api::validation::is_valid_telegram_username(clean) {
                        return ApiError::InvalidRequest(
                            "Invalid Telegram username. Must be 5-32 characters, alphanumeric or underscore".into(),
                        ).into_response();
                    }
                    clean.to_string()
                }
                _ => return ApiError::MissingTelegramUsername.into_response(),
            },
            tranquil_db_traits::CommsChannel::Signal => match &input.signal_username {
                Some(username) if !username.trim().is_empty() => {
                    username.trim().trim_start_matches('@').to_lowercase()
                }
                _ => return ApiError::MissingSignalNumber.into_response(),
            },
        })
    };
    let hostname = &tranquil_config::get().server.hostname;
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let pds_endpoint = format!("https://{}", hostname);
    let suffix = format!(".{}", hostname_for_handles);
    let handle = if input.handle.ends_with(&suffix) {
        format!("{}.{}", validated_short_handle, hostname_for_handles)
    } else if input.handle.contains('.') {
        validated_short_handle.clone()
    } else {
        format!("{}.{}", validated_short_handle, hostname_for_handles)
    };
    let (secret_key_bytes, reserved_key_id): (Vec<u8>, Option<uuid::Uuid>) =
        if let Some(signing_key_did) = &input.signing_key {
            match state
                .infra_repo
                .get_reserved_signing_key(signing_key_did)
                .await
            {
                Ok(Some(key)) => (key.private_key_bytes, Some(key.id)),
                Ok(None) => {
                    return ApiError::InvalidSigningKey.into_response();
                }
                Err(e) => {
                    error!("Error looking up reserved signing key: {:?}", e);
                    return ApiError::InternalError(None).into_response();
                }
            }
        } else {
            let secret_key = SecretKey::random(&mut OsRng);
            (secret_key.to_bytes().to_vec(), None)
        };
    let signing_key = match SigningKey::from_slice(&secret_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            error!("Error creating signing key: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let did_type = input.did_type.as_deref().unwrap_or("plc");
    let did = match did_type {
        "web" => {
            if !crate::api::server::meta::is_self_hosted_did_web_enabled() {
                return ApiError::SelfHostedDidWebDisabled.into_response();
            }
            let subdomain_host = format!("{}.{}", input.handle, hostname_for_handles);
            let encoded_subdomain = subdomain_host.replace(':', "%3A");
            let self_hosted_did = format!("did:web:{}", encoded_subdomain);
            info!(did = %self_hosted_did, "Creating self-hosted did:web account (subdomain)");
            self_hosted_did
        }
        "web-external" => {
            let d = match &input.did {
                Some(d) if !d.trim().is_empty() => d,
                _ => {
                    return ApiError::InvalidRequest(
                        "External did:web requires the 'did' field to be provided".into(),
                    )
                    .into_response();
                }
            };
            if !d.starts_with("did:web:") {
                return ApiError::InvalidDid("External DID must be a did:web".into())
                    .into_response();
            }
            if !is_did_web_byod
                && let Err(e) =
                    verify_did_web(d, hostname, &input.handle, input.signing_key.as_deref()).await
            {
                return ApiError::InvalidDid(e.to_string()).into_response();
            }
            info!(did = %d, "Creating external did:web account");
            d.clone()
        }
        _ => {
            if let Some(d) = &input.did {
                if d.starts_with("did:plc:") && is_migration {
                    info!(did = %d, "Migration with existing did:plc");
                    d.clone()
                } else if d.starts_with("did:web:") {
                    if !is_did_web_byod
                        && let Err(e) =
                            verify_did_web(d, hostname, &input.handle, input.signing_key.as_deref())
                                .await
                    {
                        return ApiError::InvalidDid(e.to_string()).into_response();
                    }
                    d.clone()
                } else if !d.trim().is_empty() {
                    return ApiError::InvalidDid(
                        "Only did:web DIDs can be provided; leave empty for did:plc. For migration with existing did:plc, provide service auth.".into()
                    )
                    .into_response();
                } else {
                    let rotation_key = tranquil_config::get()
                        .secrets
                        .plc_rotation_key
                        .clone()
                        .unwrap_or_else(|| signing_key_to_did_key(&signing_key));
                    let genesis_result = match create_genesis_operation(
                        &signing_key,
                        &rotation_key,
                        &handle,
                        &pds_endpoint,
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            error!("Error creating PLC genesis operation: {:?}", e);
                            return ApiError::InternalError(Some(
                                "Failed to create PLC operation".into(),
                            ))
                            .into_response();
                        }
                    };
                    let plc_client = PlcClient::with_cache(None, Some(state.cache.clone()));
                    if let Err(e) = plc_client
                        .send_operation(&genesis_result.did, &genesis_result.signed_operation)
                        .await
                    {
                        error!("Failed to submit PLC genesis operation: {:?}", e);
                        return ApiError::UpstreamErrorMsg(format!(
                            "Failed to register DID with PLC directory: {}",
                            e
                        ))
                        .into_response();
                    }
                    info!(did = %genesis_result.did, "Successfully registered DID with PLC directory");
                    genesis_result.did
                }
            } else {
                let rotation_key = tranquil_config::get()
                    .secrets
                    .plc_rotation_key
                    .clone()
                    .unwrap_or_else(|| signing_key_to_did_key(&signing_key));
                let genesis_result = match create_genesis_operation(
                    &signing_key,
                    &rotation_key,
                    &handle,
                    &pds_endpoint,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Error creating PLC genesis operation: {:?}", e);
                        return ApiError::InternalError(Some(
                            "Failed to create PLC operation".into(),
                        ))
                        .into_response();
                    }
                };
                let plc_client = PlcClient::with_cache(None, Some(state.cache.clone()));
                if let Err(e) = plc_client
                    .send_operation(&genesis_result.did, &genesis_result.signed_operation)
                    .await
                {
                    error!("Failed to submit PLC genesis operation: {:?}", e);
                    return ApiError::UpstreamErrorMsg(format!(
                        "Failed to register DID with PLC directory: {}",
                        e
                    ))
                    .into_response();
                }
                info!(did = %genesis_result.did, "Successfully registered DID with PLC directory");
                genesis_result.did
            }
        }
    };
    if is_migration {
        let did_typed: Did = match did.parse() {
            Ok(d) => d,
            Err(_) => return ApiError::InternalError(Some("Invalid DID".into())).into_response(),
        };
        let handle_typed: Handle = match handle.parse() {
            Ok(h) => h,
            Err(_) => return ApiError::InvalidHandle(None).into_response(),
        };
        let reactivate_input = tranquil_db_traits::MigrationReactivationInput {
            did: did_typed.clone(),
            new_handle: handle_typed.clone(),
            new_email: email.clone(),
        };
        match state
            .user_repo
            .reactivate_migration_account(&reactivate_input)
            .await
        {
            Ok(reactivated) => {
                info!(did = %did, old_handle = %reactivated.old_handle, new_handle = %handle, "Preparing existing account for inbound migration");
                let secret_key_bytes = match state
                    .user_repo
                    .get_user_key_by_id(reactivated.user_id)
                    .await
                {
                    Ok(Some(key_info)) => {
                        match crate::config::decrypt_key(
                            &key_info.key_bytes,
                            key_info.encryption_version,
                        ) {
                            Ok(k) => k,
                            Err(e) => {
                                error!("Error decrypting key for reactivated account: {:?}", e);
                                return ApiError::InternalError(None).into_response();
                            }
                        }
                    }
                    _ => {
                        error!("No signing key found for reactivated account");
                        return ApiError::InternalError(Some(
                            "Account signing key not found".into(),
                        ))
                        .into_response();
                    }
                };
                let access_meta =
                    match crate::auth::create_access_token_with_metadata(&did, &secret_key_bytes) {
                        Ok(m) => m,
                        Err(e) => {
                            error!("Error creating access token: {:?}", e);
                            return ApiError::InternalError(None).into_response();
                        }
                    };
                let refresh_meta = match crate::auth::create_refresh_token_with_metadata(
                    &did,
                    &secret_key_bytes,
                ) {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Error creating refresh token: {:?}", e);
                        return ApiError::InternalError(None).into_response();
                    }
                };
                let session_data = tranquil_db_traits::SessionTokenCreate {
                    did: did_typed.clone(),
                    access_jti: access_meta.jti.clone(),
                    refresh_jti: refresh_meta.jti.clone(),
                    access_expires_at: access_meta.expires_at,
                    refresh_expires_at: refresh_meta.expires_at,
                    login_type: tranquil_db_traits::LoginType::Modern,
                    mfa_verified: false,
                    scope: None,
                    controller_did: None,
                    app_password_name: None,
                };
                if let Err(e) = state.session_repo.create_session(&session_data).await {
                    error!("Error creating session: {:?}", e);
                    return ApiError::InternalError(None).into_response();
                }
                let hostname = &tranquil_config::get().server.hostname;
                let verification_required = if let Some(ref user_email) = email {
                    let token = crate::auth::verification_token::generate_migration_token(
                        &did_typed, user_email,
                    );
                    let formatted_token =
                        crate::auth::verification_token::format_token_for_display(&token);
                    if let Err(e) = crate::comms::comms_repo::enqueue_migration_verification(
                        state.user_repo.as_ref(),
                        state.infra_repo.as_ref(),
                        reactivated.user_id,
                        user_email,
                        &formatted_token,
                        hostname,
                    )
                    .await
                    {
                        warn!("Failed to enqueue migration verification email: {:?}", e);
                    }
                    true
                } else {
                    false
                };
                return (
                    axum::http::StatusCode::OK,
                    Json(CreateAccountOutput {
                        handle: handle.clone().into(),
                        did: did_typed.clone(),
                        did_doc: state.did_resolver.resolve_did_document(&did).await,
                        access_jwt: access_meta.token,
                        refresh_jwt: refresh_meta.token,
                        verification_required,
                        verification_channel: tranquil_db_traits::CommsChannel::Email,
                    }),
                )
                    .into_response();
            }
            Err(tranquil_db_traits::MigrationReactivationError::NotFound) => {}
            Err(tranquil_db_traits::MigrationReactivationError::NotDeactivated) => {
                return ApiError::AccountAlreadyExists.into_response();
            }
            Err(tranquil_db_traits::MigrationReactivationError::HandleTaken) => {
                return ApiError::HandleTaken.into_response();
            }
            Err(e) => {
                error!("Error reactivating migration account: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        }
    }

    let handle_typed: Handle = match handle.parse() {
        Ok(h) => h,
        Err(_) => return ApiError::InvalidHandle(None).into_response(),
    };
    let handle_available = match state
        .user_repo
        .check_handle_available_for_new_account(&handle_typed)
        .await
    {
        Ok(available) => available,
        Err(e) => {
            error!("Error checking handle availability: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    if !handle_available {
        return ApiError::HandleTaken.into_response();
    }

    let is_bootstrap = state.bootstrap_invite_code.is_some()
        && state.user_repo.count_users().await.unwrap_or(1) == 0;

    if is_bootstrap {
        match input.invite_code.as_deref() {
            Some(code) if Some(code) == state.bootstrap_invite_code.as_deref() => {}
            _ => return ApiError::InvalidInviteCode.into_response(),
        }
    } else {
        let invite_code_required = tranquil_config::get().server.invite_code_required;
        if invite_code_required
            && input
                .invite_code
                .as_ref()
                .map(|c| c.trim().is_empty())
                .unwrap_or(true)
        {
            return ApiError::InviteCodeRequired.into_response();
        }
        if let Some(code) = &input.invite_code
            && !code.trim().is_empty()
        {
            let valid = match state.user_repo.check_and_consume_invite_code(code).await {
                Ok(v) => v,
                Err(e) => {
                    error!("Error checking invite code: {:?}", e);
                    return ApiError::InternalError(None).into_response();
                }
            };
            if !valid {
                return ApiError::InvalidInviteCode.into_response();
            }
        }
    }

    if let Err(e) = validate_password(&input.password) {
        return ApiError::InvalidRequest(e.to_string()).into_response();
    }

    let password_clone = input.password.clone();
    let password_hash =
        match tokio::task::spawn_blocking(move || hash(&password_clone, DEFAULT_COST)).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                error!("Error hashing password: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
            Err(e) => {
                error!("Failed to spawn blocking task: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        };

    let deactivated_at: Option<chrono::DateTime<chrono::Utc>> = if is_migration || is_did_web_byod {
        Some(chrono::Utc::now())
    } else {
        None
    };

    let encrypted_key_bytes = match crate::config::encrypt_key(&secret_key_bytes) {
        Ok(enc) => enc,
        Err(e) => {
            error!("Error encrypting user key: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let mst = Mst::new(Arc::new(state.block_store.clone()));
    let mst_root = match mst.persist().await {
        Ok(c) => c,
        Err(e) => {
            error!("Error persisting MST: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let rev = Tid::now(LimitedU32::MIN);
    let did_for_commit: Did = match did.parse() {
        Ok(d) => d,
        Err(_) => return ApiError::InternalError(Some("Invalid DID".into())).into_response(),
    };
    let (commit_bytes, _sig) =
        match create_signed_commit(&did_for_commit, mst_root, rev.as_ref(), None, &signing_key) {
            Ok(result) => result,
            Err(e) => {
                error!("Error creating genesis commit: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        };
    let commit_cid = match state.block_store.put(&commit_bytes).await {
        Ok(c) => c,
        Err(e) => {
            error!("Error saving genesis commit: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let commit_cid_str = commit_cid.to_string();
    let rev_str = rev.as_ref().to_string();
    let genesis_block_cids = vec![mst_root.to_bytes(), commit_cid.to_bytes()];

    let birthdate_pref = if tranquil_config::get().server.age_assurance_override {
        Some(json!({
            "$type": "app.bsky.actor.defs#personalDetailsPref",
            "birthDate": "1998-05-06T00:00:00.000Z"
        }))
    } else {
        None
    };

    let preferred_comms_channel = verification_channel;

    let create_input = tranquil_db_traits::CreatePasswordAccountInput {
        handle: handle_typed.clone(),
        email: email.clone(),
        did: did_for_commit.clone(),
        password_hash,
        preferred_comms_channel,
        discord_username: input
            .discord_username
            .as_deref()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty()),
        telegram_username: input
            .telegram_username
            .as_deref()
            .map(|s| s.trim().trim_start_matches('@'))
            .filter(|s| !s.is_empty())
            .map(String::from),
        signal_username: input
            .signal_username
            .as_deref()
            .map(|s| s.trim().trim_start_matches('@'))
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase()),
        deactivated_at,
        encrypted_key_bytes,
        encryption_version: crate::config::ENCRYPTION_VERSION,
        reserved_key_id,
        commit_cid: commit_cid_str.clone(),
        repo_rev: rev_str.clone(),
        genesis_block_cids,
        invite_code: if is_bootstrap {
            None
        } else {
            input.invite_code.clone()
        },
        birthdate_pref,
    };

    let create_result = match state.user_repo.create_password_account(&create_input).await {
        Ok(r) => r,
        Err(tranquil_db_traits::CreateAccountError::HandleTaken) => {
            return ApiError::HandleNotAvailable(None).into_response();
        }
        Err(tranquil_db_traits::CreateAccountError::EmailTaken) => {
            return ApiError::EmailTaken.into_response();
        }
        Err(tranquil_db_traits::CreateAccountError::DidExists) => {
            return ApiError::AccountAlreadyExists.into_response();
        }
        Err(e) => {
            error!("Error creating password account: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let user_id = create_result.user_id;
    if !is_migration && !is_did_web_byod {
        if let Err(e) = crate::api::repo::record::sequence_identity_event(
            &state,
            &did_for_commit,
            Some(&handle_typed),
        )
        .await
        {
            warn!("Failed to sequence identity event for {}: {}", did, e);
        }
        if let Err(e) = crate::api::repo::record::sequence_account_event(
            &state,
            &did_for_commit,
            tranquil_db_traits::AccountStatus::Active,
        )
        .await
        {
            warn!("Failed to sequence account event for {}: {}", did, e);
        }
        if let Err(e) = crate::api::repo::record::sequence_genesis_commit(
            &state,
            &did_for_commit,
            &commit_cid,
            &mst_root,
            &rev_str,
        )
        .await
        {
            warn!("Failed to sequence commit event for {}: {}", did, e);
        }
        if let Err(e) = crate::api::repo::record::sequence_sync_event(
            &state,
            &did_for_commit,
            &commit_cid_str,
            Some(rev.as_ref()),
        )
        .await
        {
            warn!("Failed to sequence sync event for {}: {}", did, e);
        }
        let profile_record = json!({
            "$type": "app.bsky.actor.profile",
            "displayName": input.handle
        });
        if let Err(e) = crate::api::repo::record::create_record_internal(
            &state,
            &did_for_commit,
            &crate::types::PROFILE_COLLECTION,
            &crate::types::PROFILE_RKEY,
            &profile_record,
        )
        .await
        {
            warn!("Failed to create default profile for {}: {}", did, e);
        }
    }
    let hostname = &tranquil_config::get().server.hostname;
    if !is_migration {
        if let Some(ref recipient) = verification_recipient {
            let verification_token = crate::auth::verification_token::generate_signup_token(
                &did_for_commit,
                verification_channel,
                recipient,
            );
            let formatted_token =
                crate::auth::verification_token::format_token_for_display(&verification_token);
            if let Err(e) = crate::comms::comms_repo::enqueue_signup_verification(
                state.user_repo.as_ref(),
                state.infra_repo.as_ref(),
                user_id,
                verification_channel,
                recipient,
                &formatted_token,
                hostname,
            )
            .await
            {
                warn!(
                    "Failed to enqueue signup verification notification: {:?}",
                    e
                );
            }
        }
    } else if let Some(ref user_email) = email {
        let token =
            crate::auth::verification_token::generate_migration_token(&did_for_commit, user_email);
        let formatted_token = crate::auth::verification_token::format_token_for_display(&token);
        if let Err(e) = crate::comms::comms_repo::enqueue_migration_verification(
            state.user_repo.as_ref(),
            state.infra_repo.as_ref(),
            user_id,
            user_email,
            &formatted_token,
            hostname,
        )
        .await
        {
            warn!("Failed to enqueue migration verification email: {:?}", e);
        }
    }

    let access_meta = match crate::auth::create_access_token_with_metadata(&did, &secret_key_bytes)
    {
        Ok(m) => m,
        Err(e) => {
            error!("createAccount: Error creating access token: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let refresh_meta =
        match crate::auth::create_refresh_token_with_metadata(&did, &secret_key_bytes) {
            Ok(m) => m,
            Err(e) => {
                error!("createAccount: Error creating refresh token: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        };
    let session_data = tranquil_db_traits::SessionTokenCreate {
        did: did_for_commit.clone(),
        access_jti: access_meta.jti.clone(),
        refresh_jti: refresh_meta.jti.clone(),
        access_expires_at: access_meta.expires_at,
        refresh_expires_at: refresh_meta.expires_at,
        login_type: tranquil_db_traits::LoginType::Modern,
        mfa_verified: false,
        scope: None,
        controller_did: None,
        app_password_name: None,
    };
    if let Err(e) = state.session_repo.create_session(&session_data).await {
        error!("createAccount: Error creating session: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let did_doc = state.did_resolver.resolve_did_document(&did).await;

    if is_migration {
        info!(
            "[MIGRATION] createAccount: SUCCESS - Account ready for migration did={} handle={}",
            did, handle
        );
    }

    (
        StatusCode::OK,
        Json(CreateAccountOutput {
            handle: handle.clone().into(),
            did: did_for_commit,
            did_doc,
            access_jwt: access_meta.token,
            refresh_jwt: refresh_meta.token,
            verification_required: !is_migration,
            verification_channel,
        }),
    )
        .into_response()
}
