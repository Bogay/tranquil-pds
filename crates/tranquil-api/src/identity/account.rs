use super::did::verify_did_web;
use crate::common;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, error, info};
use tranquil_pds::api::error::ApiError;
use tranquil_pds::auth::{ServiceTokenVerifier, extract_auth_token_from_header, is_service_token};
use tranquil_pds::rate_limit::{AccountCreationLimit, RateLimited};
use tranquil_pds::state::AppState;
use tranquil_pds::types::{Did, Handle, PlainPassword};
use tranquil_pds::validation::validate_password;

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

async fn try_reactivate_migration(
    state: &AppState,
    did: &str,
    handle: &str,
    email: &Option<String>,
    verification_channel: tranquil_db_traits::CommsChannel,
    verification_recipient: Option<&str>,
) -> Option<Response> {
    let did_typed: Did = match did.parse() {
        Ok(d) => d,
        Err(_) => return Some(ApiError::InternalError(Some("Invalid DID".into())).into_response()),
    };
    let handle_typed: Handle = match handle.parse() {
        Ok(h) => h,
        Err(_) => return Some(ApiError::InvalidHandle(None).into_response()),
    };
    let reactivate_input = tranquil_db_traits::MigrationReactivationInput {
        did: did_typed.clone(),
        new_handle: handle_typed.clone(),
        new_email: email.clone(),
    };
    match state
        .repos
        .user
        .reactivate_migration_account(&reactivate_input)
        .await
    {
        Ok(reactivated) => {
            info!(did = %did, old_handle = %reactivated.old_handle, new_handle = %handle, "Preparing existing account for inbound migration");
            let secret_key_bytes = match state
                .repos
                .user
                .get_user_key_by_id(reactivated.user_id)
                .await
            {
                Ok(Some(key_info)) => {
                    match tranquil_pds::config::decrypt_key(
                        &key_info.key_bytes,
                        key_info.encryption_version,
                    ) {
                        Ok(k) => k,
                        Err(e) => {
                            error!("Error decrypting key for reactivated account: {:?}", e);
                            return Some(ApiError::InternalError(None).into_response());
                        }
                    }
                }
                _ => {
                    error!("No signing key found for reactivated account");
                    return Some(
                        ApiError::InternalError(Some("Account signing key not found".into()))
                            .into_response(),
                    );
                }
            };
            let access_meta =
                match tranquil_pds::auth::create_access_token_with_metadata(did, &secret_key_bytes)
                {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Error creating access token: {:?}", e);
                        return Some(ApiError::InternalError(None).into_response());
                    }
                };
            let refresh_meta = match tranquil_pds::auth::create_refresh_token_with_metadata(
                did,
                &secret_key_bytes,
            ) {
                Ok(m) => m,
                Err(e) => {
                    error!("Error creating refresh token: {:?}", e);
                    return Some(ApiError::InternalError(None).into_response());
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
                scope: Some("transition:generic transition:chat.bsky".to_string()),
                controller_did: None,
                app_password_name: None,
            };
            if let Err(e) = state.repos.session.create_session(&session_data).await {
                error!("Error creating session: {:?}", e);
                return Some(ApiError::InternalError(None).into_response());
            }
            let verification_required = match verification_recipient {
                Some(recipient) => {
                    super::provision::enqueue_migration_verification(
                        state,
                        reactivated.user_id,
                        &did_typed,
                        verification_channel,
                        recipient,
                    )
                    .await;
                    true
                }
                None => false,
            };
            Some(
                (
                    StatusCode::OK,
                    Json(CreateAccountOutput {
                        handle: handle.to_string().into(),
                        did: did_typed.clone(),
                        did_doc: state
                            .did_resolver
                            .fetch_did_document(did)
                            .await
                            .ok()
                            .and_then(|f| Some((*f).clone())),
                        access_jwt: access_meta.token,
                        refresh_jwt: refresh_meta.token,
                        verification_required,
                        verification_channel,
                    }),
                )
                    .into_response(),
            )
        }
        Err(tranquil_db_traits::MigrationReactivationError::NotFound) => None,
        Err(tranquil_db_traits::MigrationReactivationError::NotDeactivated) => {
            Some(ApiError::AccountAlreadyExists.into_response())
        }
        Err(tranquil_db_traits::MigrationReactivationError::HandleTaken) => {
            Some(ApiError::HandleTaken.into_response())
        }
        Err(e) => {
            error!("Error reactivating migration account: {:?}", e);
            Some(ApiError::InternalError(None).into_response())
        }
    }
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
        tranquil_pds::util::get_header_str(&headers, http::header::AUTHORIZATION),
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

    let cfg = tranquil_config::get();
    let handle = match tranquil_pds::api::validation::resolve_handle_input(&input.handle) {
        Ok(h) => h,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let email: Option<String> = input
        .email
        .as_ref()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(ref email) = email
        && !tranquil_pds::api::validation::is_valid_email(email)
    {
        return ApiError::InvalidEmail.into_response();
    }
    let verification_channel = input
        .verification_channel
        .unwrap_or(tranquil_db_traits::CommsChannel::Email);
    let verification_recipient = {
        Some(
            match common::extract_verification_recipient(
                verification_channel,
                &common::ChannelInput {
                    email: input.email.as_deref(),
                    discord_username: input.discord_username.as_deref(),
                    telegram_username: input.telegram_username.as_deref(),
                    signal_username: input.signal_username.as_deref(),
                },
            ) {
                Ok(r) => r,
                Err(e) => return e.into_response(),
            },
        )
    };
    let hostname = &cfg.server.hostname;
    let key_result =
        match super::provision::resolve_signing_key(&state, input.signing_key.as_deref()).await {
            Ok(k) => k,
            Err(e) => return e.into_response(),
        };
    let secret_key_bytes = key_result.secret_key_bytes;
    let signing_key = key_result.signing_key;
    let reserved_key_id = key_result.reserved_key_id;
    let did_type = input.did_type.as_deref().unwrap_or("plc");
    let did = match did_type {
        "web" => {
            let self_hosted_did = match common::create_self_hosted_did_web(&handle) {
                Ok(d) => d,
                Err(e) => return e.into_response(),
            };
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
                    match super::provision::submit_plc_genesis(&state, &signing_key, &handle).await
                    {
                        Ok(did) => did,
                        Err(e) => return e.into_response(),
                    }
                }
            } else {
                match super::provision::submit_plc_genesis(&state, &signing_key, &handle).await {
                    Ok(did) => did,
                    Err(e) => return e.into_response(),
                }
            }
        }
    };
    if is_migration
        && let Some(response) = try_reactivate_migration(
            &state,
            &did,
            &handle,
            &email,
            verification_channel,
            verification_recipient.as_deref(),
        )
        .await
    {
        return response;
    }

    let handle_typed: Handle = match handle.parse() {
        Ok(h) => h,
        Err(_) => return ApiError::InvalidHandle(None).into_response(),
    };
    let handle_available = match state
        .repos
        .user
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
        && state.repos.user.count_users().await.unwrap_or(1) == 0;

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
            let valid = match state.repos.user.check_and_consume_invite_code(code).await {
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

    let password_hash = match crate::common::hash_password_async(&input.password).await {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };

    let deactivated_at: Option<chrono::DateTime<chrono::Utc>> = if is_migration || is_did_web_byod {
        Some(chrono::Utc::now())
    } else {
        None
    };

    let did_for_commit: Did = match did.parse() {
        Ok(d) => d,
        Err(_) => return ApiError::InternalError(Some("Invalid DID".into())).into_response(),
    };
    let repo = match super::provision::init_genesis_repo(
        &state,
        &did_for_commit,
        &signing_key,
        &secret_key_bytes,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let commit_cid_str = repo.commit_cid.to_string();
    let rev_str = repo.repo_rev.clone();

    let birthdate_pref = if tranquil_config::get().server.age_assurance_override {
        Some(json!({
            "$type": "app.bsky.actor.defs#personalDetailsPref",
            "birthDate": "1998-05-06T00:00:00.000Z"
        }))
    } else {
        None
    };

    let comms = super::provision::normalize_comms_usernames(
        input.discord_username.as_deref(),
        input.telegram_username.as_deref(),
        input.signal_username.as_deref(),
    );
    let preferred_comms_channel = verification_channel;
    let repo_for_seq = repo.clone();

    let create_input = tranquil_db_traits::CreatePasswordAccountInput {
        handle: handle_typed.clone(),
        email: email.clone(),
        did: did_for_commit.clone(),
        password_hash,
        preferred_comms_channel,
        discord_username: comms.discord,
        telegram_username: comms.telegram,
        signal_username: comms.signal,
        deactivated_at,
        encrypted_key_bytes: repo.encrypted_key_bytes,
        encryption_version: tranquil_pds::config::ENCRYPTION_VERSION,
        reserved_key_id,
        commit_cid: commit_cid_str.clone(),
        repo_rev: rev_str.clone(),
        genesis_block_cids: repo.genesis_block_cids,
        invite_code: if is_bootstrap {
            None
        } else {
            input.invite_code.clone()
        },
        birthdate_pref,
    };

    let create_result = match state
        .repos
        .user
        .create_password_account(&create_input)
        .await
    {
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
        super::provision::sequence_new_account(
            &state,
            &did_for_commit,
            &handle_typed,
            &repo_for_seq,
            &input.handle,
        )
        .await;
    }
    if !is_migration {
        if let Some(ref recipient) = verification_recipient {
            super::provision::enqueue_signup_verification(
                &state,
                user_id,
                &did_for_commit,
                verification_channel,
                recipient,
            )
            .await;
        }
    } else if let Some(ref recipient) = verification_recipient {
        super::provision::enqueue_migration_verification(
            &state,
            user_id,
            &did_for_commit,
            verification_channel,
            recipient,
        )
        .await;
    }

    let session = match super::provision::create_and_store_session(
        &state,
        &did,
        &did_for_commit,
        &secret_key_bytes,
        "transition:generic transition:chat.bsky",
        None,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    let did_doc = state.did_resolver.fetch_did_document(&did).await.ok();

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
            did_doc: did_doc.and_then(|f| Some((*f).clone())),
            access_jwt: session.access_jwt,
            refresh_jwt: session.refresh_jwt,
            verification_required: !is_migration,
            verification_channel,
        }),
    )
        .into_response()
}
