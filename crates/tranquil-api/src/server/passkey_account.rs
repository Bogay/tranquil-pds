use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use bcrypt::{DEFAULT_COST, hash};
use chrono::{Duration, Utc};
use jacquard_common::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::{mst::Mst, storage::BlockStore};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use tranquil_db_traits::WebauthnChallengeType;
use tranquil_pds::api::SuccessResponse;
use tranquil_pds::api::error::ApiError;
use tranquil_pds::auth::NormalizedLoginIdentifier;
use uuid::Uuid;

use tranquil_pds::auth::{ServiceTokenVerifier, generate_app_password, is_service_token};
use tranquil_pds::rate_limit::{AccountCreationLimit, PasswordResetLimit, RateLimited};
use tranquil_pds::repo_ops::create_signed_commit;
use tranquil_pds::state::AppState;
use tranquil_pds::types::{Did, Handle, PlainPassword};
use tranquil_pds::validation::validate_password;

fn generate_setup_token() -> String {
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePasskeyAccountInput {
    pub handle: String,
    pub email: Option<String>,
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
pub struct CreatePasskeyAccountResponse {
    pub did: Did,
    pub handle: Handle,
    pub setup_token: String,
    pub setup_expires_at: chrono::DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_jwt: Option<String>,
}

pub async fn create_passkey_account(
    State(state): State<AppState>,
    _rate_limit: RateLimited<AccountCreationLimit>,
    headers: HeaderMap,
    Json(input): Json<CreatePasskeyAccountInput>,
) -> Response {
    let byod_auth = if let Some(extracted) = tranquil_pds::auth::extract_auth_token_from_header(
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
                    debug!(
                        "Service token verified for BYOD did:web: iss={}",
                        claims.iss
                    );
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

    let is_byod_did_web = byod_auth.is_some()
        && input
            .did
            .as_ref()
            .map(|d| d.starts_with("did:web:"))
            .unwrap_or(false);

    let cfg = tranquil_config::get();
    let hostname = &cfg.server.hostname;
    let handle = match tranquil_pds::api::validation::resolve_handle_input(&input.handle) {
        Ok(h) => h,
        Err(_) => return ApiError::InvalidHandle(None).into_response(),
    };

    let email = input
        .email
        .as_ref()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(ref email) = email
        && !tranquil_pds::api::validation::is_valid_email(email)
    {
        return ApiError::InvalidEmail.into_response();
    }

    let is_bootstrap = state.bootstrap_invite_code.is_some()
        && state.user_repo.count_users().await.unwrap_or(1) == 0;

    let _validated_invite_code = if is_bootstrap {
        match input.invite_code.as_deref() {
            Some(code) if Some(code) == state.bootstrap_invite_code.as_deref() => None,
            _ => return ApiError::InvalidInviteCode.into_response(),
        }
    } else if let Some(ref code) = input.invite_code {
        match state.infra_repo.validate_invite_code(code).await {
            Ok(validated) => Some(validated),
            Err(_) => return ApiError::InvalidInviteCode.into_response(),
        }
    } else {
        let invite_required = tranquil_config::get().server.invite_code_required;
        if invite_required {
            return ApiError::InviteCodeRequired.into_response();
        }
        None
    };

    let verification_channel = input
        .verification_channel
        .unwrap_or(tranquil_db_traits::CommsChannel::Email);
    let verification_recipient = match verification_channel {
        tranquil_db_traits::CommsChannel::Email => match &email {
            Some(e) if !e.is_empty() => e.clone(),
            _ => return ApiError::MissingEmail.into_response(),
        },
        tranquil_db_traits::CommsChannel::Discord => match &input.discord_username {
            Some(username) if !username.trim().is_empty() => {
                let clean = username.trim().to_lowercase();
                if !tranquil_pds::api::validation::is_valid_discord_username(&clean) {
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
                if !tranquil_pds::api::validation::is_valid_telegram_username(clean) {
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
    };

    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    let pds_endpoint = format!("https://{}", hostname);
    let did_type = input.did_type.as_deref().unwrap_or("plc");

    let (secret_key_bytes, reserved_key_id): (Vec<u8>, Option<Uuid>) =
        if let Some(signing_key_did) = &input.signing_key {
            match state
                .infra_repo
                .get_reserved_signing_key(signing_key_did)
                .await
            {
                Ok(Some(reserved)) => (reserved.private_key_bytes, Some(reserved.id)),
                Ok(None) => {
                    return ApiError::InvalidSigningKey.into_response();
                }
                Err(e) => {
                    error!("Error looking up reserved signing key: {:?}", e);
                    return ApiError::InternalError(None).into_response();
                }
            }
        } else {
            let secret_key = k256::SecretKey::random(&mut OsRng);
            (secret_key.to_bytes().to_vec(), None)
        };

    let secret_key = match SigningKey::from_slice(&secret_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            error!("Error creating signing key: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let did = match did_type {
        "web" => {
            if !tranquil_pds::util::is_self_hosted_did_web_enabled() {
                return ApiError::SelfHostedDidWebDisabled.into_response();
            }
            let encoded_handle = handle.replace(':', "%3A");
            let self_hosted_did = format!("did:web:{}", encoded_handle);
            info!(did = %self_hosted_did, "Creating self-hosted did:web passkey account");
            self_hosted_did
        }
        "web-external" => {
            let d = match &input.did {
                Some(d) if !d.trim().is_empty() => d.trim(),
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
            if is_byod_did_web {
                if let Some(ref auth_did) = byod_auth
                    && d != auth_did.as_str()
                {
                    return ApiError::AuthorizationError(format!(
                        "Service token issuer {} does not match DID {}",
                        auth_did, d
                    ))
                    .into_response();
                }
                info!(did = %d, "Creating external did:web passkey account (BYOD key)");
            } else {
                if let Err(e) = crate::identity::did::verify_did_web(
                    d,
                    hostname,
                    &input.handle,
                    input.signing_key.as_deref(),
                )
                .await
                {
                    return ApiError::InvalidDid(e.to_string()).into_response();
                }
                info!(did = %d, "Creating external did:web passkey account (reserved key)");
            }
            d.to_string()
        }
        _ => {
            if let Some(ref auth_did) = byod_auth {
                if let Some(ref provided_did) = input.did {
                    if provided_did.starts_with("did:plc:") {
                        if provided_did != auth_did.as_str() {
                            return ApiError::AuthorizationError(format!(
                                "Service token issuer {} does not match DID {}",
                                auth_did, provided_did
                            ))
                            .into_response();
                        }
                        info!(did = %provided_did, "Creating BYOD did:plc passkey account (migration)");
                        provided_did.clone()
                    } else {
                        return ApiError::InvalidRequest(
                            "BYOD migration requires a did:plc or did:web DID".into(),
                        )
                        .into_response();
                    }
                } else {
                    return ApiError::InvalidRequest(
                        "BYOD migration requires the 'did' field".into(),
                    )
                    .into_response();
                }
            } else {
                let rotation_key = tranquil_config::get()
                    .secrets
                    .plc_rotation_key
                    .clone()
                    .unwrap_or_else(|| tranquil_pds::plc::signing_key_to_did_key(&secret_key));

                let genesis_result = match tranquil_pds::plc::create_genesis_operation(
                    &secret_key,
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

                let plc_client =
                    tranquil_pds::plc::PlcClient::with_cache(None, Some(state.cache.clone()));
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
                genesis_result.did
            }
        }
    };

    info!(did = %did, handle = %handle, "Created DID for passkey-only account");

    let setup_token = generate_setup_token();
    let setup_token_hash = match hash(&setup_token, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Error hashing setup token: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let setup_expires_at = Utc::now() + Duration::hours(1);

    let deactivated_at: Option<chrono::DateTime<Utc>> = if is_byod_did_web {
        Some(Utc::now())
    } else {
        None
    };

    let encrypted_key_bytes = match tranquil_pds::config::encrypt_key(&secret_key_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Error encrypting signing key: {:?}", e);
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
    let did_typed: Did = match did.parse() {
        Ok(d) => d,
        Err(_) => return ApiError::InternalError(Some("Invalid DID".into())).into_response(),
    };
    let (commit_bytes, _sig) =
        match create_signed_commit(&did_typed, mst_root, rev.as_ref(), None, &secret_key) {
            Ok(result) => result,
            Err(e) => {
                error!("Error creating genesis commit: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        };
    let commit_cid: cid::Cid = match state.block_store.put(&commit_bytes).await {
        Ok(c) => c,
        Err(e) => {
            error!("Error saving genesis commit: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let genesis_block_cids = vec![mst_root.to_bytes(), commit_cid.to_bytes()];

    let birthdate_pref = if tranquil_config::get().server.age_assurance_override {
        Some(json!({
            "$type": "app.bsky.actor.defs#personalDetailsPref",
            "birthDate": "1998-05-06T00:00:00.000Z"
        }))
    } else {
        None
    };

    let handle_typed: Handle = match handle.parse() {
        Ok(h) => h,
        Err(_) => return ApiError::InvalidHandle(None).into_response(),
    };
    let create_input = tranquil_db_traits::CreatePasskeyAccountInput {
        handle: handle_typed.clone(),
        email: email.clone().unwrap_or_default(),
        did: did_typed.clone(),
        preferred_comms_channel: verification_channel,
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
        setup_token_hash,
        setup_expires_at,
        deactivated_at,
        encrypted_key_bytes,
        encryption_version: tranquil_pds::config::ENCRYPTION_VERSION,
        reserved_key_id,
        commit_cid: commit_cid.to_string(),
        repo_rev: rev.as_ref().to_string(),
        genesis_block_cids,
        invite_code: if is_bootstrap {
            None
        } else {
            input.invite_code.clone()
        },
        birthdate_pref,
    };

    let create_result = match state.user_repo.create_passkey_account(&create_input).await {
        Ok(r) => r,
        Err(tranquil_db_traits::CreateAccountError::HandleTaken) => {
            return ApiError::HandleNotAvailable(None).into_response();
        }
        Err(tranquil_db_traits::CreateAccountError::EmailTaken) => {
            return ApiError::EmailTaken.into_response();
        }
        Err(e) => {
            error!("Error creating passkey account: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let user_id = create_result.user_id;

    if !is_byod_did_web {
        if let Err(e) =
            tranquil_pds::repo_ops::sequence_identity_event(&state, &did_typed, Some(&handle_typed))
                .await
        {
            warn!("Failed to sequence identity event for {}: {}", did, e);
        }
        if let Err(e) = tranquil_pds::repo_ops::sequence_account_event(
            &state,
            &did_typed,
            tranquil_db_traits::AccountStatus::Active,
        )
        .await
        {
            warn!("Failed to sequence account event for {}: {}", did, e);
        }
        let profile_record = serde_json::json!({
            "$type": "app.bsky.actor.profile",
            "displayName": handle
        });
        if let Err(e) = tranquil_pds::repo_ops::create_record_internal(
            &state,
            &did_typed,
            &tranquil_pds::types::PROFILE_COLLECTION,
            &tranquil_pds::types::PROFILE_RKEY,
            &profile_record,
        )
        .await
        {
            warn!("Failed to create default profile for {}: {}", did, e);
        }
    }

    let verification_token = tranquil_pds::auth::verification_token::generate_signup_token(
        &did_typed,
        verification_channel,
        &verification_recipient,
    );
    let formatted_token =
        tranquil_pds::auth::verification_token::format_token_for_display(&verification_token);
    if let Err(e) = tranquil_pds::comms::comms_repo::enqueue_signup_verification(
        state.user_repo.as_ref(),
        state.infra_repo.as_ref(),
        user_id,
        verification_channel,
        &verification_recipient,
        &formatted_token,
        hostname,
    )
    .await
    {
        warn!("Failed to enqueue signup verification: {:?}", e);
    }

    info!(did = %did, handle = %handle, "Passkey-only account created, awaiting setup completion");

    let access_jwt = if byod_auth.is_some() {
        match tranquil_pds::auth::create_access_token_with_metadata(&did, &secret_key_bytes) {
            Ok(token_meta) => {
                let refresh_jti = uuid::Uuid::new_v4().to_string();
                let refresh_expires = chrono::Utc::now() + chrono::Duration::hours(24);
                let session_data = tranquil_db::SessionTokenCreate {
                    did: did_typed.clone(),
                    access_jti: token_meta.jti.clone(),
                    refresh_jti,
                    access_expires_at: token_meta.expires_at,
                    refresh_expires_at: refresh_expires,
                    login_type: tranquil_db::LoginType::Modern,
                    mfa_verified: false,
                    scope: Some("transition:generic".to_string()),
                    controller_did: None,
                    app_password_name: None,
                };
                if let Err(e) = state.session_repo.create_session(&session_data).await {
                    warn!(did = %did, "Failed to insert migration session: {:?}", e);
                }
                info!(did = %did, "Generated migration access token for BYOD passkey account");
                Some(token_meta.token)
            }
            Err(e) => {
                warn!(did = %did, "Failed to generate migration access token: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    Json(CreatePasskeyAccountResponse {
        did: did.into(),
        handle: handle.into(),
        setup_token,
        setup_expires_at,
        access_jwt,
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletePasskeySetupInput {
    pub did: Did,
    pub setup_token: String,
    pub passkey_credential: serde_json::Value,
    pub passkey_friendly_name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletePasskeySetupResponse {
    pub did: Did,
    pub handle: Handle,
    pub app_password: String,
    pub app_password_name: String,
}

pub async fn complete_passkey_setup(
    State(state): State<AppState>,
    Json(input): Json<CompletePasskeySetupInput>,
) -> Response {
    let user = match state.user_repo.get_user_for_passkey_setup(&input.did).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if user.password_required {
        return ApiError::InvalidAccount.into_response();
    }

    let token_hash = match &user.recovery_token {
        Some(h) => h,
        None => {
            return ApiError::SetupExpired.into_response();
        }
    };

    if let Some(expires_at) = user.recovery_token_expires_at
        && expires_at < Utc::now()
    {
        return ApiError::SetupExpired.into_response();
    }

    if !bcrypt::verify(&input.setup_token, token_hash).unwrap_or(false) {
        return ApiError::InvalidToken(None).into_response();
    }

    let webauthn = &state.webauthn_config;

    let reg_state = match state
        .user_repo
        .load_webauthn_challenge(&input.did, WebauthnChallengeType::Registration)
        .await
    {
        Ok(Some(json)) => match serde_json::from_str(&json) {
            Ok(s) => s,
            Err(e) => {
                error!("Error deserializing registration state: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        },
        Ok(None) => {
            return ApiError::NoChallengeInProgress.into_response();
        }
        Err(e) => {
            error!("Error loading registration state: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let credential: webauthn_rs::prelude::RegisterPublicKeyCredential =
        match serde_json::from_value(input.passkey_credential) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to parse credential: {:?}", e);
                return ApiError::InvalidCredential.into_response();
            }
        };

    let security_key = match webauthn.finish_registration(&credential, &reg_state) {
        Ok(sk) => sk,
        Err(e) => {
            warn!("Passkey registration failed: {:?}", e);
            return ApiError::RegistrationFailed.into_response();
        }
    };

    let credential_id = security_key.cred_id().to_vec();
    let public_key = match serde_json::to_vec(&security_key) {
        Ok(pk) => pk,
        Err(e) => {
            error!("Error serializing security key: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    if let Err(e) = state
        .user_repo
        .save_passkey(
            &input.did,
            &credential_id,
            &public_key,
            input.passkey_friendly_name.as_deref(),
        )
        .await
    {
        error!("Error saving passkey: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let app_password = generate_app_password();
    let app_password_name = "bsky.app".to_string();
    let password_hash = match hash(&app_password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Error hashing app password: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let setup_input = tranquil_db_traits::CompletePasskeySetupInput {
        user_id: user.id,
        did: input.did.clone(),
        app_password_name: app_password_name.clone(),
        app_password_hash: password_hash,
    };
    if let Err(e) = state.user_repo.complete_passkey_setup(&setup_input).await {
        error!("Error completing passkey setup: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let _ = state
        .user_repo
        .delete_webauthn_challenge(&input.did, WebauthnChallengeType::Registration)
        .await;

    info!(did = %input.did, "Passkey-only account setup completed");

    Json(CompletePasskeySetupResponse {
        did: input.did.clone(),
        handle: user.handle,
        app_password,
        app_password_name,
    })
    .into_response()
}

pub async fn start_passkey_registration_for_setup(
    State(state): State<AppState>,
    Json(input): Json<StartPasskeyRegistrationInput>,
) -> Response {
    let user = match state.user_repo.get_user_for_passkey_setup(&input.did).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if user.password_required {
        return ApiError::InvalidAccount.into_response();
    }

    let token_hash = match &user.recovery_token {
        Some(h) => h,
        None => {
            return ApiError::SetupExpired.into_response();
        }
    };

    if let Some(expires_at) = user.recovery_token_expires_at
        && expires_at < Utc::now()
    {
        return ApiError::SetupExpired.into_response();
    }

    if !bcrypt::verify(&input.setup_token, token_hash).unwrap_or(false) {
        return ApiError::InvalidToken(None).into_response();
    }

    let webauthn = &state.webauthn_config;

    let existing_passkeys = state
        .user_repo
        .get_passkeys_for_user(&input.did)
        .await
        .unwrap_or_default();

    let exclude_credentials: Vec<webauthn_rs::prelude::CredentialID> = existing_passkeys
        .iter()
        .map(|p| webauthn_rs::prelude::CredentialID::from(p.credential_id.clone()))
        .collect();

    let display_name = input.friendly_name.as_deref().unwrap_or(&user.handle);

    let (ccr, reg_state) = match webauthn.start_registration(
        &input.did,
        &user.handle,
        display_name,
        exclude_credentials,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to start passkey registration: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let state_json = match serde_json::to_string(&reg_state) {
        Ok(json) => json,
        Err(e) => {
            error!("Failed to serialize registration state: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    if let Err(e) = state
        .user_repo
        .save_webauthn_challenge(&input.did, WebauthnChallengeType::Registration, &state_json)
        .await
    {
        error!("Failed to save registration state: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let options = serde_json::to_value(&ccr).unwrap_or(json!({}));
    Json(json!({"options": options})).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartPasskeyRegistrationInput {
    pub did: Did,
    pub setup_token: String,
    pub friendly_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPasskeyRecoveryInput {
    #[serde(alias = "identifier")]
    pub email: String,
}

pub async fn request_passkey_recovery(
    State(state): State<AppState>,
    _rate_limit: RateLimited<PasswordResetLimit>,
    Json(input): Json<RequestPasskeyRecoveryInput>,
) -> Response {
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let identifier = input.email.trim().to_lowercase();
    let identifier = identifier.strip_prefix('@').unwrap_or(&identifier);
    let normalized_handle =
        NormalizedLoginIdentifier::normalize(&input.email, hostname_for_handles);

    let user = match state
        .user_repo
        .get_user_for_passkey_recovery(identifier, normalized_handle.as_str())
        .await
    {
        Ok(Some(u)) if !u.password_required => u,
        _ => {
            return SuccessResponse::ok().into_response();
        }
    };

    let recovery_token = generate_setup_token();
    let recovery_token_hash = match hash(&recovery_token, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => {
            return ApiError::InternalError(None).into_response();
        }
    };
    let expires_at = Utc::now() + Duration::hours(1);

    if let Err(e) = state
        .user_repo
        .set_recovery_token(&user.did, &recovery_token_hash, expires_at)
        .await
    {
        error!("Error updating recovery token: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let hostname = &tranquil_config::get().server.hostname;
    let recovery_url = format!(
        "https://{}/app/recover-passkey?did={}&token={}",
        hostname,
        urlencoding::encode(&user.did),
        urlencoding::encode(&recovery_token)
    );

    let _ = tranquil_pds::comms::comms_repo::enqueue_passkey_recovery(
        state.user_repo.as_ref(),
        state.infra_repo.as_ref(),
        user.id,
        &recovery_url,
        hostname,
    )
    .await;

    info!(did = %user.did, "Passkey recovery requested");
    SuccessResponse::ok().into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverPasskeyAccountInput {
    pub did: Did,
    pub recovery_token: String,
    pub new_password: PlainPassword,
}

pub async fn recover_passkey_account(
    State(state): State<AppState>,
    Json(input): Json<RecoverPasskeyAccountInput>,
) -> Response {
    if let Err(e) = validate_password(&input.new_password) {
        return ApiError::InvalidRequest(e.to_string()).into_response();
    }

    let user = match state.user_repo.get_user_for_recovery(&input.did).await {
        Ok(Some(u)) => u,
        _ => {
            return ApiError::InvalidRecoveryLink.into_response();
        }
    };

    let token_hash = match &user.recovery_token {
        Some(h) => h,
        None => {
            return ApiError::InvalidRecoveryLink.into_response();
        }
    };

    if let Some(expires_at) = user.recovery_token_expires_at
        && expires_at < Utc::now()
    {
        return ApiError::RecoveryLinkExpired.into_response();
    }

    if !bcrypt::verify(&input.recovery_token, token_hash).unwrap_or(false) {
        return ApiError::InvalidRecoveryLink.into_response();
    }

    let password_hash = match hash(&input.new_password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => {
            return ApiError::InternalError(None).into_response();
        }
    };

    let recover_input = tranquil_db_traits::RecoverPasskeyAccountInput {
        did: input.did.clone(),
        password_hash,
    };
    let result = match state
        .user_repo
        .recover_passkey_account(&recover_input)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("Error recovering passkey account: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if result.passkeys_deleted > 0 {
        info!(did = %input.did, count = result.passkeys_deleted, "Deleted lost passkeys during account recovery");
    }
    if let Ok(Some(prefs)) = state.user_repo.get_comms_prefs(user.id).await {
        let actual_channel =
            tranquil_pds::comms::resolve_delivery_channel(&prefs, user.preferred_comms_channel);
        if let Err(e) = state
            .user_repo
            .set_channel_verified(&input.did, actual_channel)
            .await
        {
            warn!(
                "Failed to implicitly verify channel on passkey recovery: {:?}",
                e
            );
        }
    }
    info!(did = %input.did, "Passkey-only account recovered with temporary password");
    SuccessResponse::ok().into_response()
}
