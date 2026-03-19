use crate::common;
use axum::{Json, extract::State, http::HeaderMap};
use chrono::{Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, error, info, warn};
use tranquil_db_traits::WebauthnChallengeType;
use tranquil_pds::api::error::ApiError;
use tranquil_pds::api::{OptionsResponse, SuccessResponse};
use tranquil_pds::auth::NormalizedLoginIdentifier;

use tranquil_pds::auth::{ServiceTokenVerifier, generate_app_password, is_service_token};
use tranquil_pds::rate_limit::{AccountCreationLimit, PasswordResetLimit, RateLimited};
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
pub struct CreatePasskeyAccountOutput {
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
) -> Result<Json<CreatePasskeyAccountOutput>, ApiError> {
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
                    return Err(ApiError::AuthenticationFailed(Some(format!(
                        "Service token verification failed: {}",
                        e
                    ))));
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
        Err(_) => return Err(ApiError::InvalidHandle(None)),
    };

    let email = input
        .email
        .as_ref()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(ref email) = email
        && !tranquil_pds::api::validation::is_valid_email(email)
    {
        return Err(ApiError::InvalidEmail);
    }

    let is_bootstrap = state.bootstrap_invite_code.is_some()
        && state.user_repo.count_users().await.unwrap_or(1) == 0;

    let _validated_invite_code = if is_bootstrap {
        match input.invite_code.as_deref() {
            Some(code) if Some(code) == state.bootstrap_invite_code.as_deref() => None,
            _ => return Err(ApiError::InvalidInviteCode),
        }
    } else if let Some(ref code) = input.invite_code {
        match state.infra_repo.validate_invite_code(code).await {
            Ok(validated) => Some(validated),
            Err(_) => return Err(ApiError::InvalidInviteCode),
        }
    } else {
        let invite_required = tranquil_config::get().server.invite_code_required;
        if invite_required {
            return Err(ApiError::InviteCodeRequired);
        }
        None
    };

    let verification_channel = input
        .verification_channel
        .unwrap_or(tranquil_db_traits::CommsChannel::Email);
    let verification_recipient = match common::extract_verification_recipient(
        verification_channel,
        &common::ChannelInput {
            email: email.as_deref(),
            discord_username: input.discord_username.as_deref(),
            telegram_username: input.telegram_username.as_deref(),
            signal_username: input.signal_username.as_deref(),
        },
    ) {
        Ok(r) => r,
        Err(e) => return Err(e),
    };

    let pds_endpoint = format!("https://{}", hostname);
    let did_type = input.did_type.as_deref().unwrap_or("plc");

    let key_result =
        match crate::identity::provision::resolve_signing_key(&state, input.signing_key.as_deref())
            .await
        {
            Ok(k) => k,
            Err(e) => return Err(e),
        };
    let secret_key_bytes = key_result.secret_key_bytes;
    let secret_key = key_result.signing_key;
    let reserved_key_id = key_result.reserved_key_id;

    let did = match did_type {
        "web" => {
            let self_hosted_did = match common::create_self_hosted_did_web(&handle) {
                Ok(d) => d,
                Err(e) => return Err(e),
            };
            info!(did = %self_hosted_did, "Creating self-hosted did:web passkey account");
            self_hosted_did
        }
        "web-external" => {
            let d = match &input.did {
                Some(d) if !d.trim().is_empty() => d.trim(),
                _ => {
                    return Err(ApiError::InvalidRequest(
                        "External did:web requires the 'did' field to be provided".into(),
                    ));
                }
            };
            if !d.starts_with("did:web:") {
                return Err(ApiError::InvalidDid(
                    "External DID must be a did:web".into(),
                ));
            }
            if is_byod_did_web {
                if let Some(ref auth_did) = byod_auth
                    && d != auth_did.as_str()
                {
                    return Err(ApiError::AuthorizationError(format!(
                        "Service token issuer {} does not match DID {}",
                        auth_did, d
                    )));
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
                    return Err(ApiError::InvalidDid(e.to_string()));
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
                            return Err(ApiError::AuthorizationError(format!(
                                "Service token issuer {} does not match DID {}",
                                auth_did, provided_did
                            )));
                        }
                        info!(did = %provided_did, "Creating BYOD did:plc passkey account (migration)");
                        provided_did.clone()
                    } else {
                        return Err(ApiError::InvalidRequest(
                            "BYOD migration requires a did:plc or did:web DID".into(),
                        ));
                    }
                } else {
                    return Err(ApiError::InvalidRequest(
                        "BYOD migration requires the 'did' field".into(),
                    ));
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
                        return Err(ApiError::InternalError(Some(
                            "Failed to create PLC operation".into(),
                        )));
                    }
                };

                let plc_client =
                    tranquil_pds::plc::PlcClient::with_cache(None, Some(state.cache.clone()));
                if let Err(e) = plc_client
                    .send_operation(&genesis_result.did, &genesis_result.signed_operation)
                    .await
                {
                    error!("Failed to submit PLC genesis operation: {:?}", e);
                    return Err(ApiError::UpstreamErrorMsg(format!(
                        "Failed to register DID with PLC directory: {}",
                        e
                    )));
                }
                genesis_result.did
            }
        }
    };

    info!(did = %did, handle = %handle, "Created DID for passkey-only account");

    let setup_token = generate_setup_token();
    let setup_token_hash = common::hash_or_internal_error(&setup_token)?;
    let setup_expires_at = Utc::now() + Duration::hours(1);

    let deactivated_at: Option<chrono::DateTime<Utc>> = if is_byod_did_web {
        Some(Utc::now())
    } else {
        None
    };

    let did_typed: Did = match did.parse() {
        Ok(d) => d,
        Err(_) => return Err(ApiError::InternalError(Some("Invalid DID".into()))),
    };
    let repo = match crate::identity::provision::init_genesis_repo(
        &state,
        &did_typed,
        &secret_key,
        &secret_key_bytes,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return Err(e),
    };

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
        Err(_) => return Err(ApiError::InvalidHandle(None)),
    };
    let repo_for_seq = repo.clone();
    let comms = crate::identity::provision::normalize_comms_usernames(
        input.discord_username.as_deref(),
        input.telegram_username.as_deref(),
        input.signal_username.as_deref(),
    );
    let create_input = tranquil_db_traits::CreatePasskeyAccountInput {
        handle: handle_typed.clone(),
        email: email.clone().unwrap_or_default(),
        did: did_typed.clone(),
        preferred_comms_channel: verification_channel,
        discord_username: comms.discord,
        telegram_username: comms.telegram,
        signal_username: comms.signal,
        setup_token_hash,
        setup_expires_at,
        deactivated_at,
        encrypted_key_bytes: repo.encrypted_key_bytes,
        encryption_version: tranquil_pds::config::ENCRYPTION_VERSION,
        reserved_key_id,
        commit_cid: repo.commit_cid.to_string(),
        repo_rev: repo.repo_rev.clone(),
        genesis_block_cids: repo.genesis_block_cids,
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
            return Err(ApiError::HandleNotAvailable(None));
        }
        Err(tranquil_db_traits::CreateAccountError::EmailTaken) => {
            return Err(ApiError::EmailTaken);
        }
        Err(e) => {
            error!("Error creating passkey account: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    let user_id = create_result.user_id;

    if !is_byod_did_web {
        crate::identity::provision::sequence_new_account(
            &state,
            &did_typed,
            &handle_typed,
            &repo_for_seq,
            &handle,
        )
        .await;
    }

    crate::identity::provision::enqueue_signup_verification(
        &state,
        user_id,
        &did_typed,
        verification_channel,
        &verification_recipient,
    )
    .await;

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

    Ok(Json(CreatePasskeyAccountOutput {
        did: did.into(),
        handle: handle.into(),
        setup_token,
        setup_expires_at,
        access_jwt,
    }))
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
pub struct CompletePasskeySetupOutput {
    pub did: Did,
    pub handle: Handle,
    pub app_password: String,
    pub app_password_name: String,
}

pub async fn complete_passkey_setup(
    State(state): State<AppState>,
    Json(input): Json<CompletePasskeySetupInput>,
) -> Result<Json<CompletePasskeySetupOutput>, ApiError> {
    let user = match state.user_repo.get_user_for_passkey_setup(&input.did).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Err(ApiError::AccountNotFound);
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    if user.password_required {
        return Err(ApiError::InvalidAccount);
    }

    let token_hash = match &user.recovery_token {
        Some(h) => h,
        None => {
            return Err(ApiError::SetupExpired);
        }
    };

    common::validate_token_hash(
        user.recovery_token_expires_at,
        token_hash,
        &input.setup_token,
        ApiError::SetupExpired,
        ApiError::InvalidToken(None),
    )?;

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
                return Err(ApiError::InternalError(None));
            }
        },
        Ok(None) => {
            return Err(ApiError::NoChallengeInProgress);
        }
        Err(e) => {
            error!("Error loading registration state: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    let credential: webauthn_rs::prelude::RegisterPublicKeyCredential =
        match serde_json::from_value(input.passkey_credential) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to parse credential: {:?}", e);
                return Err(ApiError::InvalidCredential);
            }
        };

    let security_key = match webauthn.finish_registration(&credential, &reg_state) {
        Ok(sk) => sk,
        Err(e) => {
            warn!("Passkey registration failed: {:?}", e);
            return Err(ApiError::RegistrationFailed);
        }
    };

    let credential_id = security_key.cred_id().to_vec();
    let public_key = match serde_json::to_vec(&security_key) {
        Ok(pk) => pk,
        Err(e) => {
            error!("Error serializing security key: {:?}", e);
            return Err(ApiError::InternalError(None));
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
        return Err(ApiError::InternalError(None));
    }

    let app_password = generate_app_password();
    let app_password_name = "bsky.app".to_string();
    let password_hash = common::hash_or_internal_error(&app_password)?;

    let setup_input = tranquil_db_traits::CompletePasskeySetupInput {
        user_id: user.id,
        did: input.did.clone(),
        app_password_name: app_password_name.clone(),
        app_password_hash: password_hash,
    };
    if let Err(e) = state.user_repo.complete_passkey_setup(&setup_input).await {
        error!("Error completing passkey setup: {:?}", e);
        return Err(ApiError::InternalError(None));
    }

    let _ = state
        .user_repo
        .delete_webauthn_challenge(&input.did, WebauthnChallengeType::Registration)
        .await;

    info!(did = %input.did, "Passkey-only account setup completed");

    Ok(Json(CompletePasskeySetupOutput {
        did: input.did.clone(),
        handle: user.handle,
        app_password,
        app_password_name,
    }))
}

pub async fn start_passkey_registration_for_setup(
    State(state): State<AppState>,
    Json(input): Json<StartPasskeyRegistrationInput>,
) -> Result<Json<OptionsResponse<serde_json::Value>>, ApiError> {
    let user = match state.user_repo.get_user_for_passkey_setup(&input.did).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Err(ApiError::AccountNotFound);
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    if user.password_required {
        return Err(ApiError::InvalidAccount);
    }

    let token_hash = match &user.recovery_token {
        Some(h) => h,
        None => {
            return Err(ApiError::SetupExpired);
        }
    };

    common::validate_token_hash(
        user.recovery_token_expires_at,
        token_hash,
        &input.setup_token,
        ApiError::SetupExpired,
        ApiError::InvalidToken(None),
    )?;

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
            return Err(ApiError::InternalError(None));
        }
    };

    let state_json = match serde_json::to_string(&reg_state) {
        Ok(json) => json,
        Err(e) => {
            error!("Failed to serialize registration state: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    if let Err(e) = state
        .user_repo
        .save_webauthn_challenge(&input.did, WebauthnChallengeType::Registration, &state_json)
        .await
    {
        error!("Failed to save registration state: {:?}", e);
        return Err(ApiError::InternalError(None));
    }

    let options = serde_json::to_value(&ccr).unwrap_or(json!({}));
    Ok(OptionsResponse::new(options))
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
) -> Result<Json<SuccessResponse>, ApiError> {
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
            return Ok(Json(SuccessResponse { success: true }));
        }
    };

    let recovery_token = generate_setup_token();
    let recovery_token_hash = common::hash_or_internal_error(&recovery_token)?;
    let expires_at = Utc::now() + Duration::hours(1);

    if let Err(e) = state
        .user_repo
        .set_recovery_token(&user.did, &recovery_token_hash, expires_at)
        .await
    {
        error!("Error updating recovery token: {:?}", e);
        return Err(ApiError::InternalError(None));
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
    Ok(Json(SuccessResponse { success: true }))
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
) -> Result<Json<SuccessResponse>, ApiError> {
    if let Err(e) = validate_password(&input.new_password) {
        return Err(ApiError::InvalidRequest(e.to_string()));
    }

    let user = match state.user_repo.get_user_for_recovery(&input.did).await {
        Ok(Some(u)) => u,
        _ => {
            return Err(ApiError::InvalidRecoveryLink);
        }
    };

    let token_hash = match &user.recovery_token {
        Some(h) => h,
        None => {
            return Err(ApiError::InvalidRecoveryLink);
        }
    };

    common::validate_token_hash(
        user.recovery_token_expires_at,
        token_hash,
        &input.recovery_token,
        ApiError::RecoveryLinkExpired,
        ApiError::InvalidRecoveryLink,
    )?;

    let password_hash = common::hash_or_internal_error(&input.new_password)?;

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
            return Err(ApiError::InternalError(None));
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
    Ok(Json(SuccessResponse { success: true }))
}
