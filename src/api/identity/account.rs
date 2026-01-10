use super::did::verify_did_web;
use crate::api::error::ApiError;
use crate::api::repo::record::utils::create_signed_commit;
use crate::auth::{ServiceTokenVerifier, is_service_token};
use crate::plc::{PlcClient, create_genesis_operation, signing_key_to_did_key};
use crate::state::{AppState, RateLimitKind};
use crate::types::{Did, Handle, Nsid, PlainPassword, Rkey};
use crate::validation::validate_password;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bcrypt::{DEFAULT_COST, hash};
use jacquard::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::{mst::Mst, storage::BlockStore};
use k256::{SecretKey, ecdsa::SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(value) = forwarded.to_str()
        && let Some(first_ip) = value.split(',').next()
    {
        return first_ip.trim().to_string();
    }
    if let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(value) = real_ip.to_str()
    {
        return value.trim().to_string();
    }
    "unknown".to_string()
}

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
    pub verification_channel: Option<String>,
    pub discord_id: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_number: Option<String>,
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
    pub verification_channel: String,
}

pub async fn create_account(
    State(state): State<AppState>,
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
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::AccountCreation, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Account creation rate limit exceeded");
        return ApiError::RateLimitExceeded(Some(
            "Too many account creation attempts. Please try again later.".into(),
        ))
        .into_response();
    }

    let migration_auth = if let Some(extracted) = crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
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
        if provided_did != auth_did {
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

    let hostname_for_validation =
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
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
        for c in input.handle.chars() {
            if !c.is_ascii_alphanumeric() && c != '.' && c != '-' {
                return ApiError::InvalidRequest(format!(
                    "Handle contains invalid character: {}",
                    c
                ))
                .into_response();
            }
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
    let verification_channel = input.verification_channel.as_deref().unwrap_or("email");
    let valid_channels = ["email", "discord", "telegram", "signal"];
    if !valid_channels.contains(&verification_channel) && !is_migration {
        return ApiError::InvalidVerificationChannel.into_response();
    }
    let verification_recipient = if is_migration {
        None
    } else {
        Some(match verification_channel {
            "email" => match &input.email {
                Some(email) if !email.trim().is_empty() => email.trim().to_string(),
                _ => return ApiError::MissingEmail.into_response(),
            },
            "discord" => match &input.discord_id {
                Some(id) if !id.trim().is_empty() => id.trim().to_string(),
                _ => return ApiError::MissingDiscordId.into_response(),
            },
            "telegram" => match &input.telegram_username {
                Some(username) if !username.trim().is_empty() => username.trim().to_string(),
                _ => return ApiError::MissingTelegramUsername.into_response(),
            },
            "signal" => match &input.signal_number {
                Some(number) if !number.trim().is_empty() => number.trim().to_string(),
                _ => return ApiError::MissingSignalNumber.into_response(),
            },
            _ => return ApiError::InvalidVerificationChannel.into_response(),
        })
    };
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let suffix = format!(".{}", hostname);
    let handle = if input.handle.ends_with(&suffix) {
        format!("{}.{}", validated_short_handle, hostname)
    } else if input.handle.contains('.') {
        validated_short_handle.clone()
    } else {
        format!("{}.{}", validated_short_handle, hostname)
    };
    let (secret_key_bytes, reserved_key_id): (Vec<u8>, Option<uuid::Uuid>) =
        if let Some(signing_key_did) = &input.signing_key {
            let reserved = sqlx::query!(
                r#"
                SELECT id, private_key_bytes
                FROM reserved_signing_keys
                WHERE public_key_did_key = $1
                  AND used_at IS NULL
                  AND expires_at > NOW()
                FOR UPDATE
                "#,
                signing_key_did
            )
            .fetch_optional(&state.db)
            .await;
            match reserved {
                Ok(Some(row)) => (row.private_key_bytes, Some(row.id)),
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
            let subdomain_host = format!("{}.{}", input.handle, hostname);
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
                    verify_did_web(d, &hostname, &input.handle, input.signing_key.as_deref()).await
            {
                return ApiError::InvalidDid(e).into_response();
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
                        && let Err(e) = verify_did_web(
                            d,
                            &hostname,
                            &input.handle,
                            input.signing_key.as_deref(),
                        )
                        .await
                    {
                        return ApiError::InvalidDid(e).into_response();
                    }
                    d.clone()
                } else if !d.trim().is_empty() {
                    return ApiError::InvalidDid(
                        "Only did:web DIDs can be provided; leave empty for did:plc. For migration with existing did:plc, provide service auth.".into()
                    )
                    .into_response();
                } else {
                    let rotation_key = std::env::var("PLC_ROTATION_KEY")
                        .unwrap_or_else(|_| signing_key_to_did_key(&signing_key));
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
                let rotation_key = std::env::var("PLC_ROTATION_KEY")
                    .unwrap_or_else(|_| signing_key_to_did_key(&signing_key));
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
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Error starting transaction: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    if is_migration {
        let existing_account: Option<(uuid::Uuid, String, Option<chrono::DateTime<chrono::Utc>>)> =
            sqlx::query_as("SELECT id, handle, deactivated_at FROM users WHERE did = $1 FOR UPDATE")
                .bind(&did)
                .fetch_optional(&mut *tx)
                .await
                .unwrap_or(None);
        if let Some((account_id, old_handle, deactivated_at)) = existing_account {
            if deactivated_at.is_some() {
                info!(did = %did, old_handle = %old_handle, new_handle = %handle, "Preparing existing account for inbound migration");
                let update_result: Result<_, sqlx::Error> =
                    sqlx::query("UPDATE users SET handle = $1 WHERE id = $2")
                        .bind(&handle)
                        .bind(account_id)
                        .execute(&mut *tx)
                        .await;
                if let Err(e) = update_result {
                    if let Some(db_err) = e.as_database_error()
                        && db_err
                            .constraint()
                            .map(|c| c.contains("handle"))
                            .unwrap_or(false)
                    {
                        return ApiError::HandleTaken.into_response();
                    }
                    error!("Error reactivating account: {:?}", e);
                    return ApiError::InternalError(None).into_response();
                }
                if let Err(e) = tx.commit().await {
                    error!("Error committing reactivation: {:?}", e);
                    return ApiError::InternalError(None).into_response();
                }
                let key_row: Option<(Vec<u8>, i32)> = sqlx::query_as(
                    "SELECT key_bytes, encryption_version FROM user_keys WHERE user_id = $1",
                )
                .bind(account_id)
                .fetch_optional(&state.db)
                .await
                .unwrap_or(None);
                let secret_key_bytes = match key_row {
                    Some((key_bytes, encryption_version)) => {
                        match crate::config::decrypt_key(&key_bytes, Some(encryption_version)) {
                            Ok(k) => k,
                            Err(e) => {
                                error!("Error decrypting key for reactivated account: {:?}", e);
                                return ApiError::InternalError(None).into_response();
                            }
                        }
                    }
                    None => {
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
                let session_result: Result<_, sqlx::Error> = sqlx::query(
                    "INSERT INTO session_tokens (did, access_jti, refresh_jti, access_expires_at, refresh_expires_at) VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(&did)
                .bind(&access_meta.jti)
                .bind(&refresh_meta.jti)
                .bind(access_meta.expires_at)
                .bind(refresh_meta.expires_at)
                .execute(&state.db)
                .await;
                if let Err(e) = session_result {
                    error!("Error creating session: {:?}", e);
                    return ApiError::InternalError(None).into_response();
                }
                return (
                    axum::http::StatusCode::OK,
                    Json(CreateAccountOutput {
                        handle: handle.clone().into(),
                        did: did.clone().into(),
                        did_doc: state.did_resolver.resolve_did_document(&did).await,
                        access_jwt: access_meta.token,
                        refresh_jwt: refresh_meta.token,
                        verification_required: false,
                        verification_channel: "email".to_string(),
                    }),
                )
                    .into_response();
            } else {
                return ApiError::AccountAlreadyExists.into_response();
            }
        }
    }
    let exists_result: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM users WHERE handle = $1 AND deactivated_at IS NULL")
            .bind(&handle)
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or(None);
    if exists_result.is_some() {
        return ApiError::HandleTaken.into_response();
    }
    let invite_code_required = std::env::var("INVITE_CODE_REQUIRED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
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
        let invite_query = sqlx::query!(
            "SELECT available_uses FROM invite_codes WHERE code = $1 FOR UPDATE",
            code
        )
        .fetch_optional(&mut *tx)
        .await;
        match invite_query {
            Ok(Some(row)) => {
                if row.available_uses <= 0 {
                    return ApiError::InvalidInviteCode.into_response();
                }
                let update_invite = sqlx::query!(
                    "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
                    code
                )
                .execute(&mut *tx)
                .await;
                if let Err(e) = update_invite {
                    error!("Error updating invite code: {:?}", e);
                    return ApiError::InternalError(None).into_response();
                }
            }
            Ok(None) => {
                return ApiError::InvalidInviteCode.into_response();
            }
            Err(e) => {
                error!("Error checking invite code: {:?}", e);
                return ApiError::InternalError(None).into_response();
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
    let is_first_user = sqlx::query_scalar!("SELECT COUNT(*) as count FROM users")
        .fetch_one(&mut *tx)
        .await
        .map(|c| c.unwrap_or(0) == 0)
        .unwrap_or(false);
    let deactivated_at: Option<chrono::DateTime<chrono::Utc>> = if is_migration || is_did_web_byod {
        Some(chrono::Utc::now())
    } else {
        None
    };
    let user_insert: Result<(uuid::Uuid,), _> = sqlx::query_as(
        r#"INSERT INTO users (
            handle, email, did, password_hash,
            preferred_comms_channel,
            discord_id, telegram_username, signal_number,
            is_admin, deactivated_at, email_verified
        ) VALUES ($1, $2, $3, $4, $5::comms_channel, $6, $7, $8, $9, $10, $11) RETURNING id"#,
    )
    .bind(&handle)
    .bind(&email)
    .bind(&did)
    .bind(&password_hash)
    .bind(verification_channel)
    .bind(
        input
            .discord_id
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty()),
    )
    .bind(
        input
            .telegram_username
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty()),
    )
    .bind(
        input
            .signal_number
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty()),
    )
    .bind(is_first_user)
    .bind(deactivated_at)
    .bind(false)
    .fetch_one(&mut *tx)
    .await;
    let user_id = match user_insert {
        Ok((id,)) => id,
        Err(e) => {
            if let Some(db_err) = e.as_database_error()
                && db_err.code().as_deref() == Some("23505")
            {
                let constraint = db_err.constraint().unwrap_or("");
                if constraint.contains("handle") || constraint.contains("users_handle") {
                    return ApiError::HandleNotAvailable(None).into_response();
                } else if constraint.contains("email") || constraint.contains("users_email") {
                    return ApiError::EmailTaken.into_response();
                } else if constraint.contains("did") || constraint.contains("users_did") {
                    return ApiError::AccountAlreadyExists.into_response();
                }
            }
            error!("Error inserting user: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let encrypted_key_bytes = match crate::config::encrypt_key(&secret_key_bytes) {
        Ok(enc) => enc,
        Err(e) => {
            error!("Error encrypting user key: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let key_insert = sqlx::query!(
        "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, NOW())",
        user_id,
        &encrypted_key_bytes[..],
        crate::config::ENCRYPTION_VERSION
    )
    .execute(&mut *tx)
    .await;
    if let Err(e) = key_insert {
        error!("Error inserting user key: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }
    if let Some(key_id) = reserved_key_id {
        let mark_used = sqlx::query!(
            "UPDATE reserved_signing_keys SET used_at = NOW() WHERE id = $1",
            key_id
        )
        .execute(&mut *tx)
        .await;
        if let Err(e) = mark_used {
            error!("Error marking reserved key as used: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    }
    let mst = Mst::new(Arc::new(state.block_store.clone()));
    let mst_root = match mst.persist().await {
        Ok(c) => c,
        Err(e) => {
            error!("Error persisting MST: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let rev = Tid::now(LimitedU32::MIN);
    let did_for_commit = Did::new_unchecked(&did);
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
    let repo_insert = sqlx::query!(
        "INSERT INTO repos (user_id, repo_root_cid, repo_rev) VALUES ($1, $2, $3)",
        user_id,
        commit_cid_str,
        rev_str
    )
    .execute(&mut *tx)
    .await;
    if let Err(e) = repo_insert {
        error!("Error initializing repo: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }
    let genesis_block_cids = vec![mst_root.to_bytes(), commit_cid.to_bytes()];
    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO user_blocks (user_id, block_cid)
        SELECT $1, block_cid FROM UNNEST($2::bytea[]) AS t(block_cid)
        ON CONFLICT (user_id, block_cid) DO NOTHING
        "#,
        user_id,
        &genesis_block_cids
    )
    .execute(&mut *tx)
    .await
    {
        error!("Error inserting user_blocks: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }
    if let Some(code) = &input.invite_code
        && !code.trim().is_empty()
    {
        let use_insert = sqlx::query!(
            "INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)",
            code,
            user_id
        )
        .execute(&mut *tx)
        .await;
        if let Err(e) = use_insert {
            error!("Error recording invite usage: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    }
    if std::env::var("PDS_AGE_ASSURANCE_OVERRIDE").is_ok() {
        let birthdate_pref = json!({
            "$type": "app.bsky.actor.defs#personalDetailsPref",
            "birthDate": "1998-05-06T00:00:00.000Z"
        });
        if let Err(e) = sqlx::query!(
            "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)
             ON CONFLICT (user_id, name) DO NOTHING",
            user_id,
            "app.bsky.actor.defs#personalDetailsPref",
            birthdate_pref
        )
        .execute(&mut *tx)
        .await
        {
            warn!("Failed to set default birthdate preference: {:?}", e);
        }
    }
    if let Err(e) = tx.commit().await {
        error!("Error committing transaction: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }
    if !is_migration && !is_did_web_byod {
        let did_typed = Did::new_unchecked(&did);
        let handle_typed = Handle::new_unchecked(&handle);
        if let Err(e) =
            crate::api::repo::record::sequence_identity_event(&state, &did_typed, Some(&handle_typed)).await
        {
            warn!("Failed to sequence identity event for {}: {}", did, e);
        }
        if let Err(e) =
            crate::api::repo::record::sequence_account_event(&state, &did_typed, true, None).await
        {
            warn!("Failed to sequence account event for {}: {}", did, e);
        }
        if let Err(e) = crate::api::repo::record::sequence_genesis_commit(
            &state,
            &did_typed,
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
            &did_typed,
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
        let profile_collection = Nsid::new_unchecked("app.bsky.actor.profile");
        let profile_rkey = Rkey::new_unchecked("self");
        if let Err(e) = crate::api::repo::record::create_record_internal(
            &state,
            &did_typed,
            &profile_collection,
            &profile_rkey,
            &profile_record,
        )
        .await
        {
            warn!("Failed to create default profile for {}: {}", did, e);
        }
    }
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if !is_migration {
        if let Some(ref recipient) = verification_recipient {
            let verification_token = crate::auth::verification_token::generate_signup_token(
                &did,
                verification_channel,
                recipient,
            );
            let formatted_token =
                crate::auth::verification_token::format_token_for_display(&verification_token);
            if let Err(e) = crate::comms::enqueue_signup_verification(
                &state.db,
                user_id,
                verification_channel,
                recipient,
                &formatted_token,
                None,
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
        let token = crate::auth::verification_token::generate_migration_token(&did, user_email);
        let formatted_token = crate::auth::verification_token::format_token_for_display(&token);
        if let Err(e) = crate::comms::enqueue_migration_verification(
            &state.db,
            user_id,
            user_email,
            &formatted_token,
            &hostname,
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
    if let Err(e) = sqlx::query!(
        "INSERT INTO session_tokens (did, access_jti, refresh_jti, access_expires_at, refresh_expires_at) VALUES ($1, $2, $3, $4, $5)",
        did,
        access_meta.jti,
        refresh_meta.jti,
        access_meta.expires_at,
        refresh_meta.expires_at
    )
    .execute(&state.db)
    .await
    {
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
            did: did.into(),
            did_doc,
            access_jwt: access_meta.token,
            refresh_jwt: refresh_meta.token,
            verification_required: !is_migration,
            verification_channel: verification_channel.to_string(),
        }),
    )
        .into_response()
}
