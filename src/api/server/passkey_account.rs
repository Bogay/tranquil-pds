use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bcrypt::{DEFAULT_COST, hash};
use chrono::{Duration, Utc};
use jacquard::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::{mst::Mst, storage::BlockStore};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::api::repo::record::utils::create_signed_commit;
use crate::auth::{ServiceTokenVerifier, extract_bearer_token_from_header, is_service_token};
use crate::state::{AppState, RateLimitKind};
use crate::validation::validate_password;

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

fn generate_app_password() -> String {
    let chars: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut rng = rand::thread_rng();
    let segments: Vec<String> = (0..4)
        .map(|_| {
            (0..4)
                .map(|_| chars[rng.gen_range(0..chars.len())] as char)
                .collect()
        })
        .collect();
    segments.join("-")
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
    pub verification_channel: Option<String>,
    pub discord_id: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_number: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePasskeyAccountResponse {
    pub did: String,
    pub handle: String,
    pub setup_token: String,
    pub setup_expires_at: chrono::DateTime<Utc>,
}

pub async fn create_passkey_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreatePasskeyAccountInput>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::AccountCreation, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Account creation rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "RateLimitExceeded",
                "message": "Too many account creation attempts. Please try again later."
            })),
        )
            .into_response();
    }

    let byod_auth = if let Some(token) =
        extract_bearer_token_from_header(headers.get("Authorization").and_then(|h| h.to_str().ok()))
    {
        if is_service_token(&token) {
            let verifier = ServiceTokenVerifier::new();
            match verifier
                .verify_service_token(&token, Some("com.atproto.server.createAccount"))
                .await
            {
                Ok(claims) => {
                    debug!("Service token verified for BYOD did:web: iss={}", claims.iss);
                    Some(claims.iss)
                }
                Err(e) => {
                    error!("Service token verification failed: {:?}", e);
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "AuthenticationFailed",
                            "message": format!("Service token verification failed: {}", e)
                        })),
                    )
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

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_suffix = format!(".{}", hostname);

    let handle = if !input.handle.contains('.') || input.handle.ends_with(&pds_suffix) {
        let handle_to_validate = if input.handle.ends_with(&pds_suffix) {
            input
                .handle
                .strip_suffix(&pds_suffix)
                .unwrap_or(&input.handle)
        } else {
            &input.handle
        };
        match crate::api::validation::validate_short_handle(handle_to_validate) {
            Ok(h) => format!("{}.{}", h, hostname),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidHandle", "message": e.to_string()})),
                )
                    .into_response();
            }
        }
    } else {
        input.handle.to_lowercase()
    };

    let email = input
        .email
        .as_ref()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(ref email) = email
        && !crate::api::validation::is_valid_email(email)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidEmail", "message": "Invalid email format"})),
        )
            .into_response();
    }

    if let Some(ref code) = input.invite_code {
        let valid = sqlx::query_scalar!(
            "SELECT available_uses > 0 AND NOT disabled FROM invite_codes WHERE code = $1",
            code
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or(Some(false));

        if valid != Some(true) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidInviteCode", "message": "Invalid or expired invite code"})),
            )
                .into_response();
        }
    } else {
        let invite_required = std::env::var("INVITE_CODE_REQUIRED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        if invite_required {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InviteCodeRequired", "message": "An invite code is required to create an account"})),
            )
                .into_response();
        }
    }

    let verification_channel = input.verification_channel.as_deref().unwrap_or("email");
    let verification_recipient = match verification_channel {
        "email" => match &email {
            Some(e) if !e.is_empty() => e.clone(),
            _ => return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "MissingEmail", "message": "Email is required when using email verification"})),
            ).into_response(),
        },
        "discord" => match &input.discord_id {
            Some(id) if !id.trim().is_empty() => id.trim().to_string(),
            _ => return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "MissingDiscordId", "message": "Discord ID is required when using Discord verification"})),
            ).into_response(),
        },
        "telegram" => match &input.telegram_username {
            Some(username) if !username.trim().is_empty() => username.trim().to_string(),
            _ => return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "MissingTelegramUsername", "message": "Telegram username is required when using Telegram verification"})),
            ).into_response(),
        },
        "signal" => match &input.signal_number {
            Some(number) if !number.trim().is_empty() => number.trim().to_string(),
            _ => return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "MissingSignalNumber", "message": "Signal phone number is required when using Signal verification"})),
            ).into_response(),
        },
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidVerificationChannel", "message": "Invalid verification channel"})),
        ).into_response(),
    };

    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    let pds_endpoint = format!("https://{}", hostname);
    let did_type = input.did_type.as_deref().unwrap_or("plc");

    let (secret_key_bytes, reserved_key_id): (Vec<u8>, Option<Uuid>) =
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
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "InvalidSigningKey",
                            "message": "Signing key not found, already used, or expired"
                        })),
                    )
                        .into_response();
                }
                Err(e) => {
                    error!("Error looking up reserved signing key: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let did = match did_type {
        "web" => {
            let subdomain_host = format!("{}.{}", input.handle, hostname);
            let encoded_subdomain = subdomain_host.replace(':', "%3A");
            let self_hosted_did = format!("did:web:{}", encoded_subdomain);
            info!(did = %self_hosted_did, "Creating self-hosted did:web passkey account");
            self_hosted_did
        }
        "web-external" => {
            let d = match &input.did {
                Some(d) if !d.trim().is_empty() => d.trim(),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "InvalidRequest", "message": "External did:web requires the 'did' field to be provided"})),
                    )
                        .into_response();
                }
            };
            if !d.starts_with("did:web:") {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        json!({"error": "InvalidDid", "message": "External DID must be a did:web"}),
                    ),
                )
                    .into_response();
            }
            if is_byod_did_web {
                if let Some(ref auth_did) = byod_auth {
                    if d != auth_did {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(json!({
                                "error": "AuthorizationError",
                                "message": format!("Service token issuer {} does not match DID {}", auth_did, d)
                            })),
                        )
                            .into_response();
                    }
                }
                info!(did = %d, "Creating external did:web passkey account (BYOD key)");
            } else {
                if let Err(e) = crate::api::identity::did::verify_did_web(
                    d,
                    &hostname,
                    &input.handle,
                    input.signing_key.as_deref(),
                )
                .await
                {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "InvalidDid", "message": e})),
                    )
                        .into_response();
                }
                info!(did = %d, "Creating external did:web passkey account (reserved key)");
            }
            d.to_string()
        }
        _ => {
            let rotation_key = std::env::var("PLC_ROTATION_KEY")
                .unwrap_or_else(|_| crate::plc::signing_key_to_did_key(&secret_key));

            let genesis_result = match crate::plc::create_genesis_operation(
                &secret_key,
                &rotation_key,
                &handle,
                &pds_endpoint,
            ) {
                Ok(r) => r,
                Err(e) => {
                    error!("Error creating PLC genesis operation: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError", "message": "Failed to create PLC operation"})),
                    )
                        .into_response();
                }
            };

            let plc_client = crate::plc::PlcClient::new(None);
            if let Err(e) = plc_client
                .send_operation(&genesis_result.did, &genesis_result.signed_operation)
                .await
            {
                error!("Failed to submit PLC genesis operation: {:?}", e);
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": "UpstreamError",
                        "message": format!("Failed to register DID with PLC directory: {}", e)
                    })),
                )
                    .into_response();
            }
            genesis_result.did
        }
    };

    info!(did = %did, handle = %handle, "Created DID for passkey-only account");

    let verification_code = format!(
        "{:06}",
        rand::Rng::gen_range(&mut rand::thread_rng(), 0..1_000_000u32)
    );
    let verification_code_expires_at = Utc::now() + Duration::minutes(30);

    let setup_token = generate_setup_token();
    let setup_token_hash = match hash(&setup_token, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Error hashing setup token: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let setup_expires_at = Utc::now() + Duration::hours(1);

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Error starting transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let is_first_user = sqlx::query_scalar!("SELECT COUNT(*) as count FROM users")
        .fetch_one(&mut *tx)
        .await
        .map(|c| c.unwrap_or(0) == 0)
        .unwrap_or(false);

    let deactivated_at: Option<chrono::DateTime<Utc>> = if is_byod_did_web {
        Some(Utc::now())
    } else {
        None
    };

    let user_insert: Result<(Uuid,), _> = sqlx::query_as(
        r#"INSERT INTO users (
            handle, email, did, password_hash, password_required,
            preferred_comms_channel,
            discord_id, telegram_username, signal_number,
            recovery_token, recovery_token_expires_at,
            is_admin, deactivated_at
        ) VALUES ($1, $2, $3, NULL, FALSE, $4::comms_channel, $5, $6, $7, $8, $9, $10, $11) RETURNING id"#,
    )
    .bind(&handle)
    .bind(&email)
    .bind(&did)
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
    .bind(&setup_token_hash)
    .bind(setup_expires_at)
    .bind(is_first_user)
    .bind(deactivated_at)
    .fetch_one(&mut *tx)
    .await;

    let user_id = match user_insert {
        Ok((id,)) => id,
        Err(e) => {
            if let Some(db_err) = e.as_database_error()
                && db_err.code().as_deref() == Some("23505")
            {
                let constraint = db_err.constraint().unwrap_or("");
                if constraint.contains("handle") {
                    return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "HandleNotAvailable", "message": "Handle already taken"})),
                        )
                            .into_response();
                } else if constraint.contains("email") {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(
                            json!({"error": "InvalidEmail", "message": "Email already registered"}),
                        ),
                    )
                        .into_response();
                }
            }
            error!("Error inserting user: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let encrypted_key_bytes = match crate::config::encrypt_key(&secret_key_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Error encrypting signing key: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(e) = sqlx::query!(
        "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, NOW())",
        user_id,
        &encrypted_key_bytes[..],
        crate::config::ENCRYPTION_VERSION
    )
    .execute(&mut *tx)
    .await
    {
        error!("Error inserting user key: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Some(key_id) = reserved_key_id
        && let Err(e) = sqlx::query!(
            "UPDATE reserved_signing_keys SET used_at = NOW() WHERE id = $1",
            key_id
        )
        .execute(&mut *tx)
        .await
    {
        error!("Error marking reserved key as used: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let mst = Mst::new(Arc::new(state.block_store.clone()));
    let mst_root = match mst.persist().await {
        Ok(c) => c,
        Err(e) => {
            error!("Error persisting MST: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let rev = Tid::now(LimitedU32::MIN);
    let (commit_bytes, _sig) = match create_signed_commit(&did, mst_root, &rev.to_string(), None, &secret_key) {
        Ok(result) => result,
        Err(e) => {
            error!("Error creating genesis commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let commit_cid: cid::Cid = match state.block_store.put(&commit_bytes).await {
        Ok(c) => c,
        Err(e) => {
            error!("Error saving genesis commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let commit_cid_str = commit_cid.to_string();
    if let Err(e) = sqlx::query!(
        "INSERT INTO repos (user_id, repo_root_cid) VALUES ($1, $2)",
        user_id,
        commit_cid_str
    )
    .execute(&mut *tx)
    .await
    {
        error!("Error inserting repo: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Some(ref code) = input.invite_code {
        let _ = sqlx::query!(
            "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
            code
        )
        .execute(&mut *tx)
        .await;

        let _ = sqlx::query!(
            "INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)",
            code,
            user_id
        )
        .execute(&mut *tx)
        .await;
    }

    if let Err(e) = sqlx::query!(
        "INSERT INTO channel_verifications (user_id, channel, code, pending_identifier, expires_at) VALUES ($1, $2::comms_channel, $3, $4, $5)",
        user_id,
        verification_channel as _,
        verification_code,
        verification_recipient,
        verification_code_expires_at
    )
    .execute(&mut *tx)
    .await
    {
        error!("Error inserting channel verification: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Err(e) = tx.commit().await {
        error!("Error committing transaction: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if !is_byod_did_web {
        if let Err(e) =
            crate::api::repo::record::sequence_identity_event(&state, &did, Some(&handle)).await
        {
            warn!("Failed to sequence identity event for {}: {}", did, e);
        }
        if let Err(e) =
            crate::api::repo::record::sequence_account_event(&state, &did, true, None).await
        {
            warn!("Failed to sequence account event for {}: {}", did, e);
        }
        let profile_record = serde_json::json!({
            "$type": "app.bsky.actor.profile",
            "displayName": handle
        });
        if let Err(e) = crate::api::repo::record::create_record_internal(
            &state,
            &did,
            "app.bsky.actor.profile",
            "self",
            &profile_record,
        )
        .await
        {
            warn!("Failed to create default profile for {}: {}", did, e);
        }
    }

    if let Err(e) = crate::comms::enqueue_signup_verification(
        &state.db,
        user_id,
        verification_channel,
        &verification_recipient,
        &verification_code,
        None,
    )
    .await
    {
        warn!("Failed to enqueue signup verification: {:?}", e);
    }

    info!(did = %did, handle = %handle, "Passkey-only account created, awaiting setup completion");

    Json(CreatePasskeyAccountResponse {
        did,
        handle,
        setup_token,
        setup_expires_at,
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletePasskeySetupInput {
    pub did: String,
    pub setup_token: String,
    pub passkey_credential: serde_json::Value,
    pub passkey_friendly_name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletePasskeySetupResponse {
    pub did: String,
    pub handle: String,
    pub app_password: String,
    pub app_password_name: String,
}

pub async fn complete_passkey_setup(
    State(state): State<AppState>,
    Json(input): Json<CompletePasskeySetupInput>,
) -> Response {
    let user = sqlx::query!(
        r#"SELECT id, handle, recovery_token, recovery_token_expires_at, password_required
           FROM users WHERE did = $1"#,
        input.did
    )
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if user.password_required {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidAccount", "message": "This account is not a passkey-only account"})),
        )
            .into_response();
    }

    let token_hash = match &user.recovery_token {
        Some(h) => h,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "SetupExpired", "message": "Setup has already been completed or expired"})),
            )
                .into_response();
        }
    };

    if let Some(expires_at) = user.recovery_token_expires_at
        && expires_at < Utc::now()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "SetupExpired", "message": "Setup token has expired"})),
        )
            .into_response();
    }

    if !bcrypt::verify(&input.setup_token, token_hash).unwrap_or(false) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "InvalidToken", "message": "Invalid setup token"})),
        )
            .into_response();
    }

    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let webauthn = match crate::auth::webauthn::WebAuthnConfig::new(&pds_hostname) {
        Ok(w) => w,
        Err(e) => {
            error!("Failed to create WebAuthn config: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let reg_state = match crate::auth::webauthn::load_registration_state(&state.db, &input.did)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "NoChallengeInProgress", "message": "Please start passkey registration first"})),
                )
                    .into_response();
        }
        Err(e) => {
            error!("Error loading registration state: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let credential: webauthn_rs::prelude::RegisterPublicKeyCredential = match serde_json::from_value(
        input.passkey_credential,
    ) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to parse credential: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"error": "InvalidCredential", "message": "Failed to parse credential"}),
                ),
            )
                .into_response();
        }
    };

    let security_key = match webauthn.finish_registration(&credential, &reg_state) {
        Ok(sk) => sk,
        Err(e) => {
            warn!("Passkey registration failed: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "RegistrationFailed", "message": "Passkey registration failed"})),
            )
                .into_response();
        }
    };

    if let Err(e) = crate::auth::webauthn::save_passkey(
        &state.db,
        &input.did,
        &security_key,
        input.passkey_friendly_name.as_deref(),
    )
    .await
    {
        error!("Error saving passkey: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let _ = crate::auth::webauthn::delete_registration_state(&state.db, &input.did).await;

    let app_password = generate_app_password();
    let app_password_name = "bsky.app".to_string();
    let password_hash = match hash(&app_password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Error hashing app password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(e) = sqlx::query!(
        "INSERT INTO app_passwords (user_id, name, password_hash, privileged) VALUES ($1, $2, $3, FALSE)",
        user.id,
        app_password_name,
        password_hash
    )
    .execute(&state.db)
    .await
    {
        error!("Error creating app password: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Err(e) = sqlx::query!(
        "UPDATE users SET recovery_token = NULL, recovery_token_expires_at = NULL WHERE did = $1",
        input.did
    )
    .execute(&state.db)
    .await
    {
        error!("Error clearing setup token: {:?}", e);
    }

    info!(did = %input.did, "Passkey-only account setup completed");

    Json(CompletePasskeySetupResponse {
        did: input.did,
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
    let user = sqlx::query!(
        r#"SELECT handle, recovery_token, recovery_token_expires_at, password_required
           FROM users WHERE did = $1"#,
        input.did
    )
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if user.password_required {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidAccount"})),
        )
            .into_response();
    }

    let token_hash = match &user.recovery_token {
        Some(h) => h,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "SetupExpired"})),
            )
                .into_response();
        }
    };

    if let Some(expires_at) = user.recovery_token_expires_at
        && expires_at < Utc::now()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "SetupExpired"})),
        )
            .into_response();
    }

    if !bcrypt::verify(&input.setup_token, token_hash).unwrap_or(false) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "InvalidToken"})),
        )
            .into_response();
    }

    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let webauthn = match crate::auth::webauthn::WebAuthnConfig::new(&pds_hostname) {
        Ok(w) => w,
        Err(e) => {
            error!("Failed to create WebAuthn config: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let existing_passkeys = crate::auth::webauthn::get_passkeys_for_user(&state.db, &input.did)
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(e) =
        crate::auth::webauthn::save_registration_state(&state.db, &input.did, &reg_state).await
    {
        error!("Failed to save registration state: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let options = serde_json::to_value(&ccr).unwrap_or(json!({}));
    Json(json!({"options": options})).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartPasskeyRegistrationInput {
    pub did: String,
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
    headers: HeaderMap,
    Json(input): Json<RequestPasskeyRecoveryInput>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::PasswordReset, &client_ip)
        .await
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "RateLimitExceeded"})),
        )
            .into_response();
    }

    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let identifier = input.email.trim().to_lowercase();
    let identifier = identifier.strip_prefix('@').unwrap_or(&identifier);
    let normalized_handle = if identifier.contains('@') || identifier.contains('.') {
        identifier.to_string()
    } else {
        format!("{}.{}", identifier, pds_hostname)
    };

    let user = sqlx::query!(
        "SELECT id, did, handle, password_required FROM users WHERE LOWER(email) = $1 OR handle = $2",
        identifier,
        normalized_handle
    )
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some(u)) if !u.password_required => u,
        _ => {
            return Json(json!({"success": true})).into_response();
        }
    };

    let recovery_token = generate_setup_token();
    let recovery_token_hash = match hash(&recovery_token, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let expires_at = Utc::now() + Duration::hours(1);

    if let Err(e) = sqlx::query!(
        "UPDATE users SET recovery_token = $1, recovery_token_expires_at = $2 WHERE did = $3",
        recovery_token_hash,
        expires_at,
        user.did
    )
    .execute(&state.db)
    .await
    {
        error!("Error updating recovery token: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let recovery_url = format!(
        "https://{}/#/recover-passkey?did={}&token={}",
        hostname,
        urlencoding::encode(&user.did),
        urlencoding::encode(&recovery_token)
    );

    let _ =
        crate::comms::enqueue_passkey_recovery(&state.db, user.id, &recovery_url, &hostname).await;

    info!(did = %user.did, "Passkey recovery requested");
    Json(json!({"success": true})).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverPasskeyAccountInput {
    pub did: String,
    pub recovery_token: String,
    pub new_password: String,
}

pub async fn recover_passkey_account(
    State(state): State<AppState>,
    Json(input): Json<RecoverPasskeyAccountInput>,
) -> Response {
    if let Err(e) = validate_password(&input.new_password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidPassword",
                "message": e.to_string()
            })),
        )
            .into_response();
    }

    let user = sqlx::query!(
        "SELECT id, did, recovery_token, recovery_token_expires_at FROM users WHERE did = $1",
        input.did
    )
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "InvalidRecoveryLink"})),
            )
                .into_response();
        }
    };

    let token_hash = match &user.recovery_token {
        Some(h) => h,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRecoveryLink"})),
            )
                .into_response();
        }
    };

    if let Some(expires_at) = user.recovery_token_expires_at
        && expires_at < Utc::now()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "RecoveryLinkExpired"})),
        )
            .into_response();
    }

    if !bcrypt::verify(&input.recovery_token, token_hash).unwrap_or(false) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "InvalidRecoveryLink"})),
        )
            .into_response();
    }

    let password_hash = match hash(&input.new_password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(e) = sqlx::query!(
        "UPDATE users SET password_hash = $1, password_required = TRUE, recovery_token = NULL, recovery_token_expires_at = NULL WHERE did = $2",
        password_hash,
        input.did
    )
    .execute(&state.db)
    .await
    {
        error!("Error updating password: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let deleted = sqlx::query!("DELETE FROM passkeys WHERE did = $1", input.did)
        .execute(&state.db)
        .await;
    match deleted {
        Ok(result) => {
            if result.rows_affected() > 0 {
                info!(did = %input.did, count = result.rows_affected(), "Deleted lost passkeys during account recovery");
            }
        }
        Err(e) => {
            warn!(did = %input.did, "Failed to delete passkeys during recovery: {:?}", e);
        }
    }

    info!(did = %input.did, "Passkey-only account recovered with temporary password");
    Json(json!({"success": true})).into_response()
}
