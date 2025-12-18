use super::did::verify_did_web;
use crate::plc::{PlcClient, create_genesis_operation, signing_key_to_did_key};
use crate::state::{AppState, RateLimitKind};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bcrypt::{DEFAULT_COST, hash};
use jacquard::types::{did::Did, integer::LimitedU32, string::Tid};
use jacquard_repo::{commit::Commit, mst::Mst, storage::BlockStore};
use k256::{SecretKey, ecdsa::SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, warn};

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(value) = forwarded.to_str()
            && let Some(first_ip) = value.split(',').next() {
                return first_ip.trim().to_string();
            }
    if let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(value) = real_ip.to_str() {
            return value.trim().to_string();
        }
    "unknown".to_string()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountInput {
    pub handle: String,
    pub email: Option<String>,
    pub password: String,
    pub invite_code: Option<String>,
    pub did: Option<String>,
    pub signing_key: Option<String>,
    pub verification_channel: Option<String>,
    pub discord_id: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_number: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountOutput {
    pub handle: String,
    pub did: String,
    pub verification_required: bool,
    pub verification_channel: String,
}

pub async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateAccountInput>,
) -> Response {
    info!("create_account called");
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
    if input.handle.contains('!') || input.handle.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"error": "InvalidHandle", "message": "Handle contains invalid characters"}),
            ),
        )
            .into_response();
    }
    let email: Option<String> = input
        .email
        .as_ref()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(ref email) = email
        && !crate::api::validation::is_valid_email(email) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidEmail", "message": "Invalid email format"})),
            )
                .into_response();
        }
    let verification_channel = input.verification_channel.as_deref().unwrap_or("email");
    let valid_channels = ["email", "discord", "telegram", "signal"];
    if !valid_channels.contains(&verification_channel) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidVerificationChannel", "message": "Invalid verification channel. Must be one of: email, discord, telegram, signal"})),
        )
            .into_response();
    }
    let verification_recipient = match verification_channel {
        "email" => match &input.email {
            Some(email) if !email.trim().is_empty() => email.trim().to_string(),
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
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let suffix = format!(".{}", hostname);
    let short_handle = if input.handle.ends_with(&suffix) {
        input.handle.strip_suffix(&suffix).unwrap_or(&input.handle)
    } else {
        &input.handle
    };
    let full_handle = format!("{}.{}", short_handle, hostname);
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
            let secret_key = SecretKey::random(&mut OsRng);
            (secret_key.to_bytes().to_vec(), None)
        };
    let signing_key = match SigningKey::from_slice(&secret_key_bytes) {
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
    let did = if let Some(d) = &input.did {
        if d.trim().is_empty() {
            let rotation_key = std::env::var("PLC_ROTATION_KEY")
                .unwrap_or_else(|_| signing_key_to_did_key(&signing_key));
            let genesis_result = match create_genesis_operation(
                &signing_key,
                &rotation_key,
                &full_handle,
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
            let plc_client = PlcClient::new(None);
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
            info!(did = %genesis_result.did, "Successfully registered DID with PLC directory");
            genesis_result.did
        } else if d.starts_with("did:web:") {
            if let Err(e) = verify_did_web(d, &hostname, &input.handle).await {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidDid", "message": e})),
                )
                    .into_response();
            }
            d.clone()
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidDid", "message": "Only did:web DIDs can be provided; leave empty for did:plc"})),
            )
                .into_response();
        }
    } else {
        let rotation_key = std::env::var("PLC_ROTATION_KEY")
            .unwrap_or_else(|_| signing_key_to_did_key(&signing_key));
        let genesis_result = match create_genesis_operation(
            &signing_key,
            &rotation_key,
            &full_handle,
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
        let plc_client = PlcClient::new(None);
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
        info!(did = %genesis_result.did, "Successfully registered DID with PLC directory");
        genesis_result.did
    };
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
    let exists_query = sqlx::query!("SELECT 1 as one FROM users WHERE handle = $1", short_handle)
        .fetch_optional(&mut *tx)
        .await;
    match exists_query {
        Ok(Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "HandleTaken", "message": "Handle already taken"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Error checking handle: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
        Ok(None) => {}
    }
    let invite_code_required = std::env::var("INVITE_CODE_REQUIRED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if invite_code_required && input.invite_code.as_ref().map(|c| c.trim().is_empty()).unwrap_or(true) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidInviteCode", "message": "Invite code is required"})),
        )
            .into_response();
    }
    if let Some(code) = &input.invite_code {
        if !code.trim().is_empty() {
            let invite_query = sqlx::query!(
                "SELECT available_uses FROM invite_codes WHERE code = $1 FOR UPDATE",
                code
            )
            .fetch_optional(&mut *tx)
            .await;
            match invite_query {
                Ok(Some(row)) => {
                    if row.available_uses <= 0 {
                        return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidInviteCode", "message": "Invite code exhausted"}))).into_response();
                    }
                    let update_invite = sqlx::query!(
                        "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
                        code
                    )
                    .execute(&mut *tx)
                    .await;
                    if let Err(e) = update_invite {
                        error!("Error updating invite code: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError"})),
                        )
                            .into_response();
                    }
                }
                Ok(None) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "InvalidInviteCode", "message": "Invite code not found"})),
                    )
                        .into_response();
                }
                Err(e) => {
                    error!("Error checking invite code: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            }
        }
    }
    let password_hash = match hash(&input.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Error hashing password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let verification_code = format!("{:06}", rand::random::<u32>() % 1_000_000);
    let code_expires_at = chrono::Utc::now() + chrono::Duration::minutes(30);
    let is_first_user = sqlx::query_scalar!("SELECT COUNT(*) as count FROM users")
        .fetch_one(&mut *tx)
        .await
        .map(|c| c.unwrap_or(0) == 0)
        .unwrap_or(false);
    let user_insert: Result<(uuid::Uuid,), _> = sqlx::query_as(
        r#"INSERT INTO users (
            handle, email, did, password_hash,
            preferred_comms_channel,
            discord_id, telegram_username, signal_number,
            is_admin
        ) VALUES ($1, $2, $3, $4, $5::comms_channel, $6, $7, $8, $9) RETURNING id"#,
    )
    .bind(short_handle)
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
    .fetch_one(&mut *tx)
    .await;
    let user_id = match user_insert {
        Ok((id,)) => id,
        Err(e) => {
            if let Some(db_err) = e.as_database_error()
                && db_err.code().as_deref() == Some("23505") {
                    let constraint = db_err.constraint().unwrap_or("");
                    if constraint.contains("handle") || constraint.contains("users_handle") {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({
                                "error": "HandleNotAvailable",
                                "message": "Handle already taken"
                            })),
                        )
                            .into_response();
                    } else if constraint.contains("email") || constraint.contains("users_email") {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({
                                "error": "InvalidEmail",
                                "message": "Email already registered"
                            })),
                        )
                            .into_response();
                    } else if constraint.contains("did") || constraint.contains("users_did") {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({
                                "error": "AccountAlreadyExists",
                                "message": "An account with this DID already exists"
                            })),
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

    if let Err(e) = sqlx::query!(
        "INSERT INTO channel_verifications (user_id, channel, code, pending_identifier, expires_at) VALUES ($1, 'email', $2, $3, $4)",
        user_id,
        verification_code,
        email,
        code_expires_at
    )
    .execute(&mut *tx)
    .await {
        error!("Error inserting verification code: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    let encrypted_key_bytes = match crate::config::encrypt_key(&secret_key_bytes) {
        Ok(enc) => enc,
        Err(e) => {
            error!("Error encrypting user key: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
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
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
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
    let did_obj = match Did::new(&did) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Invalid DID"})),
            )
                .into_response();
        }
    };
    let rev = Tid::now(LimitedU32::MIN);
    let unsigned_commit = Commit::new_unsigned(did_obj, mst_root, rev, None);
    let signed_commit = match unsigned_commit.sign(&signing_key) {
        Ok(c) => c,
        Err(e) => {
            error!("Error signing genesis commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let commit_bytes = match signed_commit.to_cbor() {
        Ok(b) => b,
        Err(e) => {
            error!("Error serializing genesis commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let commit_cid = match state.block_store.put(&commit_bytes).await {
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
    let repo_insert = sqlx::query!(
        "INSERT INTO repos (user_id, repo_root_cid) VALUES ($1, $2)",
        user_id,
        commit_cid_str
    )
    .execute(&mut *tx)
    .await;
    if let Err(e) = repo_insert {
        error!("Error initializing repo: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    if let Some(code) = &input.invite_code {
        if !code.trim().is_empty() {
            let use_insert = sqlx::query!(
                "INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)",
                code,
                user_id
            )
            .execute(&mut *tx)
            .await;
            if let Err(e) = use_insert {
                error!("Error recording invite usage: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        }
    }
    if let Err(e) = tx.commit().await {
        error!("Error committing transaction: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    if let Err(e) =
        crate::api::repo::record::sequence_identity_event(&state, &did, Some(&full_handle)).await
    {
        warn!("Failed to sequence identity event for {}: {}", did, e);
    }
    if let Err(e) = crate::api::repo::record::sequence_account_event(&state, &did, true, None).await
    {
        warn!("Failed to sequence account event for {}: {}", did, e);
    }
    let profile_record = json!({
        "$type": "app.bsky.actor.profile",
        "displayName": input.handle
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
    if let Err(e) = crate::comms::enqueue_signup_verification(
        &state.db,
        user_id,
        verification_channel,
        &verification_recipient,
        &verification_code,
    )
    .await
    {
        warn!(
            "Failed to enqueue signup verification notification: {:?}",
            e
        );
    }
    (
        StatusCode::OK,
        Json(CreateAccountOutput {
            handle: short_handle.to_string(),
            did,
            verification_required: true,
            verification_channel: verification_channel.to_string(),
        }),
    )
        .into_response()
}
