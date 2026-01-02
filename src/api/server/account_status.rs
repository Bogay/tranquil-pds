use crate::api::ApiError;
use crate::cache::Cache;
use crate::plc::PlcClient;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bcrypt::verify;
use chrono::{Duration, Utc};
use cid::Cid;
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckAccountStatusOutput {
    pub activated: bool,
    pub valid_did: bool,
    pub repo_commit: String,
    pub repo_rev: String,
    pub repo_blocks: i64,
    pub indexed_records: i64,
    pub private_state_values: i64,
    pub expected_blobs: i64,
    pub imported_blobs: i64,
}

pub async fn check_account_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let extracted = match crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    let http_uri = format!(
        "https://{}/xrpc/com.atproto.server.checkAccountStatus",
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
    );
    let did = match crate::auth::validate_token_with_dpop(
        &state.db,
        &extracted.token,
        extracted.is_dpop,
        dpop_proof,
        "GET",
        &http_uri,
        true,
    )
    .await
    {
        Ok(user) => user.did,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let user_id = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(id)) => id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let user_status = sqlx::query!("SELECT deactivated_at FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;
    let deactivated_at = match user_status {
        Ok(Some(row)) => row.deactivated_at,
        _ => None,
    };
    let repo_result = sqlx::query!(
        "SELECT repo_root_cid, repo_rev FROM repos WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await;
    let (repo_commit, repo_rev_from_db) = match repo_result {
        Ok(Some(row)) => (row.repo_root_cid, row.repo_rev),
        _ => (String::new(), None),
    };
    let block_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM user_blocks WHERE user_id = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);
    let repo_rev = if let Some(rev) = repo_rev_from_db {
        rev
    } else if !repo_commit.is_empty() {
        if let Ok(cid) = Cid::from_str(&repo_commit) {
            if let Ok(Some(block)) = state.block_store.get(&cid).await {
                Commit::from_cbor(&block)
                    .ok()
                    .map(|c| c.rev().to_string())
                    .unwrap_or_default()
            } else {
                String::new()
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    let record_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM records WHERE repo_id = $1", user_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(Some(0))
            .unwrap_or(0);
    let imported_blobs: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM blobs WHERE created_by_user = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);
    let expected_blobs: i64 = sqlx::query_scalar!(
        "SELECT COUNT(DISTINCT blob_cid) FROM record_blobs WHERE repo_id = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);
    let valid_did = is_valid_did_for_service(&state.db, &state.cache, &did).await;
    (
        StatusCode::OK,
        Json(CheckAccountStatusOutput {
            activated: deactivated_at.is_none(),
            valid_did,
            repo_commit: repo_commit.clone(),
            repo_rev,
            repo_blocks: block_count as i64,
            indexed_records: record_count,
            private_state_values: 0,
            expected_blobs,
            imported_blobs,
        }),
    )
        .into_response()
}

async fn is_valid_did_for_service(db: &sqlx::PgPool, cache: &Arc<dyn Cache>, did: &str) -> bool {
    assert_valid_did_document_for_service(db, cache, did, false)
        .await
        .is_ok()
}

async fn assert_valid_did_document_for_service(
    db: &sqlx::PgPool,
    cache: &Arc<dyn Cache>,
    did: &str,
    with_retry: bool,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let expected_endpoint = format!("https://{}", hostname);

    if did.starts_with("did:plc:") {
        let plc_client = PlcClient::with_cache(None, Some(cache.clone()));

        let max_attempts = if with_retry { 5 } else { 1 };
        let mut last_error = None;
        let mut doc_data = None;
        for attempt in 0..max_attempts {
            if attempt > 0 {
                let delay_ms = 500 * (1 << (attempt - 1));
                info!(
                    "Waiting {}ms before retry {} for DID document validation ({})",
                    delay_ms, attempt, did
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            }

            match plc_client.get_document_data(did).await {
                Ok(data) => {
                    let pds_endpoint = data
                        .get("services")
                        .and_then(|s| s.get("atproto_pds").or_else(|| s.get("atprotoPds")))
                        .and_then(|p| p.get("endpoint"))
                        .and_then(|e| e.as_str());

                    if pds_endpoint == Some(&expected_endpoint) {
                        doc_data = Some(data);
                        break;
                    } else {
                        info!(
                            "Attempt {}: DID {} has endpoint {:?}, expected {} - retrying",
                            attempt + 1,
                            did,
                            pds_endpoint,
                            expected_endpoint
                        );
                        last_error = Some(format!(
                            "DID document endpoint {:?} does not match expected {}",
                            pds_endpoint, expected_endpoint
                        ));
                    }
                }
                Err(e) => {
                    warn!(
                        "Attempt {}: Failed to fetch PLC document for {}: {:?}",
                        attempt + 1,
                        did,
                        e
                    );
                    last_error = Some(format!("Could not resolve DID document: {}", e));
                }
            }
        }

        let doc_data = match doc_data {
            Some(d) => d,
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidRequest",
                        "message": last_error.unwrap_or_else(|| "DID document validation failed".to_string())
                    })),
                ));
            }
        };

        let server_rotation_key = std::env::var("PLC_ROTATION_KEY").ok();
        if let Some(ref expected_rotation_key) = server_rotation_key {
            let rotation_keys = doc_data
                .get("rotationKeys")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|k| k.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();
            if !rotation_keys.contains(&expected_rotation_key.as_str()) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidRequest",
                        "message": "Server rotation key not included in PLC DID data"
                    })),
                ));
            }
        }

        let doc_signing_key = doc_data
            .get("verificationMethods")
            .and_then(|v| v.get("atproto"))
            .and_then(|k| k.as_str());

        let user_row = sqlx::query!(
            "SELECT uk.key_bytes, uk.encryption_version FROM user_keys uk JOIN users u ON uk.user_id = u.id WHERE u.did = $1",
            did
        )
        .fetch_optional(db)
        .await
        .map_err(|e| {
            error!("Failed to fetch user key: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
        })?;

        if let Some(row) = user_row {
            let key_bytes = crate::config::decrypt_key(&row.key_bytes, row.encryption_version)
                .map_err(|e| {
                    error!("Failed to decrypt user key: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                })?;
            let signing_key = SigningKey::from_slice(&key_bytes).map_err(|e| {
                error!("Failed to create signing key: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
            })?;
            let expected_did_key = crate::plc::signing_key_to_did_key(&signing_key);

            if doc_signing_key != Some(&expected_did_key) {
                warn!(
                    "DID {} has signing key {:?}, expected {}",
                    did, doc_signing_key, expected_did_key
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidRequest",
                        "message": "DID document verification method does not match expected signing key"
                    })),
                ));
            }
        }
    } else if let Some(host_and_path) = did.strip_prefix("did:web:") {
        let client = crate::api::proxy_client::did_resolution_client();
        let decoded = host_and_path.replace("%3A", ":");
        let parts: Vec<&str> = decoded.split(':').collect();
        let (host, path_parts) = if parts.len() > 1 && parts[1].chars().all(|c| c.is_ascii_digit())
        {
            (format!("{}:{}", parts[0], parts[1]), parts[2..].to_vec())
        } else {
            (parts[0].to_string(), parts[1..].to_vec())
        };
        let scheme =
            if host.starts_with("localhost") || host.starts_with("127.") || host.contains(':') {
                "http"
            } else {
                "https"
            };
        let url = if path_parts.is_empty() {
            format!("{}://{}/.well-known/did.json", scheme, host)
        } else {
            format!("{}://{}/{}/did.json", scheme, host, path_parts.join("/"))
        };
        let resp = client.get(&url).send().await.map_err(|e| {
            warn!("Failed to fetch did:web document for {}: {:?}", did, e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": format!("Could not resolve DID document: {}", e)
                })),
            )
        })?;
        let doc: serde_json::Value = resp.json().await.map_err(|e| {
            warn!("Failed to parse did:web document for {}: {:?}", did, e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": format!("Could not parse DID document: {}", e)
                })),
            )
        })?;

        let pds_endpoint = doc
            .get("service")
            .and_then(|s| s.as_array())
            .and_then(|arr| {
                arr.iter().find(|svc| {
                    svc.get("id").and_then(|id| id.as_str()) == Some("#atproto_pds")
                        || svc.get("type").and_then(|t| t.as_str())
                            == Some("AtprotoPersonalDataServer")
                })
            })
            .and_then(|svc| svc.get("serviceEndpoint"))
            .and_then(|e| e.as_str());

        if pds_endpoint != Some(&expected_endpoint) {
            warn!(
                "DID {} has endpoint {:?}, expected {}",
                did, pds_endpoint, expected_endpoint
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": "DID document atproto_pds service endpoint does not match PDS public url"
                })),
            ));
        }
    }

    Ok(())
}

pub async fn activate_account(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    info!("[MIGRATION] activateAccount called");
    let extracted = match crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => {
            info!("[MIGRATION] activateAccount: No auth token");
            return ApiError::AuthenticationRequired.into_response();
        }
    };
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    let http_uri = format!(
        "https://{}/xrpc/com.atproto.server.activateAccount",
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
    );
    let auth_user = match crate::auth::validate_token_with_dpop(
        &state.db,
        &extracted.token,
        extracted.is_dpop,
        dpop_proof,
        "POST",
        &http_uri,
        true,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => {
            info!("[MIGRATION] activateAccount: Auth failed: {:?}", e);
            return ApiError::from(e).into_response();
        }
    };
    info!(
        "[MIGRATION] activateAccount: Authenticated user did={}",
        auth_user.did
    );

    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth_user.is_oauth,
        auth_user.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Repo,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        info!("[MIGRATION] activateAccount: Scope check failed");
        return e;
    }

    let did = auth_user.did;

    info!(
        "[MIGRATION] activateAccount: Validating DID document for did={}",
        did
    );
    let did_validation_start = std::time::Instant::now();
    if let Err((status, json)) =
        assert_valid_did_document_for_service(&state.db, &state.cache, &did, true).await
    {
        info!(
            "[MIGRATION] activateAccount: DID document validation FAILED for {} (took {:?})",
            did,
            did_validation_start.elapsed()
        );
        return (status, json).into_response();
    }
    info!(
        "[MIGRATION] activateAccount: DID document validation SUCCESS for {} (took {:?})",
        did,
        did_validation_start.elapsed()
    );

    let handle = sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    info!(
        "[MIGRATION] activateAccount: Activating account did={} handle={:?}",
        did, handle
    );
    let result = sqlx::query!("UPDATE users SET deactivated_at = NULL WHERE did = $1", did)
        .execute(&state.db)
        .await;
    match result {
        Ok(_) => {
            info!(
                "[MIGRATION] activateAccount: DB update success for did={}",
                did
            );
            if let Some(ref h) = handle {
                let _ = state.cache.delete(&format!("handle:{}", h)).await;
            }
            info!(
                "[MIGRATION] activateAccount: Sequencing account event (active=true) for did={}",
                did
            );
            if let Err(e) =
                crate::api::repo::record::sequence_account_event(&state, &did, true, None).await
            {
                warn!(
                    "[MIGRATION] activateAccount: Failed to sequence account activation event: {}",
                    e
                );
            } else {
                info!("[MIGRATION] activateAccount: Account event sequenced successfully");
            }
            info!(
                "[MIGRATION] activateAccount: Sequencing identity event for did={} handle={:?}",
                did, handle
            );
            if let Err(e) =
                crate::api::repo::record::sequence_identity_event(&state, &did, handle.as_deref())
                    .await
            {
                warn!(
                    "[MIGRATION] activateAccount: Failed to sequence identity event for activation: {}",
                    e
                );
            } else {
                info!("[MIGRATION] activateAccount: Identity event sequenced successfully");
            }
            let repo_root = sqlx::query_scalar!(
                "SELECT r.repo_root_cid FROM repos r JOIN users u ON r.user_id = u.id WHERE u.did = $1",
                did
            )
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
            if let Some(root_cid) = repo_root {
                info!(
                    "[MIGRATION] activateAccount: Sequencing sync event for did={} root_cid={}",
                    did, root_cid
                );
                let rev = if let Ok(cid) = Cid::from_str(&root_cid) {
                    if let Ok(Some(block)) = state.block_store.get(&cid).await {
                        Commit::from_cbor(&block).ok().map(|c| c.rev().to_string())
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Err(e) = crate::api::repo::record::sequence_sync_event(
                    &state,
                    &did,
                    &root_cid,
                    rev.as_deref(),
                )
                .await
                {
                    warn!(
                        "[MIGRATION] activateAccount: Failed to sequence sync event for activation: {}",
                        e
                    );
                } else {
                    info!("[MIGRATION] activateAccount: Sync event sequenced successfully");
                }
            } else {
                warn!(
                    "[MIGRATION] activateAccount: No repo root found for did={}",
                    did
                );
            }
            info!("[MIGRATION] activateAccount: SUCCESS for did={}", did);
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!(
                "[MIGRATION] activateAccount: DB error activating account: {:?}",
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeactivateAccountInput {
    pub delete_after: Option<String>,
}

pub async fn deactivate_account(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<DeactivateAccountInput>,
) -> Response {
    let extracted = match crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    let http_uri = format!(
        "https://{}/xrpc/com.atproto.server.deactivateAccount",
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
    );
    let auth_user = match crate::auth::validate_token_with_dpop(
        &state.db,
        &extracted.token,
        extracted.is_dpop,
        dpop_proof,
        "POST",
        &http_uri,
        false,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };

    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth_user.is_oauth,
        auth_user.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Repo,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        return e;
    }

    let delete_after: Option<chrono::DateTime<chrono::Utc>> = input
        .delete_after
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let did = auth_user.did;

    let handle = sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let result = sqlx::query!(
        "UPDATE users SET deactivated_at = NOW(), delete_after = $2 WHERE did = $1",
        did,
        delete_after
    )
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            if let Some(ref h) = handle {
                let _ = state.cache.delete(&format!("handle:{}", h)).await;
            }
            if let Err(e) = crate::api::repo::record::sequence_account_event(
                &state,
                &did,
                false,
                Some("deactivated"),
            )
            .await
            {
                warn!("Failed to sequence account deactivated event: {}", e);
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error deactivating account: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

pub async fn request_account_delete(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let extracted = match crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    let http_uri = format!(
        "https://{}/xrpc/com.atproto.server.requestAccountDelete",
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
    );
    let validated = match crate::auth::validate_token_with_dpop(
        &state.db,
        &extracted.token,
        extracted.is_dpop,
        dpop_proof,
        "POST",
        &http_uri,
        true,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let did = validated.did.clone();

    if !crate::api::server::reauth::check_legacy_session_mfa(&state.db, &did).await {
        return crate::api::server::reauth::legacy_mfa_required_response(&state.db, &did).await;
    }

    let user_id = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(id)) => id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let confirmation_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(15);
    let insert = sqlx::query!(
        "INSERT INTO account_deletion_requests (token, did, expires_at) VALUES ($1, $2, $3)",
        confirmation_token,
        did,
        expires_at
    )
    .execute(&state.db)
    .await;
    if let Err(e) = insert {
        error!("DB error creating deletion token: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) =
        crate::comms::enqueue_account_deletion(&state.db, user_id, &confirmation_token, &hostname)
            .await
    {
        warn!("Failed to enqueue account deletion notification: {:?}", e);
    }
    info!("Account deletion requested for user {}", did);
    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Deserialize)]
pub struct DeleteAccountInput {
    pub did: String,
    pub password: String,
    pub token: String,
}

pub async fn delete_account(
    State(state): State<AppState>,
    Json(input): Json<DeleteAccountInput>,
) -> Response {
    let did = input.did.trim();
    let password = &input.password;
    let token = input.token.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }
    if password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "password is required"})),
        )
            .into_response();
    }
    const OLD_PASSWORD_MAX_LENGTH: usize = 512;
    if password.len() > OLD_PASSWORD_MAX_LENGTH {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Invalid password length."})),
        )
            .into_response();
    }
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidToken", "message": "token is required"})),
        )
            .into_response();
    }
    let user = sqlx::query!(
        "SELECT id, password_hash, handle FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await;
    let (user_id, password_hash, handle) = match user {
        Ok(Some(row)) => (row.id, row.password_hash, row.handle),
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in delete_account: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let password_valid = if password_hash
        .as_ref()
        .map(|h| verify(password, h).unwrap_or(false))
        .unwrap_or(false)
    {
        true
    } else {
        let app_pass_rows = sqlx::query!(
            "SELECT password_hash FROM app_passwords WHERE user_id = $1",
            user_id
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        app_pass_rows
            .iter()
            .any(|row| verify(password, &row.password_hash).unwrap_or(false))
    };
    if !password_valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationFailed", "message": "Invalid password"})),
        )
            .into_response();
    }
    let deletion_request = sqlx::query!(
        "SELECT did, expires_at FROM account_deletion_requests WHERE token = $1",
        token
    )
    .fetch_optional(&state.db)
    .await;
    let (token_did, expires_at) = match deletion_request {
        Ok(Some(row)) => (row.did, row.expires_at),
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidToken", "message": "Invalid or expired token"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching deletion token: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if token_did != did {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidToken", "message": "Token does not match account"})),
        )
            .into_response();
    }
    if Utc::now() > expires_at {
        let _ = sqlx::query!(
            "DELETE FROM account_deletion_requests WHERE token = $1",
            token
        )
        .execute(&state.db)
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "ExpiredToken", "message": "Token has expired"})),
        )
            .into_response();
    }
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let deletion_result: Result<(), sqlx::Error> = async {
        sqlx::query!("DELETE FROM session_tokens WHERE did = $1", did)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM records WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM repos WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM app_passwords WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM account_deletion_requests WHERE did = $1", did)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&mut *tx)
            .await?;
        Ok(())
    }
    .await;
    match deletion_result {
        Ok(()) => {
            if let Err(e) = tx.commit().await {
                error!("Failed to commit account deletion transaction: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
            let account_seq = crate::api::repo::record::sequence_account_event(
                &state,
                did,
                false,
                Some("deleted"),
            )
            .await;
            match account_seq {
                Ok(seq) => {
                    if let Err(e) = sqlx::query!(
                        "DELETE FROM repo_seq WHERE did = $1 AND seq != $2",
                        did,
                        seq
                    )
                    .execute(&state.db)
                    .await
                    {
                        warn!(
                            "Failed to cleanup sequences for deleted account {}: {}",
                            did, e
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to sequence account deletion event for {}: {}",
                        did, e
                    );
                }
            }
            let _ = state.cache.delete(&format!("handle:{}", handle)).await;
            info!("Account {} deleted successfully", did);
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error deleting account, rolling back: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
