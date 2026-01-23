use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::{Active, Auth, NotTakendown};
use crate::cache::Cache;
use crate::plc::PlcClient;
use crate::state::AppState;
use crate::types::PlainPassword;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use backon::{ExponentialBuilder, Retryable};
use bcrypt::verify;
use chrono::{Duration, Utc};
use cid::Cid;
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    auth: Auth<NotTakendown>,
) -> Result<Response, ApiError> {
    let did = &auth.did;
    let user_id = state
        .user_repo
        .get_id_by_did(did)
        .await
        .map_err(|_| ApiError::InternalError(None))?
        .ok_or(ApiError::InternalError(None))?;
    let is_active = state
        .user_repo
        .is_account_active_by_did(did)
        .await
        .ok()
        .flatten()
        .unwrap_or(false);
    let repo_info = state.repo_repo.get_repo(user_id).await.ok().flatten();
    let (repo_commit, repo_rev_from_db) = repo_info
        .map(|r| (r.repo_root_cid.to_string(), r.repo_rev))
        .unwrap_or_else(|| (String::new(), None));
    let block_count: i64 = state
        .repo_repo
        .count_user_blocks(user_id)
        .await
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
    let record_count: i64 = state.repo_repo.count_records(user_id).await.unwrap_or(0);
    let imported_blobs: i64 = state
        .blob_repo
        .count_blobs_by_user(user_id)
        .await
        .unwrap_or(0);
    let expected_blobs: i64 = state
        .blob_repo
        .count_distinct_record_blobs(user_id)
        .await
        .unwrap_or(0);
    let valid_did =
        is_valid_did_for_service(state.user_repo.as_ref(), state.cache.clone(), did).await;
    Ok((
        StatusCode::OK,
        Json(CheckAccountStatusOutput {
            activated: is_active,
            valid_did,
            repo_commit: repo_commit.clone(),
            repo_rev,
            repo_blocks: block_count,
            indexed_records: record_count,
            private_state_values: 0,
            expected_blobs,
            imported_blobs,
        }),
    )
        .into_response())
}

async fn is_valid_did_for_service(
    user_repo: &dyn tranquil_db_traits::UserRepository,
    cache: Arc<dyn Cache>,
    did: &crate::types::Did,
) -> bool {
    assert_valid_did_document_for_service(user_repo, cache, did, false)
        .await
        .is_ok()
}

async fn assert_valid_did_document_for_service(
    user_repo: &dyn tranquil_db_traits::UserRepository,
    cache: Arc<dyn Cache>,
    did: &crate::types::Did,
    with_retry: bool,
) -> Result<(), ApiError> {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let expected_endpoint = format!("https://{}", hostname);

    if did.as_str().starts_with("did:plc:") {
        let max_attempts = if with_retry { 5 } else { 1 };
        let cache_for_retry = cache.clone();
        let did_owned = did.as_str().to_string();
        let expected_owned = expected_endpoint.clone();
        let attempt_counter = Arc::new(AtomicUsize::new(0));

        let doc_data: serde_json::Value = (|| {
            let cache_ref = cache_for_retry.clone();
            let did_ref = did_owned.clone();
            let expected_ref = expected_owned.clone();
            let counter = attempt_counter.clone();
            async move {
                let attempt = counter.fetch_add(1, Ordering::SeqCst);
                if attempt > 0 {
                    info!(
                        "Retry {} for DID document validation ({})",
                        attempt, did_ref
                    );
                }
                let plc_client = PlcClient::with_cache(None, Some(cache_ref));
                match plc_client.get_document_data(&did_ref).await {
                    Ok(data) => {
                        let pds_endpoint = data
                            .get("services")
                            .and_then(|s: &serde_json::Value| {
                                s.get("atproto_pds").or_else(|| s.get("atprotoPds"))
                            })
                            .and_then(|p: &serde_json::Value| p.get("endpoint"))
                            .and_then(|e: &serde_json::Value| e.as_str());

                        if pds_endpoint == Some(expected_ref.as_str()) {
                            Ok(data)
                        } else {
                            info!(
                                "Attempt {}: DID {} has endpoint {:?}, expected {}",
                                attempt + 1,
                                did_ref,
                                pds_endpoint,
                                expected_ref
                            );
                            Err(format!(
                                "DID document endpoint {:?} does not match expected {}",
                                pds_endpoint, expected_ref
                            ))
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Attempt {}: Failed to fetch PLC document for {}: {:?}",
                            attempt + 1,
                            did_ref,
                            e
                        );
                        Err(format!("Could not resolve DID document: {}", e))
                    }
                }
            }
        })
        .retry(
            ExponentialBuilder::default()
                .with_min_delay(std::time::Duration::from_millis(500))
                .with_max_times(max_attempts),
        )
        .await
        .map_err(ApiError::InvalidRequest)?;

        let server_rotation_key = std::env::var("PLC_ROTATION_KEY").ok();
        if let Some(ref expected_rotation_key) = server_rotation_key {
            let rotation_keys = doc_data
                .get("rotationKeys")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|k| k.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();
            if !rotation_keys.contains(&expected_rotation_key.as_str()) {
                return Err(ApiError::InvalidRequest(
                    "Server rotation key not included in PLC DID data".into(),
                ));
            }
        }

        let doc_signing_key = doc_data
            .get("verificationMethods")
            .and_then(|v| v.get("atproto"))
            .and_then(|k| k.as_str());

        let user_key = user_repo.get_user_key_by_did(did).await.map_err(|e| {
            error!("Failed to fetch user key: {:?}", e);
            ApiError::InternalError(None)
        })?;

        if let Some(key_info) = user_key {
            let key_bytes =
                crate::config::decrypt_key(&key_info.key_bytes, key_info.encryption_version)
                    .map_err(|e| {
                        error!("Failed to decrypt user key: {}", e);
                        ApiError::InternalError(None)
                    })?;
            let signing_key = SigningKey::from_slice(&key_bytes).map_err(|e| {
                error!("Failed to create signing key: {:?}", e);
                ApiError::InternalError(None)
            })?;
            let expected_did_key = crate::plc::signing_key_to_did_key(&signing_key);

            if doc_signing_key != Some(&expected_did_key) {
                warn!(
                    "DID {} has signing key {:?}, expected {}",
                    did, doc_signing_key, expected_did_key
                );
                return Err(ApiError::InvalidRequest(
                    "DID document verification method does not match expected signing key".into(),
                ));
            }
        }
    } else if let Some(host_and_path) = did.as_str().strip_prefix("did:web:") {
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
            ApiError::InvalidRequest(format!("Could not resolve DID document: {}", e))
        })?;
        let doc: serde_json::Value = resp.json().await.map_err(|e| {
            warn!("Failed to parse did:web document for {}: {:?}", did, e);
            ApiError::InvalidRequest(format!("Could not parse DID document: {}", e))
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
            return Err(ApiError::InvalidRequest(
                "DID document atproto_pds service endpoint does not match PDS public url".into(),
            ));
        }
    }

    Ok(())
}

pub async fn activate_account(
    State(state): State<AppState>,
    auth: Auth<NotTakendown>,
) -> Result<Response, ApiError> {
    info!("[MIGRATION] activateAccount called");
    info!(
        "[MIGRATION] activateAccount: Authenticated user did={}",
        auth.did
    );

    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth.is_oauth(),
        auth.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Repo,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        info!("[MIGRATION] activateAccount: Scope check failed");
        return Ok(e);
    }

    let did = auth.did.clone();

    info!(
        "[MIGRATION] activateAccount: Validating DID document for did={}",
        did
    );
    let did_validation_start = std::time::Instant::now();
    if let Err(e) = assert_valid_did_document_for_service(
        state.user_repo.as_ref(),
        state.cache.clone(),
        &did,
        true,
    )
    .await
    {
        info!(
            "[MIGRATION] activateAccount: DID document validation FAILED for {} (took {:?})",
            did,
            did_validation_start.elapsed()
        );
        return Err(e);
    }
    info!(
        "[MIGRATION] activateAccount: DID document validation SUCCESS for {} (took {:?})",
        did,
        did_validation_start.elapsed()
    );

    let handle = state.user_repo.get_handle_by_did(&did).await.ok().flatten();
    info!(
        "[MIGRATION] activateAccount: Activating account did={} handle={:?}",
        did, handle
    );
    let result = state.user_repo.activate_account(&did).await;
    match result {
        Ok(_) => {
            info!(
                "[MIGRATION] activateAccount: DB update success for did={}",
                did
            );
            if let Some(ref h) = handle {
                let _ = state.cache.delete(&format!("handle:{}", h)).await;
            }
            let _ = state.cache.delete(&format!("plc:doc:{}", did)).await;
            let _ = state.cache.delete(&format!("plc:data:{}", did)).await;
            if state.did_resolver.refresh_did(did.as_str()).await.is_none() {
                warn!(
                    "[MIGRATION] activateAccount: Failed to refresh DID cache for {}",
                    did
                );
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
            let handle_typed = handle.clone();
            if let Err(e) = crate::api::repo::record::sequence_identity_event(
                &state,
                &did,
                handle_typed.as_ref(),
            )
            .await
            {
                warn!(
                    "[MIGRATION] activateAccount: Failed to sequence identity event for activation: {}",
                    e
                );
            } else {
                info!("[MIGRATION] activateAccount: Identity event sequenced successfully");
            }
            let repo_root = state
                .repo_repo
                .get_repo_root_by_did(&did)
                .await
                .ok()
                .flatten();
            if let Some(root_cid_link) = repo_root {
                info!(
                    "[MIGRATION] activateAccount: Sequencing sync event for did={} root_cid={}",
                    did, root_cid_link
                );
                let rev = if let Ok(cid) = Cid::from_str(root_cid_link.as_str()) {
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
                    root_cid_link.as_str(),
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
            Ok(EmptyResponse::ok().into_response())
        }
        Err(e) => {
            error!(
                "[MIGRATION] activateAccount: DB error activating account: {:?}",
                e
            );
            Err(ApiError::InternalError(None))
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
    auth: Auth<Active>,
    Json(input): Json<DeactivateAccountInput>,
) -> Result<Response, ApiError> {
    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth.is_oauth(),
        auth.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Repo,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        return Ok(e);
    }

    let delete_after: Option<chrono::DateTime<chrono::Utc>> = input
        .delete_after
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let did = auth.did.clone();

    let handle = state.user_repo.get_handle_by_did(&did).await.ok().flatten();

    let result = state.user_repo.deactivate_account(&did, delete_after).await;

    match result {
        Ok(true) => {
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
            Ok(EmptyResponse::ok().into_response())
        }
        Ok(false) => Ok(EmptyResponse::ok().into_response()),
        Err(e) => {
            error!("DB error deactivating account: {:?}", e);
            Err(ApiError::InternalError(None))
        }
    }
}

pub async fn request_account_delete(
    State(state): State<AppState>,
    auth: Auth<NotTakendown>,
) -> Result<Response, ApiError> {
    let did = &auth.did;

    if !crate::api::server::reauth::check_legacy_session_mfa(&*state.session_repo, did).await {
        return Ok(crate::api::server::reauth::legacy_mfa_required_response(
            &*state.user_repo,
            &*state.session_repo,
            did,
        )
        .await);
    }

    let user_id = state
        .user_repo
        .get_id_by_did(did)
        .await
        .ok()
        .flatten()
        .ok_or(ApiError::InternalError(None))?;
    let confirmation_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(15);
    state
        .infra_repo
        .create_deletion_request(&confirmation_token, did, expires_at)
        .await
        .map_err(|e| {
            error!("DB error creating deletion token: {:?}", e);
            ApiError::InternalError(None)
        })?;
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) = crate::comms::comms_repo::enqueue_account_deletion(
        state.user_repo.as_ref(),
        state.infra_repo.as_ref(),
        user_id,
        &confirmation_token,
        &hostname,
    )
    .await
    {
        warn!("Failed to enqueue account deletion notification: {:?}", e);
    }
    info!("Account deletion requested for user {}", did);
    Ok(EmptyResponse::ok().into_response())
}

#[derive(Deserialize)]
pub struct DeleteAccountInput {
    pub did: crate::types::Did,
    pub password: PlainPassword,
    pub token: String,
}

pub async fn delete_account(
    State(state): State<AppState>,
    Json(input): Json<DeleteAccountInput>,
) -> Response {
    let did = &input.did;
    let password = &input.password;
    let token = input.token.trim();
    if password.is_empty() {
        return ApiError::InvalidRequest("password is required".into()).into_response();
    }
    const OLD_PASSWORD_MAX_LENGTH: usize = 512;
    if password.len() > OLD_PASSWORD_MAX_LENGTH {
        return ApiError::InvalidRequest("Invalid password length".into()).into_response();
    }
    if token.is_empty() {
        return ApiError::InvalidToken(Some("token is required".into())).into_response();
    }
    let user = match state.user_repo.get_user_for_deletion(did).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return ApiError::InvalidRequest("account not found".into()).into_response();
        }
        Err(e) => {
            error!("DB error in delete_account: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let (user_id, password_hash, handle) = (user.id, user.password_hash, user.handle);
    let password_valid = if password_hash
        .as_ref()
        .map(|h| verify(password, h).unwrap_or(false))
        .unwrap_or(false)
    {
        true
    } else {
        let app_pass_hashes = state
            .session_repo
            .get_app_password_hashes_by_did(did)
            .await
            .unwrap_or_default();
        app_pass_hashes
            .iter()
            .any(|h| verify(password, h).unwrap_or(false))
    };
    if !password_valid {
        return ApiError::AuthenticationFailed(Some("Invalid password".into())).into_response();
    }
    let deletion_request = match state.infra_repo.get_deletion_request(token).await {
        Ok(Some(req)) => req,
        Ok(None) => {
            return ApiError::InvalidToken(Some("Invalid or expired token".into())).into_response();
        }
        Err(e) => {
            error!("DB error fetching deletion token: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    if &deletion_request.did != did {
        return ApiError::InvalidToken(Some("Token does not match account".into())).into_response();
    }
    if Utc::now() > deletion_request.expires_at {
        let _ = state.infra_repo.delete_deletion_request(token).await;
        return ApiError::ExpiredToken(None).into_response();
    }
    if let Err(e) = state.user_repo.delete_account_complete(user_id, did).await {
        error!("DB error deleting account: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }
    let account_seq =
        crate::api::repo::record::sequence_account_event(&state, did, false, Some("deleted")).await;
    match account_seq {
        Ok(seq) => {
            if let Err(e) = state.repo_repo.delete_sequences_except(did, seq).await {
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
    EmptyResponse::ok().into_response()
}
