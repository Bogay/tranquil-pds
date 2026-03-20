use axum::{Json, extract::State};
use backon::{ExponentialBuilder, Retryable};
use chrono::{Duration, Utc};
use cid::Cid;
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{error, info, warn};
use tranquil_pds::api::EmptyResponse;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::auth::{Auth, NotTakendown, Permissive, require_legacy_session_mfa};
use tranquil_pds::cache::Cache;
use tranquil_pds::oauth::scopes::{AccountAction, AccountAttr};
use tranquil_pds::plc::PlcClient;
use tranquil_pds::state::AppState;
use tranquil_pds::types::PlainPassword;
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
    auth: Auth<Permissive>,
) -> Result<Json<CheckAccountStatusOutput>, ApiError> {
    let did = &auth.did;
    let user_id = state
        .repos.user
        .get_id_by_did(did)
        .await
        .log_db_err("fetching user ID for account status")?
        .ok_or(ApiError::InternalError(None))?;
    let is_active = state
        .repos.user
        .is_account_active_by_did(did)
        .await
        .ok()
        .flatten()
        .unwrap_or(false);
    let repo_info = state.repos.repo.get_repo(user_id).await.ok().flatten();
    let (repo_commit, repo_rev_from_db) = repo_info
        .map(|r| (r.repo_root_cid.to_string(), r.repo_rev))
        .unwrap_or_else(|| (String::new(), None));
    let block_count: i64 = state
        .repos.repo
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
    let record_count: i64 = state.repos.repo.count_records(user_id).await.unwrap_or(0);
    let imported_blobs: i64 = state
        .repos.blob
        .count_blobs_by_user(user_id)
        .await
        .unwrap_or(0);
    let expected_blobs: i64 = state
        .repos.blob
        .count_distinct_record_blobs(user_id)
        .await
        .unwrap_or(0);
    let valid_did =
        is_valid_did_for_service(state.repos.user.as_ref(), state.cache.clone(), did).await;
    Ok(Json(CheckAccountStatusOutput {
        activated: is_active,
        valid_did,
        repo_commit: repo_commit.clone(),
        repo_rev,
        repo_blocks: block_count,
        indexed_records: record_count,
        private_state_values: 0,
        expected_blobs,
        imported_blobs,
    }))
}

async fn is_valid_did_for_service(
    user_repo: &dyn tranquil_db_traits::UserRepository,
    cache: Arc<dyn Cache>,
    did: &tranquil_pds::types::Did,
) -> bool {
    assert_valid_did_document_for_service(user_repo, cache, did, false)
        .await
        .is_ok()
}

async fn assert_valid_did_document_for_service(
    user_repo: &dyn tranquil_db_traits::UserRepository,
    cache: Arc<dyn Cache>,
    did: &tranquil_pds::types::Did,
    with_retry: bool,
) -> Result<(), ApiError> {
    let hostname = &tranquil_config::get().server.hostname;
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

        let server_rotation_key = tranquil_config::get().secrets.plc_rotation_key.clone();
        if let Some(ref expected_rotation_key) = server_rotation_key {
            let rotation_keys = doc_data
                .get("rotationKeys")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(Value::as_str).collect::<Vec<_>>())
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
            .and_then(Value::as_str);

        let user_key = user_repo
            .get_user_key_by_did(did)
            .await
            .log_db_err("fetching user key")?;

        if let Some(key_info) = user_key {
            let key_bytes =
                tranquil_pds::config::decrypt_key(&key_info.key_bytes, key_info.encryption_version)
                    .map_err(|e| {
                        error!("Failed to decrypt user key: {}", e);
                        ApiError::InternalError(None)
                    })?;
            let signing_key = SigningKey::from_slice(&key_bytes).map_err(|e| {
                error!("Failed to create signing key: {:?}", e);
                ApiError::InternalError(None)
            })?;
            let expected_did_key = tranquil_pds::plc::signing_key_to_did_key(&signing_key);

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
        let client = tranquil_pds::api::proxy_client::did_resolution_client();
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
            .and_then(Value::as_array)
            .and_then(|arr| {
                arr.iter().find(|svc| {
                    svc.get("id").and_then(|id| id.as_str()) == Some("#atproto_pds")
                        || svc.get("type").and_then(Value::as_str)
                            == Some(tranquil_pds::plc::ServiceType::Pds.as_str())
                })
            })
            .and_then(|svc| svc.get("serviceEndpoint"))
            .and_then(Value::as_str);

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
    auth: Auth<Permissive>,
) -> Result<Json<EmptyResponse>, ApiError> {
    info!("[MIGRATION] activateAccount called");
    info!(
        "[MIGRATION] activateAccount: Authenticated user did={}",
        auth.did
    );

    auth.check_account_scope(AccountAttr::Repo, AccountAction::Manage)
        .inspect_err(|_| {
            info!("[MIGRATION] activateAccount: Scope check failed");
        })?;

    let did = auth.did.clone();

    info!(
        "[MIGRATION] activateAccount: Validating DID document for did={}",
        did
    );
    let did_validation_start = std::time::Instant::now();
    if let Err(e) = assert_valid_did_document_for_service(
        state.repos.user.as_ref(),
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

    let handle = state.repos.user.get_handle_by_did(&did).await.ok().flatten();
    info!(
        "[MIGRATION] activateAccount: Activating account did={} handle={:?}",
        did, handle
    );
    let result = state.repos.user.activate_account(&did).await;
    match result {
        Ok(_) => {
            info!(
                "[MIGRATION] activateAccount: DB update success for did={}",
                did
            );
            if let Some(ref h) = handle {
                let _ = state
                    .cache
                    .delete(&tranquil_pds::cache_keys::handle_key(h))
                    .await;
            }
            let _ = state
                .cache
                .delete(&tranquil_pds::cache_keys::plc_doc_key(&did))
                .await;
            let _ = state
                .cache
                .delete(&tranquil_pds::cache_keys::plc_data_key(&did))
                .await;
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
            if let Err(e) = tranquil_pds::repo_ops::sequence_account_event(
                &state,
                &did,
                tranquil_db_traits::AccountStatus::Active,
            )
            .await
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
            if let Err(e) =
                tranquil_pds::repo_ops::sequence_identity_event(&state, &did, handle_typed.as_ref())
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
                .repos.repo
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
                if let Err(e) = tranquil_pds::repo_ops::sequence_sync_event(
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
            Ok(Json(EmptyResponse {}))
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
    auth: Auth<Permissive>,
    Json(input): Json<DeactivateAccountInput>,
) -> Result<Json<EmptyResponse>, ApiError> {
    auth.check_account_scope(AccountAttr::Repo, AccountAction::Manage)?;

    let delete_after: Option<chrono::DateTime<chrono::Utc>> = input
        .delete_after
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let did = auth.did.clone();

    let handle = state.repos.user.get_handle_by_did(&did).await.ok().flatten();

    let result = state.repos.user.deactivate_account(&did, delete_after).await;

    match result {
        Ok(true) => {
            if let Some(ref h) = handle {
                let _ = state
                    .cache
                    .delete(&tranquil_pds::cache_keys::handle_key(h))
                    .await;
            }
            if let Err(e) = tranquil_pds::repo_ops::sequence_account_event(
                &state,
                &did,
                tranquil_db_traits::AccountStatus::Deactivated,
            )
            .await
            {
                warn!("Failed to sequence account deactivated event: {}", e);
            }
            Ok(Json(EmptyResponse {}))
        }
        Ok(false) => Ok(Json(EmptyResponse {})),
        Err(e) => {
            error!("DB error deactivating account: {:?}", e);
            Err(ApiError::InternalError(None))
        }
    }
}

pub async fn request_account_delete(
    State(state): State<AppState>,
    auth: Auth<NotTakendown>,
) -> Result<Json<EmptyResponse>, ApiError> {
    let session_mfa = require_legacy_session_mfa(&state, &auth).await?;

    let user_id = state
        .repos.user
        .get_id_by_did(session_mfa.did())
        .await
        .ok()
        .flatten()
        .ok_or(ApiError::InternalError(None))?;
    let confirmation_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(15);
    state
        .repos.infra
        .create_deletion_request(&confirmation_token, session_mfa.did(), expires_at)
        .await
        .log_db_err("creating deletion token")?;
    let hostname = &tranquil_config::get().server.hostname;
    if let Err(e) = tranquil_pds::comms::comms_repo::enqueue_account_deletion(
        state.repos.user.as_ref(),
        state.repos.infra.as_ref(),
        user_id,
        &confirmation_token,
        hostname,
    )
    .await
    {
        warn!("Failed to enqueue account deletion notification: {:?}", e);
    }
    info!("Account deletion requested for user {}", session_mfa.did());
    Ok(Json(EmptyResponse {}))
}

#[derive(Deserialize)]
pub struct DeleteAccountInput {
    pub did: tranquil_pds::types::Did,
    pub password: PlainPassword,
    pub token: String,
}

pub async fn delete_account(
    State(state): State<AppState>,
    Json(input): Json<DeleteAccountInput>,
) -> Result<Json<EmptyResponse>, ApiError> {
    let did = &input.did;
    let password = &input.password;
    let token = input.token.trim();
    if password.is_empty() {
        return Err(ApiError::InvalidRequest("password is required".into()));
    }
    const OLD_PASSWORD_MAX_LENGTH: usize = 512;
    if password.len() > OLD_PASSWORD_MAX_LENGTH {
        return Err(ApiError::InvalidRequest("Invalid password length".into()));
    }
    if token.is_empty() {
        return Err(ApiError::InvalidToken(Some("token is required".into())));
    }
    let user = state
        .repos.user
        .get_user_for_deletion(did)
        .await
        .map_err(|e| {
            error!("DB error in delete_account: {:?}", e);
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::InvalidRequest("account not found".into()))?;
    let (user_id, password_hash, handle) = (user.id, user.password_hash, user.handle);
    if crate::common::verify_credential(
        state.repos.session.as_ref(),
        user_id,
        password,
        password_hash.as_deref(),
    )
    .await
    .is_none()
    {
        return Err(ApiError::AuthenticationFailed(Some(
            "Invalid password".into(),
        )));
    }
    let deletion_request = state
        .repos.infra
        .get_deletion_request(token)
        .await
        .map_err(|e| {
            error!("DB error fetching deletion token: {:?}", e);
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::InvalidToken(Some(
            "Invalid or expired token".into(),
        )))?;
    if &deletion_request.did != did {
        return Err(ApiError::InvalidToken(Some(
            "Token does not match account".into(),
        )));
    }
    if Utc::now() > deletion_request.expires_at {
        let _ = state.repos.infra.delete_deletion_request(token).await;
        return Err(ApiError::ExpiredToken(None));
    }
    state
        .repos.user
        .delete_account_complete(user_id, did)
        .await
        .map_err(|e| {
            error!("DB error deleting account: {:?}", e);
            ApiError::InternalError(None)
        })?;
    let account_seq = tranquil_pds::repo_ops::sequence_account_event(
        &state,
        did,
        tranquil_db_traits::AccountStatus::Deleted,
    )
    .await;
    match account_seq {
        Ok(seq) => {
            if let Err(e) = state.repos.repo.delete_sequences_except(did, seq).await {
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
    let _ = state
        .cache
        .delete(&tranquil_pds::cache_keys::handle_key(&handle))
        .await;
    info!("Account {} deleted successfully", did);
    Ok(Json(EmptyResponse {}))
}
