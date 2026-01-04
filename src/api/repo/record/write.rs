use super::validation::validate_record_with_status;
use crate::api::error::ApiError;
use crate::api::repo::record::utils::{CommitParams, RecordOp, commit_and_log, extract_blob_cids};
use crate::delegation::{self, DelegationActionType};
use crate::repo::tracking::TrackingBlockStore;
use crate::state::AppState;
use crate::types::{AtIdentifier, AtUri, Did, Nsid, Rkey};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cid::Cid;
use jacquard_repo::{commit::Commit, mst::Mst, storage::BlockStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::str::FromStr;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

pub async fn has_verified_comms_channel(db: &PgPool, did: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT
            email_verified,
            discord_verified,
            telegram_verified,
            signal_verified
        FROM users
        WHERE did = $1
        "#,
    )
    .bind(did)
    .fetch_optional(db)
    .await?;
    match row {
        Some(r) => {
            let email_verified: bool = r.get("email_verified");
            let discord_verified: bool = r.get("discord_verified");
            let telegram_verified: bool = r.get("telegram_verified");
            let signal_verified: bool = r.get("signal_verified");
            Ok(email_verified || discord_verified || telegram_verified || signal_verified)
        }
        None => Ok(false),
    }
}

pub struct RepoWriteAuth {
    pub did: Did,
    pub user_id: Uuid,
    pub current_root_cid: Cid,
    pub is_oauth: bool,
    pub scope: Option<String>,
    pub controller_did: Option<Did>,
}

pub async fn prepare_repo_write(
    state: &AppState,
    headers: &HeaderMap,
    repo_did: &str,
    http_method: &str,
    http_uri: &str,
) -> Result<RepoWriteAuth, Response> {
    let extracted = crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    )
    .ok_or_else(|| ApiError::AuthenticationRequired.into_response())?;
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    let auth_user = crate::auth::validate_token_with_dpop(
        &state.db,
        &extracted.token,
        extracted.is_dpop,
        dpop_proof,
        http_method,
        http_uri,
        false,
    )
    .await
    .map_err(|e| {
        tracing::warn!(error = ?e, is_dpop = extracted.is_dpop, "Token validation failed in prepare_repo_write");
        let mut response = ApiError::from(e).into_response();
        if matches!(e, crate::auth::TokenValidationError::TokenExpired) {
            let scheme = if extracted.is_dpop { "DPoP" } else { "Bearer" };
            let www_auth = format!(
                "{} error=\"invalid_token\", error_description=\"Token has expired\"",
                scheme
            );
            response.headers_mut().insert(
                "WWW-Authenticate",
                www_auth.parse().unwrap(),
            );
            if extracted.is_dpop {
                let nonce = crate::oauth::verify::generate_dpop_nonce();
                response.headers_mut().insert("DPoP-Nonce", nonce.parse().unwrap());
            }
        }
        response
    })?;
    if repo_did != auth_user.did {
        return Err(
            ApiError::InvalidRepo("Repo does not match authenticated user".into()).into_response(),
        );
    }
    if crate::util::is_account_migrated(&state.db, &auth_user.did)
        .await
        .unwrap_or(false)
    {
        return Err(ApiError::AccountMigrated.into_response());
    }
    let is_verified = has_verified_comms_channel(&state.db, &auth_user.did)
        .await
        .unwrap_or(false);
    let is_delegated = crate::delegation::is_delegated_account(&state.db, &auth_user.did)
        .await
        .unwrap_or(false);
    if !is_verified && !is_delegated {
        return Err(ApiError::AccountNotVerified.into_response());
    }
    let user_id = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", &auth_user.did)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            error!("DB error fetching user: {}", e);
            ApiError::InternalError(None).into_response()
        })?
        .ok_or_else(|| ApiError::InternalError(Some("User not found".into())).into_response())?;
    let root_cid_str: String = sqlx::query_scalar!(
        "SELECT repo_root_cid FROM repos WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("DB error fetching repo root: {}", e);
        ApiError::InternalError(None).into_response()
    })?
    .ok_or_else(|| ApiError::InternalError(Some("Repo root not found".into())).into_response())?;
    let current_root_cid = Cid::from_str(&root_cid_str)
        .map_err(|_| ApiError::InternalError(Some("Invalid repo root CID".into())).into_response())?;
    Ok(RepoWriteAuth {
        did: auth_user.did.clone(),
        user_id,
        current_root_cid,
        is_oauth: auth_user.is_oauth,
        scope: auth_user.scope,
        controller_did: auth_user.controller_did.clone(),
    })
}
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct CreateRecordInput {
    pub repo: AtIdentifier,
    pub collection: Nsid,
    pub rkey: Option<Rkey>,
    pub validate: Option<bool>,
    pub record: serde_json::Value,
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitInfo {
    pub cid: String,
    pub rev: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRecordOutput {
    pub uri: AtUri,
    pub cid: String,
    pub commit: CommitInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<String>,
}
pub async fn create_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Json(input): Json<CreateRecordInput>,
) -> Response {
    let auth = match prepare_repo_write(
        &state,
        &headers,
        &input.repo,
        "POST",
        &crate::util::build_full_url(&uri.to_string()),
    )
    .await
    {
        Ok(res) => res,
        Err(err_res) => return err_res,
    };

    if let Err(e) = crate::auth::scope_check::check_repo_scope(
        auth.is_oauth,
        auth.scope.as_deref(),
        crate::oauth::RepoAction::Create,
        &input.collection,
    ) {
        return e;
    }

    let did = auth.did;
    let user_id = auth.user_id;
    let current_root_cid = auth.current_root_cid;
    let controller_did = auth.controller_did;

    if let Some(swap_commit) = &input.swap_commit
        && Cid::from_str(swap_commit).ok() != Some(current_root_cid)
    {
        return ApiError::InvalidSwap(Some("Repo has been modified".into())).into_response();
    }
    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = match tracking_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        _ => return ApiError::InternalError(Some("Commit block not found".into())).into_response(),
    };
    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        _ => return ApiError::InternalError(Some("Failed to parse commit".into())).into_response(),
    };
    let mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let validation_status = if input.validate == Some(false) {
        None
    } else {
        let require_lexicon = input.validate == Some(true);
        match validate_record_with_status(
            &input.record,
            &input.collection,
            input.rkey.as_ref().map(|r| r.as_str()),
            require_lexicon,
        ) {
            Ok(status) => Some(status),
            Err(err_response) => return *err_response,
        }
    };
    let rkey = input.rkey.unwrap_or_else(Rkey::generate);
    let record_ipld = crate::util::json_to_ipld(&input.record);
    let mut record_bytes = Vec::new();
    if serde_ipld_dagcbor::to_writer(&mut record_bytes, &record_ipld).is_err() {
        return ApiError::InvalidRecord("Failed to serialize record".into()).into_response();
    }
    let record_cid = match tracking_store.put(&record_bytes).await {
        Ok(c) => c,
        _ => {
            return ApiError::InternalError(Some("Failed to save record block".into())).into_response()
        }
    };
    let key = format!("{}/{}", input.collection, rkey);
    let new_mst = match mst.add(&key, record_cid).await {
        Ok(m) => m,
        _ => return ApiError::InternalError(Some("Failed to add to MST".into())).into_response(),
    };
    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        _ => return ApiError::InternalError(Some("Failed to persist MST".into())).into_response(),
    };
    let op = RecordOp::Create {
        collection: input.collection.to_string(),
        rkey: rkey.to_string(),
        cid: record_cid,
    };
    let mut relevant_blocks = std::collections::BTreeMap::new();
    if new_mst
        .blocks_for_path(&key, &mut relevant_blocks)
        .await
        .is_err()
    {
        return ApiError::InternalError(Some("Failed to get new MST blocks for path".into()))
            .into_response();
    }
    if mst
        .blocks_for_path(&key, &mut relevant_blocks)
        .await
        .is_err()
    {
        return ApiError::InternalError(Some("Failed to get old MST blocks for path".into()))
            .into_response();
    }
    relevant_blocks.insert(record_cid, bytes::Bytes::from(record_bytes));
    let mut written_cids = tracking_store.get_all_relevant_cids();
    for cid in relevant_blocks.keys() {
        if !written_cids.contains(cid) {
            written_cids.push(*cid);
        }
    }
    let written_cids_str = written_cids
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>();
    let blob_cids = extract_blob_cids(&input.record);
    let commit_result = match commit_and_log(
        &state,
        CommitParams {
            did: &did,
            user_id,
            current_root_cid: Some(current_root_cid),
            prev_data_cid: Some(commit.data),
            new_mst_root,
            ops: vec![op],
            blocks_cids: &written_cids_str,
            blobs: &blob_cids,
        },
    )
    .await
    {
        Ok(res) => res,
        Err(e) => return ApiError::InternalError(Some(e)).into_response(),
    };

    if let Some(ref controller) = controller_did {
        let _ = delegation::log_delegation_action(
            &state.db,
            &did,
            controller,
            Some(controller),
            DelegationActionType::RepoWrite,
            Some(json!({
                "action": "create",
                "collection": input.collection,
                "rkey": rkey
            })),
            None,
            None,
        )
        .await;
    }

    (
        StatusCode::OK,
        Json(CreateRecordOutput {
            uri: AtUri::from_parts(&did, &input.collection, &rkey),
            cid: record_cid.to_string(),
            commit: CommitInfo {
                cid: commit_result.commit_cid.to_string(),
                rev: commit_result.rev,
            },
            validation_status: validation_status.map(|s| s.to_string()),
        }),
    )
        .into_response()
}
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PutRecordInput {
    pub repo: AtIdentifier,
    pub collection: Nsid,
    pub rkey: Rkey,
    pub validate: Option<bool>,
    pub record: serde_json::Value,
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
    #[serde(rename = "swapRecord")]
    pub swap_record: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PutRecordOutput {
    pub uri: AtUri,
    pub cid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<CommitInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<String>,
}
pub async fn put_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Json(input): Json<PutRecordInput>,
) -> Response {
    let auth = match prepare_repo_write(
        &state,
        &headers,
        &input.repo,
        "POST",
        &crate::util::build_full_url(&uri.to_string()),
    )
    .await
    {
        Ok(res) => res,
        Err(err_res) => return err_res,
    };

    if let Err(e) = crate::auth::scope_check::check_repo_scope(
        auth.is_oauth,
        auth.scope.as_deref(),
        crate::oauth::RepoAction::Create,
        &input.collection,
    ) {
        return e;
    }
    if let Err(e) = crate::auth::scope_check::check_repo_scope(
        auth.is_oauth,
        auth.scope.as_deref(),
        crate::oauth::RepoAction::Update,
        &input.collection,
    ) {
        return e;
    }

    let did = auth.did;
    let user_id = auth.user_id;
    let current_root_cid = auth.current_root_cid;
    let controller_did = auth.controller_did;

    if let Some(swap_commit) = &input.swap_commit
        && Cid::from_str(swap_commit).ok() != Some(current_root_cid)
    {
        return ApiError::InvalidSwap(Some("Repo has been modified".into())).into_response();
    }
    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = match tracking_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        _ => return ApiError::InternalError(Some("Commit block not found".into())).into_response(),
    };
    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        _ => return ApiError::InternalError(Some("Failed to parse commit".into())).into_response(),
    };
    let mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let key = format!("{}/{}", input.collection, input.rkey);
    let validation_status = if input.validate == Some(false) {
        None
    } else {
        let require_lexicon = input.validate == Some(true);
        match validate_record_with_status(
            &input.record,
            &input.collection,
            Some(input.rkey.as_str()),
            require_lexicon,
        ) {
            Ok(status) => Some(status),
            Err(err_response) => return *err_response,
        }
    };
    if let Some(swap_record_str) = &input.swap_record {
        let expected_cid = Cid::from_str(swap_record_str).ok();
        let actual_cid = mst.get(&key).await.ok().flatten();
        if expected_cid != actual_cid {
            return ApiError::InvalidSwap(Some("Record has been modified or does not exist".into()))
                .into_response();
        }
    }
    let existing_cid = mst.get(&key).await.ok().flatten();
    let record_ipld = crate::util::json_to_ipld(&input.record);
    let mut record_bytes = Vec::new();
    if serde_ipld_dagcbor::to_writer(&mut record_bytes, &record_ipld).is_err() {
        return ApiError::InvalidRecord("Failed to serialize record".into()).into_response();
    }
    let record_cid = match tracking_store.put(&record_bytes).await {
        Ok(c) => c,
        _ => {
            return ApiError::InternalError(Some("Failed to save record block".into())).into_response()
        }
    };
    if existing_cid == Some(record_cid) {
        return (
            StatusCode::OK,
            Json(PutRecordOutput {
                uri: AtUri::from_parts(&did, &input.collection, &input.rkey),
                cid: record_cid.to_string(),
                commit: None,
                validation_status: validation_status.map(|s| s.to_string()),
            }),
        )
            .into_response();
    }
    let new_mst = if existing_cid.is_some() {
        match mst.update(&key, record_cid).await {
            Ok(m) => m,
            Err(_) => {
                return ApiError::InternalError(Some("Failed to update MST".into())).into_response()
            }
        }
    } else {
        match mst.add(&key, record_cid).await {
            Ok(m) => m,
            Err(_) => {
                return ApiError::InternalError(Some("Failed to add to MST".into())).into_response()
            }
        }
    };
    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        Err(_) => {
            return ApiError::InternalError(Some("Failed to persist MST".into())).into_response()
        }
    };
    let op = if existing_cid.is_some() {
        RecordOp::Update {
            collection: input.collection.to_string(),
            rkey: input.rkey.to_string(),
            cid: record_cid,
            prev: existing_cid,
        }
    } else {
        RecordOp::Create {
            collection: input.collection.to_string(),
            rkey: input.rkey.to_string(),
            cid: record_cid,
        }
    };
    let mut relevant_blocks = std::collections::BTreeMap::new();
    if new_mst
        .blocks_for_path(&key, &mut relevant_blocks)
        .await
        .is_err()
    {
        return ApiError::InternalError(Some("Failed to get new MST blocks for path".into()))
            .into_response();
    }
    if mst
        .blocks_for_path(&key, &mut relevant_blocks)
        .await
        .is_err()
    {
        return ApiError::InternalError(Some("Failed to get old MST blocks for path".into()))
            .into_response();
    }
    relevant_blocks.insert(record_cid, bytes::Bytes::from(record_bytes));
    let mut written_cids = tracking_store.get_all_relevant_cids();
    for cid in relevant_blocks.keys() {
        if !written_cids.contains(cid) {
            written_cids.push(*cid);
        }
    }
    let written_cids_str = written_cids
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>();
    let is_update = existing_cid.is_some();
    let blob_cids = extract_blob_cids(&input.record);
    let commit_result = match commit_and_log(
        &state,
        CommitParams {
            did: &did,
            user_id,
            current_root_cid: Some(current_root_cid),
            prev_data_cid: Some(commit.data),
            new_mst_root,
            ops: vec![op],
            blocks_cids: &written_cids_str,
            blobs: &blob_cids,
        },
    )
    .await
    {
        Ok(res) => res,
        Err(e) => return ApiError::InternalError(Some(e)).into_response(),
    };

    if let Some(ref controller) = controller_did {
        let _ = delegation::log_delegation_action(
            &state.db,
            &did,
            controller,
            Some(controller),
            DelegationActionType::RepoWrite,
            Some(json!({
                "action": if is_update { "update" } else { "create" },
                "collection": input.collection,
                "rkey": input.rkey
            })),
            None,
            None,
        )
        .await;
    }

    (
        StatusCode::OK,
        Json(PutRecordOutput {
            uri: AtUri::from_parts(&did, &input.collection, &input.rkey),
            cid: record_cid.to_string(),
            commit: Some(CommitInfo {
                cid: commit_result.commit_cid.to_string(),
                rev: commit_result.rev,
            }),
            validation_status: validation_status.map(|s| s.to_string()),
        }),
    )
        .into_response()
}
