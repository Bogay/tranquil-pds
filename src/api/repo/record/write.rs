use super::validation::validate_record_with_status;
use crate::validation::ValidationStatus;
use crate::api::repo::record::utils::{CommitParams, RecordOp, commit_and_log, extract_blob_cids};
use crate::delegation::{self, DelegationActionType};
use crate::repo::tracking::TrackingBlockStore;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cid::Cid;
use jacquard::types::{
    integer::LimitedU32,
    string::{Nsid, Tid},
};
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
    pub did: String,
    pub user_id: Uuid,
    pub current_root_cid: Cid,
    pub is_oauth: bool,
    pub scope: Option<String>,
    pub controller_did: Option<String>,
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
    .ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response()
    })?;
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
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": e.to_string()})),
        )
            .into_response()
    })?;
    if repo_did != auth_user.did {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "InvalidRepo", "message": "Repo does not match authenticated user"})),
        )
            .into_response());
    }
    if crate::util::is_account_migrated(&state.db, &auth_user.did)
        .await
        .unwrap_or(false)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "AccountMigrated",
                "message": "Account has been migrated to another PDS. Repo operations are not allowed."
            })),
        )
            .into_response());
    }
    let is_verified = has_verified_comms_channel(&state.db, &auth_user.did)
        .await
        .unwrap_or(false);
    let is_delegated = crate::delegation::is_delegated_account(&state.db, &auth_user.did)
        .await
        .unwrap_or(false);
    if !is_verified && !is_delegated {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "AccountNotVerified",
                "message": "You must verify at least one notification channel (email, Discord, Telegram, or Signal) before creating records"
            })),
        )
            .into_response());
    }
    let user_id = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", auth_user.did)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            error!("DB error fetching user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User not found"})),
            )
                .into_response()
        })?;
    let root_cid_str: String = sqlx::query_scalar!(
        "SELECT repo_root_cid FROM repos WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("DB error fetching repo root: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response()
    })?
    .ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Repo root not found"})),
        )
            .into_response()
    })?;
    let current_root_cid = Cid::from_str(&root_cid_str).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Invalid repo root CID"})),
        )
            .into_response()
    })?;
    Ok(RepoWriteAuth {
        did: auth_user.did,
        user_id,
        current_root_cid,
        is_oauth: auth_user.is_oauth,
        scope: auth_user.scope,
        controller_did: auth_user.controller_did,
    })
}
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct CreateRecordInput {
    pub repo: String,
    pub collection: String,
    pub rkey: Option<String>,
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
    pub uri: String,
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
    let auth =
        match prepare_repo_write(&state, &headers, &input.repo, "POST", &uri.to_string()).await {
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
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "InvalidSwap", "message": "Repo has been modified"})),
        )
            .into_response();
    }
    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = match tracking_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Commit block not found"})),
            )
                .into_response();
        }
    };
    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to parse commit"})),
            )
                .into_response();
        }
    };
    let mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let collection_nsid = match input.collection.parse::<Nsid>() {
        Ok(n) => n,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidCollection"})),
            )
                .into_response();
        }
    };
    let validation_status = if input.validate == Some(false) {
        None
    } else {
        let require_lexicon = input.validate == Some(true);
        match validate_record_with_status(
            &input.record,
            &input.collection,
            input.rkey.as_deref(),
            require_lexicon,
        ) {
            Ok(status) => Some(status),
            Err(err_response) => return *err_response,
        }
    };
    let rkey = input
        .rkey
        .unwrap_or_else(|| Tid::now(LimitedU32::MIN).to_string());
    let mut record_bytes = Vec::new();
    if serde_ipld_dagcbor::to_writer(&mut record_bytes, &input.record).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": "Failed to serialize record"})),
        )
            .into_response();
    }
    let record_cid = match tracking_store.put(&record_bytes).await {
        Ok(c) => c,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to save record block"})),
            )
                .into_response();
        }
    };
    let key = format!("{}/{}", collection_nsid, rkey);
    let new_mst = match mst.add(&key, record_cid).await {
        Ok(m) => m,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to add to MST"})),
            )
                .into_response();
        }
    };
    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to persist MST"})),
            )
                .into_response();
        }
    };
    let op = RecordOp::Create {
        collection: input.collection.clone(),
        rkey: rkey.clone(),
        cid: record_cid,
    };
    let mut relevant_blocks = std::collections::BTreeMap::new();
    if new_mst
        .blocks_for_path(&key, &mut relevant_blocks)
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get new MST blocks for path"}))).into_response();
    }
    if mst
        .blocks_for_path(&key, &mut relevant_blocks)
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get old MST blocks for path"}))).into_response();
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
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": e})),
            )
                .into_response();
        }
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
            uri: format!("at://{}/{}/{}", did, input.collection, rkey),
            cid: record_cid.to_string(),
            commit: CommitInfo {
                cid: commit_result.commit_cid.to_string(),
                rev: commit_result.rev,
            },
            validation_status: validation_status.map(|s| match s {
                ValidationStatus::Valid => "valid".to_string(),
                ValidationStatus::Unknown => "unknown".to_string(),
                ValidationStatus::Invalid => "invalid".to_string(),
            }),
        }),
    )
        .into_response()
}
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PutRecordInput {
    pub repo: String,
    pub collection: String,
    pub rkey: String,
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
    pub uri: String,
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
    let auth =
        match prepare_repo_write(&state, &headers, &input.repo, "POST", &uri.to_string()).await {
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
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "InvalidSwap", "message": "Repo has been modified"})),
        )
            .into_response();
    }
    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = match tracking_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Commit block not found"})),
            )
                .into_response();
        }
    };
    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to parse commit"})),
            )
                .into_response();
        }
    };
    let mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let collection_nsid = match input.collection.parse::<Nsid>() {
        Ok(n) => n,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidCollection"})),
            )
                .into_response();
        }
    };
    let key = format!("{}/{}", collection_nsid, input.rkey);
    let validation_status = if input.validate == Some(false) {
        None
    } else {
        let require_lexicon = input.validate == Some(true);
        match validate_record_with_status(
            &input.record,
            &input.collection,
            Some(&input.rkey),
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
            return (StatusCode::CONFLICT, Json(json!({"error": "InvalidSwap", "message": "Record has been modified or does not exist"}))).into_response();
        }
    }
    let existing_cid = mst.get(&key).await.ok().flatten();
    let mut record_bytes = Vec::new();
    if serde_ipld_dagcbor::to_writer(&mut record_bytes, &input.record).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": "Failed to serialize record"})),
        )
            .into_response();
    }
    let record_cid = match tracking_store.put(&record_bytes).await {
        Ok(c) => c,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to save record block"})),
            )
                .into_response();
        }
    };
    if existing_cid == Some(record_cid) {
        return (
            StatusCode::OK,
            Json(PutRecordOutput {
                uri: format!("at://{}/{}/{}", did, input.collection, input.rkey),
                cid: record_cid.to_string(),
                commit: None,
                validation_status: validation_status.map(|s| match s {
                    ValidationStatus::Valid => "valid".to_string(),
                    ValidationStatus::Unknown => "unknown".to_string(),
                    ValidationStatus::Invalid => "invalid".to_string(),
                }),
            }),
        )
            .into_response();
    }
    let new_mst = if existing_cid.is_some() {
        match mst.update(&key, record_cid).await {
            Ok(m) => m,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError", "message": "Failed to update MST"})),
                )
                    .into_response();
            }
        }
    } else {
        match mst.add(&key, record_cid).await {
            Ok(m) => m,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError", "message": "Failed to add to MST"})),
                )
                    .into_response();
            }
        }
    };
    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to persist MST"})),
            )
                .into_response();
        }
    };
    let op = if existing_cid.is_some() {
        RecordOp::Update {
            collection: input.collection.clone(),
            rkey: input.rkey.clone(),
            cid: record_cid,
            prev: existing_cid,
        }
    } else {
        RecordOp::Create {
            collection: input.collection.clone(),
            rkey: input.rkey.clone(),
            cid: record_cid,
        }
    };
    let mut relevant_blocks = std::collections::BTreeMap::new();
    if new_mst
        .blocks_for_path(&key, &mut relevant_blocks)
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get new MST blocks for path"}))).into_response();
    }
    if mst
        .blocks_for_path(&key, &mut relevant_blocks)
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get old MST blocks for path"}))).into_response();
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
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": e})),
            )
                .into_response();
        }
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
            uri: format!("at://{}/{}/{}", did, input.collection, input.rkey),
            cid: record_cid.to_string(),
            commit: Some(CommitInfo {
                cid: commit_result.commit_cid.to_string(),
                rev: commit_result.rev,
            }),
            validation_status: validation_status.map(|s| match s {
                ValidationStatus::Valid => "valid".to_string(),
                ValidationStatus::Unknown => "unknown".to_string(),
                ValidationStatus::Invalid => "invalid".to_string(),
            }),
        }),
    )
        .into_response()
}
