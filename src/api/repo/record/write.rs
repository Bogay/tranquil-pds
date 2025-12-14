use super::validation::validate_record;
use crate::api::repo::record::utils::{commit_and_log, RecordOp};
use crate::repo::tracking::TrackingBlockStore;
use crate::state::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use cid::Cid;
use jacquard::types::{integer::LimitedU32, string::{Nsid, Tid}};
use jacquard_repo::{commit::Commit, mst::Mst, storage::BlockStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::str::FromStr;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;
pub async fn has_verified_notification_channel(db: &PgPool, did: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT
            email_confirmed,
            discord_verified,
            telegram_verified,
            signal_verified
        FROM users
        WHERE did = $1
        "#
    )
    .bind(did)
    .fetch_optional(db)
    .await?;
    match row {
        Some(r) => {
            let email_confirmed: bool = r.get("email_confirmed");
            let discord_verified: bool = r.get("discord_verified");
            let telegram_verified: bool = r.get("telegram_verified");
            let signal_verified: bool = r.get("signal_verified");
            Ok(email_confirmed || discord_verified || telegram_verified || signal_verified)
        }
        None => Ok(false),
    }
}
pub async fn prepare_repo_write(
    state: &AppState,
    headers: &HeaderMap,
    repo_did: &str,
) -> Result<(String, Uuid, Cid), Response> {
    let token = crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response()
    })?;
    let auth_user = crate::auth::validate_bearer_token(&state.db, &token)
        .await
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
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
    match has_verified_notification_channel(&state.db, &auth_user.did).await {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "AccountNotVerified",
                    "message": "You must verify at least one notification channel (email, Discord, Telegram, or Signal) before creating records"
                })),
            )
                .into_response());
        }
        Err(e) => {
            error!("DB error checking notification channels: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response());
        }
    }
    let user_id = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", auth_user.did)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            error!("DB error fetching user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User not found"})),
            )
                .into_response()
        })?;
    let root_cid_str: String =
        sqlx::query_scalar!("SELECT repo_root_cid FROM repos WHERE user_id = $1", user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                error!("DB error fetching repo root: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response()
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
    Ok((auth_user.did, user_id, current_root_cid))
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
pub struct CreateRecordOutput {
    pub uri: String,
    pub cid: String,
}
pub async fn create_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateRecordInput>,
) -> Response {
    let (did, user_id, current_root_cid) =
        match prepare_repo_write(&state, &headers, &input.repo).await {
            Ok(res) => res,
            Err(err_res) => return err_res,
        };
    if let Some(swap_commit) = &input.swap_commit {
        if Cid::from_str(swap_commit).ok() != Some(current_root_cid) {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "InvalidSwap", "message": "Repo has been modified"})),
            )
                .into_response();
        }
    }
    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = match tracking_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Commit block not found"}))).into_response(),
    };
    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to parse commit"}))).into_response(),
    };
    let mst = Mst::load(
        Arc::new(tracking_store.clone()),
        commit.data,
        None,
    );
    let collection_nsid = match input.collection.parse::<Nsid>() {
        Ok(n) => n,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidCollection"}))).into_response(),
    };
    if input.validate.unwrap_or(true) {
        if let Err(err_response) = validate_record(&input.record, &input.collection) {
            return err_response;
        }
    }
    let rkey = input.rkey.unwrap_or_else(|| Tid::now(LimitedU32::MIN).to_string());
    let mut record_bytes = Vec::new();
    if serde_ipld_dagcbor::to_writer(&mut record_bytes, &input.record).is_err() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidRecord", "message": "Failed to serialize record"}))).into_response();
    }
    let record_cid = match tracking_store.put(&record_bytes).await {
        Ok(c) => c,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to save record block"}))).into_response(),
    };
    let key = format!("{}/{}", collection_nsid, rkey);
    let new_mst = match mst.add(&key, record_cid).await {
        Ok(m) => m,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to add to MST"}))).into_response(),
    };
    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to persist MST"}))).into_response(),
    };
    let op = RecordOp::Create { collection: input.collection.clone(), rkey: rkey.clone(), cid: record_cid };
    let mut relevant_blocks = std::collections::BTreeMap::new();
    if let Err(_) = new_mst.blocks_for_path(&key, &mut relevant_blocks).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get new MST blocks for path"}))).into_response();
    }
    if let Err(_) = mst.blocks_for_path(&key, &mut relevant_blocks).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get old MST blocks for path"}))).into_response();
    }
    relevant_blocks.insert(record_cid, bytes::Bytes::from(record_bytes));
    let mut written_cids = tracking_store.get_all_relevant_cids();
    for cid in relevant_blocks.keys() {
        if !written_cids.contains(cid) {
            written_cids.push(*cid);
        }
    }
    let written_cids_str = written_cids.iter().map(|c| c.to_string()).collect::<Vec<_>>();
    if let Err(e) = commit_and_log(&state, &did, user_id, Some(current_root_cid), Some(commit.data), new_mst_root, vec![op], &written_cids_str).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": e}))).into_response();
    };
    (StatusCode::OK, Json(CreateRecordOutput {
        uri: format!("at://{}/{}/{}", did, input.collection, rkey),
        cid: record_cid.to_string(),
    })).into_response()
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
}
pub async fn put_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<PutRecordInput>,
) -> Response {
    let (did, user_id, current_root_cid) =
        match prepare_repo_write(&state, &headers, &input.repo).await {
            Ok(res) => res,
            Err(err_res) => return err_res,
        };
    if let Some(swap_commit) = &input.swap_commit {
        if Cid::from_str(swap_commit).ok() != Some(current_root_cid) {
            return (StatusCode::CONFLICT, Json(json!({"error": "InvalidSwap", "message": "Repo has been modified"}))).into_response();
        }
    }
    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = match tracking_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Commit block not found"}))).into_response(),
    };
    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to parse commit"}))).into_response(),
    };
    let mst = Mst::load(
        Arc::new(tracking_store.clone()),
        commit.data,
        None,
    );
    let collection_nsid = match input.collection.parse::<Nsid>() {
        Ok(n) => n,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidCollection"}))).into_response(),
    };
    let key = format!("{}/{}", collection_nsid, input.rkey);
    if input.validate.unwrap_or(true) {
        if let Err(err_response) = validate_record(&input.record, &input.collection) {
            return err_response;
        }
    }
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
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidRecord", "message": "Failed to serialize record"}))).into_response();
    }
    let record_cid = match tracking_store.put(&record_bytes).await {
        Ok(c) => c,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to save record block"}))).into_response(),
    };
    let new_mst = if existing_cid.is_some() {
        match mst.update(&key, record_cid).await {
            Ok(m) => m,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to update MST"}))).into_response(),
        }
    } else {
        match mst.add(&key, record_cid).await {
            Ok(m) => m,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to add to MST"}))).into_response(),
        }
    };
    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to persist MST"}))).into_response(),
    };
    let op = if existing_cid.is_some() {
        RecordOp::Update { collection: input.collection.clone(), rkey: input.rkey.clone(), cid: record_cid, prev: existing_cid }
    } else {
        RecordOp::Create { collection: input.collection.clone(), rkey: input.rkey.clone(), cid: record_cid }
    };
    let mut relevant_blocks = std::collections::BTreeMap::new();
    if let Err(_) = new_mst.blocks_for_path(&key, &mut relevant_blocks).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get new MST blocks for path"}))).into_response();
    }
    if let Err(_) = mst.blocks_for_path(&key, &mut relevant_blocks).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get old MST blocks for path"}))).into_response();
    }
    relevant_blocks.insert(record_cid, bytes::Bytes::from(record_bytes));
    let mut written_cids = tracking_store.get_all_relevant_cids();
    for cid in relevant_blocks.keys() {
        if !written_cids.contains(cid) {
            written_cids.push(*cid);
        }
    }
    let written_cids_str = written_cids.iter().map(|c| c.to_string()).collect::<Vec<_>>();
    if let Err(e) = commit_and_log(&state, &did, user_id, Some(current_root_cid), Some(commit.data), new_mst_root, vec![op], &written_cids_str).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": e}))).into_response();
    };
    (StatusCode::OK, Json(PutRecordOutput {
        uri: format!("at://{}/{}/{}", did, input.collection, input.rkey),
        cid: record_cid.to_string(),
    })).into_response()
}
