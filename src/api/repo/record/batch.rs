use super::validation::validate_record;
use super::write::has_verified_comms_channel;
use crate::api::repo::record::utils::{CommitParams, RecordOp, commit_and_log, extract_blob_cids};
use crate::delegation::{self, DelegationActionType};
use crate::repo::tracking::TrackingBlockStore;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
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
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info};

const MAX_BATCH_WRITES: usize = 200;

#[derive(Deserialize)]
#[serde(tag = "$type")]
pub enum WriteOp {
    #[serde(rename = "com.atproto.repo.applyWrites#create")]
    Create {
        collection: String,
        rkey: Option<String>,
        value: serde_json::Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#update")]
    Update {
        collection: String,
        rkey: String,
        value: serde_json::Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#delete")]
    Delete { collection: String, rkey: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyWritesInput {
    pub repo: String,
    pub validate: Option<bool>,
    pub writes: Vec<WriteOp>,
    pub swap_commit: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "$type")]
pub enum WriteResult {
    #[serde(rename = "com.atproto.repo.applyWrites#createResult")]
    CreateResult { uri: String, cid: String },
    #[serde(rename = "com.atproto.repo.applyWrites#updateResult")]
    UpdateResult { uri: String, cid: String },
    #[serde(rename = "com.atproto.repo.applyWrites#deleteResult")]
    DeleteResult {},
}

#[derive(Serialize)]
pub struct ApplyWritesOutput {
    pub commit: CommitInfo,
    pub results: Vec<WriteResult>,
}

#[derive(Serialize)]
pub struct CommitInfo {
    pub cid: String,
    pub rev: String,
}

pub async fn apply_writes(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<ApplyWritesInput>,
) -> Response {
    info!(
        "apply_writes called: repo={}, writes={}",
        input.repo,
        input.writes.len()
    );
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };
    let auth_user = match crate::auth::validate_bearer_token(&state.db, &token).await {
        Ok(user) => user,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
    };
    let did = auth_user.did.clone();
    let is_oauth = auth_user.is_oauth;
    let scope = auth_user.scope;
    let controller_did = auth_user.controller_did.clone();
    if input.repo != did {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "InvalidRepo", "message": "Repo does not match authenticated user"})),
        )
            .into_response();
    }
    let is_verified = has_verified_comms_channel(&state.db, &did)
        .await
        .unwrap_or(false);
    let is_delegated = crate::delegation::is_delegated_account(&state.db, &did)
        .await
        .unwrap_or(false);
    if !is_verified && !is_delegated {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "AccountNotVerified",
                "message": "You must verify at least one notification channel (email, Discord, Telegram, or Signal) before creating records"
            })),
        )
            .into_response();
    }
    if input.writes.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "writes array is empty"})),
        )
            .into_response();
    }
    if input.writes.len() > MAX_BATCH_WRITES {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": format!("Too many writes (max {})", MAX_BATCH_WRITES)})),
        )
            .into_response();
    }

    let has_custom_scope = scope
        .as_ref()
        .map(|s| s != "com.atproto.access")
        .unwrap_or(false);
    if is_oauth || has_custom_scope {
        use std::collections::HashSet;
        let create_collections: HashSet<&str> = input
            .writes
            .iter()
            .filter_map(|w| {
                if let WriteOp::Create { collection, .. } = w {
                    Some(collection.as_str())
                } else {
                    None
                }
            })
            .collect();
        let update_collections: HashSet<&str> = input
            .writes
            .iter()
            .filter_map(|w| {
                if let WriteOp::Update { collection, .. } = w {
                    Some(collection.as_str())
                } else {
                    None
                }
            })
            .collect();
        let delete_collections: HashSet<&str> = input
            .writes
            .iter()
            .filter_map(|w| {
                if let WriteOp::Delete { collection, .. } = w {
                    Some(collection.as_str())
                } else {
                    None
                }
            })
            .collect();

        for collection in create_collections {
            if let Err(e) = crate::auth::scope_check::check_repo_scope(
                is_oauth,
                scope.as_deref(),
                crate::oauth::RepoAction::Create,
                collection,
            ) {
                return e;
            }
        }
        for collection in update_collections {
            if let Err(e) = crate::auth::scope_check::check_repo_scope(
                is_oauth,
                scope.as_deref(),
                crate::oauth::RepoAction::Update,
                collection,
            ) {
                return e;
            }
        }
        for collection in delete_collections {
            if let Err(e) = crate::auth::scope_check::check_repo_scope(
                is_oauth,
                scope.as_deref(),
                crate::oauth::RepoAction::Delete,
                collection,
            ) {
                return e;
            }
        }
    }

    let user_id: uuid::Uuid = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(id)) => id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User not found"})),
            )
                .into_response();
        }
    };
    let root_cid_str: String = match sqlx::query_scalar!(
        "SELECT repo_root_cid FROM repos WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(cid_str)) => cid_str,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Repo root not found"})),
            )
                .into_response();
        }
    };
    let current_root_cid = match Cid::from_str(&root_cid_str) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Invalid repo root CID"})),
            )
                .into_response();
        }
    };
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
    let original_mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let mut mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let mut results: Vec<WriteResult> = Vec::new();
    let mut ops: Vec<RecordOp> = Vec::new();
    let mut modified_keys: Vec<String> = Vec::new();
    let mut all_blob_cids: Vec<String> = Vec::new();
    for write in &input.writes {
        match write {
            WriteOp::Create {
                collection,
                rkey,
                value,
            } => {
                if input.validate.unwrap_or(true)
                    && let Err(err_response) = validate_record(value, collection)
                {
                    return *err_response;
                }
                all_blob_cids.extend(extract_blob_cids(value));
                let rkey = rkey
                    .clone()
                    .unwrap_or_else(|| Tid::now(LimitedU32::MIN).to_string());
                let mut record_bytes = Vec::new();
                if serde_ipld_dagcbor::to_writer(&mut record_bytes, value).is_err() {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidRecord", "message": "Failed to serialize record"}))).into_response();
                }
                let record_cid = match tracking_store.put(&record_bytes).await {
                    Ok(c) => c,
                    Err(_) => return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            json!({"error": "InternalError", "message": "Failed to store record"}),
                        ),
                    )
                        .into_response(),
                };
                let collection_nsid = match collection.parse::<Nsid>() {
                    Ok(n) => n,
                    Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidCollection", "message": "Invalid collection NSID"}))).into_response(),
                };
                let key = format!("{}/{}", collection_nsid, rkey);
                modified_keys.push(key.clone());
                mst = match mst.add(&key, record_cid).await {
                    Ok(m) => m,
                    Err(_) => return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError", "message": "Failed to add to MST"})),
                    )
                        .into_response(),
                };
                let uri = format!("at://{}/{}/{}", did, collection, rkey);
                results.push(WriteResult::CreateResult {
                    uri,
                    cid: record_cid.to_string(),
                });
                ops.push(RecordOp::Create {
                    collection: collection.clone(),
                    rkey,
                    cid: record_cid,
                });
            }
            WriteOp::Update {
                collection,
                rkey,
                value,
            } => {
                if input.validate.unwrap_or(true)
                    && let Err(err_response) = validate_record(value, collection)
                {
                    return *err_response;
                }
                all_blob_cids.extend(extract_blob_cids(value));
                let mut record_bytes = Vec::new();
                if serde_ipld_dagcbor::to_writer(&mut record_bytes, value).is_err() {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidRecord", "message": "Failed to serialize record"}))).into_response();
                }
                let record_cid = match tracking_store.put(&record_bytes).await {
                    Ok(c) => c,
                    Err(_) => return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            json!({"error": "InternalError", "message": "Failed to store record"}),
                        ),
                    )
                        .into_response(),
                };
                let collection_nsid = match collection.parse::<Nsid>() {
                    Ok(n) => n,
                    Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidCollection", "message": "Invalid collection NSID"}))).into_response(),
                };
                let key = format!("{}/{}", collection_nsid, rkey);
                modified_keys.push(key.clone());
                let prev_record_cid = mst.get(&key).await.ok().flatten();
                mst = match mst.update(&key, record_cid).await {
                    Ok(m) => m,
                    Err(_) => return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError", "message": "Failed to update MST"})),
                    )
                        .into_response(),
                };
                let uri = format!("at://{}/{}/{}", did, collection, rkey);
                results.push(WriteResult::UpdateResult {
                    uri,
                    cid: record_cid.to_string(),
                });
                ops.push(RecordOp::Update {
                    collection: collection.clone(),
                    rkey: rkey.clone(),
                    cid: record_cid,
                    prev: prev_record_cid,
                });
            }
            WriteOp::Delete { collection, rkey } => {
                let collection_nsid = match collection.parse::<Nsid>() {
                    Ok(n) => n,
                    Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidCollection", "message": "Invalid collection NSID"}))).into_response(),
                };
                let key = format!("{}/{}", collection_nsid, rkey);
                modified_keys.push(key.clone());
                let prev_record_cid = mst.get(&key).await.ok().flatten();
                mst = match mst.delete(&key).await {
                    Ok(m) => m,
                    Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to delete from MST"}))).into_response(),
                };
                results.push(WriteResult::DeleteResult {});
                ops.push(RecordOp::Delete {
                    collection: collection.clone(),
                    rkey: rkey.clone(),
                    prev: prev_record_cid,
                });
            }
        }
    }
    let new_mst_root = match mst.persist().await {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to persist MST"})),
            )
                .into_response();
        }
    };
    let mut relevant_blocks = std::collections::BTreeMap::new();
    for key in &modified_keys {
        if mst
            .blocks_for_path(key, &mut relevant_blocks)
            .await
            .is_err()
        {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get new MST blocks for path"}))).into_response();
        }
        if original_mst
            .blocks_for_path(key, &mut relevant_blocks)
            .await
            .is_err()
        {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get old MST blocks for path"}))).into_response();
        }
    }
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
    let commit_res = match commit_and_log(
        &state,
        CommitParams {
            did: &did,
            user_id,
            current_root_cid: Some(current_root_cid),
            prev_data_cid: Some(commit.data),
            new_mst_root,
            ops,
            blocks_cids: &written_cids_str,
            blobs: &all_blob_cids,
        },
    )
    .await
    {
        Ok(res) => res,
        Err(e) => {
            error!("Commit failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to commit changes"})),
            )
                .into_response();
        }
    };

    if let Some(ref controller) = controller_did {
        let write_summary: Vec<serde_json::Value> = input
            .writes
            .iter()
            .map(|w| match w {
                WriteOp::Create {
                    collection, rkey, ..
                } => json!({
                    "action": "create",
                    "collection": collection,
                    "rkey": rkey
                }),
                WriteOp::Update {
                    collection, rkey, ..
                } => json!({
                    "action": "update",
                    "collection": collection,
                    "rkey": rkey
                }),
                WriteOp::Delete { collection, rkey } => json!({
                    "action": "delete",
                    "collection": collection,
                    "rkey": rkey
                }),
            })
            .collect();

        let _ = delegation::log_delegation_action(
            &state.db,
            &did,
            controller,
            Some(controller),
            DelegationActionType::RepoWrite,
            Some(json!({
                "action": "apply_writes",
                "count": input.writes.len(),
                "writes": write_summary
            })),
            None,
            None,
        )
        .await;
    }

    (
        StatusCode::OK,
        Json(ApplyWritesOutput {
            commit: CommitInfo {
                cid: commit_res.commit_cid.to_string(),
                rev: commit_res.rev,
            },
            results,
        }),
    )
        .into_response()
}
