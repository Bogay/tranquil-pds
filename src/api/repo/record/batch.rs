use super::validation::validate_record_with_status;
use super::write::has_verified_comms_channel;
use crate::api::error::ApiError;
use crate::api::repo::record::utils::{CommitParams, RecordOp, commit_and_log, extract_blob_cids};
use crate::auth::BearerAuth;
use crate::delegation::{self, DelegationActionType};
use crate::repo::tracking::TrackingBlockStore;
use crate::state::AppState;
use crate::types::{AtIdentifier, AtUri, Nsid, Rkey};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cid::Cid;
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
        collection: Nsid,
        rkey: Option<Rkey>,
        value: serde_json::Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#update")]
    Update {
        collection: Nsid,
        rkey: Rkey,
        value: serde_json::Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#delete")]
    Delete { collection: Nsid, rkey: Rkey },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyWritesInput {
    pub repo: AtIdentifier,
    pub validate: Option<bool>,
    pub writes: Vec<WriteOp>,
    pub swap_commit: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "$type")]
pub enum WriteResult {
    #[serde(rename = "com.atproto.repo.applyWrites#createResult")]
    CreateResult {
        uri: AtUri,
        cid: String,
        #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
        validation_status: Option<String>,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#updateResult")]
    UpdateResult {
        uri: AtUri,
        cid: String,
        #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
        validation_status: Option<String>,
    },
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
    auth: BearerAuth,
    Json(input): Json<ApplyWritesInput>,
) -> Response {
    info!(
        "apply_writes called: repo={}, writes={}",
        input.repo,
        input.writes.len()
    );
    let auth_user = auth.0;
    let did = auth_user.did.clone();
    let is_oauth = auth_user.is_oauth;
    let scope = auth_user.scope;
    let controller_did = auth_user.controller_did.clone();
    if input.repo.as_str() != did {
        return ApiError::InvalidRepo("Repo does not match authenticated user".into())
            .into_response();
    }
    if crate::util::is_account_migrated(&state.db, &did)
        .await
        .unwrap_or(false)
    {
        return ApiError::AccountMigrated.into_response();
    }
    let is_verified = has_verified_comms_channel(&state.db, &did)
        .await
        .unwrap_or(false);
    let is_delegated = crate::delegation::is_delegated_account(&state.db, &did)
        .await
        .unwrap_or(false);
    if !is_verified && !is_delegated {
        return ApiError::AccountNotVerified.into_response();
    }
    if input.writes.is_empty() {
        return ApiError::InvalidRequest("writes array is empty".into()).into_response();
    }
    if input.writes.len() > MAX_BATCH_WRITES {
        return ApiError::InvalidRequest(format!("Too many writes (max {})", MAX_BATCH_WRITES))
            .into_response();
    }

    let has_custom_scope = scope
        .as_ref()
        .map(|s| s != "com.atproto.access")
        .unwrap_or(false);
    if is_oauth || has_custom_scope {
        use std::collections::HashSet;
        let create_collections: HashSet<&Nsid> = input
            .writes
            .iter()
            .filter_map(|w| {
                if let WriteOp::Create { collection, .. } = w {
                    Some(collection)
                } else {
                    None
                }
            })
            .collect();
        let update_collections: HashSet<&Nsid> = input
            .writes
            .iter()
            .filter_map(|w| {
                if let WriteOp::Update { collection, .. } = w {
                    Some(collection)
                } else {
                    None
                }
            })
            .collect();
        let delete_collections: HashSet<&Nsid> = input
            .writes
            .iter()
            .filter_map(|w| {
                if let WriteOp::Delete { collection, .. } = w {
                    Some(collection)
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

    let user_id: uuid::Uuid =
        match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did.as_str())
            .fetch_optional(&state.db)
            .await
        {
            Ok(Some(id)) => id,
            _ => return ApiError::InternalError(Some("User not found".into())).into_response(),
        };
    let root_cid_str: String = match sqlx::query_scalar!(
        "SELECT repo_root_cid FROM repos WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(cid_str)) => cid_str,
        _ => return ApiError::InternalError(Some("Repo root not found".into())).into_response(),
    };
    let current_root_cid = match Cid::from_str(&root_cid_str) {
        Ok(c) => c,
        Err(_) => {
            return ApiError::InternalError(Some("Invalid repo root CID".into())).into_response();
        }
    };
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
                let validation_status = if input.validate == Some(false) {
                    None
                } else {
                    let require_lexicon = input.validate == Some(true);
                    match validate_record_with_status(
                        value,
                        collection,
                        rkey.as_ref().map(|r| r.as_str()),
                        require_lexicon,
                    ) {
                        Ok(status) => Some(status),
                        Err(err_response) => return *err_response,
                    }
                };
                all_blob_cids.extend(extract_blob_cids(value));
                let rkey = rkey.clone().unwrap_or_else(Rkey::generate);
                let record_ipld = crate::util::json_to_ipld(value);
                let mut record_bytes = Vec::new();
                if serde_ipld_dagcbor::to_writer(&mut record_bytes, &record_ipld).is_err() {
                    return ApiError::InvalidRecord("Failed to serialize record".into())
                        .into_response();
                }
                let record_cid = match tracking_store.put(&record_bytes).await {
                    Ok(c) => c,
                    Err(_) => {
                        return ApiError::InternalError(Some("Failed to store record".into()))
                            .into_response();
                    }
                };
                let key = format!("{}/{}", collection, rkey);
                modified_keys.push(key.clone());
                mst = match mst.add(&key, record_cid).await {
                    Ok(m) => m,
                    Err(_) => {
                        return ApiError::InternalError(Some("Failed to add to MST".into()))
                            .into_response();
                    }
                };
                let uri = AtUri::from_parts(&did, collection, &rkey);
                results.push(WriteResult::CreateResult {
                    uri,
                    cid: record_cid.to_string(),
                    validation_status: validation_status.map(|s| s.to_string()),
                });
                ops.push(RecordOp::Create {
                    collection: collection.to_string(),
                    rkey: rkey.to_string(),
                    cid: record_cid,
                });
            }
            WriteOp::Update {
                collection,
                rkey,
                value,
            } => {
                let validation_status = if input.validate == Some(false) {
                    None
                } else {
                    let require_lexicon = input.validate == Some(true);
                    match validate_record_with_status(
                        value,
                        collection,
                        Some(rkey.as_str()),
                        require_lexicon,
                    ) {
                        Ok(status) => Some(status),
                        Err(err_response) => return *err_response,
                    }
                };
                all_blob_cids.extend(extract_blob_cids(value));
                let record_ipld = crate::util::json_to_ipld(value);
                let mut record_bytes = Vec::new();
                if serde_ipld_dagcbor::to_writer(&mut record_bytes, &record_ipld).is_err() {
                    return ApiError::InvalidRecord("Failed to serialize record".into())
                        .into_response();
                }
                let record_cid = match tracking_store.put(&record_bytes).await {
                    Ok(c) => c,
                    Err(_) => {
                        return ApiError::InternalError(Some("Failed to store record".into()))
                            .into_response();
                    }
                };
                let key = format!("{}/{}", collection, rkey);
                modified_keys.push(key.clone());
                let prev_record_cid = mst.get(&key).await.ok().flatten();
                mst = match mst.update(&key, record_cid).await {
                    Ok(m) => m,
                    Err(_) => {
                        return ApiError::InternalError(Some("Failed to update MST".into()))
                            .into_response();
                    }
                };
                let uri = AtUri::from_parts(&did, collection, rkey);
                results.push(WriteResult::UpdateResult {
                    uri,
                    cid: record_cid.to_string(),
                    validation_status: validation_status.map(|s| s.to_string()),
                });
                ops.push(RecordOp::Update {
                    collection: collection.to_string(),
                    rkey: rkey.to_string(),
                    cid: record_cid,
                    prev: prev_record_cid,
                });
            }
            WriteOp::Delete { collection, rkey } => {
                let key = format!("{}/{}", collection, rkey);
                modified_keys.push(key.clone());
                let prev_record_cid = mst.get(&key).await.ok().flatten();
                mst = match mst.delete(&key).await {
                    Ok(m) => m,
                    Err(_) => {
                        return ApiError::InternalError(Some("Failed to delete from MST".into()))
                            .into_response();
                    }
                };
                results.push(WriteResult::DeleteResult {});
                ops.push(RecordOp::Delete {
                    collection: collection.to_string(),
                    rkey: rkey.to_string(),
                    prev: prev_record_cid,
                });
            }
        }
    }
    let new_mst_root = match mst.persist().await {
        Ok(c) => c,
        Err(_) => {
            return ApiError::InternalError(Some("Failed to persist MST".into())).into_response();
        }
    };
    let mut new_mst_blocks = std::collections::BTreeMap::new();
    let mut old_mst_blocks = std::collections::BTreeMap::new();
    for key in &modified_keys {
        if mst.blocks_for_path(key, &mut new_mst_blocks).await.is_err() {
            return ApiError::InternalError(Some("Failed to get new MST blocks for path".into()))
                .into_response();
        }
        if original_mst
            .blocks_for_path(key, &mut old_mst_blocks)
            .await
            .is_err()
        {
            return ApiError::InternalError(Some("Failed to get old MST blocks for path".into()))
                .into_response();
        }
    }
    let mut relevant_blocks = new_mst_blocks.clone();
    relevant_blocks.extend(old_mst_blocks.iter().map(|(k, v)| (*k, v.clone())));
    let written_cids: Vec<Cid> = tracking_store
        .get_all_relevant_cids()
        .into_iter()
        .chain(relevant_blocks.keys().copied())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let written_cids_str: Vec<String> = written_cids.iter().map(|c| c.to_string()).collect();
    let prev_record_cids = ops.iter().filter_map(|op| match op {
        RecordOp::Update {
            prev: Some(cid), ..
        }
        | RecordOp::Delete {
            prev: Some(cid), ..
        } => Some(*cid),
        _ => None,
    });
    let obsolete_cids: Vec<Cid> = std::iter::once(current_root_cid)
        .chain(
            old_mst_blocks
                .keys()
                .filter(|cid| !new_mst_blocks.contains_key(*cid))
                .copied(),
        )
        .chain(prev_record_cids)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
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
            obsolete_cids,
        },
    )
    .await
    {
        Ok(res) => res,
        Err(e) if e.contains("ConcurrentModification") => {
            return ApiError::InvalidSwap(Some("Repo has been modified".into())).into_response();
        }
        Err(e) => {
            error!("Commit failed: {}", e);
            return ApiError::InternalError(Some("Failed to commit changes".into()))
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
