use super::validation::validate_record_with_status;
use crate::api::error::ApiError;
use crate::api::repo::record::utils::{CommitParams, RecordOp, commit_and_log, extract_blob_cids};
use crate::auth::BearerAuth;
use crate::delegation::DelegationActionType;
use crate::repo::tracking::TrackingBlockStore;
use crate::state::AppState;
use crate::types::{AtIdentifier, AtUri, Did, Nsid, Rkey};
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

struct WriteAccumulator {
    mst: Mst<TrackingBlockStore>,
    results: Vec<WriteResult>,
    ops: Vec<RecordOp>,
    modified_keys: Vec<String>,
    all_blob_cids: Vec<String>,
}

async fn process_single_write(
    write: &WriteOp,
    acc: WriteAccumulator,
    did: &Did,
    validate: Option<bool>,
    tracking_store: &TrackingBlockStore,
) -> Result<WriteAccumulator, Response> {
    let WriteAccumulator {
        mst,
        mut results,
        mut ops,
        mut modified_keys,
        mut all_blob_cids,
    } = acc;

    match write {
        WriteOp::Create {
            collection,
            rkey,
            value,
        } => {
            let validation_status = match validate {
                Some(false) => None,
                _ => {
                    let require_lexicon = validate == Some(true);
                    match validate_record_with_status(
                        value,
                        collection,
                        rkey.as_ref(),
                        require_lexicon,
                    ) {
                        Ok(status) => Some(status),
                        Err(err_response) => return Err(*err_response),
                    }
                }
            };
            all_blob_cids.extend(extract_blob_cids(value));
            let rkey = rkey.clone().unwrap_or_else(Rkey::generate);
            let record_ipld = crate::util::json_to_ipld(value);
            let record_bytes = serde_ipld_dagcbor::to_vec(&record_ipld).map_err(|_| {
                ApiError::InvalidRecord("Failed to serialize record".into()).into_response()
            })?;
            let record_cid = tracking_store.put(&record_bytes).await.map_err(|_| {
                ApiError::InternalError(Some("Failed to store record".into())).into_response()
            })?;
            let key = format!("{}/{}", collection, rkey);
            modified_keys.push(key.clone());
            let new_mst = mst.add(&key, record_cid).await.map_err(|_| {
                ApiError::InternalError(Some("Failed to add to MST".into())).into_response()
            })?;
            let uri = AtUri::from_parts(did, collection, &rkey);
            results.push(WriteResult::CreateResult {
                uri,
                cid: record_cid.to_string(),
                validation_status: validation_status.map(|s| s.to_string()),
            });
            ops.push(RecordOp::Create {
                collection: collection.clone(),
                rkey: rkey.clone(),
                cid: record_cid,
            });
            Ok(WriteAccumulator {
                mst: new_mst,
                results,
                ops,
                modified_keys,
                all_blob_cids,
            })
        }
        WriteOp::Update {
            collection,
            rkey,
            value,
        } => {
            let validation_status = match validate {
                Some(false) => None,
                _ => {
                    let require_lexicon = validate == Some(true);
                    match validate_record_with_status(
                        value,
                        collection,
                        Some(rkey),
                        require_lexicon,
                    ) {
                        Ok(status) => Some(status),
                        Err(err_response) => return Err(*err_response),
                    }
                }
            };
            all_blob_cids.extend(extract_blob_cids(value));
            let record_ipld = crate::util::json_to_ipld(value);
            let record_bytes = serde_ipld_dagcbor::to_vec(&record_ipld).map_err(|_| {
                ApiError::InvalidRecord("Failed to serialize record".into()).into_response()
            })?;
            let record_cid = tracking_store.put(&record_bytes).await.map_err(|_| {
                ApiError::InternalError(Some("Failed to store record".into())).into_response()
            })?;
            let key = format!("{}/{}", collection, rkey);
            modified_keys.push(key.clone());
            let prev_record_cid = mst.get(&key).await.ok().flatten();
            let new_mst = mst.update(&key, record_cid).await.map_err(|_| {
                ApiError::InternalError(Some("Failed to update MST".into())).into_response()
            })?;
            let uri = AtUri::from_parts(did, collection, rkey);
            results.push(WriteResult::UpdateResult {
                uri,
                cid: record_cid.to_string(),
                validation_status: validation_status.map(|s| s.to_string()),
            });
            ops.push(RecordOp::Update {
                collection: collection.clone(),
                rkey: rkey.clone(),
                cid: record_cid,
                prev: prev_record_cid,
            });
            Ok(WriteAccumulator {
                mst: new_mst,
                results,
                ops,
                modified_keys,
                all_blob_cids,
            })
        }
        WriteOp::Delete { collection, rkey } => {
            let key = format!("{}/{}", collection, rkey);
            modified_keys.push(key.clone());
            let prev_record_cid = mst.get(&key).await.ok().flatten();
            let new_mst = mst.delete(&key).await.map_err(|_| {
                ApiError::InternalError(Some("Failed to delete from MST".into())).into_response()
            })?;
            results.push(WriteResult::DeleteResult {});
            ops.push(RecordOp::Delete {
                collection: collection.clone(),
                rkey: rkey.clone(),
                prev: prev_record_cid,
            });
            Ok(WriteAccumulator {
                mst: new_mst,
                results,
                ops,
                modified_keys,
                all_blob_cids,
            })
        }
    }
}

async fn process_writes(
    writes: &[WriteOp],
    initial_mst: Mst<TrackingBlockStore>,
    did: &Did,
    validate: Option<bool>,
    tracking_store: &TrackingBlockStore,
) -> Result<WriteAccumulator, Response> {
    use futures::stream::{self, TryStreamExt};
    let initial_acc = WriteAccumulator {
        mst: initial_mst,
        results: Vec::new(),
        ops: Vec::new(),
        modified_keys: Vec::new(),
        all_blob_cids: Vec::new(),
    };
    stream::iter(writes.iter().map(Ok::<_, Response>))
        .try_fold(initial_acc, |acc, write| async move {
            process_single_write(write, acc, did, validate, tracking_store).await
        })
        .await
}

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
    if state
        .user_repo
        .is_account_migrated(&did)
        .await
        .unwrap_or(false)
    {
        return ApiError::AccountMigrated.into_response();
    }
    let is_verified = state
        .user_repo
        .has_verified_comms_channel(&did)
        .await
        .unwrap_or(false);
    let is_delegated = state
        .delegation_repo
        .is_delegated_account(&did)
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

        let scope_checks = create_collections
            .iter()
            .map(|c| (crate::oauth::RepoAction::Create, c))
            .chain(
                update_collections
                    .iter()
                    .map(|c| (crate::oauth::RepoAction::Update, c)),
            )
            .chain(
                delete_collections
                    .iter()
                    .map(|c| (crate::oauth::RepoAction::Delete, c)),
            );

        if let Some(err) = scope_checks
            .filter_map(|(action, collection)| {
                crate::auth::scope_check::check_repo_scope(
                    is_oauth,
                    scope.as_deref(),
                    action,
                    collection,
                )
                .err()
            })
            .next()
        {
            return err;
        }
    }

    let user_id: uuid::Uuid = match state.user_repo.get_id_by_did(&did).await {
        Ok(Some(id)) => id,
        _ => return ApiError::InternalError(Some("User not found".into())).into_response(),
    };
    let root_cid_str = match state.repo_repo.get_repo_root_cid_by_user_id(user_id).await {
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
    let initial_mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let WriteAccumulator {
        mst,
        results,
        ops,
        modified_keys,
        all_blob_cids,
    } = match process_writes(
        &input.writes,
        initial_mst,
        &did,
        input.validate,
        &tracking_store,
    )
    .await
    {
        Ok(acc) => acc,
        Err(response) => return response,
    };
    let new_mst_root = match mst.persist().await {
        Ok(c) => c,
        Err(_) => {
            return ApiError::InternalError(Some("Failed to persist MST".into())).into_response();
        }
    };
    let (new_mst_blocks, old_mst_blocks) = {
        let mut new_blocks = std::collections::BTreeMap::new();
        let mut old_blocks = std::collections::BTreeMap::new();
        for key in &modified_keys {
            if mst.blocks_for_path(key, &mut new_blocks).await.is_err() {
                return ApiError::InternalError(Some(
                    "Failed to get new MST blocks for path".into(),
                ))
                .into_response();
            }
            if original_mst
                .blocks_for_path(key, &mut old_blocks)
                .await
                .is_err()
            {
                return ApiError::InternalError(Some(
                    "Failed to get old MST blocks for path".into(),
                ))
                .into_response();
            }
        }
        (new_blocks, old_blocks)
    };
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

        let _ = state
            .delegation_repo
            .log_delegation_action(
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
