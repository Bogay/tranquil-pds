use super::validation::validate_record_with_status;
use super::validation_mode::{ValidationMode, deserialize_validation_mode};
use tranquil_pds::api::error::ApiError;
use crate::repo::record::utils::{CommitParams, RecordOp, commit_and_log, extract_blob_cids};
use tranquil_pds::auth::{
    Active, Auth, WriteOpKind, require_not_migrated, require_verified_or_delegated,
    verify_batch_write_scopes,
};
use tranquil_pds::cid_types::CommitCid;
use tranquil_pds::delegation::DelegationActionType;
use tranquil_pds::repo::tracking::TrackingBlockStore;
use tranquil_pds::state::AppState;
use tranquil_pds::types::{AtIdentifier, AtUri, Did, Nsid, Rkey};
use tranquil_pds::validation::ValidationStatus;
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
use tracing::info;

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
    validate: ValidationMode,
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
            let validation_status = if validate.should_skip() {
                None
            } else {
                match validate_record_with_status(
                    value,
                    collection,
                    rkey.as_ref(),
                    validate.requires_lexicon(),
                )
                .await
                {
                    Ok(status) => Some(status),
                    Err(err_response) => return Err(*err_response),
                }
            };
            all_blob_cids.extend(extract_blob_cids(value));
            let rkey = rkey.clone().unwrap_or_else(Rkey::generate);
            let record_ipld = tranquil_pds::util::json_to_ipld(value);
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
                validation_status,
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
            let validation_status = if validate.should_skip() {
                None
            } else {
                match validate_record_with_status(
                    value,
                    collection,
                    Some(rkey),
                    validate.requires_lexicon(),
                )
                .await
                {
                    Ok(status) => Some(status),
                    Err(err_response) => return Err(*err_response),
                }
            };
            all_blob_cids.extend(extract_blob_cids(value));
            let record_ipld = tranquil_pds::util::json_to_ipld(value);
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
                validation_status,
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
    validate: ValidationMode,
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
    #[serde(default, deserialize_with = "deserialize_validation_mode")]
    pub validate: ValidationMode,
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
        validation_status: Option<ValidationStatus>,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#updateResult")]
    UpdateResult {
        uri: AtUri,
        cid: String,
        #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
        validation_status: Option<ValidationStatus>,
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
    auth: Auth<Active>,
    Json(input): Json<ApplyWritesInput>,
) -> Result<Response, ApiError> {
    info!(
        "apply_writes called: repo={}, writes={}",
        input.repo,
        input.writes.len()
    );

    if input.writes.is_empty() {
        return Err(ApiError::InvalidRequest("writes array is empty".into()));
    }
    if input.writes.len() > MAX_BATCH_WRITES {
        return Err(ApiError::InvalidRequest(format!(
            "Too many writes (max {})",
            MAX_BATCH_WRITES
        )));
    }

    let batch_proof = match verify_batch_write_scopes(
        &auth,
        &auth,
        &input.writes,
        |w| match w {
            WriteOp::Create { collection, .. } => collection.as_str(),
            WriteOp::Update { collection, .. } => collection.as_str(),
            WriteOp::Delete { collection, .. } => collection.as_str(),
        },
        |w| match w {
            WriteOp::Create { .. } => WriteOpKind::Create,
            WriteOp::Update { .. } => WriteOpKind::Update,
            WriteOp::Delete { .. } => WriteOpKind::Delete,
        },
    ) {
        Ok(proof) => proof,
        Err(e) => return Ok(e.into_response()),
    };

    let principal_did = batch_proof.principal_did();
    let controller_did = batch_proof.controller_did().map(|c| c.into_did());

    if input.repo.as_str() != principal_did.as_str() {
        return Err(ApiError::InvalidRepo(
            "Repo does not match authenticated user".into(),
        ));
    }

    let did = principal_did.into_did();
    if let Err(e) = require_not_migrated(&state, &did).await {
        return Ok(e);
    }
    if let Err(e) = require_verified_or_delegated(&state, batch_proof.user()).await {
        return Ok(e);
    }

    let user_id: uuid::Uuid = state
        .user_repo
        .get_id_by_did(&did)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| ApiError::InternalError(Some("User not found".into())))?;

    let _write_lock = state.repo_write_locks.lock(user_id).await;

    let root_cid_str = state
        .repo_repo
        .get_repo_root_cid_by_user_id(user_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| ApiError::InternalError(Some("Repo root not found".into())))?;
    let current_root_cid = CommitCid::from_str(&root_cid_str)
        .map_err(|_| ApiError::InternalError(Some("Invalid repo root CID".into())))?;
    if let Some(swap_commit) = &input.swap_commit
        && CommitCid::from_str(swap_commit).ok().as_ref() != Some(&current_root_cid)
    {
        return Err(ApiError::InvalidSwap(Some("Repo has been modified".into())));
    }
    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = tracking_store
        .get(current_root_cid.as_cid())
        .await
        .ok()
        .flatten()
        .ok_or_else(|| ApiError::InternalError(Some("Commit block not found".into())))?;
    let commit = Commit::from_cbor(&commit_bytes)
        .map_err(|_| ApiError::InternalError(Some("Failed to parse commit".into())))?;
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
        Err(response) => return Ok(response),
    };
    let new_mst_root = mst
        .persist()
        .await
        .map_err(|_| ApiError::InternalError(Some("Failed to persist MST".into())))?;
    let (new_mst_blocks, old_mst_blocks) = {
        let mut new_blocks = std::collections::BTreeMap::new();
        let mut old_blocks = std::collections::BTreeMap::new();
        for key in &modified_keys {
            mst.blocks_for_path(key, &mut new_blocks)
                .await
                .map_err(|_| {
                    ApiError::InternalError(Some("Failed to get new MST blocks for path".into()))
                })?;
            original_mst
                .blocks_for_path(key, &mut old_blocks)
                .await
                .map_err(|_| {
                    ApiError::InternalError(Some("Failed to get old MST blocks for path".into()))
                })?;
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
    let obsolete_cids: Vec<Cid> = std::iter::once(current_root_cid.into_cid())
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
            current_root_cid: Some(current_root_cid.into_cid()),
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
        Err(e) => return Err(ApiError::from(e)),
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

    Ok((
        StatusCode::OK,
        Json(ApplyWritesOutput {
            commit: CommitInfo {
                cid: commit_res.commit_cid.to_string(),
                rev: commit_res.rev,
            },
            results,
        }),
    )
        .into_response())
}
