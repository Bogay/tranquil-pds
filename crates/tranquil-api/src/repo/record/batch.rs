use super::validation::validate_record_with_status;
use super::validation_mode::{ValidationMode, deserialize_validation_mode};
use crate::repo::record::write::CommitInfo;
use axum::{Json, extract::State};
use jacquard_repo::{mst::Mst, storage::BlockStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::auth::{
    Active, Auth, WriteOpKind, require_not_migrated, require_verified_or_delegated,
    verify_batch_write_scopes,
};
use tranquil_pds::repo::TrackingBlockStore;
use tranquil_pds::repo_ops::{
    FinalizeParams, RecordOp, begin_repo_write, extract_blob_cids, finalize_repo_write,
};
use tranquil_pds::state::AppState;
use tranquil_pds::types::{AtIdentifier, AtUri, Did, Nsid, Rkey};
use tranquil_pds::validation::ValidationStatus;

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
) -> Result<WriteAccumulator, ApiError> {
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
                Some(
                    validate_record_with_status(
                        value,
                        collection,
                        rkey.as_ref(),
                        validate.requires_lexicon(),
                    )
                    .await?,
                )
            };
            all_blob_cids.extend(extract_blob_cids(value));
            let rkey = rkey.clone().unwrap_or_else(Rkey::generate);
            let record_ipld = tranquil_pds::util::json_to_ipld(value);
            let record_bytes = serde_ipld_dagcbor::to_vec(&record_ipld)
                .map_err(|_| ApiError::InvalidRecord("Failed to serialize record".into()))?;
            let record_cid = tracking_store
                .put(&record_bytes)
                .await
                .map_err(|_| ApiError::InternalError(Some("Failed to store record".into())))?;
            let key = format!("{}/{}", collection, rkey);
            modified_keys.push(key.clone());
            let new_mst = mst
                .add(&key, record_cid)
                .await
                .map_err(|_| ApiError::InternalError(Some("Failed to add to MST".into())))?;
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
                Some(
                    validate_record_with_status(
                        value,
                        collection,
                        Some(rkey),
                        validate.requires_lexicon(),
                    )
                    .await?,
                )
            };
            all_blob_cids.extend(extract_blob_cids(value));
            let record_ipld = tranquil_pds::util::json_to_ipld(value);
            let record_bytes = serde_ipld_dagcbor::to_vec(&record_ipld)
                .map_err(|_| ApiError::InvalidRecord("Failed to serialize record".into()))?;
            let record_cid = tracking_store
                .put(&record_bytes)
                .await
                .map_err(|_| ApiError::InternalError(Some("Failed to store record".into())))?;
            let key = format!("{}/{}", collection, rkey);
            modified_keys.push(key.clone());
            let prev_record_cid = mst.get(&key).await.ok().flatten();
            let new_mst = mst
                .update(&key, record_cid)
                .await
                .map_err(|_| ApiError::InternalError(Some("Failed to update MST".into())))?;
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
            let new_mst = mst
                .delete(&key)
                .await
                .map_err(|_| ApiError::InternalError(Some("Failed to delete from MST".into())))?;
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
) -> Result<WriteAccumulator, ApiError> {
    use futures::stream::{self, TryStreamExt};
    let initial_acc = WriteAccumulator {
        mst: initial_mst,
        results: Vec::new(),
        ops: Vec::new(),
        modified_keys: Vec::new(),
        all_blob_cids: Vec::new(),
    };
    stream::iter(writes.iter().map(Ok::<_, ApiError>))
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

pub async fn apply_writes(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<ApplyWritesInput>,
) -> Result<Json<ApplyWritesOutput>, ApiError> {
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

    let batch_proof = verify_batch_write_scopes(
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
    )?;

    let principal_did = batch_proof.principal_did();
    let controller_did = batch_proof.controller_did().map(|c| c.into_did());

    if input.repo.as_str() != principal_did.as_str() {
        return Err(ApiError::InvalidRepo(
            "Repo does not match authenticated user".into(),
        ));
    }

    let did = principal_did.into_did();
    require_not_migrated(&state, &did).await?;
    require_verified_or_delegated(&state, batch_proof.user()).await?;

    let user_id: uuid::Uuid = state
        .repos.user
        .get_id_by_did(&did)
        .await
        .log_db_err("fetching user for batch write")?
        .ok_or(ApiError::InternalError(Some("User not found".into())))?;

    let (ctx, mst) = begin_repo_write(&state, user_id, input.swap_commit.as_deref()).await?;

    let WriteAccumulator {
        mst: final_mst,
        results,
        ops,
        modified_keys,
        all_blob_cids,
    } = process_writes(
        &input.writes,
        mst,
        &did,
        input.validate,
        &ctx.tracking_store,
    )
    .await?;

    let write_summary: Option<serde_json::Value> = controller_did.as_ref().map(|_| {
        let writes: Vec<serde_json::Value> = input
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
        json!({
            "action": "apply_writes",
            "count": input.writes.len(),
            "writes": writes
        })
    });

    let commit_result = finalize_repo_write(
        &state,
        ctx,
        final_mst,
        FinalizeParams {
            did: &did,
            user_id,
            controller_did: controller_did.as_ref(),
            delegation_detail: write_summary,
            ops,
            modified_keys: &modified_keys,
            blob_cids: &all_blob_cids,
        },
    )
    .await?;

    Ok(Json(ApplyWritesOutput {
        commit: CommitInfo {
            cid: commit_result.commit_cid.to_string(),
            rev: commit_result.rev,
        },
        results,
    }))
}
