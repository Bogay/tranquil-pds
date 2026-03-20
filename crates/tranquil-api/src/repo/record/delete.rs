use crate::repo::record::write::{CommitInfo, prepare_repo_write};
use axum::{Json, extract::State};
use cid::Cid;
use jacquard_repo::{commit::Commit, mst::Mst, storage::BlockStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use tracing::error;
use tranquil_pds::api::error::ApiError;
use tranquil_pds::auth::{Active, Auth, VerifyScope};
use tranquil_pds::repo::TrackingBlockStore;
use tranquil_pds::repo_ops::{
    CommitError, FinalizeParams, RecordOp, begin_repo_write, finalize_repo_write,
};
use tranquil_pds::state::AppState;
use tranquil_pds::types::{AtIdentifier, AtUri, Did, Nsid, Rkey};

#[derive(Deserialize)]
pub struct DeleteRecordInput {
    pub repo: AtIdentifier,
    pub collection: Nsid,
    pub rkey: Rkey,
    #[serde(rename = "swapRecord")]
    pub swap_record: Option<String>,
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRecordOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<CommitInfo>,
}

pub async fn delete_record(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<DeleteRecordInput>,
) -> Result<Json<DeleteRecordOutput>, ApiError> {
    let scope_proof = auth.verify_repo_delete(&input.collection)?;
    let repo_auth = prepare_repo_write(&state, &scope_proof, &input.repo).await?;
    let did = repo_auth.did;
    let user_id = repo_auth.user_id;
    let controller_did = repo_auth.controller_did;

    let (ctx, mst) = begin_repo_write(&state, user_id, input.swap_commit.as_deref()).await?;

    let key = format!("{}/{}", input.collection, input.rkey);

    if let Some(swap_record_str) = &input.swap_record {
        let expected_cid = Cid::from_str(swap_record_str).ok();
        let actual_cid = mst.get(&key).await.ok().flatten();
        if expected_cid != actual_cid {
            return Err(ApiError::InvalidSwap(Some(
                "Record has been modified or does not exist".into(),
            )));
        }
    }

    let prev_record_cid = mst.get(&key).await.ok().flatten();
    if prev_record_cid.is_none() {
        return Ok(Json(DeleteRecordOutput { commit: None }));
    }

    let new_mst = mst.delete(&key).await.map_err(|e| {
        error!("Failed to delete from MST: {:?}", e);
        ApiError::InternalError(Some("Failed to delete from MST".into()))
    })?;

    let op = RecordOp::Delete {
        collection: input.collection.clone(),
        rkey: input.rkey.clone(),
        prev: prev_record_cid,
    };

    let modified_keys = [key];

    let commit_result = finalize_repo_write(
        &state,
        ctx,
        new_mst,
        FinalizeParams {
            did: &did,
            user_id,
            controller_did: controller_did.as_ref(),
            delegation_detail: controller_did.as_ref().map(|_| {
                json!({
                    "action": "delete",
                    "collection": input.collection,
                    "rkey": input.rkey
                })
            }),
            ops: vec![op],
            modified_keys: &modified_keys,
            blob_cids: &[],
        },
    )
    .await?;

    let deleted_uri = AtUri::from_parts(&did, &input.collection, &input.rkey);
    if let Err(e) = state
        .repos.backlink
        .remove_backlinks_by_uri(&deleted_uri)
        .await
    {
        error!("Failed to remove backlinks for {}: {}", deleted_uri, e);
    }

    Ok(Json(DeleteRecordOutput {
        commit: Some(CommitInfo {
            cid: commit_result.commit_cid.to_string(),
            rev: commit_result.rev,
        }),
    }))
}

use uuid::Uuid;

pub async fn delete_record_internal(
    state: &AppState,
    did: &Did,
    user_id: Uuid,
    collection: &Nsid,
    rkey: &Rkey,
) -> Result<(), CommitError> {
    use tranquil_pds::repo_ops::{CommitParams, RecordOp, commit_and_log};

    let _write_lock = state.repo_write_locks.lock(user_id).await;

    let root_cid_str = state
        .repos.repo
        .get_repo_root_cid_by_user_id(user_id)
        .await
        .map_err(|e| CommitError::DatabaseError(e.to_string()))?
        .ok_or(CommitError::RepoNotFound)?;

    let current_root_cid =
        Cid::from_str(root_cid_str.as_str()).map_err(|e| CommitError::InvalidCid(e.to_string()))?;

    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = tracking_store
        .get(&current_root_cid)
        .await
        .map_err(|e| CommitError::BlockStoreFailed(format!("{:?}", e)))?
        .ok_or(CommitError::BlockStoreFailed(
            "Commit block not found".into(),
        ))?;

    let commit = Commit::from_cbor(&commit_bytes)
        .map_err(|e| CommitError::CommitParseFailed(format!("{:?}", e)))?;

    let mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let key = format!("{}/{}", collection, rkey);

    let prev_record_cid = mst
        .get(&key)
        .await
        .map_err(|e| CommitError::MstOperationFailed(format!("{:?}", e)))?;

    let Some(prev_cid) = prev_record_cid else {
        return Ok(());
    };

    let new_mst = mst
        .delete(&key)
        .await
        .map_err(|e| CommitError::MstOperationFailed(format!("{:?}", e)))?;

    let new_mst_root = new_mst
        .persist()
        .await
        .map_err(|e| CommitError::MstOperationFailed(format!("{:?}", e)))?;

    let op = RecordOp::Delete {
        collection: collection.clone(),
        rkey: rkey.clone(),
        prev: Some(prev_cid),
    };

    let mut new_mst_blocks = std::collections::BTreeMap::new();
    let mut old_mst_blocks = std::collections::BTreeMap::new();

    new_mst
        .blocks_for_path(&key, &mut new_mst_blocks)
        .await
        .map_err(|e| CommitError::MstOperationFailed(format!("{:?}", e)))?;

    mst.blocks_for_path(&key, &mut old_mst_blocks)
        .await
        .map_err(|e| CommitError::MstOperationFailed(format!("{:?}", e)))?;

    let obsolete_cids: Vec<Cid> = std::iter::once(current_root_cid)
        .chain(
            old_mst_blocks
                .keys()
                .filter(|cid| !new_mst_blocks.contains_key(*cid))
                .copied(),
        )
        .chain(std::iter::once(prev_cid))
        .collect();

    let mut relevant_blocks = new_mst_blocks;
    relevant_blocks.extend(old_mst_blocks);

    let written_cids: Vec<Cid> = tracking_store
        .get_all_relevant_cids()
        .into_iter()
        .chain(relevant_blocks.keys().copied())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let written_cids_str: Vec<String> = written_cids.iter().map(ToString::to_string).collect();

    commit_and_log(
        state,
        CommitParams {
            did,
            user_id,
            current_root_cid: Some(current_root_cid),
            prev_data_cid: Some(commit.data),
            new_mst_root,
            ops: vec![op],
            blocks_cids: &written_cids_str,
            blobs: &[],
            obsolete_cids,
        },
    )
    .await?;

    Ok(())
}
