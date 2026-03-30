use crate::repo::record::write::{CommitInfo, prepare_repo_write};
use axum::{Json, extract::State};
use cid::Cid;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use tracing::error;
use tranquil_pds::api::error::ApiError;
use tranquil_pds::auth::{Active, Auth, VerifyScope};
use tranquil_pds::cid_types::RecordCid;
use tranquil_pds::repo_ops::{FinalizeParams, RecordOp, begin_repo_write, finalize_repo_write};
use tranquil_pds::state::AppState;
use tranquil_pds::types::{AtIdentifier, AtUri, Nsid, Rkey};

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

    let prev_record_cid = mst.get(&key).await.map_err(|e| {
        error!("Failed to read prev record from MST: {}", e);
        ApiError::InternalError(Some("Failed to read MST".into()))
    })?;
    let Some(prev_record_cid) = prev_record_cid else {
        return Ok(Json(DeleteRecordOutput { commit: None }));
    };

    let new_mst = mst.delete(&key).await.map_err(|e| {
        error!("Failed to delete from MST: {}", e);
        ApiError::InternalError(Some("Failed to delete from MST".into()))
    })?;

    let op = RecordOp::Delete {
        collection: input.collection.clone(),
        rkey: input.rkey.clone(),
        prev: RecordCid::from(prev_record_cid),
    };

    let modified_keys = [key];
    let deleted_uri = AtUri::from_parts(&did, &input.collection, &input.rkey);

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
            backlinks_to_add: vec![],
            backlinks_to_remove: vec![deleted_uri],
        },
    )
    .await?;

    Ok(Json(DeleteRecordOutput {
        commit: Some(CommitInfo {
            cid: commit_result.commit_cid.to_string(),
            rev: commit_result.rev,
        }),
    }))
}
