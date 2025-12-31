use crate::api::repo::record::utils::{CommitParams, RecordOp, commit_and_log};
use crate::api::repo::record::write::{CommitInfo, prepare_repo_write};
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
use jacquard::types::string::Nsid;
use jacquard_repo::{commit::Commit, mst::Mst, storage::BlockStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use tracing::error;

#[derive(Deserialize)]
pub struct DeleteRecordInput {
    pub repo: String,
    pub collection: String,
    pub rkey: String,
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
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Json(input): Json<DeleteRecordInput>,
) -> Response {
    let auth =
        match prepare_repo_write(&state, &headers, &input.repo, "POST", &uri.to_string()).await {
            Ok(res) => res,
            Err(err_res) => return err_res,
        };

    if let Err(e) = crate::auth::scope_check::check_repo_scope(
        auth.is_oauth,
        auth.scope.as_deref(),
        crate::oauth::RepoAction::Delete,
        &input.collection,
    ) {
        return e;
    }

    if crate::util::is_account_migrated(&state.db, &auth.did)
        .await
        .unwrap_or(false)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "AccountMigrated",
                "message": "Account has been migrated. Repo operations are not allowed."
            })),
        )
            .into_response();
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
    if let Some(swap_record_str) = &input.swap_record {
        let expected_cid = Cid::from_str(swap_record_str).ok();
        let actual_cid = mst.get(&key).await.ok().flatten();
        if expected_cid != actual_cid {
            return (StatusCode::CONFLICT, Json(json!({"error": "InvalidSwap", "message": "Record has been modified or does not exist"}))).into_response();
        }
    }
    let prev_record_cid = mst.get(&key).await.ok().flatten();
    if prev_record_cid.is_none() {
        return (StatusCode::OK, Json(DeleteRecordOutput { commit: None })).into_response();
    }
    let new_mst = match mst.delete(&key).await {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to delete from MST: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": format!("Failed to delete from MST: {:?}", e)}))).into_response();
        }
    };
    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to persist MST: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to persist MST"})),
            )
                .into_response();
        }
    };
    let collection_for_audit = input.collection.clone();
    let rkey_for_audit = input.rkey.clone();
    let op = RecordOp::Delete {
        collection: input.collection,
        rkey: input.rkey,
        prev: prev_record_cid,
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
            blobs: &[],
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
                "action": "delete",
                "collection": collection_for_audit,
                "rkey": rkey_for_audit
            })),
            None,
            None,
        )
        .await;
    }

    (
        StatusCode::OK,
        Json(DeleteRecordOutput {
            commit: Some(CommitInfo {
                cid: commit_result.commit_cid.to_string(),
                rev: commit_result.rev,
            }),
        }),
    )
        .into_response()
}
