use crate::api::repo::record::utils::{commit_and_log, RecordOp};
use crate::api::repo::record::write::prepare_repo_write;
use crate::repo::tracking::TrackingBlockStore;
use crate::state::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use cid::Cid;
use jacquard::types::string::Nsid;
use jacquard_repo::{commit::Commit, mst::Mst, storage::BlockStore};
use serde::Deserialize;
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
pub async fn delete_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<DeleteRecordInput>,
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
        return (StatusCode::OK, Json(json!({}))).into_response();
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
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to persist MST"}))).into_response();
        }
    };
    let op = RecordOp::Delete { collection: input.collection, rkey: input.rkey, prev: prev_record_cid };
    let mut relevant_blocks = std::collections::BTreeMap::new();
    if let Err(_) = new_mst.blocks_for_path(&key, &mut relevant_blocks).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get new MST blocks for path"}))).into_response();
    }
    if let Err(_) = mst.blocks_for_path(&key, &mut relevant_blocks).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get old MST blocks for path"}))).into_response();
    }
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
    (StatusCode::OK, Json(json!({}))).into_response()
}
