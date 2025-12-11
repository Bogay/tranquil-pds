use crate::api::repo::record::utils::{commit_and_log, RecordOp};
use crate::repo::tracking::TrackingBlockStore;
use crate::state::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use cid::Cid;
use jacquard::types::string::Nsid;
use jacquard_repo::{commit::Commit, mst::Mst, storage::BlockStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use tracing::error;

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
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
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

    let did = auth_user.did;

    if input.repo != did {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "InvalidRepo", "message": "Repo does not match authenticated user"})),
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

    if input.writes.len() > 200 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Too many writes (max 200)"})),
        )
            .into_response();
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

    let root_cid_str: String =
        match sqlx::query_scalar!("SELECT repo_root_cid FROM repos WHERE user_id = $1", user_id)
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
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Commit block not found"})),
            )
                .into_response()
        }
    };

    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to parse commit"})),
            )
                .into_response()
        }
    };

    let mut mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);

    let mut results: Vec<WriteResult> = Vec::new();
    let mut ops: Vec<RecordOp> = Vec::new();

    for write in &input.writes {
        match write {
            WriteOp::Create {
                collection,
                rkey,
                value,
            } => {
                let rkey = rkey
                    .clone()
                    .unwrap_or_else(|| Utc::now().format("%Y%m%d%H%M%S%f").to_string());
                let mut record_bytes = Vec::new();
                serde_ipld_dagcbor::to_writer(&mut record_bytes, value).unwrap();
                let record_cid = tracking_store.put(&record_bytes).await.unwrap();

                let key = format!("{}/{}", collection.parse::<Nsid>().unwrap(), rkey);
                mst = mst.add(&key, record_cid).await.unwrap();

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
                let mut record_bytes = Vec::new();
                serde_ipld_dagcbor::to_writer(&mut record_bytes, value).unwrap();
                let record_cid = tracking_store.put(&record_bytes).await.unwrap();

                let key = format!("{}/{}", collection.parse::<Nsid>().unwrap(), rkey);
                mst = mst.update(&key, record_cid).await.unwrap();

                let uri = format!("at://{}/{}/{}", did, collection, rkey);
                results.push(WriteResult::UpdateResult {
                    uri,
                    cid: record_cid.to_string(),
                });
                ops.push(RecordOp::Update {
                    collection: collection.clone(),
                    rkey: rkey.clone(),
                    cid: record_cid,
                });
            }
            WriteOp::Delete { collection, rkey } => {
                let key = format!("{}/{}", collection.parse::<Nsid>().unwrap(), rkey);
                mst = mst.delete(&key).await.unwrap();

                results.push(WriteResult::DeleteResult {});
                ops.push(RecordOp::Delete {
                    collection: collection.clone(),
                    rkey: rkey.clone(),
                });
            }
        }
    }

    let new_mst_root = mst.persist().await.unwrap();
    let written_cids = tracking_store.get_written_cids();
    let written_cids_str = written_cids
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>();

    let commit_res = match commit_and_log(
        &state,
        &did,
        user_id,
        Some(current_root_cid),
        new_mst_root,
        ops,
        &written_cids_str,
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
