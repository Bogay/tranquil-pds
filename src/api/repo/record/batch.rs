use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use cid::Cid;
use jacquard::types::{
    did::Did,
    integer::LimitedU32,
    string::{Nsid, Tid},
};
use jacquard_repo::{commit::Commit, mst::Mst, storage::BlockStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
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
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }
    let token = auth_header
        .unwrap()
        .to_str()
        .unwrap_or("")
        .replace("Bearer ", "");

    let session = sqlx::query(
        "SELECT s.did, k.key_bytes FROM sessions s JOIN users u ON s.did = u.did JOIN user_keys k ON u.id = k.user_id WHERE s.access_jwt = $1"
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let (did, key_bytes) = match session {
        Some(row) => (
            row.get::<String, _>("did"),
            row.get::<Vec<u8>, _>("key_bytes"),
        ),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
    };

    if let Err(_) = crate::auth::verify_token(&token, &key_bytes) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationFailed", "message": "Invalid token signature"})),
        )
            .into_response();
    }

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

    let user_query = sqlx::query("SELECT id FROM users WHERE did = $1")
        .bind(&did)
        .fetch_optional(&state.db)
        .await;

    let user_id: uuid::Uuid = match user_query {
        Ok(Some(row)) => row.get("id"),
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User not found"})),
            )
                .into_response();
        }
    };

    let repo_root_query = sqlx::query("SELECT repo_root_cid FROM repos WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    let current_root_cid = match repo_root_query {
        Ok(Some(row)) => {
            let cid_str: String = row.get("repo_root_cid");
            match Cid::from_str(&cid_str) {
                Ok(c) => c,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError", "message": "Invalid repo root CID"})),
                    )
                        .into_response();
                }
            }
        }
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Repo root not found"})),
            )
                .into_response();
        }
    };

    if let Some(swap_commit) = &input.swap_commit {
        let swap_cid = match Cid::from_str(swap_commit) {
            Ok(c) => c,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidSwap", "message": "Invalid swapCommit CID"})),
                )
                    .into_response();
            }
        };
        if swap_cid != current_root_cid {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "InvalidSwap", "message": "Repo has been modified"})),
            )
                .into_response();
        }
    }

    let commit_bytes = match state.block_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Commit block not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to load commit block: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let mst_root = commit.data;
    let store = Arc::new(state.block_store.clone());
    let mut mst = Mst::load(store.clone(), mst_root, None);

    let mut results: Vec<WriteResult> = Vec::new();
    let mut record_ops: Vec<(String, String, Option<String>)> = Vec::new();

    for write in &input.writes {
        match write {
            WriteOp::Create {
                collection,
                rkey,
                value,
            } => {
                let collection_nsid = match collection.parse::<Nsid>() {
                    Ok(n) => n,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "InvalidCollection"})),
                        )
                            .into_response();
                    }
                };

                let rkey = rkey
                    .clone()
                    .unwrap_or_else(|| Utc::now().format("%Y%m%d%H%M%S%f").to_string());

                let mut record_bytes = Vec::new();
                if let Err(e) = serde_ipld_dagcbor::to_writer(&mut record_bytes, value) {
                    error!("Error serializing record: {:?}", e);
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "InvalidRecord", "message": "Failed to serialize record"})),
                    )
                        .into_response();
                }

                let record_cid = match state.block_store.put(&record_bytes).await {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Failed to save record block: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError"})),
                        )
                            .into_response();
                    }
                };

                let key = format!("{}/{}", collection_nsid, rkey);
                mst = match mst.add(&key, record_cid).await {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Failed to add to MST: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError"})),
                        )
                            .into_response();
                    }
                };

                let uri = format!("at://{}/{}/{}", did, collection, rkey);
                results.push(WriteResult::CreateResult {
                    uri: uri.clone(),
                    cid: record_cid.to_string(),
                });
                record_ops.push((collection.clone(), rkey, Some(record_cid.to_string())));
            }
            WriteOp::Update {
                collection,
                rkey,
                value,
            } => {
                let collection_nsid = match collection.parse::<Nsid>() {
                    Ok(n) => n,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "InvalidCollection"})),
                        )
                            .into_response();
                    }
                };

                let mut record_bytes = Vec::new();
                if let Err(e) = serde_ipld_dagcbor::to_writer(&mut record_bytes, value) {
                    error!("Error serializing record: {:?}", e);
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "InvalidRecord", "message": "Failed to serialize record"})),
                    )
                        .into_response();
                }

                let record_cid = match state.block_store.put(&record_bytes).await {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Failed to save record block: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError"})),
                        )
                            .into_response();
                    }
                };

                let key = format!("{}/{}", collection_nsid, rkey);
                mst = match mst.update(&key, record_cid).await {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Failed to update MST: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError"})),
                        )
                            .into_response();
                    }
                };

                let uri = format!("at://{}/{}/{}", did, collection, rkey);
                results.push(WriteResult::UpdateResult {
                    uri: uri.clone(),
                    cid: record_cid.to_string(),
                });
                record_ops.push((collection.clone(), rkey.clone(), Some(record_cid.to_string())));
            }
            WriteOp::Delete { collection, rkey } => {
                let collection_nsid = match collection.parse::<Nsid>() {
                    Ok(n) => n,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "InvalidCollection"})),
                        )
                            .into_response();
                    }
                };

                let key = format!("{}/{}", collection_nsid, rkey);
                mst = match mst.delete(&key).await {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Failed to delete from MST: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError"})),
                        )
                            .into_response();
                    }
                };

                results.push(WriteResult::DeleteResult {});
                record_ops.push((collection.clone(), rkey.clone(), None));
            }
        }
    }

    let new_mst_root = match mst.persist().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to persist MST: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let did_obj = match Did::new(&did) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Invalid DID"})),
            )
                .into_response();
        }
    };

    let rev = Tid::now(LimitedU32::MIN);
    let new_commit = Commit::new_unsigned(did_obj, new_mst_root, rev.clone(), Some(current_root_cid));

    let new_commit_bytes = match new_commit.to_cbor() {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to serialize new commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let new_root_cid = match state.block_store.put(&new_commit_bytes).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to save new commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let update_repo = sqlx::query("UPDATE repos SET repo_root_cid = $1 WHERE user_id = $2")
        .bind(new_root_cid.to_string())
        .bind(user_id)
        .execute(&state.db)
        .await;

    if let Err(e) = update_repo {
        error!("Failed to update repo root in DB: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    for (collection, rkey, record_cid) in record_ops {
        match record_cid {
            Some(cid) => {
                let _ = sqlx::query(
                    "INSERT INTO records (repo_id, collection, rkey, record_cid) VALUES ($1, $2, $3, $4)
                     ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = $4, created_at = NOW()",
                )
                .bind(user_id)
                .bind(&collection)
                .bind(&rkey)
                .bind(&cid)
                .execute(&state.db)
                .await;
            }
            None => {
                let _ = sqlx::query(
                    "DELETE FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3",
                )
                .bind(user_id)
                .bind(&collection)
                .bind(&rkey)
                .execute(&state.db)
                .await;
            }
        }
    }

    (
        StatusCode::OK,
        Json(ApplyWritesOutput {
            commit: CommitInfo {
                cid: new_root_cid.to_string(),
                rev: rev.to_string(),
            },
            results,
        }),
    )
        .into_response()
}
