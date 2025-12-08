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
use std::str::FromStr;
use std::sync::Arc;
use tracing::error;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct CreateRecordInput {
    pub repo: String,
    pub collection: String,
    pub rkey: Option<String>,
    pub validate: Option<bool>,
    pub record: serde_json::Value,
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRecordOutput {
    pub uri: String,
    pub cid: String,
}

pub async fn create_record(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<CreateRecordInput>,
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

    let session = sqlx::query!(
            "SELECT s.did, k.key_bytes FROM sessions s JOIN users u ON s.did = u.did JOIN user_keys k ON u.id = k.user_id WHERE s.access_jwt = $1",
            token
        )
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let (did, key_bytes) = match session {
        Some(row) => (
            row.did,
            row.key_bytes,
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
        return (StatusCode::FORBIDDEN, Json(json!({"error": "InvalidRepo", "message": "Repo does not match authenticated user"}))).into_response();
    }

    let user_query = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;

    let user_id: uuid::Uuid = match user_query {
        Ok(Some(row)) => row.id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User not found"})),
            )
                .into_response();
        }
    };

    let repo_root_query = sqlx::query!("SELECT repo_root_cid FROM repos WHERE user_id = $1", user_id)
        .fetch_optional(&state.db)
        .await;

    let current_root_cid = match repo_root_query {
        Ok(Some(row)) => {
            let cid_str: String = row.repo_root_cid;
            Cid::from_str(&cid_str).ok()
        }
        _ => None,
    };

    if current_root_cid.is_none() {
        error!("Repo root not found for user {}", did);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Repo root not found"})),
        )
            .into_response();
    }
    let current_root_cid = current_root_cid.unwrap();

    let commit_bytes = match state.block_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            error!("Commit block not found: {}", current_root_cid);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
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
    let mst = Mst::load(store.clone(), mst_root, None);

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

    let rkey = input
        .rkey
        .unwrap_or_else(|| Utc::now().format("%Y%m%d%H%M%S%f").to_string());

    if input.validate.unwrap_or(true) {
        if input.collection == "app.bsky.feed.post" {
            if input.record.get("text").is_none() || input.record.get("createdAt").is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidRecord", "message": "Record validation failed"})),
                )
                    .into_response();
            }
        }
    }

    let mut record_bytes = Vec::new();
    if let Err(e) = serde_ipld_dagcbor::to_writer(&mut record_bytes, &input.record) {
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
    let new_mst = match mst.add(&key, record_cid).await {
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

    let new_mst_root = match new_mst.persist().await {
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

    let new_commit = Commit::new_unsigned(did_obj, new_mst_root, rev, Some(current_root_cid));

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

    let update_repo = sqlx::query!("UPDATE repos SET repo_root_cid = $1 WHERE user_id = $2", new_root_cid.to_string(), user_id)
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

    let record_insert = sqlx::query!(
        "INSERT INTO records (repo_id, collection, rkey, record_cid) VALUES ($1, $2, $3, $4)
         ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = $4, created_at = NOW()",
        user_id,
        input.collection,
        rkey,
        record_cid.to_string()
    )
    .execute(&state.db)
    .await;

    if let Err(e) = record_insert {
        error!("Error inserting record index: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to index record"})),
        )
            .into_response();
    }

    let output = CreateRecordOutput {
        uri: format!("at://{}/{}/{}", input.repo, input.collection, rkey),
        cid: record_cid.to_string(),
    };
    (StatusCode::OK, Json(output)).into_response()
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PutRecordInput {
    pub repo: String,
    pub collection: String,
    pub rkey: String,
    pub validate: Option<bool>,
    pub record: serde_json::Value,
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
    #[serde(rename = "swapRecord")]
    pub swap_record: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PutRecordOutput {
    pub uri: String,
    pub cid: String,
}

pub async fn put_record(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<PutRecordInput>,
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

    let session = sqlx::query!(
            "SELECT s.did, k.key_bytes FROM sessions s JOIN users u ON s.did = u.did JOIN user_keys k ON u.id = k.user_id WHERE s.access_jwt = $1",
            token
        )
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let (did, key_bytes) = match session {
        Some(row) => (
            row.did,
            row.key_bytes,
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
        return (StatusCode::FORBIDDEN, Json(json!({"error": "InvalidRepo", "message": "Repo does not match authenticated user"}))).into_response();
    }

    let user_query = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;

    let user_id: uuid::Uuid = match user_query {
        Ok(Some(row)) => row.id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User not found"})),
            )
                .into_response();
        }
    };

    let repo_root_query = sqlx::query!("SELECT repo_root_cid FROM repos WHERE user_id = $1", user_id)
        .fetch_optional(&state.db)
        .await;

    let current_root_cid = match repo_root_query {
        Ok(Some(row)) => {
            let cid_str: String = row.repo_root_cid;
            Cid::from_str(&cid_str).ok()
        }
        _ => None,
    };

    if current_root_cid.is_none() {
        error!("Repo root not found for user {}", did);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Repo root not found"})),
        )
            .into_response();
    }
    let current_root_cid = current_root_cid.unwrap();

    let commit_bytes = match state.block_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            error!("Commit block not found: {}", current_root_cid);
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
                Json(json!({"error": "InternalError", "message": "Failed to load commit block"})),
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
                Json(json!({"error": "InternalError", "message": "Failed to parse commit"})),
            )
                .into_response();
        }
    };

    let mst_root = commit.data;
    let store = Arc::new(state.block_store.clone());
    let mst = Mst::load(store.clone(), mst_root, None);

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

    let rkey = input.rkey.clone();

    if input.validate.unwrap_or(true) {
        if input.collection == "app.bsky.feed.post" {
            if input.record.get("text").is_none() || input.record.get("createdAt").is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidRecord", "message": "Record validation failed"})),
                )
                    .into_response();
            }
        }
    }

    let mut record_bytes = Vec::new();
    if let Err(e) = serde_ipld_dagcbor::to_writer(&mut record_bytes, &input.record) {
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
                Json(json!({"error": "InternalError", "message": "Failed to save record block"})),
            )
                .into_response();
        }
    };

    let key = format!("{}/{}", collection_nsid, rkey);

    let existing = match mst.get(&key).await {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to check MST key: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({"error": "InternalError", "message": "Failed to check existing record"}),
                ),
            )
                .into_response();
        }
    };

    if let Some(swap_record_str) = &input.swap_record {
        let swap_record_cid = match Cid::from_str(swap_record_str) {
            Ok(c) => c,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        json!({"error": "InvalidSwapRecord", "message": "Invalid swapRecord CID"}),
                    ),
                )
                    .into_response();
            }
        };
        match &existing {
            Some(current_cid) if *current_cid != swap_record_cid => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "InvalidSwap", "message": "Record has been modified"})),
                )
                    .into_response();
            }
            None => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "InvalidSwap", "message": "Record does not exist"})),
                )
                    .into_response();
            }
            _ => {}
        }
    }

    let new_mst = if existing.is_some() {
        match mst.update(&key, record_cid).await {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to update MST: {:?}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": format!("Failed to update MST: {:?}", e)}))).into_response();
            }
        }
    } else {
        match mst.add(&key, record_cid).await {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to add to MST: {:?}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": format!("Failed to add to MST: {:?}", e)}))).into_response();
            }
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

    let new_commit = Commit::new_unsigned(did_obj, new_mst_root, rev, Some(current_root_cid));

    let new_commit_bytes = match new_commit.to_cbor() {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to serialize new commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({"error": "InternalError", "message": "Failed to serialize new commit"}),
                ),
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
                Json(json!({"error": "InternalError", "message": "Failed to save new commit"})),
            )
                .into_response();
        }
    };

    let update_repo = sqlx::query!("UPDATE repos SET repo_root_cid = $1 WHERE user_id = $2", new_root_cid.to_string(), user_id)
        .execute(&state.db)
        .await;

    if let Err(e) = update_repo {
        error!("Failed to update repo root in DB: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to update repo root in DB"})),
        )
            .into_response();
    }

    let record_insert = sqlx::query!(
        "INSERT INTO records (repo_id, collection, rkey, record_cid) VALUES ($1, $2, $3, $4)
         ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = $4, created_at = NOW()",
        user_id,
        input.collection,
        rkey,
        record_cid.to_string()
    )
    .execute(&state.db)
    .await;

    if let Err(e) = record_insert {
        error!("Error inserting record index: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to index record"})),
        )
            .into_response();
    }

    let output = PutRecordOutput {
        uri: format!("at://{}/{}/{}", input.repo, input.collection, rkey),
        cid: record_cid.to_string(),
    };
    (StatusCode::OK, Json(output)).into_response()
}
