use axum::{
    extract::{State, Query},
    Json,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::state::AppState;
use chrono::Utc;
use sqlx::Row;
use cid::Cid;
use std::str::FromStr;
use jacquard_repo::{mst::Mst, commit::Commit, storage::BlockStore};
use jacquard::types::{string::{Nsid, Tid}, did::Did, integer::LimitedU32};
use tracing::error;
use std::sync::Arc;
use sha2::{Sha256, Digest};
use multihash::Multihash;
use axum::body::Bytes;

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
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationRequired"}))).into_response();
    }
    let token = auth_header.unwrap().to_str().unwrap_or("").replace("Bearer ", "");

    let session = sqlx::query(
            "SELECT s.did, k.key_bytes FROM sessions s JOIN users u ON s.did = u.did JOIN user_keys k ON u.id = k.user_id WHERE s.access_jwt = $1"
        )
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let (did, key_bytes) = match session {
        Some(row) => (row.get::<String, _>("did"), row.get::<Vec<u8>, _>("key_bytes")),
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed"}))).into_response(),
    };

    if let Err(_) = crate::auth::verify_token(&token, &key_bytes) {
         return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed", "message": "Invalid token signature"}))).into_response();
    }

    if input.repo != did {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "InvalidRepo", "message": "Repo does not match authenticated user"}))).into_response();
    }

    let user_query = sqlx::query("SELECT id FROM users WHERE did = $1")
        .bind(&did)
        .fetch_optional(&state.db)
        .await;

    let user_id: uuid::Uuid = match user_query {
        Ok(Some(row)) => row.get("id"),
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "User not found"}))).into_response(),
    };

    let repo_root_query = sqlx::query("SELECT repo_root_cid FROM repos WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    let current_root_cid = match repo_root_query {
        Ok(Some(row)) => {
            let cid_str: String = row.get("repo_root_cid");
            Cid::from_str(&cid_str).ok()
        },
        _ => None,
    };

    if current_root_cid.is_none() {
         error!("Repo root not found for user {}", did);
         return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Repo root not found"}))).into_response();
    }
    let current_root_cid = current_root_cid.unwrap();

    let commit_bytes = match state.block_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        Ok(None) => {
             error!("Commit block not found: {}", current_root_cid);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        },
        Err(e) => {
             error!("Failed to load commit block: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        Err(e) => {
             error!("Failed to parse commit: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let mst_root = commit.data;
    let store = Arc::new(state.block_store.clone());
    let mst = Mst::load(store.clone(), mst_root, None);

    let collection_nsid = match input.collection.parse::<Nsid>() {
        Ok(n) => n,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidCollection"}))).into_response(),
    };

    let rkey = input.rkey.unwrap_or_else(|| {
        Utc::now().format("%Y%m%d%H%M%S%f").to_string()
    });

    let mut record_bytes = Vec::new();
    if let Err(e) = serde_ipld_dagcbor::to_writer(&mut record_bytes, &input.record) {
        error!("Error serializing record: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidRecord", "message": "Failed to serialize record"}))).into_response();
    }

    let record_cid = match state.block_store.put(&record_bytes).await {
        Ok(c) => c,
        Err(e) => {
             error!("Failed to save record block: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let key = format!("{}/{}", collection_nsid, rkey);
    if let Err(e) = mst.update(&key, record_cid).await {
         error!("Failed to update MST: {:?}", e);
         return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
    }

    let new_mst_root = match mst.root().await {
        Ok(c) => c,
        Err(e) => {
             error!("Failed to get new MST root: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let did_obj = match Did::new(&did) {
        Ok(d) => d,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Invalid DID"}))).into_response(),
    };

    let rev = Tid::now(LimitedU32::MIN);

    let new_commit = Commit::new_unsigned(
        did_obj,
        new_mst_root,
        rev,
        Some(current_root_cid)
    );

    let new_commit_bytes = match new_commit.to_cbor() {
        Ok(b) => b,
        Err(e) => {
             error!("Failed to serialize new commit: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let new_root_cid = match state.block_store.put(&new_commit_bytes).await {
        Ok(c) => c,
        Err(e) => {
             error!("Failed to save new commit: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let update_repo = sqlx::query("UPDATE repos SET repo_root_cid = $1 WHERE user_id = $2")
        .bind(new_root_cid.to_string())
        .bind(user_id)
        .execute(&state.db)
        .await;

    if let Err(e) = update_repo {
        error!("Failed to update repo root in DB: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
    }

    let record_insert = sqlx::query(
        "INSERT INTO records (repo_id, collection, rkey, record_cid) VALUES ($1, $2, $3, $4)
         ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = $4, created_at = NOW()"
    )
        .bind(user_id)
        .bind(&input.collection)
        .bind(&rkey)
        .bind(record_cid.to_string())
        .execute(&state.db)
        .await;

    if let Err(e) = record_insert {
        error!("Error inserting record index: {:?}", e);
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
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationRequired"}))).into_response();
    }
    let token = auth_header.unwrap().to_str().unwrap_or("").replace("Bearer ", "");

    let session = sqlx::query(
            "SELECT s.did, k.key_bytes FROM sessions s JOIN users u ON s.did = u.did JOIN user_keys k ON u.id = k.user_id WHERE s.access_jwt = $1"
        )
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let (did, key_bytes) = match session {
        Some(row) => (row.get::<String, _>("did"), row.get::<Vec<u8>, _>("key_bytes")),
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed"}))).into_response(),
    };

    if let Err(_) = crate::auth::verify_token(&token, &key_bytes) {
         return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed", "message": "Invalid token signature"}))).into_response();
    }

    if input.repo != did {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "InvalidRepo", "message": "Repo does not match authenticated user"}))).into_response();
    }

    let user_query = sqlx::query("SELECT id FROM users WHERE did = $1")
        .bind(&did)
        .fetch_optional(&state.db)
        .await;

    let user_id: uuid::Uuid = match user_query {
        Ok(Some(row)) => row.get("id"),
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "User not found"}))).into_response(),
    };

    let repo_root_query = sqlx::query("SELECT repo_root_cid FROM repos WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    let current_root_cid = match repo_root_query {
        Ok(Some(row)) => {
            let cid_str: String = row.get("repo_root_cid");
            Cid::from_str(&cid_str).ok()
        },
        _ => None,
    };

    if current_root_cid.is_none() {
         error!("Repo root not found for user {}", did);
         return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Repo root not found"}))).into_response();
    }
    let current_root_cid = current_root_cid.unwrap();

    let commit_bytes = match state.block_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        Ok(None) => {
             error!("Commit block not found: {}", current_root_cid);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Commit block not found"}))).into_response();
        },
        Err(e) => {
             error!("Failed to load commit block: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to load commit block"}))).into_response();
        }
    };

    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        Err(e) => {
             error!("Failed to parse commit: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to parse commit"}))).into_response();
        }
    };

    let mst_root = commit.data;
    let store = Arc::new(state.block_store.clone());
    let mst = Mst::load(store.clone(), mst_root, None);

    let collection_nsid = match input.collection.parse::<Nsid>() {
        Ok(n) => n,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidCollection"}))).into_response(),
    };

    let rkey = input.rkey.clone();

    let mut record_bytes = Vec::new();
    if let Err(e) = serde_ipld_dagcbor::to_writer(&mut record_bytes, &input.record) {
        error!("Error serializing record: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidRecord", "message": "Failed to serialize record"}))).into_response();
    }

    let record_cid = match state.block_store.put(&record_bytes).await {
        Ok(c) => c,
        Err(e) => {
             error!("Failed to save record block: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to save record block"}))).into_response();
        }
    };

    let key = format!("{}/{}", collection_nsid, rkey);
    if let Err(e) = mst.update(&key, record_cid).await {
         error!("Failed to update MST: {:?}", e);
         return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": format!("Failed to update MST: {:?}", e)}))).into_response();
    }

    let new_mst_root = match mst.root().await {
        Ok(c) => c,
        Err(e) => {
             error!("Failed to get new MST root: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get new MST root"}))).into_response();
        }
    };

    let did_obj = match Did::new(&did) {
        Ok(d) => d,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Invalid DID"}))).into_response(),
    };

    let rev = Tid::now(LimitedU32::MIN);

    let new_commit = Commit::new_unsigned(
        did_obj,
        new_mst_root,
        rev,
        Some(current_root_cid)
    );

    let new_commit_bytes = match new_commit.to_cbor() {
        Ok(b) => b,
        Err(e) => {
             error!("Failed to serialize new commit: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to serialize new commit"}))).into_response();
        }
    };

    let new_root_cid = match state.block_store.put(&new_commit_bytes).await {
        Ok(c) => c,
        Err(e) => {
             error!("Failed to save new commit: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to save new commit"}))).into_response();
        }
    };

    let update_repo = sqlx::query("UPDATE repos SET repo_root_cid = $1 WHERE user_id = $2")
        .bind(new_root_cid.to_string())
        .bind(user_id)
        .execute(&state.db)
        .await;

    if let Err(e) = update_repo {
        error!("Failed to update repo root in DB: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to update repo root in DB"}))).into_response();
    }

    let record_insert = sqlx::query(
        "INSERT INTO records (repo_id, collection, rkey, record_cid) VALUES ($1, $2, $3, $4)
         ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = $4, created_at = NOW()"
    )
        .bind(user_id)
        .bind(&input.collection)
        .bind(&rkey)
        .bind(record_cid.to_string())
        .execute(&state.db)
        .await;

    if let Err(e) = record_insert {
        error!("Error inserting record index: {:?}", e);
    }

    let output = PutRecordOutput {
        uri: format!("at://{}/{}/{}", input.repo, input.collection, rkey),
        cid: record_cid.to_string(),
    };
    (StatusCode::OK, Json(output)).into_response()
}

#[derive(Deserialize)]
pub struct GetRecordInput {
    pub repo: String,
    pub collection: String,
    pub rkey: String,
    pub cid: Option<String>,
}

pub async fn get_record(
    State(state): State<AppState>,
    Query(input): Query<GetRecordInput>,
) -> Response {
    let user_row = if input.repo.starts_with("did:") {
         sqlx::query("SELECT id FROM users WHERE did = $1")
            .bind(&input.repo)
            .fetch_optional(&state.db)
            .await
    } else {
         sqlx::query("SELECT id FROM users WHERE handle = $1")
            .bind(&input.repo)
            .fetch_optional(&state.db)
            .await
    };

    let user_id: uuid::Uuid = match user_row {
        Ok(Some(row)) => row.get("id"),
        _ => return (StatusCode::NOT_FOUND, Json(json!({"error": "NotFound", "message": "Repo not found"}))).into_response(),
    };

    let record_row = sqlx::query("SELECT record_cid FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3")
        .bind(user_id)
        .bind(&input.collection)
        .bind(&input.rkey)
        .fetch_optional(&state.db)
        .await;

    let record_cid_str: String = match record_row {
        Ok(Some(row)) => row.get("record_cid"),
        _ => return (StatusCode::NOT_FOUND, Json(json!({"error": "NotFound", "message": "Record not found"}))).into_response(),
    };

    if let Some(expected_cid) = &input.cid {
        if &record_cid_str != expected_cid {
             return (StatusCode::NOT_FOUND, Json(json!({"error": "NotFound", "message": "Record CID mismatch"}))).into_response();
        }
    }

    let cid = match Cid::from_str(&record_cid_str) {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Invalid CID in DB"}))).into_response(),
    };

    let block = match state.block_store.get(&cid).await {
        Ok(Some(b)) => b,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Record block not found"}))).into_response(),
    };

    let value: serde_json::Value = match serde_ipld_dagcbor::from_slice(&block) {
        Ok(v) => v,
        Err(e) => {
             error!("Failed to deserialize record: {:?}", e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    Json(json!({
        "uri": format!("at://{}/{}/{}", input.repo, input.collection, input.rkey),
        "cid": record_cid_str,
        "value": value
    })).into_response()
}

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
    headers: axum::http::HeaderMap,
    Json(input): Json<DeleteRecordInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationRequired"}))).into_response();
    }
    let token = auth_header.unwrap().to_str().unwrap_or("").replace("Bearer ", "");

    let session = sqlx::query(
            "SELECT s.did, k.key_bytes FROM sessions s JOIN users u ON s.did = u.did JOIN user_keys k ON u.id = k.user_id WHERE s.access_jwt = $1"
        )
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let (did, key_bytes) = match session {
        Some(row) => (row.get::<String, _>("did"), row.get::<Vec<u8>, _>("key_bytes")),
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed"}))).into_response(),
    };

    if let Err(_) = crate::auth::verify_token(&token, &key_bytes) {
         return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed", "message": "Invalid token signature"}))).into_response();
    }

    if input.repo != did {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "InvalidRepo", "message": "Repo does not match authenticated user"}))).into_response();
    }

    let user_query = sqlx::query("SELECT id FROM users WHERE did = $1")
        .bind(&did)
        .fetch_optional(&state.db)
        .await;

    let user_id: uuid::Uuid = match user_query {
        Ok(Some(row)) => row.get("id"),
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "User not found"}))).into_response(),
    };

    let repo_root_query = sqlx::query("SELECT repo_root_cid FROM repos WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    let current_root_cid = match repo_root_query {
        Ok(Some(row)) => {
            let cid_str: String = row.get("repo_root_cid");
            Cid::from_str(&cid_str).ok()
        },
        _ => None,
    };

    if current_root_cid.is_none() {
         return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Repo root not found"}))).into_response();
    }
    let current_root_cid = current_root_cid.unwrap();

    let commit_bytes = match state.block_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        Ok(None) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Commit block not found"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": format!("Failed to load commit block: {:?}", e)}))).into_response(),
    };

    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": format!("Failed to parse commit: {:?}", e)}))).into_response(),
    };

    let mst_root = commit.data;
    let store = Arc::new(state.block_store.clone());
    let mst = Mst::load(store.clone(), mst_root, None);

    let collection_nsid = match input.collection.parse::<Nsid>() {
        Ok(n) => n,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidCollection"}))).into_response(),
    };

    let key = format!("{}/{}", collection_nsid, input.rkey);

    // TODO: Check swapRecord if provided? Skipping for brevity/robustness

    if let Err(e) = mst.delete(&key).await {
         error!("Failed to delete from MST: {:?}", e);
         return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": format!("Failed to delete from MST: {:?}", e)}))).into_response();
    }

    let new_mst_root = match mst.root().await {
        Ok(c) => c,
        Err(_e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to get new MST root"}))).into_response(),
    };

    let did_obj = match Did::new(&did) {
        Ok(d) => d,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Invalid DID"}))).into_response(),
    };

    let rev = Tid::now(LimitedU32::MIN);

    let new_commit = Commit::new_unsigned(
        did_obj,
        new_mst_root,
        rev,
        Some(current_root_cid)
    );

    let new_commit_bytes = match new_commit.to_cbor() {
        Ok(b) => b,
        Err(_e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to serialize new commit"}))).into_response(),
    };

    let new_root_cid = match state.block_store.put(&new_commit_bytes).await {
        Ok(c) => c,
        Err(_e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to save new commit"}))).into_response(),
    };

    let update_repo = sqlx::query("UPDATE repos SET repo_root_cid = $1 WHERE user_id = $2")
        .bind(new_root_cid.to_string())
        .bind(user_id)
        .execute(&state.db)
        .await;

    if let Err(e) = update_repo {
        error!("Failed to update repo root in DB: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to update repo root in DB"}))).into_response();
    }

    let record_delete = sqlx::query("DELETE FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3")
        .bind(user_id)
        .bind(&input.collection)
        .bind(&input.rkey)
        .execute(&state.db)
        .await;

    if let Err(e) = record_delete {
        error!("Error deleting record index: {:?}", e);
    }

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Deserialize)]
pub struct ListRecordsInput {
    pub repo: String,
    pub collection: String,
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    #[serde(rename = "rkeyStart")]
    pub rkey_start: Option<String>,
    #[serde(rename = "rkeyEnd")]
    pub rkey_end: Option<String>,
    pub reverse: Option<bool>,
}

#[derive(Serialize)]
pub struct ListRecordsOutput {
    pub cursor: Option<String>,
    pub records: Vec<serde_json::Value>,
}

pub async fn list_records(
    State(state): State<AppState>,
    Query(input): Query<ListRecordsInput>,
) -> Response {
    let user_row = if input.repo.starts_with("did:") {
         sqlx::query("SELECT id FROM users WHERE did = $1")
            .bind(&input.repo)
            .fetch_optional(&state.db)
            .await
    } else {
         sqlx::query("SELECT id FROM users WHERE handle = $1")
            .bind(&input.repo)
            .fetch_optional(&state.db)
            .await
    };

    let user_id: uuid::Uuid = match user_row {
        Ok(Some(row)) => row.get("id"),
        _ => return (StatusCode::NOT_FOUND, Json(json!({"error": "NotFound", "message": "Repo not found"}))).into_response(),
    };

    let limit = input.limit.unwrap_or(50).clamp(1, 100);
    let reverse = input.reverse.unwrap_or(false);

    // Simplistic query construction - no sophisticated cursor handling or rkey ranges for now, just basic pagination
    // TODO: Implement rkeyStart/End and correct cursor logic

    let query_str = format!(
        "SELECT rkey, record_cid FROM records WHERE repo_id = $1 AND collection = $2 {} ORDER BY rkey {} LIMIT {}",
        if let Some(_c) = &input.cursor {
            if reverse { "AND rkey < $3" } else { "AND rkey > $3" }
        } else {
            ""
        },
        if reverse { "DESC" } else { "ASC" },
        limit
    );

    let mut query = sqlx::query(&query_str)
        .bind(user_id)
        .bind(&input.collection);

    if let Some(c) = &input.cursor {
        query = query.bind(c);
    }

    let rows = match query.fetch_all(&state.db).await {
        Ok(r) => r,
        Err(e) => {
            error!("Error listing records: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let mut records = Vec::new();
    let mut last_rkey = None;

    for row in rows {
        let rkey: String = row.get("rkey");
        let cid_str: String = row.get("record_cid");
        last_rkey = Some(rkey.clone());

        if let Ok(cid) = Cid::from_str(&cid_str) {
            if let Ok(Some(block)) = state.block_store.get(&cid).await {
                if let Ok(value) = serde_ipld_dagcbor::from_slice::<serde_json::Value>(&block) {
                    records.push(json!({
                        "uri": format!("at://{}/{}/{}", input.repo, input.collection, rkey),
                        "cid": cid_str,
                        "value": value
                    }));
                }
            }
        }
    }

    Json(ListRecordsOutput {
        cursor: last_rkey,
        records,
    }).into_response()
}

#[derive(Deserialize)]
pub struct DescribeRepoInput {
    pub repo: String,
}

pub async fn describe_repo(
    State(state): State<AppState>,
    Query(input): Query<DescribeRepoInput>,
) -> Response {
    let user_row = if input.repo.starts_with("did:") {
         sqlx::query("SELECT id, handle, did FROM users WHERE did = $1")
            .bind(&input.repo)
            .fetch_optional(&state.db)
            .await
    } else {
         sqlx::query("SELECT id, handle, did FROM users WHERE handle = $1")
            .bind(&input.repo)
            .fetch_optional(&state.db)
            .await
    };

    let (user_id, handle, did) = match user_row {
        Ok(Some(row)) => (row.get::<uuid::Uuid, _>("id"), row.get::<String, _>("handle"), row.get::<String, _>("did")),
        _ => return (StatusCode::NOT_FOUND, Json(json!({"error": "NotFound", "message": "Repo not found"}))).into_response(),
    };

    let collections_query = sqlx::query("SELECT DISTINCT collection FROM records WHERE repo_id = $1")
        .bind(user_id)
        .fetch_all(&state.db)
        .await;

    let collections: Vec<String> = match collections_query {
        Ok(rows) => rows.iter().map(|r| r.get("collection")).collect(),
        Err(_) => Vec::new(),
    };

    let did_doc = json!({
        "id": did,
        "alsoKnownAs": [format!("at://{}", handle)]
    });

    Json(json!({
        "handle": handle,
        "did": did,
        "didDoc": did_doc,
        "collections": collections,
        "handleIsCorrect": true
    })).into_response()
}

pub async fn upload_blob(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationRequired"}))).into_response();
    }
    let token = auth_header.unwrap().to_str().unwrap_or("").replace("Bearer ", "");

    let session = sqlx::query(
            "SELECT s.did, k.key_bytes FROM sessions s JOIN users u ON s.did = u.did JOIN user_keys k ON u.id = k.user_id WHERE s.access_jwt = $1"
        )
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let (did, key_bytes) = match session {
        Some(row) => (row.get::<String, _>("did"), row.get::<Vec<u8>, _>("key_bytes")),
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed"}))).into_response(),
    };

    if let Err(_) = crate::auth::verify_token(&token, &key_bytes) {
         return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed", "message": "Invalid token signature"}))).into_response();
    }

    let mime_type = headers.get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let size = body.len() as i64;
    let data = body.to_vec();

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    let multihash = Multihash::wrap(0x12, &hash).unwrap();
    let cid = Cid::new_v1(0x55, multihash);
    let cid_str = cid.to_string();

    let storage_key = format!("blobs/{}", cid_str);

    if let Err(e) = state.blob_store.put(&storage_key, &data).await {
         error!("Failed to upload blob to storage: {:?}", e);
         return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Failed to store blob"}))).into_response();
    }

    let user_query = sqlx::query("SELECT id FROM users WHERE did = $1")
        .bind(&did)
        .fetch_optional(&state.db)
        .await;

    let user_id: uuid::Uuid = match user_query {
        Ok(Some(row)) => row.get("id"),
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response(),
    };

    let insert = sqlx::query(
        "INSERT INTO blobs (cid, mime_type, size_bytes, created_by_user, storage_key) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (cid) DO NOTHING"
    )
    .bind(&cid_str)
    .bind(&mime_type)
    .bind(size)
    .bind(user_id)
    .bind(&storage_key)
    .execute(&state.db)
    .await;

    if let Err(e) = insert {
         error!("Failed to insert blob record: {:?}", e);
         return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
    }

    Json(json!({
        "blob": {
            "ref": {
                "$link": cid_str
            },
            "mimeType": mime_type,
            "size": size
        }
    })).into_response()
}
