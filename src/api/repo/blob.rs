use crate::state::AppState;
use axum::body::Bytes;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cid::Cid;
use jacquard_repo::storage::BlockStore;
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use tracing::error;

const MAX_BLOB_SIZE: usize = 1_000_000;

pub async fn upload_blob(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > MAX_BLOB_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error": "BlobTooLarge", "message": format!("Blob size {} exceeds maximum of {} bytes", body.len(), MAX_BLOB_SIZE)})),
        )
            .into_response();
    }
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
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
    let mime_type = headers
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let size = body.len() as i64;
    let data = body.to_vec();
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    let multihash = match Multihash::wrap(0x12, &hash) {
        Ok(mh) => mh,
        Err(e) => {
            error!("Failed to create multihash for blob: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to hash blob"})),
            )
                .into_response();
        }
    };
    let cid = Cid::new_v1(0x55, multihash);
    let cid_str = cid.to_string();
    let storage_key = format!("blobs/{}", cid_str);
    let user_query = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;
    let user_id = match user_query {
        Ok(Some(row)) => row.id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let insert = sqlx::query!(
        "INSERT INTO blobs (cid, mime_type, size_bytes, created_by_user, storage_key) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (cid) DO NOTHING RETURNING cid",
        cid_str,
        mime_type,
        size,
        user_id,
        storage_key
    )
    .fetch_optional(&mut *tx)
    .await;
    let was_inserted = match insert {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            error!("Failed to insert blob record: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if was_inserted
        && let Err(e) = state
            .blob_store
            .put_bytes(&storage_key, bytes::Bytes::from(data))
            .await
        {
            error!("Failed to upload blob to storage: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to store blob"})),
            )
                .into_response();
        }
    if let Err(e) = tx.commit().await {
        error!("Failed to commit blob transaction: {:?}", e);
        if was_inserted
            && let Err(cleanup_err) = state.blob_store.delete(&storage_key).await {
                error!(
                    "Failed to cleanup orphaned blob {}: {:?}",
                    storage_key, cleanup_err
                );
            }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    Json(json!({
        "blob": {
            "$type": "blob",
            "ref": {
                "$link": cid_str
            },
            "mimeType": mime_type,
            "size": size
        }
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct ListMissingBlobsParams {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordBlob {
    pub cid: String,
    pub record_uri: String,
}

#[derive(Serialize)]
pub struct ListMissingBlobsOutput {
    pub cursor: Option<String>,
    pub blobs: Vec<RecordBlob>,
}

fn find_blobs(val: &serde_json::Value, blobs: &mut Vec<String>) {
    if let Some(obj) = val.as_object() {
        if let Some(type_val) = obj.get("$type")
            && type_val == "blob"
                && let Some(r) = obj.get("ref")
                    && let Some(link) = r.get("$link")
                        && let Some(s) = link.as_str() {
                            blobs.push(s.to_string());
                        }
        for (_, v) in obj {
            find_blobs(v, blobs);
        }
    } else if let Some(arr) = val.as_array() {
        for v in arr {
            find_blobs(v, blobs);
        }
    }
}

pub async fn list_missing_blobs(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<ListMissingBlobsParams>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
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
    let user_query = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;
    let user_id = match user_query {
        Ok(Some(row)) => row.id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let limit = params.limit.unwrap_or(500).clamp(1, 1000);
    let cursor_str = params.cursor.unwrap_or_default();
    let (cursor_collection, cursor_rkey) = if cursor_str.contains('|') {
        let parts: Vec<&str> = cursor_str.split('|').collect();
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (String::new(), String::new())
    };
    let records_query = sqlx::query!(
        "SELECT collection, rkey, record_cid FROM records WHERE repo_id = $1 AND (collection, rkey) > ($2, $3) ORDER BY collection, rkey LIMIT $4",
        user_id,
        cursor_collection,
        cursor_rkey,
        limit
    )
    .fetch_all(&state.db)
    .await;
    let records = match records_query {
        Ok(r) => r,
        Err(e) => {
            error!("DB error fetching records: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let mut missing_blobs = Vec::new();
    let mut last_cursor = None;
    for row in &records {
        let collection = &row.collection;
        let rkey = &row.rkey;
        let record_cid_str = &row.record_cid;
        last_cursor = Some(format!("{}|{}", collection, rkey));
        let record_cid = match Cid::from_str(record_cid_str) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let block_bytes = match state.block_store.get(&record_cid).await {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let record_val: serde_json::Value = match serde_ipld_dagcbor::from_slice(&block_bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mut blobs = Vec::new();
        find_blobs(&record_val, &mut blobs);
        for blob_cid_str in blobs {
            let exists = sqlx::query!(
                "SELECT 1 as one FROM blobs WHERE cid = $1 AND created_by_user = $2",
                blob_cid_str,
                user_id
            )
            .fetch_optional(&state.db)
            .await;
            match exists {
                Ok(None) => {
                    missing_blobs.push(RecordBlob {
                        cid: blob_cid_str,
                        record_uri: format!("at://{}/{}/{}", did, collection, rkey),
                    });
                }
                Err(e) => {
                    error!("DB error checking blob existence: {:?}", e);
                }
                _ => {}
            }
        }
    }
    // if we fetched fewer records than limit, we are done, so cursor is None.
    // otherwise, cursor is the last one we saw.
    // ...right?
    let next_cursor = if records.len() < limit as usize {
        None
    } else {
        last_cursor
    };
    (
        StatusCode::OK,
        Json(ListMissingBlobsOutput {
            cursor: next_cursor,
            blobs: missing_blobs,
        }),
    )
        .into_response()
}
