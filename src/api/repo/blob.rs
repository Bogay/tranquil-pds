use crate::state::AppState;
use axum::body::Bytes;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cid::Cid;
use multihash::Multihash;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use tracing::error;

pub async fn upload_blob(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
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
    let multihash = Multihash::wrap(0x12, &hash).unwrap();
    let cid = Cid::new_v1(0x55, multihash);
    let cid_str = cid.to_string();

    let storage_key = format!("blobs/{}", cid_str);

    if let Err(e) = state.blob_store.put(&storage_key, &data).await {
        error!("Failed to upload blob to storage: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to store blob"})),
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
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
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
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    Json(json!({
        "blob": {
            "ref": {
                "$link": cid_str
            },
            "mimeType": mime_type,
            "size": size
        }
    }))
    .into_response()
}
