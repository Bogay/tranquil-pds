use crate::state::AppState;
use axum::{
    Json,
    body::Body,
    extract::{Query, State},
    http::StatusCode,
    http::header,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;

#[derive(Deserialize)]
pub struct GetBlobParams {
    pub did: String,
    pub cid: String,
}

pub async fn get_blob(
    State(state): State<AppState>,
    Query(params): Query<GetBlobParams>,
) -> Response {
    let did = params.did.trim();
    let cid = params.cid.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }
    if cid.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "cid is required"})),
        )
            .into_response();
    }
    let user_exists = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;
    match user_exists {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RepoNotFound", "message": "Could not find repo for DID"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in get_blob: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
        Ok(Some(_)) => {}
    }
    let blob_result = sqlx::query!(
        "SELECT storage_key, mime_type FROM blobs WHERE cid = $1",
        cid
    )
    .fetch_optional(&state.db)
    .await;
    match blob_result {
        Ok(Some(row)) => {
            let storage_key = &row.storage_key;
            let mime_type = &row.mime_type;
            match state.blob_store.get(storage_key).await {
                Ok(data) => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, mime_type)
                    .body(Body::from(data))
                    .unwrap(),
                Err(e) => {
                    error!("Failed to fetch blob from storage: {:?}", e);
                    (
                        StatusCode::NOT_FOUND,
                        Json(json!({"error": "BlobNotFound", "message": "Blob not found in storage"})),
                    )
                        .into_response()
                }
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "BlobNotFound", "message": "Blob not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error in get_blob: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct ListBlobsParams {
    pub did: String,
    pub since: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
pub struct ListBlobsOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub cids: Vec<String>,
}

pub async fn list_blobs(
    State(state): State<AppState>,
    Query(params): Query<ListBlobsParams>,
) -> Response {
    let did = params.did.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }
    let limit = params.limit.unwrap_or(500).clamp(1, 1000);
    let cursor_cid = params.cursor.as_deref().unwrap_or("");
    let user_result = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;
    let user_id = match user_result {
        Ok(Some(row)) => row.id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RepoNotFound", "message": "Could not find repo for DID"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in list_blobs: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let cids_result: Result<Vec<String>, sqlx::Error> = if let Some(since) = &params.since {
        let since_time = chrono::DateTime::parse_from_rfc3339(since)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());
        sqlx::query!(
            r#"
            SELECT cid FROM blobs
            WHERE created_by_user = $1 AND cid > $2 AND created_at > $3
            ORDER BY cid ASC
            LIMIT $4
            "#,
            user_id,
            cursor_cid,
            since_time,
            limit + 1
        )
        .fetch_all(&state.db)
        .await
        .map(|rows| rows.into_iter().map(|r| r.cid).collect())
    } else {
        sqlx::query!(
            r#"
            SELECT cid FROM blobs
            WHERE created_by_user = $1 AND cid > $2
            ORDER BY cid ASC
            LIMIT $3
            "#,
            user_id,
            cursor_cid,
            limit + 1
        )
        .fetch_all(&state.db)
        .await
        .map(|rows| rows.into_iter().map(|r| r.cid).collect())
    };
    match cids_result {
        Ok(cids) => {
            let has_more = cids.len() as i64 > limit;
            let cids: Vec<String> = cids.into_iter().take(limit as usize).collect();
            let next_cursor = if has_more { cids.last().cloned() } else { None };
            (
                StatusCode::OK,
                Json(ListBlobsOutput {
                    cursor: next_cursor,
                    cids,
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("DB error in list_blobs: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
