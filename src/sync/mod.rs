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
use sqlx::Row;
use tracing::{error, info};

#[derive(Deserialize)]
pub struct GetLatestCommitParams {
    pub did: String,
}

#[derive(Serialize)]
pub struct GetLatestCommitOutput {
    pub cid: String,
    pub rev: String,
}

pub async fn get_latest_commit(
    State(state): State<AppState>,
    Query(params): Query<GetLatestCommitParams>,
) -> Response {
    let did = params.did.trim();

    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }

    let result = sqlx::query(
        r#"
        SELECT r.repo_root_cid
        FROM repos r
        JOIN users u ON r.user_id = u.id
        WHERE u.did = $1
        "#,
    )
    .bind(did)
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => {
            let cid: String = row.get("repo_root_cid");
            (
                StatusCode::OK,
                Json(GetLatestCommitOutput {
                    cid,
                    rev: chrono::Utc::now().timestamp_millis().to_string(),
                }),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "RepoNotFound", "message": "Could not find repo for DID"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error in get_latest_commit: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct ListReposParams {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoInfo {
    pub did: String,
    pub head: String,
    pub rev: String,
    pub active: bool,
}

#[derive(Serialize)]
pub struct ListReposOutput {
    pub cursor: Option<String>,
    pub repos: Vec<RepoInfo>,
}

pub async fn list_repos(
    State(state): State<AppState>,
    Query(params): Query<ListReposParams>,
) -> Response {
    let limit = params.limit.unwrap_or(50).min(1000);
    let cursor_did = params.cursor.as_deref().unwrap_or("");

    let result = sqlx::query(
        r#"
        SELECT u.did, r.repo_root_cid
        FROM repos r
        JOIN users u ON r.user_id = u.id
        WHERE u.did > $1
        ORDER BY u.did ASC
        LIMIT $2
        "#,
    )
    .bind(cursor_did)
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await;

    match result {
        Ok(rows) => {
            let has_more = rows.len() as i64 > limit;
            let repos: Vec<RepoInfo> = rows
                .iter()
                .take(limit as usize)
                .map(|row| {
                    let did: String = row.get("did");
                    let head: String = row.get("repo_root_cid");
                    RepoInfo {
                        did,
                        head,
                        rev: chrono::Utc::now().timestamp_millis().to_string(),
                        active: true,
                    }
                })
                .collect();

            let next_cursor = if has_more {
                repos.last().map(|r| r.did.clone())
            } else {
                None
            };

            (
                StatusCode::OK,
                Json(ListReposOutput {
                    cursor: next_cursor,
                    repos,
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("DB error in list_repos: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

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

    let user_exists = sqlx::query("SELECT id FROM users WHERE did = $1")
        .bind(did)
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

    let blob_result = sqlx::query("SELECT storage_key, mime_type FROM blobs WHERE cid = $1")
        .bind(cid)
        .fetch_optional(&state.db)
        .await;

    match blob_result {
        Ok(Some(row)) => {
            let storage_key: String = row.get("storage_key");
            let mime_type: String = row.get("mime_type");

            match state.blob_store.get(&storage_key).await {
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

    let limit = params.limit.unwrap_or(500).min(1000);
    let cursor_cid = params.cursor.as_deref().unwrap_or("");

    let user_result = sqlx::query("SELECT id FROM users WHERE did = $1")
        .bind(did)
        .fetch_optional(&state.db)
        .await;

    let user_id: uuid::Uuid = match user_result {
        Ok(Some(row)) => row.get("id"),
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

    let result = if let Some(since) = &params.since {
        sqlx::query(
            r#"
            SELECT cid FROM blobs
            WHERE created_by_user = $1 AND cid > $2 AND created_at > $3
            ORDER BY cid ASC
            LIMIT $4
            "#,
        )
        .bind(user_id)
        .bind(cursor_cid)
        .bind(since)
        .bind(limit + 1)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query(
            r#"
            SELECT cid FROM blobs
            WHERE created_by_user = $1 AND cid > $2
            ORDER BY cid ASC
            LIMIT $3
            "#,
        )
        .bind(user_id)
        .bind(cursor_cid)
        .bind(limit + 1)
        .fetch_all(&state.db)
        .await
    };

    match result {
        Ok(rows) => {
            let has_more = rows.len() as i64 > limit;
            let cids: Vec<String> = rows
                .iter()
                .take(limit as usize)
                .map(|row| row.get("cid"))
                .collect();

            let next_cursor = if has_more {
                cids.last().cloned()
            } else {
                None
            };

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

#[derive(Deserialize)]
pub struct GetRepoStatusParams {
    pub did: String,
}

#[derive(Serialize)]
pub struct GetRepoStatusOutput {
    pub did: String,
    pub active: bool,
    pub rev: Option<String>,
}

pub async fn get_repo_status(
    State(state): State<AppState>,
    Query(params): Query<GetRepoStatusParams>,
) -> Response {
    let did = params.did.trim();

    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }

    let result = sqlx::query(
        r#"
        SELECT u.did, r.repo_root_cid
        FROM users u
        LEFT JOIN repos r ON u.id = r.user_id
        WHERE u.did = $1
        "#,
    )
    .bind(did)
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => {
            let user_did: String = row.get("did");
            let repo_root: Option<String> = row.get("repo_root_cid");

            let rev = repo_root.map(|_| chrono::Utc::now().timestamp_millis().to_string());

            (
                StatusCode::OK,
                Json(GetRepoStatusOutput {
                    did: user_did,
                    active: true,
                    rev,
                }),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "RepoNotFound", "message": "Could not find repo for DID"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error in get_repo_status: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct NotifyOfUpdateParams {
    pub hostname: String,
}

pub async fn notify_of_update(
    State(_state): State<AppState>,
    Query(params): Query<NotifyOfUpdateParams>,
) -> Response {
    info!("Received notifyOfUpdate from hostname: {}", params.hostname);
    // TODO: Queue job for crawler interaction or relay notification
    info!("TODO: Queue job for notifyOfUpdate (not implemented)");

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Deserialize)]
pub struct RequestCrawlInput {
    pub hostname: String,
}

pub async fn request_crawl(
    State(_state): State<AppState>,
    Json(input): Json<RequestCrawlInput>,
) -> Response {
    info!("Received requestCrawl for hostname: {}", input.hostname);
    // TODO: Queue job for crawling
    info!("TODO: Queue job for requestCrawl (not implemented)");

    (StatusCode::OK, Json(json!({}))).into_response()
}
