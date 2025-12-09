use crate::state::AppState;
use axum::{
    Json,
    body::Body,
    extract::{Query, State},
    http::StatusCode,
    http::header,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use cid::Cid;
use jacquard_repo::{commit::Commit, storage::BlockStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::io::Write;
use tracing::{error, info};

fn write_varint<W: Write>(mut writer: W, mut value: u64) -> std::io::Result<()> {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }
    Ok(())
}

fn ld_write<W: Write>(mut writer: W, data: &[u8]) -> std::io::Result<()> {
    write_varint(&mut writer, data.len() as u64)?;
    writer.write_all(data)?;
    Ok(())
}

fn encode_car_header(root_cid: &Cid) -> Vec<u8> {
    let header = serde_ipld_dagcbor::to_vec(&serde_json::json!({
        "version": 1u64,
        "roots": [root_cid.to_bytes()]
    }))
    .unwrap_or_default();
    header
}

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

    let result = sqlx::query!(
        r#"
        SELECT r.repo_root_cid
        FROM repos r
        JOIN users u ON r.user_id = u.id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => {
            (
                StatusCode::OK,
                Json(GetLatestCommitOutput {
                    cid: row.repo_root_cid,
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

    let result = sqlx::query!(
        r#"
        SELECT u.did, r.repo_root_cid
        FROM repos r
        JOIN users u ON r.user_id = u.id
        WHERE u.did > $1
        ORDER BY u.did ASC
        LIMIT $2
        "#,
        cursor_did,
        limit + 1
    )
    .fetch_all(&state.db)
    .await;

    match result {
        Ok(rows) => {
            let has_more = rows.len() as i64 > limit;
            let repos: Vec<RepoInfo> = rows
                .iter()
                .take(limit as usize)
                .map(|row| {
                    RepoInfo {
                        did: row.did.clone(),
                        head: row.repo_root_cid.clone(),
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

    let blob_result = sqlx::query!("SELECT storage_key, mime_type FROM blobs WHERE cid = $1", cid)
        .fetch_optional(&state.db)
        .await;

    match blob_result {
        Ok(Some(row)) => {
            let storage_key = &row.storage_key;
            let mime_type = &row.mime_type;

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
            let cids: Vec<String> = cids
                .into_iter()
                .take(limit as usize)
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

    let result = sqlx::query!(
        r#"
        SELECT u.did, r.repo_root_cid
        FROM users u
        LEFT JOIN repos r ON u.id = r.user_id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => {
            let rev = Some(chrono::Utc::now().timestamp_millis().to_string());

            (
                StatusCode::OK,
                Json(GetRepoStatusOutput {
                    did: row.did,
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
    info!("TODO: Queue job for requestCrawl (not implemented)");

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Deserialize)]
pub struct GetBlocksParams {
    pub did: String,
    pub cids: String,
}

pub async fn get_blocks(
    State(state): State<AppState>,
    Query(params): Query<GetBlocksParams>,
) -> Response {
    let did = params.did.trim();

    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }

    let cid_strings: Vec<&str> = params.cids.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();

    if cid_strings.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "cids is required"})),
        )
            .into_response();
    }

    let repo_result = sqlx::query!(
        r#"
        SELECT r.repo_root_cid
        FROM repos r
        JOIN users u ON r.user_id = u.id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_optional(&state.db)
    .await;

    let repo_root_cid_str = match repo_result {
        Ok(Some(row)) => row.repo_root_cid,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RepoNotFound", "message": "Could not find repo for DID"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in get_blocks: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let root_cid = match repo_root_cid_str.parse::<Cid>() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse root CID: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let mut requested_cids: Vec<Cid> = Vec::new();
    for cid_str in &cid_strings {
        match cid_str.parse::<Cid>() {
            Ok(c) => requested_cids.push(c),
            Err(e) => {
                error!("Failed to parse CID '{}': {:?}", cid_str, e);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidRequest", "message": format!("Invalid CID: {}", cid_str)})),
                )
                    .into_response();
            }
        }
    }

    let mut buf = Vec::new();
    let header = encode_car_header(&root_cid);
    if let Err(e) = ld_write(&mut buf, &header) {
        error!("Failed to write CAR header: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    for cid in &requested_cids {
        let cid_bytes = cid.to_bytes();
        let block_result = sqlx::query!(
            "SELECT data FROM blocks WHERE cid = $1",
            &cid_bytes
        )
        .fetch_optional(&state.db)
        .await;

        match block_result {
            Ok(Some(row)) => {
                let mut block_data = Vec::new();
                block_data.extend_from_slice(&cid_bytes);
                block_data.extend_from_slice(&row.data);
                if let Err(e) = ld_write(&mut buf, &block_data) {
                    error!("Failed to write block: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "BlockNotFound", "message": format!("Block not found: {}", cid)})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error fetching block: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        }
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.ipld.car")
        .body(Body::from(buf))
        .unwrap()
}

#[derive(Deserialize)]
pub struct GetRepoParams {
    pub did: String,
    pub since: Option<String>,
}

pub async fn get_repo(
    State(state): State<AppState>,
    Query(params): Query<GetRepoParams>,
) -> Response {
    let did = params.did.trim();

    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }

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
            error!("DB error in get_repo: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let repo_result = sqlx::query!("SELECT repo_root_cid FROM repos WHERE user_id = $1", user_id)
        .fetch_optional(&state.db)
        .await;

    let repo_root_cid_str = match repo_result {
        Ok(Some(row)) => row.repo_root_cid,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RepoNotFound", "message": "Repository not initialized"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in get_repo: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let root_cid = match repo_root_cid_str.parse::<Cid>() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse root CID: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let commit_bytes = match state.block_store.get(&root_cid).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            error!("Commit block not found: {}", root_cid);
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

    let mut collected_blocks: Vec<(Cid, Bytes)> = Vec::new();
    let mut visited: HashSet<Vec<u8>> = HashSet::new();

    collected_blocks.push((root_cid, commit_bytes.clone()));
    visited.insert(root_cid.to_bytes());

    let mst_root_cid = commit.data;
    if !visited.contains(&mst_root_cid.to_bytes()) {
        visited.insert(mst_root_cid.to_bytes());
        if let Ok(Some(data)) = state.block_store.get(&mst_root_cid).await {
            collected_blocks.push((mst_root_cid, data));
        }
    }

    let records = sqlx::query!("SELECT record_cid FROM records WHERE repo_id = $1", user_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    for record in records {
        if let Ok(cid) = record.record_cid.parse::<Cid>() {
            if !visited.contains(&cid.to_bytes()) {
                visited.insert(cid.to_bytes());
                if let Ok(Some(data)) = state.block_store.get(&cid).await {
                    collected_blocks.push((cid, data));
                }
            }
        }
    }

    let mut buf = Vec::new();
    let header = encode_car_header(&root_cid);
    if let Err(e) = ld_write(&mut buf, &header) {
        error!("Failed to write CAR header: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    for (cid, data) in &collected_blocks {
        let mut block_data = Vec::new();
        block_data.extend_from_slice(&cid.to_bytes());
        block_data.extend_from_slice(data);
        if let Err(e) = ld_write(&mut buf, &block_data) {
            error!("Failed to write block: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.ipld.car")
        .body(Body::from(buf))
        .unwrap()
}

#[derive(Deserialize)]
pub struct GetRecordParams {
    pub did: String,
    pub collection: String,
    pub rkey: String,
}

pub async fn get_record(
    State(state): State<AppState>,
    Query(params): Query<GetRecordParams>,
) -> Response {
    let did = params.did.trim();
    let collection = params.collection.trim();
    let rkey = params.rkey.trim();

    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }

    if collection.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "collection is required"})),
        )
            .into_response();
    }

    if rkey.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "rkey is required"})),
        )
            .into_response();
    }

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
            error!("DB error in sync get_record: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let record_result = sqlx::query!(
        "SELECT record_cid FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3",
        user_id,
        collection,
        rkey
    )
    .fetch_optional(&state.db)
    .await;

    let record_cid_str = match record_result {
        Ok(Some(row)) => row.record_cid,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RecordNotFound", "message": "Record not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in sync get_record: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let record_cid = match record_cid_str.parse::<Cid>() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse record CID: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let repo_result = sqlx::query!("SELECT repo_root_cid FROM repos WHERE user_id = $1", user_id)
        .fetch_optional(&state.db)
        .await;

    let repo_root_cid_str = match repo_result {
        Ok(Some(row)) => row.repo_root_cid,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RepoNotFound", "message": "Repository not initialized"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in sync get_record: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let root_cid = match repo_root_cid_str.parse::<Cid>() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse root CID: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let mut collected_blocks: Vec<(Cid, Bytes)> = Vec::new();

    let commit_bytes = match state.block_store.get(&root_cid).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            error!("Commit block not found: {}", root_cid);
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

    collected_blocks.push((root_cid, commit_bytes.clone()));

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

    let mst_root_cid = commit.data;
    if let Ok(Some(data)) = state.block_store.get(&mst_root_cid).await {
        collected_blocks.push((mst_root_cid, data));
    }

    if let Ok(Some(data)) = state.block_store.get(&record_cid).await {
        collected_blocks.push((record_cid, data));
    } else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "RecordNotFound", "message": "Record block not found"})),
        )
            .into_response();
    }

    let mut buf = Vec::new();
    let header = encode_car_header(&root_cid);
    if let Err(e) = ld_write(&mut buf, &header) {
        error!("Failed to write CAR header: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    for (cid, data) in &collected_blocks {
        let mut block_data = Vec::new();
        block_data.extend_from_slice(&cid.to_bytes());
        block_data.extend_from_slice(data);
        if let Err(e) = ld_write(&mut buf, &block_data) {
            error!("Failed to write block: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.ipld.car")
        .body(Body::from(buf))
        .unwrap()
}
