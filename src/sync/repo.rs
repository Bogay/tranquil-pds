use crate::state::AppState;
use crate::sync::car::{encode_car_header, ld_write};
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
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use tracing::error;

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
    let car_header = encode_car_header(&root_cid);
    if let Err(e) = ld_write(&mut buf, &car_header) {
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
    let car_header = encode_car_header(&root_cid);
    if let Err(e) = ld_write(&mut buf, &car_header) {
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
    let car_header = encode_car_header(&root_cid);
    if let Err(e) = ld_write(&mut buf, &car_header) {
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
