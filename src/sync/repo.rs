use crate::state::AppState;
use crate::sync::car::encode_car_header;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use cid::Cid;
use jacquard_repo::storage::BlockStore;
use serde::Deserialize;
use serde_json::json;
use std::io::Write;
use std::str::FromStr;
use tracing::error;

#[derive(Deserialize)]
pub struct GetBlocksQuery {
    pub did: String,
    pub cids: String,
}

pub async fn get_blocks(
    State(state): State<AppState>,
    Query(query): Query<GetBlocksQuery>,
) -> Response {
    let user_exists = sqlx::query!("SELECT id FROM users WHERE did = $1", query.did)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    if user_exists.is_none() {
        return (StatusCode::NOT_FOUND, "Repo not found").into_response();
    }

    let cids_str: Vec<&str> = query.cids.split(',').collect();
    let mut cids = Vec::new();
    for s in cids_str {
        match Cid::from_str(s) {
            Ok(cid) => cids.push(cid),
            Err(_) => return (StatusCode::BAD_REQUEST, "Invalid CID").into_response(),
        }
    }

    let blocks_res = state.block_store.get_many(&cids).await;
    let blocks = match blocks_res {
        Ok(blocks) => blocks,
        Err(e) => {
            error!("Failed to get blocks: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to get blocks").into_response();
        }
    };

    let root_cid = cids.first().cloned().unwrap_or_default();

    if cids.is_empty() {
         return (StatusCode::BAD_REQUEST, "No CIDs provided").into_response();
    }

    let header = encode_car_header(&root_cid);

    let mut car_bytes = header;

    for (i, block_opt) in blocks.into_iter().enumerate() {
        if let Some(block) = block_opt {
            let cid = cids[i];
            let cid_bytes = cid.to_bytes();
            let total_len = cid_bytes.len() + block.len();

            let mut writer = Vec::new();
            crate::sync::car::write_varint(&mut writer, total_len as u64).unwrap();
            writer.write_all(&cid_bytes).unwrap();
            writer.write_all(&block).unwrap();

            car_bytes.extend_from_slice(&writer);
        }
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
        car_bytes,
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct GetRepoQuery {
    pub did: String,
    pub since: Option<String>,
}

pub async fn get_repo(
    State(state): State<AppState>,
    Query(query): Query<GetRepoQuery>,
) -> Response {
    let repo_row = sqlx::query!(
        r#"
        SELECT r.repo_root_cid
        FROM repos r
        JOIN users u ON u.id = r.user_id
        WHERE u.did = $1
        "#,
        query.did
    )
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let head_str = match repo_row {
        Some(r) => r.repo_root_cid,
        None => {
            let user_exists = sqlx::query!("SELECT id FROM users WHERE did = $1", query.did)
                .fetch_optional(&state.db)
                .await
                .unwrap_or(None);

            if user_exists.is_none() {
                 return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "RepoNotFound", "message": "Repo not found"})),
                )
                    .into_response();
            } else {
                 return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "RepoNotFound", "message": "Repo not initialized"})),
                )
                    .into_response();
            }
        }
    };

    let head_cid = match Cid::from_str(&head_str) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Invalid head CID"})),
            )
                .into_response();
        }
    };

    let mut car_bytes = encode_car_header(&head_cid);

    let mut stack = vec![head_cid];
    let mut visited = std::collections::HashSet::new();
    let mut limit = 20000;

    while let Some(cid) = stack.pop() {
        if visited.contains(&cid) {
            continue;
        }
        visited.insert(cid);
        if limit == 0 { break; }
        limit -= 1;

        if let Ok(Some(block)) = state.block_store.get(&cid).await {
            let cid_bytes = cid.to_bytes();
            let total_len = cid_bytes.len() + block.len();
            let mut writer = Vec::new();
            crate::sync::car::write_varint(&mut writer, total_len as u64).unwrap();
            writer.write_all(&cid_bytes).unwrap();
            writer.write_all(&block).unwrap();
            car_bytes.extend_from_slice(&writer);

             if let Ok(value) = serde_ipld_dagcbor::from_slice::<serde_json::Value>(&block) {
                extract_links_json(&value, &mut stack);
            }
        }
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
        car_bytes,
    )
        .into_response()
}

fn extract_links_json(value: &serde_json::Value, stack: &mut Vec<Cid>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(s)) = map.get("/") {
                if let Ok(cid) = Cid::from_str(s) {
                    stack.push(cid);
                }
            } else if let Some(serde_json::Value::String(s)) = map.get("$link") {
                 if let Ok(cid) = Cid::from_str(s) {
                    stack.push(cid);
                }
            } else {
                for v in map.values() {
                    extract_links_json(v, stack);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_links_json(v, stack);
            }
        }
        _ => {}
    }
}

#[derive(Deserialize)]
pub struct GetRecordQuery {
    pub did: String,
    pub collection: String,
    pub rkey: String,
}

pub async fn get_record(
    State(state): State<AppState>,
    Query(query): Query<GetRecordQuery>,
) -> Response {
    let user = sqlx::query!("SELECT id FROM users WHERE did = $1", query.did)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let user_id = match user {
        Some(u) => u.id,
        None => {
             return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RepoNotFound", "message": "Repo not found"})),
            )
                .into_response();
        }
    };

    let record = sqlx::query!(
        "SELECT record_cid FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3",
        user_id,
        query.collection,
        query.rkey
    )
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let record_cid_str = match record {
        Some(r) => r.record_cid,
        None => {
             return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RecordNotFound", "message": "Record not found"})),
            )
                .into_response();
        }
    };

    let cid = match Cid::from_str(&record_cid_str) {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid CID").into_response(),
    };

    let block_res = state.block_store.get(&cid).await;
    let block = match block_res {
        Ok(Some(b)) => b,
        _ => return (StatusCode::NOT_FOUND, "Block not found").into_response(),
    };

    let header = encode_car_header(&cid);
    let mut car_bytes = header;

    let cid_bytes = cid.to_bytes();
    let total_len = cid_bytes.len() + block.len();
    let mut writer = Vec::new();
    crate::sync::car::write_varint(&mut writer, total_len as u64).unwrap();
    writer.write_all(&cid_bytes).unwrap();
    writer.write_all(&block).unwrap();
    car_bytes.extend_from_slice(&writer);

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
        car_bytes,
    )
        .into_response()
}
