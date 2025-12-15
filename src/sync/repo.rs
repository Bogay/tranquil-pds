use crate::state::AppState;
use crate::sync::car::encode_car_header;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use cid::Cid;
use ipld_core::ipld::Ipld;
use jacquard_repo::storage::BlockStore;
use serde::Deserialize;
use serde_json::json;
use std::io::Write;
use std::str::FromStr;
use tracing::error;

const MAX_REPO_BLOCKS_TRAVERSAL: usize = 20_000;

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
    if cids.is_empty() {
         return (StatusCode::BAD_REQUEST, "No CIDs provided").into_response();
    }
    let root_cid = cids[0];
    let header = match encode_car_header(&root_cid) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to encode CAR header: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to encode CAR").into_response();
        }
    };
    let mut car_bytes = header;
    for (i, block_opt) in blocks.into_iter().enumerate() {
        if let Some(block) = block_opt {
            let cid = cids[i];
            let cid_bytes = cid.to_bytes();
            let total_len = cid_bytes.len() + block.len();
            let mut writer = Vec::new();
            crate::sync::car::write_varint(&mut writer, total_len as u64)
                .expect("Writing to Vec<u8> should never fail");
            writer.write_all(&cid_bytes)
                .expect("Writing to Vec<u8> should never fail");
            writer.write_all(&block)
                .expect("Writing to Vec<u8> should never fail");
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
    let mut car_bytes = match encode_car_header(&head_cid) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": format!("Failed to encode CAR header: {}", e)})),
            )
                .into_response();
        }
    };
    let mut stack = vec![head_cid];
    let mut visited = std::collections::HashSet::new();
    let mut remaining = MAX_REPO_BLOCKS_TRAVERSAL;
    while let Some(cid) = stack.pop() {
        if visited.contains(&cid) {
            continue;
        }
        visited.insert(cid);
        if remaining == 0 { break; }
        remaining -= 1;
        if let Ok(Some(block)) = state.block_store.get(&cid).await {
            let cid_bytes = cid.to_bytes();
            let total_len = cid_bytes.len() + block.len();
            let mut writer = Vec::new();
            crate::sync::car::write_varint(&mut writer, total_len as u64)
                .expect("Writing to Vec<u8> should never fail");
            writer.write_all(&cid_bytes)
                .expect("Writing to Vec<u8> should never fail");
            writer.write_all(&block)
                .expect("Writing to Vec<u8> should never fail");
            car_bytes.extend_from_slice(&writer);
            if let Ok(value) = serde_ipld_dagcbor::from_slice::<Ipld>(&block) {
                extract_links_ipld(&value, &mut stack);
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

fn extract_links_ipld(value: &Ipld, stack: &mut Vec<Cid>) {
    match value {
        Ipld::Link(cid) => {
            stack.push(*cid);
        }
        Ipld::Map(map) => {
            for v in map.values() {
                extract_links_ipld(v, stack);
            }
        }
        Ipld::List(arr) => {
            for v in arr {
                extract_links_ipld(v, stack);
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
    use jacquard_repo::commit::Commit;
    use jacquard_repo::mst::Mst;
    use std::collections::BTreeMap;
    use std::sync::Arc;

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
    let commit_cid_str = match repo_row {
        Some(r) => r.repo_root_cid,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RepoNotFound", "message": "Repo not found"})),
            )
                .into_response();
        }
    };
    let commit_cid = match Cid::from_str(&commit_cid_str) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Invalid commit CID"})),
            )
                .into_response();
        }
    };
    let commit_bytes = match state.block_store.get(&commit_cid).await {
        Ok(Some(b)) => b,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Commit block not found"})),
            )
                .into_response();
        }
    };
    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to parse commit"})),
            )
                .into_response();
        }
    };
    let mst = Mst::load(Arc::new(state.block_store.clone()), commit.data, None);
    let key = format!("{}/{}", query.collection, query.rkey);
    let record_cid = match mst.get(&key).await {
        Ok(Some(cid)) => cid,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RecordNotFound", "message": "Record not found"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to lookup record"})),
            )
                .into_response();
        }
    };
    let record_block = match state.block_store.get(&record_cid).await {
        Ok(Some(b)) => b,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RecordNotFound", "message": "Record block not found"})),
            )
                .into_response();
        }
    };
    let mut proof_blocks: BTreeMap<Cid, bytes::Bytes> = BTreeMap::new();
    if let Err(_) = mst.blocks_for_path(&key, &mut proof_blocks).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to build proof path"})),
        )
            .into_response();
    }
    let header = match encode_car_header(&commit_cid) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to encode CAR header: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let mut car_bytes = header;
    let write_block = |car: &mut Vec<u8>, cid: &Cid, data: &[u8]| {
        let cid_bytes = cid.to_bytes();
        let total_len = cid_bytes.len() + data.len();
        let mut writer = Vec::new();
        crate::sync::car::write_varint(&mut writer, total_len as u64)
            .expect("Writing to Vec<u8> should never fail");
        writer.write_all(&cid_bytes)
            .expect("Writing to Vec<u8> should never fail");
        writer.write_all(data)
            .expect("Writing to Vec<u8> should never fail");
        car.extend_from_slice(&writer);
    };
    write_block(&mut car_bytes, &commit_cid, &commit_bytes);
    for (cid, data) in &proof_blocks {
        write_block(&mut car_bytes, cid, data);
    }
    write_block(&mut car_bytes, &record_cid, &record_block);
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
        car_bytes,
    )
        .into_response()
}
