use crate::api::error::ApiError;
use crate::state::AppState;
use crate::sync::car::encode_car_header;
use crate::sync::util::assert_repo_availability;
use axum::{
    extract::{Query, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cid::Cid;
use ipld_core::ipld::Ipld;
use jacquard_repo::storage::BlockStore;
use serde::Deserialize;
use std::io::Write;
use std::str::FromStr;
use tracing::error;

const MAX_REPO_BLOCKS_TRAVERSAL: usize = 20_000;

fn parse_get_blocks_query(query_string: &str) -> Result<(String, Vec<String>), String> {
    let did = crate::util::parse_repeated_query_param(Some(query_string), "did")
        .into_iter()
        .next()
        .ok_or("Missing required parameter: did")?;
    let cids = crate::util::parse_repeated_query_param(Some(query_string), "cids");
    Ok((did, cids))
}

pub async fn get_blocks(State(state): State<AppState>, RawQuery(query): RawQuery) -> Response {
    let Some(query_string) = query else {
        return ApiError::InvalidRequest("Missing query parameters".into()).into_response();
    };

    let (did, cid_strings) = match parse_get_blocks_query(&query_string) {
        Ok(parsed) => parsed,
        Err(msg) => return ApiError::InvalidRequest(msg).into_response(),
    };

    let _account = match assert_repo_availability(&state.db, &did, false).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let cids: Vec<Cid> = match cid_strings
        .iter()
        .map(|s| Cid::from_str(s).map_err(|_| s.clone()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(cids) => cids,
        Err(invalid) => {
            return ApiError::InvalidRequest(format!("Invalid CID: {}", invalid)).into_response()
        }
    };

    if cids.is_empty() {
        return ApiError::InvalidRequest("No CIDs provided".into()).into_response();
    }

    let blocks = match state.block_store.get_many(&cids).await {
        Ok(blocks) => blocks,
        Err(e) => {
            error!("Failed to get blocks: {}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let missing_cids: Vec<String> = blocks
        .iter()
        .zip(&cids)
        .filter_map(|(block_opt, cid)| block_opt.is_none().then(|| cid.to_string()))
        .collect();
    if !missing_cids.is_empty() {
        return ApiError::InvalidRequest(format!(
            "Could not find blocks: {}",
            missing_cids.join(", ")
        ))
        .into_response();
    }

    let header = match crate::sync::car::encode_car_header_null_root() {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to encode CAR header: {}", e);
            return ApiError::InternalError(None).into_response();
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
            writer
                .write_all(&cid_bytes)
                .expect("Writing to Vec<u8> should never fail");
            writer
                .write_all(&block)
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
    let account = match assert_repo_availability(&state.db, &query.did, false).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let Some(head_str) = account.repo_root_cid else {
        return ApiError::RepoNotFound(Some("Repo not initialized".into())).into_response();
    };

    let Ok(head_cid) = Cid::from_str(&head_str) else {
        return ApiError::InternalError(None).into_response();
    };

    if let Some(since) = &query.since {
        return get_repo_since(&state, &query.did, &head_cid, since).await;
    }

    let mut car_bytes = match encode_car_header(&head_cid) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to encode CAR header: {}", e);
            return ApiError::InternalError(None).into_response();
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
        if remaining == 0 {
            break;
        }
        remaining -= 1;
        if let Ok(Some(block)) = state.block_store.get(&cid).await {
            let cid_bytes = cid.to_bytes();
            let total_len = cid_bytes.len() + block.len();
            let mut writer = Vec::new();
            crate::sync::car::write_varint(&mut writer, total_len as u64)
                .expect("Writing to Vec<u8> should never fail");
            writer
                .write_all(&cid_bytes)
                .expect("Writing to Vec<u8> should never fail");
            writer
                .write_all(&block)
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

async fn get_repo_since(state: &AppState, did: &str, head_cid: &Cid, since: &str) -> Response {
    let events = sqlx::query!(
        r#"
        SELECT blocks_cids, commit_cid
        FROM repo_seq
        WHERE did = $1 AND rev > $2
        ORDER BY seq DESC
        "#,
        did,
        since
    )
    .fetch_all(&state.db)
    .await;

    let events = match events {
        Ok(e) => e,
        Err(e) => {
            error!("DB error in get_repo_since: {:?}", e);
            return ApiError::InternalError(Some("Database error".into())).into_response();
        }
    };

    let mut block_cids: Vec<Cid> = Vec::new();
    for event in &events {
        if let Some(cids) = &event.blocks_cids {
            for cid_str in cids {
                if let Ok(cid) = Cid::from_str(cid_str)
                    && !block_cids.contains(&cid)
                {
                    block_cids.push(cid);
                }
            }
        }
        if let Some(commit_cid_str) = &event.commit_cid
            && let Ok(cid) = Cid::from_str(commit_cid_str)
            && !block_cids.contains(&cid)
        {
            block_cids.push(cid);
        }
    }

    let mut car_bytes = match encode_car_header(head_cid) {
        Ok(h) => h,
        Err(e) => {
            return ApiError::InternalError(Some(format!("Failed to encode CAR header: {}", e)))
                .into_response();
        }
    };

    if block_cids.is_empty() {
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
            car_bytes,
        )
            .into_response();
    }

    let blocks = match state.block_store.get_many(&block_cids).await {
        Ok(b) => b,
        Err(e) => {
            error!("Block store error in get_repo_since: {:?}", e);
            return ApiError::InternalError(Some("Failed to get blocks".into())).into_response();
        }
    };

    for (i, block_opt) in blocks.into_iter().enumerate() {
        if let Some(block) = block_opt {
            let cid = block_cids[i];
            let cid_bytes = cid.to_bytes();
            let total_len = cid_bytes.len() + block.len();
            let mut writer = Vec::new();
            crate::sync::car::write_varint(&mut writer, total_len as u64)
                .expect("Writing to Vec<u8> should never fail");
            writer
                .write_all(&cid_bytes)
                .expect("Writing to Vec<u8> should never fail");
            writer
                .write_all(&block)
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

    let account = match assert_repo_availability(&state.db, &query.did, false).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let commit_cid_str = match account.repo_root_cid {
        Some(cid) => cid,
        None => {
            return ApiError::RepoNotFound(Some("Repo not initialized".into())).into_response();
        }
    };
    let Ok(commit_cid) = Cid::from_str(&commit_cid_str) else {
        return ApiError::InternalError(Some("Invalid commit CID".into())).into_response();
    };
    let commit_bytes = match state.block_store.get(&commit_cid).await {
        Ok(Some(b)) => b,
        _ => {
            return ApiError::InternalError(Some("Commit block not found".into())).into_response();
        }
    };
    let Ok(commit) = Commit::from_cbor(&commit_bytes) else {
        return ApiError::InternalError(Some("Failed to parse commit".into())).into_response();
    };
    let mst = Mst::load(Arc::new(state.block_store.clone()), commit.data, None);
    let key = format!("{}/{}", query.collection, query.rkey);
    let record_cid = match mst.get(&key).await {
        Ok(Some(cid)) => cid,
        Ok(None) => {
            return ApiError::RecordNotFound.into_response();
        }
        Err(_) => {
            return ApiError::InternalError(Some("Failed to lookup record".into())).into_response();
        }
    };
    let record_block = match state.block_store.get(&record_cid).await {
        Ok(Some(b)) => b,
        _ => {
            return ApiError::RecordNotFound.into_response();
        }
    };
    let mut proof_blocks: BTreeMap<Cid, bytes::Bytes> = BTreeMap::new();
    if mst.blocks_for_path(&key, &mut proof_blocks).await.is_err() {
        return ApiError::InternalError(Some("Failed to build proof path".into())).into_response();
    }
    let header = match encode_car_header(&commit_cid) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to encode CAR header: {}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let mut car_bytes = header;
    let write_block = |car: &mut Vec<u8>, cid: &Cid, data: &[u8]| {
        let cid_bytes = cid.to_bytes();
        let total_len = cid_bytes.len() + data.len();
        let mut writer = Vec::new();
        crate::sync::car::write_varint(&mut writer, total_len as u64)
            .expect("Writing to Vec<u8> should never fail");
        writer
            .write_all(&cid_bytes)
            .expect("Writing to Vec<u8> should never fail");
        writer
            .write_all(data)
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
