use crate::api::error::ApiError;
use crate::auth::{extract_bearer_token_from_header, validate_bearer_token_allow_takendown};
use crate::state::AppState;
use crate::sync::car::encode_car_header;
use crate::sync::util::assert_repo_availability;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cid::Cid;
use ipld_core::ipld::Ipld;
use jacquard_repo::storage::BlockStore;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::str::FromStr;

const MAX_REPO_BLOCKS_TRAVERSAL: usize = 20_000;

async fn check_admin_or_self(state: &AppState, headers: &HeaderMap, did: &str) -> bool {
    let token = match extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return false,
    };
    match validate_bearer_token_allow_takendown(&state.db, &token).await {
        Ok(auth_user) => auth_user.is_admin || auth_user.did == did,
        Err(_) => false,
    }
}

#[derive(Deserialize)]
pub struct GetHeadParams {
    pub did: String,
}

#[derive(Serialize)]
pub struct GetHeadOutput {
    pub root: String,
}

pub async fn get_head(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<GetHeadParams>,
) -> Response {
    let did = params.did.trim();
    if did.is_empty() {
        return ApiError::InvalidRequest("did is required".into()).into_response();
    }
    let is_admin_or_self = check_admin_or_self(&state, &headers, did).await;
    let account = match assert_repo_availability(&state.db, did, is_admin_or_self).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    match account.repo_root_cid {
        Some(root) => (StatusCode::OK, Json(GetHeadOutput { root })).into_response(),
        None => ApiError::RepoNotFound(Some(format!("Could not find root for DID: {}", did)))
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct GetCheckoutParams {
    pub did: String,
}

pub async fn get_checkout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<GetCheckoutParams>,
) -> Response {
    let did = params.did.trim();
    if did.is_empty() {
        return ApiError::InvalidRequest("did is required".into()).into_response();
    }
    let is_admin_or_self = check_admin_or_self(&state, &headers, did).await;
    let account = match assert_repo_availability(&state.db, did, is_admin_or_self).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Some(head_str) = account.repo_root_cid else {
        return ApiError::RepoNotFound(Some("Repo not initialized".into())).into_response();
    };
    let Ok(head_cid) = Cid::from_str(&head_str) else {
        return ApiError::InternalError(Some("Invalid head CID".into())).into_response();
    };
    let Ok(mut car_bytes) = encode_car_header(&head_cid) else {
        return ApiError::InternalError(Some("Failed to encode CAR header".into())).into_response();
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
