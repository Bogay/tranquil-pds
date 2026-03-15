use tranquil_pds::api::error::ApiError;
use tranquil_pds::state::AppState;
use tranquil_pds::sync::car::{encode_car_block, encode_car_header};
use tranquil_pds::sync::util::{RepoAccessLevel, assert_repo_availability};
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use cid::Cid;
use ipld_core::ipld::Ipld;
use jacquard_repo::storage::BlockStore;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tranquil_types::Did;

const MAX_REPO_BLOCKS_TRAVERSAL: usize = 20_000;

async fn check_admin_or_self(state: &AppState, headers: &HeaderMap, did: &Did) -> bool {
    let extracted = match tranquil_pds::auth::extract_auth_token_from_header(tranquil_pds::util::get_header_str(
        headers,
        axum::http::header::AUTHORIZATION,
    )) {
        Some(t) => t,
        None => return false,
    };
    let dpop_proof = tranquil_pds::util::get_header_str(headers, tranquil_pds::util::HEADER_DPOP);
    let http_uri = "/";
    match tranquil_pds::auth::validate_token_with_dpop(
        state.user_repo.as_ref(),
        state.oauth_repo.as_ref(),
        &extracted.token,
        extracted.scheme,
        dpop_proof,
        Method::GET.as_str(),
        http_uri,
        tranquil_pds::auth::AccountRequirement::AnyStatus,
    )
    .await
    {
        Ok(auth_user) => auth_user.is_admin || auth_user.did == *did,
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
    let did_str = params.did.trim();
    if did_str.is_empty() {
        return ApiError::InvalidRequest("did is required".into()).into_response();
    }
    let did: Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => return ApiError::InvalidRequest("invalid did".into()).into_response(),
    };
    let is_admin_or_self = check_admin_or_self(&state, &headers, &did).await;
    let account = match assert_repo_availability(
        state.repo_repo.as_ref(),
        &did,
        if is_admin_or_self {
            RepoAccessLevel::Privileged
        } else {
            RepoAccessLevel::Public
        },
    )
    .await
    {
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
    let did_str = params.did.trim();
    if did_str.is_empty() {
        return ApiError::InvalidRequest("did is required".into()).into_response();
    }
    let did: Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => return ApiError::InvalidRequest("invalid did".into()).into_response(),
    };
    let is_admin_or_self = check_admin_or_self(&state, &headers, &did).await;
    let account = match assert_repo_availability(
        state.repo_repo.as_ref(),
        &did,
        if is_admin_or_self {
            RepoAccessLevel::Privileged
        } else {
            RepoAccessLevel::Public
        },
    )
    .await
    {
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
            car_bytes.extend_from_slice(&encode_car_block(&cid, &block));
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
            map.values().for_each(|v| extract_links_ipld(v, stack));
        }
        Ipld::List(arr) => {
            arr.iter().for_each(|v| extract_links_ipld(v, stack));
        }
        _ => {}
    }
}
