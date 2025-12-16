use crate::state::AppState;
use crate::sync::car::encode_car_header;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cid::Cid;
use ipld_core::ipld::Ipld;
use jacquard_repo::storage::BlockStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Write;
use std::str::FromStr;
use tracing::error;

const MAX_REPO_BLOCKS_TRAVERSAL: usize = 20_000;

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
    Query(params): Query<GetHeadParams>,
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
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(GetHeadOutput {
                root: row.repo_root_cid,
            }),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "HeadNotFound", "message": "Could not find root for DID"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error in get_head: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct GetCheckoutParams {
    pub did: String,
}

pub async fn get_checkout(
    State(state): State<AppState>,
    Query(params): Query<GetCheckoutParams>,
) -> Response {
    let did = params.did.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }
    let repo_row = sqlx::query!(
        r#"
        SELECT r.repo_root_cid
        FROM repos r
        JOIN users u ON u.id = r.user_id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);
    let head_str = match repo_row {
        Some(r) => r.repo_root_cid,
        None => {
            let user_exists = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
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
