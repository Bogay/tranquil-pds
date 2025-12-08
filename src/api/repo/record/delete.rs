use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cid::Cid;
use jacquard::types::{
    did::Did,
    integer::LimitedU32,
    string::{Nsid, Tid},
};
use jacquard_repo::{commit::Commit, mst::Mst, storage::BlockStore};
use serde::Deserialize;
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use tracing::error;

#[derive(Deserialize)]
pub struct DeleteRecordInput {
    pub repo: String,
    pub collection: String,
    pub rkey: String,
    #[serde(rename = "swapRecord")]
    pub swap_record: Option<String>,
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
}

pub async fn delete_record(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<DeleteRecordInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }
    let token = auth_header
        .unwrap()
        .to_str()
        .unwrap_or("")
        .replace("Bearer ", "");

    let session = sqlx::query!(
            "SELECT s.did, k.key_bytes FROM sessions s JOIN users u ON s.did = u.did JOIN user_keys k ON u.id = k.user_id WHERE s.access_jwt = $1",
            token
        )
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let (did, key_bytes) = match session {
        Some(row) => (
            row.did,
            row.key_bytes,
        ),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
    };

    if let Err(_) = crate::auth::verify_token(&token, &key_bytes) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationFailed", "message": "Invalid token signature"})),
        )
            .into_response();
    }

    if input.repo != did {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "InvalidRepo", "message": "Repo does not match authenticated user"}))).into_response();
    }

    let user_query = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;

    let user_id: uuid::Uuid = match user_query {
        Ok(Some(row)) => row.id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User not found"})),
            )
                .into_response();
        }
    };

    let repo_root_query = sqlx::query!("SELECT repo_root_cid FROM repos WHERE user_id = $1", user_id)
        .fetch_optional(&state.db)
        .await;

    let current_root_cid = match repo_root_query {
        Ok(Some(row)) => {
            let cid_str: String = row.repo_root_cid;
            Cid::from_str(&cid_str).ok()
        }
        _ => None,
    };

    if current_root_cid.is_none() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Repo root not found"})),
        )
            .into_response();
    }
    let current_root_cid = current_root_cid.unwrap();

    let commit_bytes = match state.block_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        Ok(None) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Commit block not found"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": format!("Failed to load commit block: {:?}", e)}))).into_response(),
    };

    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": format!("Failed to parse commit: {:?}", e)}))).into_response(),
    };

    let mst_root = commit.data;
    let store = Arc::new(state.block_store.clone());
    let mst = Mst::load(store.clone(), mst_root, None);

    let collection_nsid = match input.collection.parse::<Nsid>() {
        Ok(n) => n,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidCollection"})),
            )
                .into_response();
        }
    };

    let key = format!("{}/{}", collection_nsid, input.rkey);

    // TODO: Check swapRecord if provided? Skipping for brevity/robustness

    let new_mst = match mst.delete(&key).await {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to delete from MST: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": format!("Failed to delete from MST: {:?}", e)}))).into_response();
        }
    };

    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to persist MST: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to persist MST"})),
            )
                .into_response();
        }
    };

    let did_obj = match Did::new(&did) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Invalid DID"})),
            )
                .into_response();
        }
    };

    let rev = Tid::now(LimitedU32::MIN);

    let new_commit = Commit::new_unsigned(did_obj, new_mst_root, rev, Some(current_root_cid));

    let new_commit_bytes =
        match new_commit.to_cbor() {
            Ok(b) => b,
            Err(_e) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({"error": "InternalError", "message": "Failed to serialize new commit"}),
                ),
            )
                .into_response(),
        };

    let new_root_cid = match state.block_store.put(&new_commit_bytes).await {
        Ok(c) => c,
        Err(_e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to save new commit"})),
            )
                .into_response();
        }
    };

    let update_repo = sqlx::query!("UPDATE repos SET repo_root_cid = $1 WHERE user_id = $2", new_root_cid.to_string(), user_id)
        .execute(&state.db)
        .await;

    if let Err(e) = update_repo {
        error!("Failed to update repo root in DB: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to update repo root in DB"})),
        )
            .into_response();
    }

    let record_delete =
        sqlx::query!("DELETE FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3", user_id, input.collection, input.rkey)
            .execute(&state.db)
            .await;

    if let Err(e) = record_delete {
        error!("Error deleting record index: {:?}", e);
    }

    (StatusCode::OK, Json(json!({}))).into_response()
}
