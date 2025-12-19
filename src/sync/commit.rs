use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cid::Cid;
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use tracing::error;

async fn get_rev_from_commit(state: &AppState, cid_str: &str) -> Option<String> {
    let cid = Cid::from_str(cid_str).ok()?;
    let block = state.block_store.get(&cid).await.ok()??;
    let commit = Commit::from_cbor(&block).ok()?;
    Some(commit.rev().to_string())
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
            let rev = get_rev_from_commit(&state, &row.repo_root_cid)
                .await
                .unwrap_or_else(|| chrono::Utc::now().timestamp_millis().to_string());
            (
                StatusCode::OK,
                Json(GetLatestCommitOutput {
                    cid: row.repo_root_cid,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub repos: Vec<RepoInfo>,
}

pub async fn list_repos(
    State(state): State<AppState>,
    Query(params): Query<ListReposParams>,
) -> Response {
    let limit = params.limit.unwrap_or(50).clamp(1, 1000);
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
            let mut repos: Vec<RepoInfo> = Vec::new();
            for row in rows.iter().take(limit as usize) {
                let rev = get_rev_from_commit(&state, &row.repo_root_cid)
                    .await
                    .unwrap_or_else(|| chrono::Utc::now().timestamp_millis().to_string());
                repos.push(RepoInfo {
                    did: row.did.clone(),
                    head: row.repo_root_cid.clone(),
                    rev,
                    active: true,
                });
            }
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
            let rev = get_rev_from_commit(&state, &row.repo_root_cid).await;
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
