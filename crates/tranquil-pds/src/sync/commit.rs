use crate::api::error::ApiError;
use crate::state::AppState;
use crate::sync::util::{AccountStatus, assert_repo_availability, get_account_with_status};
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
use std::str::FromStr;
use tracing::error;
use tranquil_types::Did;

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
    let did_str = params.did.trim();
    if did_str.is_empty() {
        return ApiError::InvalidRequest("did is required".into()).into_response();
    }
    let did: Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => return ApiError::InvalidRequest("invalid did".into()).into_response(),
    };

    let account = match assert_repo_availability(state.repo_repo.as_ref(), &did, false).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let Some(repo_root_cid) = account.repo_root_cid else {
        return ApiError::RepoNotFound(Some("Repo not initialized".into())).into_response();
    };

    let Some(rev) = get_rev_from_commit(&state, &repo_root_cid).await else {
        error!(
            "Failed to parse commit for DID {}: CID {}",
            did_str, repo_root_cid
        );
        return ApiError::InternalError(Some("Failed to read repo commit".into())).into_response();
    };

    (
        StatusCode::OK,
        Json(GetLatestCommitOutput {
            cid: repo_root_cid,
            rev,
        }),
    )
        .into_response()
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
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
    let cursor_did: Option<Did> = params
        .cursor
        .as_ref()
        .and_then(|s| s.parse().ok());
    let cursor_ref = cursor_did.as_ref();
    let result = state.repo_repo.list_repos_paginated(cursor_ref, limit + 1).await;
    match result {
        Ok(rows) => {
            let has_more = rows.len() as i64 > limit;
            let mut repos: Vec<RepoInfo> = Vec::new();
            for row in rows.iter().take(limit as usize) {
                let cid_str = row.repo_root_cid.to_string();
                let rev = match get_rev_from_commit(&state, &cid_str).await {
                    Some(r) => r,
                    None => {
                        if let Some(ref stored_rev) = row.repo_rev {
                            stored_rev.clone()
                        } else {
                            tracing::warn!(
                                "Failed to parse commit for DID {} in list_repos: CID {}",
                                row.did,
                                row.repo_root_cid
                            );
                            continue;
                        }
                    }
                };
                let status = if row.takedown_ref.is_some() {
                    AccountStatus::Takendown
                } else if row.deactivated_at.is_some() {
                    AccountStatus::Deactivated
                } else {
                    AccountStatus::Active
                };
                repos.push(RepoInfo {
                    did: row.did.to_string(),
                    head: cid_str,
                    rev,
                    active: status.is_active(),
                    status: status.as_str().map(String::from),
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
            ApiError::InternalError(Some("Database error".into())).into_response()
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
}

pub async fn get_repo_status(
    State(state): State<AppState>,
    Query(params): Query<GetRepoStatusParams>,
) -> Response {
    let did_str = params.did.trim();
    if did_str.is_empty() {
        return ApiError::InvalidRequest("did is required".into()).into_response();
    }
    let did: Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => return ApiError::InvalidRequest("invalid did".into()).into_response(),
    };

    let account = match get_account_with_status(state.repo_repo.as_ref(), &did).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return ApiError::RepoNotFound(Some(format!("Could not find repo for DID: {}", did_str)))
                .into_response();
        }
        Err(e) => {
            error!("DB error in get_repo_status: {:?}", e);
            return ApiError::InternalError(Some("Database error".into())).into_response();
        }
    };

    let rev = if account.status.is_active() {
        if let Some(ref cid) = account.repo_root_cid {
            get_rev_from_commit(&state, cid).await
        } else {
            None
        }
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(GetRepoStatusOutput {
            did: account.did,
            active: account.status.is_active(),
            status: account.status.as_str().map(String::from),
            rev,
        }),
    )
        .into_response()
}
