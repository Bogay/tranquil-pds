use axum::{
    Json,
    body::Body,
    extract::{Query, State},
    http::StatusCode,
    http::header,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::error;
use tranquil_pds::api::error::ApiError;
use tranquil_pds::state::AppState;
use tranquil_pds::sync::util::{RepoAccessLevel, assert_repo_availability};
use tranquil_types::{CidLink, Did};

#[derive(Deserialize)]
pub struct GetBlobParams {
    pub did: Did,
    pub cid: CidLink,
}

pub async fn get_blob(
    State(state): State<AppState>,
    Query(params): Query<GetBlobParams>,
) -> Response {
    let did = params.did;
    let cid = params.cid;

    let _account =
        match assert_repo_availability(state.repos.repo.as_ref(), &did, RepoAccessLevel::Public)
            .await
        {
            Ok(a) => a,
            Err(e) => return e.into_response(),
        };

    let blob_result = state.repos.blob.get_blob_metadata(&cid).await;
    match blob_result {
        Ok(Some(metadata)) => match state.blob_store.get(&metadata.storage_key).await {
            Ok(data) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, &metadata.mime_type)
                .header(header::CONTENT_LENGTH, metadata.size_bytes.to_string())
                .header("x-content-type-options", "nosniff")
                .header("content-security-policy", "default-src 'none'; sandbox")
                .body(Body::from(data))
                .unwrap_or_else(|_| ApiError::InternalError(None).into_response()),
            Err(e) => {
                error!("Failed to fetch blob from storage: {:?}", e);
                ApiError::BlobNotFound(Some("Blob not found in storage".into())).into_response()
            }
        },
        Ok(None) => ApiError::BlobNotFound(Some("Blob not found".into())).into_response(),
        Err(e) => {
            error!("DB error in get_blob: {:?}", e);
            ApiError::InternalError(Some(format!("Database error: {}", e))).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct ListBlobsParams {
    pub did: Did,
    pub since: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
pub struct ListBlobsOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub cids: Vec<String>,
}

pub async fn list_blobs(
    State(state): State<AppState>,
    Query(params): Query<ListBlobsParams>,
) -> Response {
    let did = params.did;

    let account =
        match assert_repo_availability(state.repos.repo.as_ref(), &did, RepoAccessLevel::Public)
            .await
        {
            Ok(a) => a,
            Err(e) => return e.into_response(),
        };

    let limit = params.limit.unwrap_or(500).clamp(1, 1000);
    let cursor_cid = params.cursor.as_deref().unwrap_or("");
    let user_id = account.user_id;

    let cids_result: Result<Vec<String>, _> = if let Some(since) = &params.since {
        state
            .repos.blob
            .list_blobs_since_rev(&did, since)
            .await
            .map(|cids| {
                let mut cid_strs: Vec<String> = cids.into_iter().map(|c| c.to_string()).collect();
                cid_strs.sort();
                cid_strs
                    .into_iter()
                    .filter(|c| c.as_str() > cursor_cid)
                    .take(usize::try_from(limit + 1).unwrap_or(0))
                    .collect()
            })
    } else {
        state
            .repos.blob
            .list_blobs_by_user(user_id, Some(cursor_cid), limit + 1)
            .await
            .map(|cids| cids.into_iter().map(|c| c.to_string()).collect())
    };
    match cids_result {
        Ok(cids) => {
            let limit_usize = usize::try_from(limit).unwrap_or(0);
            let has_more = cids.len() > limit_usize;
            let cids: Vec<String> = cids.into_iter().take(limit_usize).collect();
            let next_cursor = if has_more { cids.last().cloned() } else { None };
            (
                StatusCode::OK,
                Json(ListBlobsOutput {
                    cursor: next_cursor,
                    cids,
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("DB error in list_blobs: {:?}", e);
            ApiError::InternalError(Some(format!("Database error: {}", e))).into_response()
        }
    }
}
