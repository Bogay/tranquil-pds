use crate::state::AppState;
use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    http::header,
    response::{IntoResponse, Response},
};
use tracing::error;

pub async fn get_logo(State(state): State<AppState>) -> Response {
    let logo_cid = match state.infra_repo.get_server_config("logo_cid").await {
        Ok(cid) => cid,
        Err(e) => {
            error!("DB error fetching logo_cid: {:?}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let cid_str = match logo_cid {
        Some(c) if !c.is_empty() => c,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let cid = match crate::types::CidLink::new(&cid_str) {
        Ok(c) => c,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let metadata = match state.blob_repo.get_blob_metadata(&cid).await {
        Ok(Some(m)) => m,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!("DB error fetching blob: {:?}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match state.blob_store.get(&metadata.storage_key).await {
        Ok(data) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, &metadata.mime_type)
            .header(header::CACHE_CONTROL, "public, max-age=3600")
            .body(Body::from(data))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(e) => {
            error!("Failed to fetch logo from storage: {:?}", e);
            StatusCode::NOT_FOUND.into_response()
        }
    }
}
