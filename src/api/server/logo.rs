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
    let logo_cid: Option<String> =
        match sqlx::query_scalar("SELECT value FROM server_config WHERE key = 'logo_cid'")
            .fetch_optional(&state.db)
            .await
        {
            Ok(cid) => cid,
            Err(e) => {
                error!("DB error fetching logo_cid: {:?}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let cid = match logo_cid {
        Some(c) if !c.is_empty() => c,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };

    let blob = match sqlx::query!(
        "SELECT storage_key, mime_type FROM blobs WHERE cid = $1",
        cid
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!("DB error fetching blob: {:?}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match state.blob_store.get(&blob.storage_key).await {
        Ok(data) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, &blob.mime_type)
            .header(header::CACHE_CONTROL, "public, max-age=3600")
            .body(Body::from(data))
            .unwrap(),
        Err(e) => {
            error!("Failed to fetch logo from storage: {:?}", e);
            StatusCode::NOT_FOUND.into_response()
        }
    }
}
