use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use tracing::info;
#[derive(Deserialize)]
pub struct NotifyOfUpdateParams {
    pub hostname: String,
}
pub async fn notify_of_update(
    State(_state): State<AppState>,
    Query(params): Query<NotifyOfUpdateParams>,
) -> Response {
    info!("Received notifyOfUpdate from hostname: {}", params.hostname);
    (StatusCode::OK, Json(json!({}))).into_response()
}
#[derive(Deserialize)]
pub struct RequestCrawlInput {
    pub hostname: String,
}
pub async fn request_crawl(
    State(_state): State<AppState>,
    Json(input): Json<RequestCrawlInput>,
) -> Response {
    info!("Received requestCrawl for hostname: {}", input.hostname);
    (StatusCode::OK, Json(json!({}))).into_response()
}
