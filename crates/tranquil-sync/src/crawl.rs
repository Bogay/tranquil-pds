use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tracing::info;
use tranquil_pds::api::EmptyResponse;
use tranquil_pds::state::AppState;

#[derive(Deserialize)]
pub struct NotifyOfUpdateParams {
    pub hostname: String,
}

pub async fn notify_of_update(
    State(_state): State<AppState>,
    Query(params): Query<NotifyOfUpdateParams>,
) -> Response {
    info!("Received notifyOfUpdate from hostname: {}", params.hostname);
    EmptyResponse::ok().into_response()
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
    EmptyResponse::ok().into_response()
}
