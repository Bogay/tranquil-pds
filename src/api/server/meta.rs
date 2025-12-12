use crate::state::AppState;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;

use tracing::error;

pub async fn robots_txt() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain")],
        "# Hello!\n\n# Crawling the public API is allowed\nUser-agent: *\nAllow: /\n",
    )
}

pub async fn describe_server() -> impl IntoResponse {
    let domains_str =
        std::env::var("AVAILABLE_USER_DOMAINS").unwrap_or_else(|_| "example.com".to_string());
    let domains: Vec<&str> = domains_str.split(',').map(|s| s.trim()).collect();

    Json(json!({
        "availableUserDomains": domains
    }))
}

pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query!("SELECT 1 as one").fetch_one(&state.db).await {
        Ok(_) => (StatusCode::OK, "OK"),
        Err(e) => {
            error!("Health check failed: {:?}", e);
            (StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
        }
    }
}
