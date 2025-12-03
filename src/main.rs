mod api;
mod state;
mod auth;
mod repo;

use axum::{
    extract::State,
    routing::{get, post},
    Router,
    Json,
    response::IntoResponse,
    http::StatusCode,
};
use serde_json::json;
use std::net::SocketAddr;
use state::AppState;
use tracing::{info, error};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let state = AppState::new(pool);

    let app = Router::new()
        .route("/health", get(health))
        .route("/xrpc/com.atproto.server.describeServer", get(describe_server))
        .route("/xrpc/com.atproto.server.createAccount", post(api::server::create_account))
        .route("/xrpc/com.atproto.server.createSession", post(api::server::create_session))
        .route("/xrpc/com.atproto.server.getSession", get(api::server::get_session))
        .route("/xrpc/com.atproto.server.deleteSession", post(api::server::delete_session))
        .route("/xrpc/com.atproto.server.refreshSession", post(api::server::refresh_session))
        .route("/xrpc/com.atproto.repo.createRecord", post(api::repo::create_record))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, "OK"),
        Err(e) => {
            error!("Health check failed: {:?}", e);
            (StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
        }
    }
}

async fn describe_server() -> impl IntoResponse {
    let domains_str = std::env::var("AVAILABLE_USER_DOMAINS").unwrap_or_else(|_| "example.com".to_string());
    let domains: Vec<&str> = domains_str.split(',').map(|s| s.trim()).collect();

    Json(json!({
        "availableUserDomains": domains
    }))
}
