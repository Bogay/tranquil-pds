pub mod api;
pub mod state;
pub mod auth;
pub mod repo;

use axum::{
    routing::{get, post, any},
    Router,
};
use state::AppState;

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(api::server::health))
        .route("/xrpc/com.atproto.server.describeServer", get(api::server::describe_server))
        .route("/xrpc/com.atproto.server.createAccount", post(api::server::create_account))
        .route("/xrpc/com.atproto.server.createSession", post(api::server::create_session))
        .route("/xrpc/com.atproto.server.getSession", get(api::server::get_session))
        .route("/xrpc/com.atproto.server.deleteSession", post(api::server::delete_session))
        .route("/xrpc/com.atproto.server.refreshSession", post(api::server::refresh_session))
        .route("/xrpc/com.atproto.repo.createRecord", post(api::repo::create_record))
        .route("/xrpc/{*method}", any(api::proxy::proxy_handler))
        .with_state(state)
}
