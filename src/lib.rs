pub mod api;
pub mod auth;
pub mod repo;
pub mod state;
pub mod storage;

use axum::{
    Router,
    routing::{any, get, post},
};
use state::AppState;

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(api::server::health))
        .route(
            "/xrpc/com.atproto.server.describeServer",
            get(api::server::describe_server),
        )
        .route(
            "/xrpc/com.atproto.server.createAccount",
            post(api::identity::create_account),
        )
        .route(
            "/xrpc/com.atproto.server.createSession",
            post(api::server::create_session),
        )
        .route(
            "/xrpc/com.atproto.server.getSession",
            get(api::server::get_session),
        )
        .route(
            "/xrpc/com.atproto.server.deleteSession",
            post(api::server::delete_session),
        )
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(api::server::refresh_session),
        )
        .route(
            "/xrpc/com.atproto.repo.createRecord",
            post(api::repo::create_record),
        )
        .route(
            "/xrpc/com.atproto.repo.putRecord",
            post(api::repo::put_record),
        )
        .route(
            "/xrpc/com.atproto.repo.getRecord",
            get(api::repo::get_record),
        )
        .route(
            "/xrpc/com.atproto.repo.deleteRecord",
            post(api::repo::delete_record),
        )
        .route(
            "/xrpc/com.atproto.repo.listRecords",
            get(api::repo::list_records),
        )
        .route(
            "/xrpc/com.atproto.repo.describeRepo",
            get(api::repo::describe_repo),
        )
        .route(
            "/xrpc/com.atproto.repo.uploadBlob",
            post(api::repo::upload_blob),
        )
        .route(
            "/xrpc/app.bsky.feed.getTimeline",
            get(api::feed::get_timeline),
        )
        .route("/.well-known/did.json", get(api::identity::well_known_did))
        .route("/u/{handle}/did.json", get(api::identity::user_did_doc))
        .route("/xrpc/{*method}", any(api::proxy::proxy_handler))
        .with_state(state)
}
