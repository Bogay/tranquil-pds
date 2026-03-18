pub mod api;
pub mod appview;
pub mod auth;
pub mod cache;
pub mod cache_keys;
pub mod cid_types;
pub mod circuit_breaker;
pub mod comms;
pub mod config;
pub mod crawlers;
pub mod delegation;
pub mod handle;
pub mod image;
pub mod metrics;
pub mod moderation;
pub mod oauth;
pub mod plc;
pub mod rate_limit;
pub mod repo;
pub mod repo_ops;
pub mod repo_write_lock;
pub mod scheduled;
pub mod sso;
pub mod state;
pub mod storage;
pub mod sync;
pub mod types;
pub mod util;
pub mod validation;

use api::proxy::XrpcProxyLayer;
use axum::{Json, Router, extract::DefaultBodyLimit, http::Method, middleware, routing::get};
use http::StatusCode;
use serde_json::json;
use state::AppState;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
};
pub use tranquil_db_traits::AccountStatus;
pub use types::{AccountState, AtIdentifier, AtUri, Did, Handle, Nsid, Rkey};

#[cfg(debug_assertions)]
pub const BUILD_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (built ",
    env!("BUILD_TIMESTAMP"),
    ")"
);
#[cfg(not(debug_assertions))]
pub const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct ExternalRoutes {
    pub xrpc: Router<AppState>,
    pub oauth: Router<AppState>,
    pub well_known: Router<AppState>,
    pub extra: Router<AppState>,
}

impl Default for ExternalRoutes {
    fn default() -> Self {
        Self {
            xrpc: Router::new(),
            oauth: Router::new(),
            well_known: Router::new(),
            extra: Router::new(),
        }
    }
}

pub fn app(state: AppState) -> Router {
    app_with_routes(state, ExternalRoutes::default())
}

pub fn app_with_routes(state: AppState, external: ExternalRoutes) -> Router {
    let xrpc_router = external.xrpc
        .fallback(async || (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({"error": "MethodNotImplemented", "message": "Method not implemented. For app.bsky.* methods, include an atproto-proxy header specifying your AppView."})),
        ));
    let xrpc_service = ServiceBuilder::new()
        .layer(XrpcProxyLayer::new(state.clone()))
        .service(
            xrpc_router
                .layer(middleware::from_fn(oauth::verify::dpop_nonce_middleware))
                .with_state(state.clone()),
        );

    let oauth_router = external.oauth;

    let well_known_router = external.well_known;

    let router = Router::new()
        .nest_service("/xrpc", xrpc_service)
        .nest("/oauth", oauth_router)
        .nest("/.well-known", well_known_router)
        .route("/metrics", get(metrics::metrics_handler))
        .merge(external.extra)
        .layer(DefaultBodyLimit::max(
            tranquil_config::get().server.max_blob_size as usize,
        ))
        .layer(axum::middleware::map_response(rewrite_422_to_400))
        .layer(middleware::from_fn(metrics::metrics_middleware))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    http::header::AUTHORIZATION,
                    http::header::CONTENT_TYPE,
                    http::header::CONTENT_ENCODING,
                    http::header::ACCEPT_ENCODING,
                    util::HEADER_DPOP,
                    util::HEADER_ATPROTO_PROXY,
                    util::HEADER_ATPROTO_ACCEPT_LABELERS,
                    util::HEADER_X_BSKY_TOPICS,
                ])
                .expose_headers([
                    http::header::WWW_AUTHENTICATE,
                    util::HEADER_DPOP_NONCE,
                    util::HEADER_ATPROTO_REPO_REV,
                    util::HEADER_ATPROTO_CONTENT_LABELERS,
                ]),
        )
        .with_state(state);

    if cfg!(feature = "frontend") && tranquil_config::get().frontend.enabled {
        let frontend_dir = &tranquil_config::get().frontend.dir;
        let index_path = format!("{}/index.html", frontend_dir);
        let homepage_path = format!("{}/homepage.html", frontend_dir);

        let homepage_exists = std::path::Path::new(&homepage_path).exists();
        let homepage_file = if homepage_exists {
            homepage_path
        } else {
            index_path.clone()
        };

        let spa_router = Router::new().fallback_service(ServeFile::new(&index_path));

        let serve_dir = ServeDir::new(frontend_dir).not_found_service(ServeFile::new(&index_path));

        return router
            .route_service("/", ServeFile::new(&homepage_file))
            .nest("/app", spa_router)
            .fallback_service(serve_dir);
    }

    router
}

async fn rewrite_422_to_400(response: axum::response::Response) -> axum::response::Response {
    if response.status() != StatusCode::UNPROCESSABLE_ENTITY {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            parts.status = StatusCode::BAD_REQUEST;
            parts.headers.remove(http::header::CONTENT_LENGTH);
            let fallback = json!({"error": "InvalidRequest", "message": "Invalid request body"});
            return axum::response::Response::from_parts(
                parts,
                axum::body::Body::from(serde_json::to_vec(&fallback).unwrap_or_default()),
            );
        }
    };
    let raw = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_else(|| {
            String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| "Invalid request body".into())
        });
    let message = humanize_json_error(&raw);

    parts.status = StatusCode::BAD_REQUEST;
    parts.headers.remove(http::header::CONTENT_LENGTH);
    let error_name = classify_deserialization_error(&raw);
    let new_body = json!({
        "error": error_name,
        "message": message
    });
    axum::response::Response::from_parts(
        parts,
        axum::body::Body::from(serde_json::to_vec(&new_body).unwrap_or_default()),
    )
}

fn humanize_json_error(raw: &str) -> String {
    if raw.contains("missing field") {
        raw.split("missing field `")
            .nth(1)
            .and_then(|s| s.split('`').next())
            .map(|field| format!("Missing required field: {}", field))
            .unwrap_or_else(|| raw.to_string())
    } else if raw.contains("invalid type") {
        format!("Invalid field type: {}", raw)
    } else if raw.contains("Invalid JSON") || raw.contains("syntax") {
        "Invalid JSON syntax".to_string()
    } else if raw.contains("Content-Type") || raw.contains("content type") {
        "Content-Type must be application/json".to_string()
    } else {
        raw.to_string()
    }
}

fn classify_deserialization_error(raw: &str) -> &'static str {
    match raw {
        s if s.contains("invalid handle") => "InvalidHandle",
        _ => "InvalidRequest",
    }
}
