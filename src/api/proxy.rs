use axum::{
    extract::{Path, Query},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    body::Bytes,
};
use reqwest::Client;
use tracing::{info, error};
use std::collections::HashMap;

pub async fn proxy_handler(
    Path(method): Path<String>,
    method_verb: Method,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {

    let proxy_header = headers.get("atproto-proxy")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let appview_url = match proxy_header {
        Some(url) => url,
        None => match std::env::var("APPVIEW_URL") {
            Ok(url) => url,
            Err(_) => return (StatusCode::BAD_GATEWAY, "No upstream AppView configured").into_response(),
        },
    };

    let target_url = format!("{}/xrpc/{}", appview_url, method);

    info!("Proxying {} request to {}", method_verb, target_url);

    let client = Client::new();

    let mut request_builder = client
        .request(method_verb, &target_url)
        .query(&params);

    for (key, value) in headers.iter() {
        if key != "host" && key != "content-length" {
            request_builder = request_builder.header(key, value);
        }
    }

    request_builder = request_builder.body(body);

    match request_builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    error!("Error reading proxy response body: {:?}", e);
                    return (StatusCode::BAD_GATEWAY, "Error reading upstream response").into_response();
                }
            };

            let mut response_builder = Response::builder().status(status);

            for (key, value) in headers.iter() {
                response_builder = response_builder.header(key, value);
            }

            match response_builder.body(axum::body::Body::from(body)) {
                Ok(r) => r,
                Err(e) => {
                     error!("Error building proxy response: {:?}", e);
                     (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
                }
            }
        },
        Err(e) => {
            error!("Error sending proxy request: {:?}", e);
            if e.is_timeout() {
                (StatusCode::GATEWAY_TIMEOUT, "Upstream Timeout").into_response()
            } else {
                (StatusCode::BAD_GATEWAY, "Upstream Error").into_response()
            }
        }
    }
}
