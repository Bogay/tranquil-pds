use crate::api::proxy_client::proxy_client;
use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info};

#[derive(Deserialize)]
pub struct DescribeRepoInput {
    pub repo: String,
}

async fn proxy_describe_repo_to_appview(state: &AppState, raw_query: Option<&str>) -> Response {
    let resolved = match state.appview_registry.get_appview_for_method("com.atproto.repo.describeRepo").await {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Repo not found"})),
            )
                .into_response();
        }
    };
    let target_url = match raw_query {
        Some(q) => format!("{}/xrpc/com.atproto.repo.describeRepo?{}", resolved.url, q),
        None => format!("{}/xrpc/com.atproto.repo.describeRepo", resolved.url),
    };
    info!("Proxying describeRepo to AppView: {}", target_url);
    let client = proxy_client();
    match client.get(&target_url).send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            match resp.bytes().await {
                Ok(body) => {
                    let mut builder = Response::builder().status(status);
                    if let Some(ct) = content_type {
                        builder = builder.header("content-type", ct);
                    }
                    builder
                        .body(axum::body::Body::from(body))
                        .unwrap_or_else(|_| {
                            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
                        })
                }
                Err(e) => {
                    error!("Error reading AppView response: {:?}", e);
                    (StatusCode::BAD_GATEWAY, Json(json!({"error": "UpstreamError"}))).into_response()
                }
            }
        }
        Err(e) => {
            error!("Error proxying to AppView: {:?}", e);
            (StatusCode::BAD_GATEWAY, Json(json!({"error": "UpstreamError"}))).into_response()
        }
    }
}

pub async fn describe_repo(
    State(state): State<AppState>,
    Query(input): Query<DescribeRepoInput>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let user_row = if input.repo.starts_with("did:") {
        sqlx::query!(
            "SELECT id, handle, did FROM users WHERE did = $1",
            input.repo
        )
        .fetch_optional(&state.db)
        .await
        .map(|opt| opt.map(|r| (r.id, r.handle, r.did)))
    } else {
        sqlx::query!(
            "SELECT id, handle, did FROM users WHERE handle = $1",
            input.repo
        )
        .fetch_optional(&state.db)
        .await
        .map(|opt| opt.map(|r| (r.id, r.handle, r.did)))
    };
    let (user_id, handle, did) = match user_row {
        Ok(Some((id, handle, did))) => (id, handle, did),
        _ => {
            return proxy_describe_repo_to_appview(&state, raw_query.as_deref()).await;
        }
    };
    let collections_query = sqlx::query!(
        "SELECT DISTINCT collection FROM records WHERE repo_id = $1",
        user_id
    )
    .fetch_all(&state.db)
    .await;
    let collections: Vec<String> = match collections_query {
        Ok(rows) => rows.iter().map(|r| r.collection.clone()).collect(),
        Err(_) => Vec::new(),
    };
    let did_doc = json!({
        "id": did,
        "alsoKnownAs": [format!("at://{}", handle)]
    });
    Json(json!({
        "handle": handle,
        "did": did,
        "didDoc": did_doc,
        "collections": collections,
        "handleIsCorrect": true
    }))
    .into_response()
}
