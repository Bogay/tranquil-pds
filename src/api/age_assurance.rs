use crate::auth::{extract_bearer_token_from_header, validate_bearer_token};
use crate::state::AppState;
use axum::{
    Json,
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

pub async fn get_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if std::env::var("PDS_AGE_ASSURANCE_OVERRIDE").is_err() {
        return proxy_to_appview(state, headers, "app.bsky.ageassurance.getState", query).await;
    }

    let created_at = get_account_created_at(&state, &headers).await;
    let now = chrono::Utc::now().to_rfc3339();

    (
        StatusCode::OK,
        Json(json!({
            "state": {
                "status": "assured",
                "access": "full",
                "lastInitiatedAt": now
            },
            "metadata": {
                "accountCreatedAt": created_at
            }
        })),
    )
        .into_response()
}

pub async fn get_age_assurance_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if std::env::var("PDS_AGE_ASSURANCE_OVERRIDE").is_err() {
        return proxy_to_appview(
            state,
            headers,
            "app.bsky.unspecced.getAgeAssuranceState",
            query,
        )
        .await;
    }

    (StatusCode::OK, Json(json!({"status": "assured"}))).into_response()
}

async fn get_account_created_at(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
    tracing::debug!(?auth_header, "age assurance: extracting token");

    let token = extract_bearer_token_from_header(auth_header)?;
    tracing::debug!("age assurance: got token, validating");

    let auth_user = match validate_bearer_token(&state.db, &token).await {
        Ok(user) => {
            tracing::debug!(did = %user.did, "age assurance: validated user");
            user
        }
        Err(e) => {
            tracing::warn!(?e, "age assurance: token validation failed");
            return None;
        }
    };

    let row = match sqlx::query!("SELECT created_at FROM users WHERE did = $1", auth_user.did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(r) => {
            tracing::debug!(?r, "age assurance: query result");
            r
        }
        Err(e) => {
            tracing::warn!(?e, "age assurance: query failed");
            return None;
        }
    };

    row.map(|r| r.created_at.to_rfc3339())
}

async fn proxy_to_appview(
    state: AppState,
    headers: HeaderMap,
    method: &str,
    query: Option<String>,
) -> Response {
    if headers.get("atproto-proxy").is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": "Missing required atproto-proxy header"
            })),
        )
            .into_response();
    }

    crate::api::proxy::proxy_handler(
        State(state),
        Path(method.to_string()),
        Method::GET,
        headers,
        RawQuery(query),
        Bytes::new(),
    )
    .await
}
