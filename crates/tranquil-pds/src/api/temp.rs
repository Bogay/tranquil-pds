use crate::api::error::ApiError;
use crate::auth::{Active, Auth, Permissive};
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use cid::Cid;
use jacquard_repo::storage::BlockStore;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSignupQueueOutput {
    pub activated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place_in_queue: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_time_ms: Option<i64>,
}

pub async fn check_signup_queue(auth: Option<Auth<Permissive>>) -> Response {
    if let Some(ref user) = auth
        && user.is_oauth()
    {
        return ApiError::Forbidden.into_response();
    }
    Json(CheckSignupQueueOutput {
        activated: true,
        place_in_queue: None,
        estimated_time_ms: None,
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DereferenceScopeInput {
    pub scope: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DereferenceScopeOutput {
    pub scope: String,
}

pub async fn dereference_scope(
    State(state): State<AppState>,
    _auth: Auth<Active>,
    Json(input): Json<DereferenceScopeInput>,
) -> Result<Response, ApiError> {
    let scope_parts: Vec<&str> = input.scope.split_whitespace().collect();
    let mut resolved_scopes: Vec<String> = Vec::new();

    for part in scope_parts {
        if let Some(cid_str) = part.strip_prefix("ref:") {
            let cache_key = crate::cache_keys::scope_ref_key(cid_str);
            if let Some(cached) = state.cache.get(&cache_key).await {
                for s in cached.split_whitespace() {
                    if !resolved_scopes.contains(&s.to_string()) {
                        resolved_scopes.push(s.to_string());
                    }
                }
                continue;
            }

            let cid = match Cid::from_str(cid_str) {
                Ok(c) => c,
                Err(_) => {
                    tracing::warn!("Invalid CID in scope ref: {}", cid_str);
                    continue;
                }
            };

            let block_bytes = match state.block_store.get(&cid).await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    tracing::warn!("Scope ref block not found: {}", cid_str);
                    continue;
                }
                Err(e) => {
                    tracing::warn!("Error fetching scope ref block {}: {:?}", cid_str, e);
                    continue;
                }
            };

            let scope_record: serde_json::Value = match serde_ipld_dagcbor::from_slice(&block_bytes)
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("Failed to decode scope ref block {}: {:?}", cid_str, e);
                    continue;
                }
            };

            if let Some(scope_value) = scope_record.get("scope").and_then(|v| v.as_str()) {
                let _ = state
                    .cache
                    .set(
                        &cache_key,
                        scope_value,
                        std::time::Duration::from_secs(3600),
                    )
                    .await;
                for s in scope_value.split_whitespace() {
                    if !resolved_scopes.contains(&s.to_string()) {
                        resolved_scopes.push(s.to_string());
                    }
                }
            }
        } else if !resolved_scopes.contains(&part.to_string()) {
            resolved_scopes.push(part.to_string());
        }
    }

    Ok(Json(DereferenceScopeOutput {
        scope: resolved_scopes.join(" "),
    })
    .into_response())
}
