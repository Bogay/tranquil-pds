use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use jacquard_repo::storage::BlockStore;
use crate::api::proxy_client::proxy_client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::{error, info};

#[derive(Deserialize)]
pub struct GetProfileParams {
    pub actor: String,
}

#[derive(Deserialize)]
pub struct GetProfilesParams {
    pub actors: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProfileViewDetailed {
    pub did: String,
    pub handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize)]
pub struct GetProfilesOutput {
    pub profiles: Vec<ProfileViewDetailed>,
}

async fn get_local_profile_record(state: &AppState, did: &str) -> Option<Value> {
    let user_id: uuid::Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
        .ok()??;
    let record_row = sqlx::query!(
        "SELECT record_cid FROM records WHERE repo_id = $1 AND collection = 'app.bsky.actor.profile' AND rkey = 'self'",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .ok()??;
    let cid: cid::Cid = record_row.record_cid.parse().ok()?;
    let block_bytes = state.block_store.get(&cid).await.ok()??;
    serde_ipld_dagcbor::from_slice(&block_bytes).ok()
}

fn munge_profile_with_local(profile: &mut ProfileViewDetailed, local_record: &Value) {
    if let Some(display_name) = local_record.get("displayName").and_then(|v| v.as_str()) {
        profile.display_name = Some(display_name.to_string());
    }
    if let Some(description) = local_record.get("description").and_then(|v| v.as_str()) {
        profile.description = Some(description.to_string());
    }
}

async fn proxy_to_appview(
    method: &str,
    params: &HashMap<String, String>,
    auth_did: &str,
    auth_key_bytes: Option<&[u8]>,
) -> Result<(StatusCode, Value), Response> {
    let appview_url = match std::env::var("APPVIEW_URL") {
        Ok(url) => url,
        Err(_) => {
            return Err(
                (StatusCode::BAD_GATEWAY, Json(json!({"error": "UpstreamError", "message": "No upstream AppView configured"}))).into_response()
            );
        }
    };
    let target_url = format!("{}/xrpc/{}", appview_url, method);
    info!("Proxying GET request to {}", target_url);
    let client = proxy_client();
    let mut request_builder = client.get(&target_url).query(params);
    if let Some(key_bytes) = auth_key_bytes {
        let appview_did = std::env::var("APPVIEW_DID").unwrap_or_else(|_| "did:web:api.bsky.app".to_string());
        match crate::auth::create_service_token(auth_did, &appview_did, method, key_bytes) {
            Ok(service_token) => {
                request_builder = request_builder.header("Authorization", format!("Bearer {}", service_token));
            }
            Err(e) => {
                error!("Failed to create service token: {:?}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response());
            }
        }
    }
    match request_builder.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            match resp.json::<Value>().await {
                Ok(body) => Ok((status, body)),
                Err(e) => {
                    error!("Error parsing proxy response: {:?}", e);
                    Err((StatusCode::BAD_GATEWAY, Json(json!({"error": "UpstreamError"}))).into_response())
                }
            }
        }
        Err(e) => {
            error!("Error sending proxy request: {:?}", e);
            if e.is_timeout() {
                Err((StatusCode::GATEWAY_TIMEOUT, Json(json!({"error": "UpstreamTimeout"}))).into_response())
            } else {
                Err((StatusCode::BAD_GATEWAY, Json(json!({"error": "UpstreamError"}))).into_response())
            }
        }
    }
}

pub async fn get_profile(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetProfileParams>,
) -> Response {
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
    let auth_user = if let Some(h) = auth_header {
        if let Some(token) = crate::auth::extract_bearer_token_from_header(Some(h)) {
            crate::auth::validate_bearer_token(&state.db, &token).await.ok()
        } else {
            None
        }
    } else {
        None
    };
    let auth_did = auth_user.as_ref().map(|u| u.did.clone());
    let auth_key_bytes = auth_user.as_ref().and_then(|u| u.key_bytes.clone());
    let mut query_params = HashMap::new();
    query_params.insert("actor".to_string(), params.actor.clone());
    let (status, body) = match proxy_to_appview("app.bsky.actor.getProfile", &query_params, auth_did.as_deref().unwrap_or(""), auth_key_bytes.as_deref()).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    if !status.is_success() {
        return (status, Json(body)).into_response();
    }
    let mut profile: ProfileViewDetailed = match serde_json::from_value(body) {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": "UpstreamError", "message": "Invalid profile response"}))).into_response();
        }
    };
    if let Some(ref did) = auth_did {
        if profile.did == *did {
            if let Some(local_record) = get_local_profile_record(&state, did).await {
                munge_profile_with_local(&mut profile, &local_record);
            }
        }
    }
    (StatusCode::OK, Json(profile)).into_response()
}

pub async fn get_profiles(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetProfilesParams>,
) -> Response {
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
    let auth_user = if let Some(h) = auth_header {
        if let Some(token) = crate::auth::extract_bearer_token_from_header(Some(h)) {
            crate::auth::validate_bearer_token(&state.db, &token).await.ok()
        } else {
            None
        }
    } else {
        None
    };
    let auth_did = auth_user.as_ref().map(|u| u.did.clone());
    let auth_key_bytes = auth_user.as_ref().and_then(|u| u.key_bytes.clone());
    let mut query_params = HashMap::new();
    query_params.insert("actors".to_string(), params.actors.clone());
    let (status, body) = match proxy_to_appview("app.bsky.actor.getProfiles", &query_params, auth_did.as_deref().unwrap_or(""), auth_key_bytes.as_deref()).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    if !status.is_success() {
        return (status, Json(body)).into_response();
    }
    let mut output: GetProfilesOutput = match serde_json::from_value(body) {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": "UpstreamError", "message": "Invalid profiles response"}))).into_response();
        }
    };
    if let Some(ref did) = auth_did {
        for profile in &mut output.profiles {
            if profile.did == *did {
                if let Some(local_record) = get_local_profile_record(&state, did).await {
                    munge_profile_with_local(profile, &local_record);
                }
                break;
            }
        }
    }
    (StatusCode::OK, Json(output)).into_response()
}
