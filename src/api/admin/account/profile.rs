use crate::api::repo::record::create_record_internal;
use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProfileInput {
    pub did: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRecordAdminInput {
    pub did: String,
    pub collection: String,
    pub rkey: Option<String>,
    pub record: serde_json::Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProfileOutput {
    pub uri: String,
    pub cid: String,
}

pub async fn create_profile(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    Json(input): Json<CreateProfileInput>,
) -> Response {
    let did = input.did.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }

    let mut profile_record = json!({
        "$type": "app.bsky.actor.profile"
    });

    if let Some(display_name) = &input.display_name {
        profile_record["displayName"] = json!(display_name);
    }
    if let Some(description) = &input.description {
        profile_record["description"] = json!(description);
    }

    match create_record_internal(
        &state,
        did,
        "app.bsky.actor.profile",
        "self",
        &profile_record,
    )
    .await
    {
        Ok((uri, commit_cid)) => {
            info!(did = %did, uri = %uri, "Created profile for user");
            (
                StatusCode::OK,
                Json(CreateProfileOutput {
                    uri,
                    cid: commit_cid.to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to create profile for {}: {}", did, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": e})),
            )
                .into_response()
        }
    }
}

pub async fn create_record_admin(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    Json(input): Json<CreateRecordAdminInput>,
) -> Response {
    let did = input.did.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }

    let rkey = input
        .rkey
        .unwrap_or_else(|| chrono::Utc::now().format("%Y%m%d%H%M%S%f").to_string());

    match create_record_internal(&state, did, &input.collection, &rkey, &input.record).await {
        Ok((uri, commit_cid)) => {
            info!(did = %did, uri = %uri, "Admin created record");
            (
                StatusCode::OK,
                Json(CreateProfileOutput {
                    uri,
                    cid: commit_cid.to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to create record for {}: {}", did, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": e})),
            )
                .into_response()
        }
    }
}
