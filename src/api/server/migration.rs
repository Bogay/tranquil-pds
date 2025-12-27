use crate::api::ApiError;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetMigrationStatusOutput {
    pub did: String,
    pub did_type: String,
    pub migrated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrated_to_pds: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrated_at: Option<DateTime<Utc>>,
}

pub async fn get_migration_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let extracted = match crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    let http_uri = format!(
        "https://{}/xrpc/com.tranquil.account.getMigrationStatus",
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
    );
    let auth_user = match crate::auth::validate_token_with_dpop(
        &state.db,
        &extracted.token,
        extracted.is_dpop,
        dpop_proof,
        "GET",
        &http_uri,
        true,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let user = match sqlx::query!(
        "SELECT did, migrated_to_pds, migrated_at FROM users WHERE did = $1",
        auth_user.did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            tracing::error!("DB error getting migration status: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    let did_type = if user.did.starts_with("did:plc:") {
        "plc"
    } else if user.did.starts_with("did:web:") {
        "web"
    } else {
        "unknown"
    };
    let migrated = user.migrated_to_pds.is_some();
    (
        StatusCode::OK,
        Json(GetMigrationStatusOutput {
            did: user.did,
            did_type: did_type.to_string(),
            migrated,
            migrated_to_pds: user.migrated_to_pds,
            migrated_at: user.migrated_at,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMigrationForwardingInput {
    pub pds_url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMigrationForwardingOutput {
    pub success: bool,
    pub migrated_to_pds: String,
    pub migrated_at: DateTime<Utc>,
}

pub async fn update_migration_forwarding(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateMigrationForwardingInput>,
) -> Response {
    let extracted = match crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    let http_uri = format!(
        "https://{}/xrpc/com.tranquil.account.updateMigrationForwarding",
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
    );
    let auth_user = match crate::auth::validate_token_with_dpop(
        &state.db,
        &extracted.token,
        extracted.is_dpop,
        dpop_proof,
        "POST",
        &http_uri,
        true,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };
    if !auth_user.did.starts_with("did:web:") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": "Migration forwarding is only available for did:web accounts. did:plc accounts use PLC directory for identity updates."
            })),
        )
            .into_response();
    }
    let pds_url = input.pds_url.trim();
    if pds_url.is_empty() {
        return ApiError::InvalidRequest("pds_url is required".into()).into_response();
    }
    if !pds_url.starts_with("https://") {
        return ApiError::InvalidRequest("pds_url must start with https://".into()).into_response();
    }
    let pds_url_clean = pds_url.trim_end_matches('/');
    let now = Utc::now();
    let result = sqlx::query!(
        "UPDATE users SET migrated_to_pds = $1, migrated_at = $2 WHERE did = $3",
        pds_url_clean,
        now,
        auth_user.did
    )
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => {
            tracing::info!(
                "Updated migration forwarding for {} to {}",
                auth_user.did,
                pds_url_clean
            );
            (
                StatusCode::OK,
                Json(UpdateMigrationForwardingOutput {
                    success: true,
                    migrated_to_pds: pds_url_clean.to_string(),
                    migrated_at: now,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("DB error updating migration forwarding: {:?}", e);
            ApiError::InternalError.into_response()
        }
    }
}

pub async fn clear_migration_forwarding(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let extracted = match crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    let http_uri = format!(
        "https://{}/xrpc/com.tranquil.account.clearMigrationForwarding",
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
    );
    let auth_user = match crate::auth::validate_token_with_dpop(
        &state.db,
        &extracted.token,
        extracted.is_dpop,
        dpop_proof,
        "POST",
        &http_uri,
        true,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };
    if !auth_user.did.starts_with("did:web:") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": "Migration forwarding is only available for did:web accounts"
            })),
        )
            .into_response();
    }
    let result = sqlx::query!(
        "UPDATE users SET migrated_to_pds = NULL, migrated_at = NULL WHERE did = $1",
        auth_user.did
    )
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => {
            tracing::info!("Cleared migration forwarding for {}", auth_user.did);
            (StatusCode::OK, Json(json!({ "success": true }))).into_response()
        }
        Err(e) => {
            tracing::error!("DB error clearing migration forwarding: {:?}", e);
            ApiError::InternalError.into_response()
        }
    }
}
