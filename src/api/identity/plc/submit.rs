use crate::api::ApiError;
use crate::plc::{signing_key_to_did_key, validate_plc_operation, PlcClient};
use crate::state::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use k256::ecdsa::SigningKey;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{error, info, warn};

#[derive(Debug, Deserialize)]
pub struct SubmitPlcOperationInput {
    pub operation: Value,
}

pub async fn submit_plc_operation(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<SubmitPlcOperationInput>,
) -> Response {
    let bearer = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };

    let auth_user = match crate::auth::validate_bearer_token(&state.db, &bearer).await {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };

    let did = &auth_user.did;

    if let Err(e) = validate_plc_operation(&input.operation) {
        return ApiError::InvalidRequest(format!("Invalid operation: {}", e)).into_response();
    }

    let op = &input.operation;
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let public_url = format!("https://{}", hostname);

    let user = match sqlx::query!("SELECT id, handle FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(row)) => row,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound"})),
            )
                .into_response();
        }
    };

    let key_row = match sqlx::query!(
        "SELECT key_bytes, encryption_version FROM user_keys WHERE user_id = $1",
        user.id
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User signing key not found"})),
            )
                .into_response();
        }
    };

    let key_bytes = match crate::config::decrypt_key(&key_row.key_bytes, key_row.encryption_version)
    {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to decrypt user key: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let signing_key = match SigningKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to create signing key: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let user_did_key = signing_key_to_did_key(&signing_key);

    if let Some(rotation_keys) = op.get("rotationKeys").and_then(|v| v.as_array()) {
        let server_rotation_key =
            std::env::var("PLC_ROTATION_KEY").unwrap_or_else(|_| user_did_key.clone());

        let has_server_key = rotation_keys
            .iter()
            .any(|k| k.as_str() == Some(&server_rotation_key));

        if !has_server_key {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": "Rotation keys do not include server's rotation key"
                })),
            )
                .into_response();
        }
    }

    if let Some(services) = op.get("services").and_then(|v| v.as_object()) {
        if let Some(pds) = services.get("atproto_pds").and_then(|v| v.as_object()) {
            let service_type = pds.get("type").and_then(|v| v.as_str());
            let endpoint = pds.get("endpoint").and_then(|v| v.as_str());

            if service_type != Some("AtprotoPersonalDataServer") {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidRequest",
                        "message": "Incorrect type on atproto_pds service"
                    })),
                )
                    .into_response();
            }

            if endpoint != Some(&public_url) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidRequest",
                        "message": "Incorrect endpoint on atproto_pds service"
                    })),
                )
                    .into_response();
            }
        }
    }

    if let Some(verification_methods) = op.get("verificationMethods").and_then(|v| v.as_object()) {
        if let Some(atproto_key) = verification_methods.get("atproto").and_then(|v| v.as_str()) {
            if atproto_key != user_did_key {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidRequest",
                        "message": "Incorrect signing key in verificationMethods"
                    })),
                )
                    .into_response();
            }
        }
    }

    if let Some(also_known_as) = op.get("alsoKnownAs").and_then(|v| v.as_array()) {
        let expected_handle = format!("at://{}", user.handle);
        let first_aka = also_known_as.first().and_then(|v| v.as_str());

        if first_aka != Some(&expected_handle) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": "Incorrect handle in alsoKnownAs"
                })),
            )
                .into_response();
        }
    }

    let plc_client = PlcClient::new(None);
    if let Err(e) = plc_client.send_operation(did, &input.operation).await {
        error!("Failed to submit PLC operation: {:?}", e);
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": "UpstreamError",
                "message": format!("Failed to submit to PLC directory: {}", e)
            })),
        )
            .into_response();
    }

    if let Err(e) = sqlx::query!(
        "INSERT INTO repo_seq (did, event_type) VALUES ($1, 'identity')",
        did
    )
    .execute(&state.db)
    .await
    {
        warn!("Failed to sequence identity event: {:?}", e);
    }

    info!("Submitted PLC operation for user {}", did);

    (StatusCode::OK, Json(json!({}))).into_response()
}
