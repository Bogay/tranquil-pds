use crate::api::ApiError;
use crate::circuit_breaker::{CircuitBreakerError, with_circuit_breaker};
use crate::plc::{
    PlcClient, PlcError, PlcOpOrTombstone, PlcService, create_update_op, sign_operation,
};
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use tracing::{error, info, warn};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignPlcOperationInput {
    pub token: Option<String>,
    pub rotation_keys: Option<Vec<String>>,
    pub also_known_as: Option<Vec<String>>,
    pub verification_methods: Option<HashMap<String, String>>,
    pub services: Option<HashMap<String, ServiceInput>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceInput {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

#[derive(Debug, Serialize)]
pub struct SignPlcOperationOutput {
    pub operation: Value,
}

pub async fn sign_plc_operation(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<SignPlcOperationInput>,
) -> Response {
    let bearer = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let auth_user =
        match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &bearer).await {
            Ok(user) => user,
            Err(e) => return ApiError::from(e).into_response(),
        };
    if let Err(e) = crate::auth::scope_check::check_identity_scope(
        auth_user.is_oauth,
        auth_user.scope.as_deref(),
        crate::oauth::scopes::IdentityAttr::Wildcard,
    ) {
        return e;
    }
    let did = &auth_user.did;
    let token = match &input.token {
        Some(t) => t,
        None => {
            return ApiError::InvalidRequest(
                "Email confirmation token required to sign PLC operations".into(),
            )
            .into_response();
        }
    };
    let user = match sqlx::query!("SELECT id FROM users WHERE did = $1", did)
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
    let token_row = match sqlx::query!(
        "SELECT id, expires_at FROM plc_operation_tokens WHERE user_id = $1 AND token = $2",
        user.id,
        token
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidToken",
                    "message": "Invalid or expired token"
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if Utc::now() > token_row.expires_at {
        let _ = sqlx::query!(
            "DELETE FROM plc_operation_tokens WHERE id = $1",
            token_row.id
        )
        .execute(&state.db)
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "ExpiredToken",
                "message": "Token has expired"
            })),
        )
            .into_response();
    }
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
    let plc_client = PlcClient::new(None);
    let did_clone = did.clone();
    let result: Result<PlcOpOrTombstone, CircuitBreakerError<PlcError>> =
        with_circuit_breaker(&state.circuit_breakers.plc_directory, || async {
            plc_client.get_last_op(&did_clone).await
        })
        .await;
    let last_op = match result {
        Ok(op) => op,
        Err(CircuitBreakerError::CircuitOpen(e)) => {
            warn!("PLC directory circuit breaker open: {}", e);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "ServiceUnavailable",
                    "message": "PLC directory service temporarily unavailable"
                })),
            )
                .into_response();
        }
        Err(CircuitBreakerError::OperationFailed(PlcError::NotFound)) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "NotFound",
                    "message": "DID not found in PLC directory"
                })),
            )
                .into_response();
        }
        Err(CircuitBreakerError::OperationFailed(e)) => {
            error!("Failed to fetch PLC operation: {:?}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": "UpstreamError",
                    "message": "Failed to communicate with PLC directory"
                })),
            )
                .into_response();
        }
    };
    if last_op.is_tombstone() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": "DID is tombstoned"
            })),
        )
            .into_response();
    }
    let services = input.services.map(|s| {
        s.into_iter()
            .map(|(k, v)| {
                (
                    k,
                    PlcService {
                        service_type: v.service_type,
                        endpoint: v.endpoint,
                    },
                )
            })
            .collect()
    });
    let unsigned_op = match create_update_op(
        &last_op,
        input.rotation_keys,
        input.verification_methods,
        input.also_known_as,
        services,
    ) {
        Ok(op) => op,
        Err(PlcError::Tombstoned) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": "Cannot update tombstoned DID"
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to create PLC operation: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let signed_op = match sign_operation(&unsigned_op, &signing_key) {
        Ok(op) => op,
        Err(e) => {
            error!("Failed to sign PLC operation: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let _ = sqlx::query!(
        "DELETE FROM plc_operation_tokens WHERE id = $1",
        token_row.id
    )
    .execute(&state.db)
    .await;
    info!("Signed PLC operation for user {}", did);
    (
        StatusCode::OK,
        Json(SignPlcOperationOutput {
            operation: signed_op,
        }),
    )
        .into_response()
}
