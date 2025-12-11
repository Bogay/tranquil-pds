use crate::plc::{
    create_update_op, sign_operation, signing_key_to_did_key, validate_plc_operation,
    PlcClient, PlcError, PlcService,
};
use crate::state::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use k256::ecdsa::SigningKey;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::{error, info, warn};

fn generate_plc_token() -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz234567".chars().collect();
    let part1: String = (0..5).map(|_| chars[rng.gen_range(0..chars.len())]).collect();
    let part2: String = (0..5).map(|_| chars[rng.gen_range(0..chars.len())]).collect();
    format!("{}-{}", part1, part2)
}

pub async fn request_plc_operation_signature(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    let auth_user = match crate::auth::validate_bearer_token(&state.db, &token).await {
        Ok(user) => user,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed", "message": e})),
            )
                .into_response();
        }
    };

    let did = &auth_user.did;

    let user = match sqlx::query!(
        "SELECT id FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound"})),
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

    let _ = sqlx::query!(
        "DELETE FROM plc_operation_tokens WHERE user_id = $1 OR expires_at < NOW()",
        user.id
    )
    .execute(&state.db)
    .await;

    let plc_token = generate_plc_token();
    let expires_at = Utc::now() + Duration::minutes(10);

    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO plc_operation_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)
        "#,
        user.id,
        plc_token,
        expires_at
    )
    .execute(&state.db)
    .await
    {
        error!("Failed to create PLC token: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());

    if let Err(e) = crate::notifications::enqueue_plc_operation(
        &state.db,
        user.id,
        &plc_token,
        &hostname,
    )
    .await
    {
        warn!("Failed to enqueue PLC operation notification: {:?}", e);
    }

    info!("PLC operation signature requested for user {}", did);

    (StatusCode::OK, Json(json!({}))).into_response()
}

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
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    let auth_user = match crate::auth::validate_bearer_token(&state.db, &bearer).await {
        Ok(user) => user,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed", "message": e})),
            )
                .into_response();
        }
    };

    let did = &auth_user.did;

    let token = match &input.token {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": "Email confirmation token required to sign PLC operations"
                })),
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
        let _ = sqlx::query!("DELETE FROM plc_operation_tokens WHERE id = $1", token_row.id)
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
    let last_op = match plc_client.get_last_op(did).await {
        Ok(op) => op,
        Err(PlcError::NotFound) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "NotFound",
                    "message": "DID not found in PLC directory"
                })),
            )
                .into_response();
        }
        Err(e) => {
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

    let _ = sqlx::query!("DELETE FROM plc_operation_tokens WHERE id = $1", token_row.id)
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
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    let auth_user = match crate::auth::validate_bearer_token(&state.db, &bearer).await {
        Ok(user) => user,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed", "message": e})),
            )
                .into_response();
        }
    };

    let did = &auth_user.did;

    if let Err(e) = validate_plc_operation(&input.operation) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": format!("Invalid operation: {}", e)
            })),
        )
            .into_response();
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
