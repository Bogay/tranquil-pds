use crate::api::{ApiError, EmptyResponse};
use crate::circuit_breaker::with_circuit_breaker;
use crate::plc::{PlcClient, signing_key_to_did_key, validate_plc_operation};
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use k256::ecdsa::SigningKey;
use serde::Deserialize;
use serde_json::Value;
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
        None => {
            return ApiError::AuthenticationRequired.into_response();
        }
    };
    let auth_user =
        match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &bearer).await {
            Ok(user) => user,
            Err(e) => {
                return ApiError::from(e).into_response();
            }
        };
    if let Err(e) = crate::auth::scope_check::check_identity_scope(
        auth_user.is_oauth,
        auth_user.scope.as_deref(),
        crate::oauth::scopes::IdentityAttr::Wildcard,
    ) {
        return e;
    }
    let did = &auth_user.did;
    if did.starts_with("did:web:") {
        return ApiError::InvalidRequest(
            "PLC operations are only valid for did:plc identities".into(),
        )
        .into_response();
    }
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
            return ApiError::AccountNotFound.into_response();
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
            return ApiError::InternalError(Some("User signing key not found".into())).into_response();
        }
    };
    let key_bytes = match crate::config::decrypt_key(&key_row.key_bytes, key_row.encryption_version)
    {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to decrypt user key: {}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let signing_key = match SigningKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to create signing key: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let user_did_key = signing_key_to_did_key(&signing_key);
    let server_rotation_key =
        std::env::var("PLC_ROTATION_KEY").unwrap_or_else(|_| user_did_key.clone());
    if let Some(rotation_keys) = op.get("rotationKeys").and_then(|v| v.as_array()) {
        let has_server_key = rotation_keys
            .iter()
            .any(|k| k.as_str() == Some(&server_rotation_key));
        if !has_server_key {
            return ApiError::InvalidRequest(
                "Rotation keys do not include server's rotation key".into(),
            )
            .into_response();
        }
    }
    if let Some(services) = op.get("services").and_then(|v| v.as_object())
        && let Some(pds) = services.get("atproto_pds").and_then(|v| v.as_object())
    {
        let service_type = pds.get("type").and_then(|v| v.as_str());
        let endpoint = pds.get("endpoint").and_then(|v| v.as_str());
        if service_type != Some("AtprotoPersonalDataServer") {
            return ApiError::InvalidRequest("Incorrect type on atproto_pds service".into())
                .into_response();
        }
        if endpoint != Some(&public_url) {
            return ApiError::InvalidRequest("Incorrect endpoint on atproto_pds service".into())
                .into_response();
        }
    }
    if let Some(verification_methods) = op.get("verificationMethods").and_then(|v| v.as_object())
        && let Some(atproto_key) = verification_methods.get("atproto").and_then(|v| v.as_str())
        && atproto_key != user_did_key
    {
        return ApiError::InvalidRequest("Incorrect signing key in verificationMethods".into())
            .into_response();
    }
    if let Some(also_known_as) = (!user.handle.is_empty())
        .then(|| op.get("alsoKnownAs").and_then(|v| v.as_array()))
        .flatten()
    {
        let expected_handle = format!("at://{}", user.handle);
        let first_aka = also_known_as.first().and_then(|v| v.as_str());
        if first_aka != Some(&expected_handle) {
            return ApiError::InvalidRequest("Incorrect handle in alsoKnownAs".into())
                .into_response();
        }
    }
    let plc_client = PlcClient::with_cache(None, Some(state.cache.clone()));
    let operation_clone = input.operation.clone();
    let did_clone = did.clone();
    if let Err(e) = with_circuit_breaker(&state.circuit_breakers.plc_directory, || async {
        plc_client
            .send_operation(&did_clone, &operation_clone)
            .await
    })
    .await
    {
        return ApiError::from(e).into_response();
    }
    match sqlx::query!(
        "INSERT INTO repo_seq (did, event_type, handle) VALUES ($1, 'identity', $2) RETURNING seq",
        did,
        user.handle
    )
    .fetch_one(&state.db)
    .await
    {
        Ok(row) => {
            if let Err(e) = sqlx::query(&format!("NOTIFY repo_updates, '{}'", row.seq))
                .execute(&state.db)
                .await
            {
                warn!("Failed to notify identity event: {:?}", e);
            }
        }
        Err(e) => {
            warn!("Failed to sequence identity event: {:?}", e);
        }
    }
    let _ = state.cache.delete(&format!("handle:{}", user.handle)).await;
    if state.did_resolver.refresh_did(did).await.is_none() {
        warn!(did = %did, "Failed to refresh DID cache after PLC update");
    }
    info!(did = %did, "PLC operation submitted successfully");
    EmptyResponse::ok().into_response()
}
