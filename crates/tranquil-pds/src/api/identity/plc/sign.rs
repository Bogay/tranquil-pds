use crate::api::ApiError;
use crate::auth::BearerAuthAllowDeactivated;
use crate::circuit_breaker::with_circuit_breaker;
use crate::plc::{PlcClient, PlcError, PlcService, create_update_op, sign_operation};
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
use serde_json::Value;
use std::collections::HashMap;
use tracing::{error, info};

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
    auth: BearerAuthAllowDeactivated,
    Json(input): Json<SignPlcOperationInput>,
) -> Response {
    let auth_user = auth.0;
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
    let token = match &input.token {
        Some(t) => t,
        None => {
            return ApiError::InvalidRequest(
                "Email confirmation token required to sign PLC operations".into(),
            )
            .into_response();
        }
    };
    let user_id = match state.user_repo.get_id_by_did(did).await {
        Ok(Some(id)) => id,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let token_expiry = match state.infra_repo.get_plc_token_expiry(user_id, token).await {
        Ok(Some(expiry)) => expiry,
        Ok(None) => {
            return ApiError::InvalidToken(Some("Invalid or expired token".into())).into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    if Utc::now() > token_expiry {
        let _ = state.infra_repo.delete_plc_token(user_id, token).await;
        return ApiError::ExpiredToken(Some("Token has expired".into())).into_response();
    }
    let key_row = match state.user_repo.get_user_key_by_id(user_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ApiError::InternalError(Some("User signing key not found".into()))
                .into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
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
    let plc_client = PlcClient::with_cache(None, Some(state.cache.clone()));
    let did_clone = did.clone();
    let last_op = match with_circuit_breaker(&state.circuit_breakers.plc_directory, || async {
        plc_client.get_last_op(&did_clone).await
    })
    .await
    {
        Ok(op) => op,
        Err(e) => return ApiError::from(e).into_response(),
    };
    if last_op.is_tombstone() {
        return ApiError::from(PlcError::Tombstoned).into_response();
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
            return ApiError::InvalidRequest("Cannot update tombstoned DID".into()).into_response();
        }
        Err(e) => {
            error!("Failed to create PLC operation: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let signed_op = match sign_operation(&unsigned_op, &signing_key) {
        Ok(op) => op,
        Err(e) => {
            error!("Failed to sign PLC operation: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let _ = state.infra_repo.delete_plc_token(user_id, token).await;
    info!("Signed PLC operation for user {}", did);
    (
        StatusCode::OK,
        Json(SignPlcOperationOutput {
            operation: signed_op,
        }),
    )
        .into_response()
}
