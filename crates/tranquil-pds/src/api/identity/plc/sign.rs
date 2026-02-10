use crate::api::ApiError;
use crate::api::error::DbResultExt;
use crate::auth::{Auth, Permissive};
use crate::circuit_breaker::with_circuit_breaker;
use crate::plc::{PlcClient, PlcError, PlcService, ServiceType, create_update_op, sign_operation};
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
    pub service_type: ServiceType,
    pub endpoint: String,
}

#[derive(Debug, Serialize)]
pub struct SignPlcOperationOutput {
    pub operation: Value,
}

pub async fn sign_plc_operation(
    State(state): State<AppState>,
    auth: Auth<Permissive>,
    Json(input): Json<SignPlcOperationInput>,
) -> Result<Response, ApiError> {
    if let Err(e) = crate::auth::scope_check::check_identity_scope(
        &auth.auth_source,
        auth.scope.as_deref(),
        crate::oauth::scopes::IdentityAttr::Wildcard,
    ) {
        return Ok(e);
    }
    let did = &auth.did;
    if did.starts_with("did:web:") {
        return Err(ApiError::InvalidRequest(
            "PLC operations are only valid for did:plc identities".into(),
        ));
    }
    let token = input.token.as_ref().ok_or_else(|| {
        ApiError::InvalidRequest("Email confirmation token required to sign PLC operations".into())
    })?;

    let user_id = state
        .user_repo
        .get_id_by_did(did)
        .await
        .log_db_err("fetching user id")?
        .ok_or(ApiError::AccountNotFound)?;

    let token_expiry = state
        .infra_repo
        .get_plc_token_expiry(user_id, token)
        .await
        .log_db_err("fetching PLC token expiry")?
        .ok_or_else(|| ApiError::InvalidToken(Some("Invalid or expired token".into())))?;

    if Utc::now() > token_expiry {
        let _ = state.infra_repo.delete_plc_token(user_id, token).await;
        return Err(ApiError::ExpiredToken(Some("Token has expired".into())));
    }
    let key_row = state
        .user_repo
        .get_user_key_by_id(user_id)
        .await
        .log_db_err("fetching user key")?
        .ok_or_else(|| ApiError::InternalError(Some("User signing key not found".into())))?;

    let key_bytes = crate::config::decrypt_key(&key_row.key_bytes, key_row.encryption_version)
        .map_err(|e| {
            error!("Failed to decrypt user key: {}", e);
            ApiError::InternalError(None)
        })?;

    let signing_key = SigningKey::from_slice(&key_bytes).map_err(|e| {
        error!("Failed to create signing key: {:?}", e);
        ApiError::InternalError(None)
    })?;

    let plc_client = PlcClient::with_cache(None, Some(state.cache.clone()));
    let did_clone = did.clone();
    let last_op = with_circuit_breaker(&state.circuit_breakers.plc_directory, || async {
        plc_client.get_last_op(&did_clone).await
    })
    .await
    .map_err(ApiError::from)?;

    if last_op.is_tombstone() {
        return Err(ApiError::from(PlcError::Tombstoned));
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
    let unsigned_op = create_update_op(
        &last_op,
        input.rotation_keys,
        input.verification_methods,
        input.also_known_as,
        services,
    )
    .map_err(|e| match e {
        PlcError::Tombstoned => ApiError::InvalidRequest("Cannot update tombstoned DID".into()),
        _ => {
            error!("Failed to create PLC operation: {:?}", e);
            ApiError::InternalError(None)
        }
    })?;

    let signed_op = sign_operation(&unsigned_op, &signing_key).map_err(|e| {
        error!("Failed to sign PLC operation: {:?}", e);
        ApiError::InternalError(None)
    })?;

    let _ = state.infra_repo.delete_plc_token(user_id, token).await;
    info!("Signed PLC operation for user {}", did);
    Ok((
        StatusCode::OK,
        Json(SignPlcOperationOutput {
            operation: signed_op,
        }),
    )
        .into_response())
}
