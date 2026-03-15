use tranquil_pds::api::error::DbResultExt;
use tranquil_pds::api::{ApiError, EmptyResponse};
use tranquil_pds::auth::{Auth, Permissive};
use tranquil_pds::circuit_breaker::with_circuit_breaker;
use tranquil_pds::plc::{PlcClient, signing_key_to_did_key, validate_plc_operation};
use tranquil_pds::state::AppState;
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
    auth: Auth<Permissive>,
    Json(input): Json<SubmitPlcOperationInput>,
) -> Result<Response, ApiError> {
    if let Err(e) = tranquil_pds::auth::scope_check::check_identity_scope(
        &auth.auth_source,
        auth.scope.as_deref(),
        tranquil_pds::oauth::scopes::IdentityAttr::Wildcard,
    ) {
        return Ok(e);
    }
    let did = &auth.did;
    if did.starts_with("did:web:") {
        return Err(ApiError::InvalidRequest(
            "PLC operations are only valid for did:plc identities".into(),
        ));
    }
    validate_plc_operation(&input.operation)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid operation: {}", e)))?;

    let op = &input.operation;
    let hostname = &tranquil_config::get().server.hostname;
    let public_url = format!("https://{}", hostname);
    let user = state
        .user_repo
        .get_id_and_handle_by_did(did)
        .await
        .log_db_err("fetching user")?
        .ok_or(ApiError::AccountNotFound)?;

    let key_row = state
        .user_repo
        .get_user_key_by_id(user.id)
        .await
        .log_db_err("fetching user key")?
        .ok_or_else(|| ApiError::InternalError(Some("User signing key not found".into())))?;

    let key_bytes = tranquil_pds::config::decrypt_key(&key_row.key_bytes, key_row.encryption_version)
        .map_err(|e| {
            error!("Failed to decrypt user key: {}", e);
            ApiError::InternalError(None)
        })?;

    let signing_key = SigningKey::from_slice(&key_bytes).map_err(|e| {
        error!("Failed to create signing key: {:?}", e);
        ApiError::InternalError(None)
    })?;

    let user_did_key = signing_key_to_did_key(&signing_key);
    let server_rotation_key = tranquil_config::get()
        .secrets
        .plc_rotation_key
        .clone()
        .unwrap_or_else(|| user_did_key.clone());
    if let Some(rotation_keys) = op.get("rotationKeys").and_then(|v| v.as_array()) {
        let has_server_key = rotation_keys
            .iter()
            .any(|k| k.as_str() == Some(&server_rotation_key));
        if !has_server_key {
            return Err(ApiError::InvalidRequest(
                "Rotation keys do not include server's rotation key".into(),
            ));
        }
    }
    if let Some(services) = op.get("services").and_then(|v| v.as_object())
        && let Some(pds) = services.get("atproto_pds").and_then(|v| v.as_object())
    {
        let service_type = pds.get("type").and_then(|v| v.as_str());
        let endpoint = pds.get("endpoint").and_then(|v| v.as_str());
        if service_type != Some(tranquil_pds::plc::ServiceType::Pds.as_str()) {
            return Err(ApiError::InvalidRequest(
                "Incorrect type on atproto_pds service".into(),
            ));
        }
        if endpoint != Some(&public_url) {
            return Err(ApiError::InvalidRequest(
                "Incorrect endpoint on atproto_pds service".into(),
            ));
        }
    }
    if let Some(verification_methods) = op.get("verificationMethods").and_then(|v| v.as_object())
        && let Some(atproto_key) = verification_methods.get("atproto").and_then(|v| v.as_str())
        && atproto_key != user_did_key
    {
        return Err(ApiError::InvalidRequest(
            "Incorrect signing key in verificationMethods".into(),
        ));
    }
    if let Some(also_known_as) = (!user.handle.is_empty())
        .then(|| op.get("alsoKnownAs").and_then(|v| v.as_array()))
        .flatten()
    {
        let expected_handle = format!("at://{}", user.handle);
        let first_aka = also_known_as.first().and_then(|v| v.as_str());
        if first_aka != Some(&expected_handle) {
            return Err(ApiError::InvalidRequest(
                "Incorrect handle in alsoKnownAs".into(),
            ));
        }
    }
    let plc_client = PlcClient::with_cache(None, Some(state.cache.clone()));
    let operation_clone = input.operation.clone();
    let did_clone = did.clone();
    with_circuit_breaker(&state.circuit_breakers.plc_directory, || async {
        plc_client
            .send_operation(&did_clone, &operation_clone)
            .await
    })
    .await
    .map_err(ApiError::from)?;

    match state
        .repo_repo
        .insert_identity_event(did, Some(&user.handle))
        .await
    {
        Ok(seq) => {
            if let Err(e) = state.repo_repo.notify_update(seq).await {
                warn!("Failed to notify identity event: {:?}", e);
            }
        }
        Err(e) => {
            warn!("Failed to sequence identity event: {:?}", e);
        }
    }
    let _ = state
        .cache
        .delete(&tranquil_pds::cache_keys::handle_key(&user.handle))
        .await;
    let _ = state
        .cache
        .delete(&tranquil_pds::cache_keys::plc_doc_key(did))
        .await;
    let _ = state
        .cache
        .delete(&tranquil_pds::cache_keys::plc_data_key(did))
        .await;
    if state.did_resolver.refresh_did(did).await.is_none() {
        warn!(did = %did, "Failed to refresh DID cache after PLC update");
    }
    info!(did = %did, "PLC operation submitted successfully");
    Ok(EmptyResponse::ok().into_response())
}
