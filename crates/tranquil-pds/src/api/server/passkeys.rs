use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::webauthn::WebAuthnConfig;
use crate::auth::{Active, Auth};
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use webauthn_rs::prelude::*;

fn get_webauthn() -> Result<WebAuthnConfig, ApiError> {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    WebAuthnConfig::new(&hostname).map_err(|e| {
        error!("Failed to create WebAuthn config: {}", e);
        ApiError::InternalError(Some("WebAuthn configuration failed".into()))
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartRegistrationInput {
    pub friendly_name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartRegistrationResponse {
    pub options: serde_json::Value,
}

pub async fn start_passkey_registration(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<StartRegistrationInput>,
) -> Result<Response, ApiError> {
    let webauthn = get_webauthn()?;

    let handle = state
        .user_repo
        .get_handle_by_did(&auth.did)
        .await
        .map_err(|e| {
            error!("DB error fetching user: {:?}", e);
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::AccountNotFound)?;

    let existing_passkeys = state
        .user_repo
        .get_passkeys_for_user(&auth.did)
        .await
        .map_err(|e| {
            error!("DB error fetching existing passkeys: {:?}", e);
            ApiError::InternalError(None)
        })?;

    let exclude_credentials: Vec<CredentialID> = existing_passkeys
        .iter()
        .map(|p| CredentialID::from(p.credential_id.clone()))
        .collect();

    let display_name = input.friendly_name.as_deref().unwrap_or(&handle);

    let (ccr, reg_state) = webauthn
        .start_registration(&auth.did, &handle, display_name, exclude_credentials)
        .map_err(|e| {
            error!("Failed to start passkey registration: {}", e);
            ApiError::InternalError(Some("Failed to start registration".into()))
        })?;

    let state_json = serde_json::to_string(&reg_state).map_err(|e| {
        error!("Failed to serialize registration state: {:?}", e);
        ApiError::InternalError(None)
    })?;

    state
        .user_repo
        .save_webauthn_challenge(&auth.did, "registration", &state_json)
        .await
        .map_err(|e| {
            error!("Failed to save registration state: {:?}", e);
            ApiError::InternalError(None)
        })?;

    let options = serde_json::to_value(&ccr).unwrap_or(serde_json::json!({}));

    info!(did = %auth.did, "Passkey registration started");

    Ok(Json(StartRegistrationResponse { options }).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishRegistrationInput {
    pub credential: serde_json::Value,
    pub friendly_name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishRegistrationResponse {
    pub id: String,
    pub credential_id: String,
}

pub async fn finish_passkey_registration(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<FinishRegistrationInput>,
) -> Result<Response, ApiError> {
    let webauthn = get_webauthn()?;

    let reg_state_json = state
        .user_repo
        .load_webauthn_challenge(&auth.did, "registration")
        .await
        .map_err(|e| {
            error!("DB error loading registration state: {:?}", e);
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::NoRegistrationInProgress)?;

    let reg_state: SecurityKeyRegistration =
        serde_json::from_str(&reg_state_json).map_err(|e| {
            error!("Failed to deserialize registration state: {:?}", e);
            ApiError::InternalError(None)
        })?;

    let credential: RegisterPublicKeyCredential = serde_json::from_value(input.credential)
        .map_err(|e| {
            warn!("Failed to parse credential: {:?}", e);
            ApiError::InvalidCredential
        })?;

    let passkey = webauthn
        .finish_registration(&credential, &reg_state)
        .map_err(|e| {
            warn!("Failed to finish passkey registration: {}", e);
            ApiError::RegistrationFailed
        })?;

    let public_key = serde_json::to_vec(&passkey).map_err(|e| {
        error!("Failed to serialize passkey: {:?}", e);
        ApiError::InternalError(None)
    })?;

    let passkey_id = state
        .user_repo
        .save_passkey(
            &auth.did,
            passkey.cred_id(),
            &public_key,
            input.friendly_name.as_deref(),
        )
        .await
        .map_err(|e| {
            error!("Failed to save passkey: {:?}", e);
            ApiError::InternalError(None)
        })?;

    if let Err(e) = state
        .user_repo
        .delete_webauthn_challenge(&auth.did, "registration")
        .await
    {
        warn!("Failed to delete registration state: {:?}", e);
    }

    let credential_id_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        passkey.cred_id(),
    );

    info!(did = %auth.did, passkey_id = %passkey_id, "Passkey registered");

    Ok(Json(FinishRegistrationResponse {
        id: passkey_id.to_string(),
        credential_id: credential_id_base64,
    })
    .into_response())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyInfo {
    pub id: String,
    pub credential_id: String,
    pub friendly_name: Option<String>,
    pub created_at: String,
    pub last_used: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPasskeysResponse {
    pub passkeys: Vec<PasskeyInfo>,
}

pub async fn list_passkeys(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let passkeys = state
        .user_repo
        .get_passkeys_for_user(&auth.did)
        .await
        .map_err(|e| {
            error!("DB error fetching passkeys: {:?}", e);
            ApiError::InternalError(None)
        })?;

    let passkey_infos: Vec<PasskeyInfo> = passkeys
        .into_iter()
        .map(|pk| PasskeyInfo {
            id: pk.id.to_string(),
            credential_id: pk.credential_id_base64(),
            friendly_name: pk.friendly_name,
            created_at: pk.created_at.to_rfc3339(),
            last_used: pk.last_used.map(|dt| dt.to_rfc3339()),
        })
        .collect();

    Ok(Json(ListPasskeysResponse {
        passkeys: passkey_infos,
    })
    .into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletePasskeyInput {
    pub id: String,
}

pub async fn delete_passkey(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<DeletePasskeyInput>,
) -> Result<Response, ApiError> {
    if !crate::api::server::reauth::check_legacy_session_mfa(&*state.session_repo, &auth.did).await
    {
        return Ok(crate::api::server::reauth::legacy_mfa_required_response(
            &*state.user_repo,
            &*state.session_repo,
            &auth.did,
        )
        .await);
    }

    if crate::api::server::reauth::check_reauth_required(&*state.session_repo, &auth.did).await {
        return Ok(crate::api::server::reauth::reauth_required_response(
            &*state.user_repo,
            &*state.session_repo,
            &auth.did,
        )
        .await);
    }

    let id: uuid::Uuid = input.id.parse().map_err(|_| ApiError::InvalidId)?;

    match state.user_repo.delete_passkey(id, &auth.did).await {
        Ok(true) => {
            info!(did = %auth.did, passkey_id = %id, "Passkey deleted");
            Ok(EmptyResponse::ok().into_response())
        }
        Ok(false) => Err(ApiError::PasskeyNotFound),
        Err(e) => {
            error!("DB error deleting passkey: {:?}", e);
            Err(ApiError::InternalError(None))
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePasskeyInput {
    pub id: String,
    pub friendly_name: String,
}

pub async fn update_passkey(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<UpdatePasskeyInput>,
) -> Result<Response, ApiError> {
    let id: uuid::Uuid = input.id.parse().map_err(|_| ApiError::InvalidId)?;

    match state
        .user_repo
        .update_passkey_name(id, &auth.did, &input.friendly_name)
        .await
    {
        Ok(true) => {
            info!(did = %auth.did, passkey_id = %id, "Passkey renamed");
            Ok(EmptyResponse::ok().into_response())
        }
        Ok(false) => Err(ApiError::PasskeyNotFound),
        Err(e) => {
            error!("DB error updating passkey: {:?}", e);
            Err(ApiError::InternalError(None))
        }
    }
}

pub async fn has_passkeys_for_user(state: &AppState, did: &crate::types::Did) -> bool {
    state.user_repo.has_passkeys(did).await.unwrap_or(false)
}
