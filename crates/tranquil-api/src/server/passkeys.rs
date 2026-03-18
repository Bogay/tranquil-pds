use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use tranquil_db_traits::WebauthnChallengeType;
use tranquil_pds::api::EmptyResponse;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::auth::{Active, Auth, require_legacy_session_mfa, require_reauth_window};
use tranquil_pds::state::AppState;
use webauthn_rs::prelude::*;

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
    let webauthn = &state.webauthn_config;

    let handle = state
        .user_repo
        .get_handle_by_did(&auth.did)
        .await
        .log_db_err("fetching user")?
        .ok_or(ApiError::AccountNotFound)?;

    let existing_passkeys = state
        .user_repo
        .get_passkeys_for_user(&auth.did)
        .await
        .log_db_err("fetching existing passkeys")?;

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
        .save_webauthn_challenge(&auth.did, WebauthnChallengeType::Registration, &state_json)
        .await
        .log_db_err("saving registration state")?;

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
    let webauthn = &state.webauthn_config;

    let reg_state_json = state
        .user_repo
        .load_webauthn_challenge(&auth.did, WebauthnChallengeType::Registration)
        .await
        .log_db_err("loading registration state")?
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
        .log_db_err("saving passkey")?;

    if let Err(e) = state
        .user_repo
        .delete_webauthn_challenge(&auth.did, WebauthnChallengeType::Registration)
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
        .log_db_err("fetching passkeys")?;

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
    let session_mfa = match require_legacy_session_mfa(&state, &auth).await {
        Ok(proof) => proof,
        Err(response) => return Ok(response),
    };

    let reauth_mfa = match require_reauth_window(&state, &auth).await {
        Ok(proof) => proof,
        Err(response) => return Ok(response),
    };

    let id: uuid::Uuid = input.id.parse().map_err(|_| ApiError::InvalidId)?;

    match state.user_repo.delete_passkey(id, reauth_mfa.did()).await {
        Ok(true) => {
            info!(did = %session_mfa.did(), passkey_id = %id, "Passkey deleted");
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

pub async fn has_passkeys_for_user(state: &AppState, did: &tranquil_pds::types::Did) -> bool {
    state.user_repo.has_passkeys(did).await.unwrap_or(false)
}
