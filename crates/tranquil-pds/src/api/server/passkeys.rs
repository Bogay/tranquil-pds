use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::BearerAuth;
use crate::auth::webauthn::WebAuthnConfig;
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
    auth: BearerAuth,
    Json(input): Json<StartRegistrationInput>,
) -> Response {
    let webauthn = match get_webauthn() {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };

    let handle = match state.user_repo.get_handle_by_did(&auth.0.did).await {
        Ok(Some(h)) => h,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let existing_passkeys = match state.user_repo.get_passkeys_for_user(&auth.0.did).await {
        Ok(passkeys) => passkeys,
        Err(e) => {
            error!("DB error fetching existing passkeys: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let exclude_credentials: Vec<CredentialID> = existing_passkeys
        .iter()
        .map(|p| CredentialID::from(p.credential_id.clone()))
        .collect();

    let display_name = input.friendly_name.as_deref().unwrap_or(&handle);

    let (ccr, reg_state) = match webauthn.start_registration(
        &auth.0.did,
        &handle,
        display_name,
        exclude_credentials,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to start passkey registration: {}", e);
            return ApiError::InternalError(Some("Failed to start registration".into()))
                .into_response();
        }
    };

    let state_json = match serde_json::to_string(&reg_state) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to serialize registration state: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if let Err(e) = state
        .user_repo
        .save_webauthn_challenge(&auth.0.did, "registration", &state_json)
        .await
    {
        error!("Failed to save registration state: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let options = serde_json::to_value(&ccr).unwrap_or(serde_json::json!({}));

    info!(did = %auth.0.did, "Passkey registration started");

    Json(StartRegistrationResponse { options }).into_response()
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
    auth: BearerAuth,
    Json(input): Json<FinishRegistrationInput>,
) -> Response {
    let webauthn = match get_webauthn() {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };

    let reg_state_json = match state
        .user_repo
        .load_webauthn_challenge(&auth.0.did, "registration")
        .await
    {
        Ok(Some(json)) => json,
        Ok(None) => {
            return ApiError::NoRegistrationInProgress.into_response();
        }
        Err(e) => {
            error!("DB error loading registration state: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let reg_state: SecurityKeyRegistration = match serde_json::from_str(&reg_state_json) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to deserialize registration state: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let credential: RegisterPublicKeyCredential = match serde_json::from_value(input.credential) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to parse credential: {:?}", e);
            return ApiError::InvalidCredential.into_response();
        }
    };

    let passkey = match webauthn.finish_registration(&credential, &reg_state) {
        Ok(pk) => pk,
        Err(e) => {
            warn!("Failed to finish passkey registration: {}", e);
            return ApiError::RegistrationFailed.into_response();
        }
    };

    let public_key = match serde_json::to_vec(&passkey) {
        Ok(pk) => pk,
        Err(e) => {
            error!("Failed to serialize passkey: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let passkey_id = match state
        .user_repo
        .save_passkey(
            &auth.0.did,
            passkey.cred_id(),
            &public_key,
            input.friendly_name.as_deref(),
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to save passkey: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if let Err(e) = state
        .user_repo
        .delete_webauthn_challenge(&auth.0.did, "registration")
        .await
    {
        warn!("Failed to delete registration state: {:?}", e);
    }

    let credential_id_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        passkey.cred_id(),
    );

    info!(did = %auth.0.did, passkey_id = %passkey_id, "Passkey registered");

    Json(FinishRegistrationResponse {
        id: passkey_id.to_string(),
        credential_id: credential_id_base64,
    })
    .into_response()
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

pub async fn list_passkeys(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let passkeys = match state.user_repo.get_passkeys_for_user(&auth.0.did).await {
        Ok(pks) => pks,
        Err(e) => {
            error!("DB error fetching passkeys: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

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

    Json(ListPasskeysResponse {
        passkeys: passkey_infos,
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletePasskeyInput {
    pub id: String,
}

pub async fn delete_passkey(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<DeletePasskeyInput>,
) -> Response {
    if !crate::api::server::reauth::check_legacy_session_mfa(&*state.session_repo, &auth.0.did)
        .await
    {
        return crate::api::server::reauth::legacy_mfa_required_response(
            &*state.user_repo,
            &*state.session_repo,
            &auth.0.did,
        )
        .await;
    }

    if crate::api::server::reauth::check_reauth_required(&*state.session_repo, &auth.0.did).await {
        return crate::api::server::reauth::reauth_required_response(
            &*state.user_repo,
            &*state.session_repo,
            &auth.0.did,
        )
        .await;
    }

    let id: uuid::Uuid = match input.id.parse() {
        Ok(id) => id,
        Err(_) => {
            return ApiError::InvalidId.into_response();
        }
    };

    match state.user_repo.delete_passkey(id, &auth.0.did).await {
        Ok(true) => {
            info!(did = %auth.0.did, passkey_id = %id, "Passkey deleted");
            EmptyResponse::ok().into_response()
        }
        Ok(false) => ApiError::PasskeyNotFound.into_response(),
        Err(e) => {
            error!("DB error deleting passkey: {:?}", e);
            ApiError::InternalError(None).into_response()
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
    auth: BearerAuth,
    Json(input): Json<UpdatePasskeyInput>,
) -> Response {
    let id: uuid::Uuid = match input.id.parse() {
        Ok(id) => id,
        Err(_) => {
            return ApiError::InvalidId.into_response();
        }
    };

    match state
        .user_repo
        .update_passkey_name(id, &auth.0.did, &input.friendly_name)
        .await
    {
        Ok(true) => {
            info!(did = %auth.0.did, passkey_id = %id, "Passkey renamed");
            EmptyResponse::ok().into_response()
        }
        Ok(false) => ApiError::PasskeyNotFound.into_response(),
        Err(e) => {
            error!("DB error updating passkey: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

pub async fn has_passkeys_for_user(state: &AppState, did: &crate::types::Did) -> bool {
    state.user_repo.has_passkeys(did).await.unwrap_or(false)
}
