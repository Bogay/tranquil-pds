use crate::auth::BearerAuth;
use crate::auth::webauthn::{
    self, WebAuthnConfig, delete_passkey as db_delete_passkey, delete_registration_state,
    get_passkeys_for_user, load_registration_state, save_passkey, save_registration_state,
    update_passkey_name as db_update_passkey_name,
};
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info, warn};
use webauthn_rs::prelude::*;

fn get_webauthn() -> Result<WebAuthnConfig, (StatusCode, Json<serde_json::Value>)> {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    WebAuthnConfig::new(&hostname).map_err(|e| {
        error!("Failed to create WebAuthn config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "WebAuthn configuration failed"})),
        )
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

    let user = sqlx::query!("SELECT handle FROM users WHERE did = $1", auth.0.did)
        .fetch_optional(&state.db)
        .await;

    let handle = match user {
        Ok(Some(row)) => row.handle,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let existing_passkeys = match get_passkeys_for_user(&state.db, &auth.0.did).await {
        Ok(passkeys) => passkeys,
        Err(e) => {
            error!("DB error fetching existing passkeys: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to start registration"})),
            )
                .into_response();
        }
    };

    if let Err(e) = save_registration_state(&state.db, &auth.0.did, &reg_state).await {
        error!("Failed to save registration state: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let options = serde_json::to_value(&ccr).unwrap_or(json!({}));

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

    let reg_state = match load_registration_state(&state.db, &auth.0.did).await {
        Ok(Some(state)) => state,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "NoRegistrationInProgress",
                    "message": "No registration in progress. Call startPasskeyRegistration first."
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error loading registration state: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let credential: RegisterPublicKeyCredential = match serde_json::from_value(input.credential) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to parse credential: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidCredential",
                    "message": "Failed to parse credential response"
                })),
            )
                .into_response();
        }
    };

    let passkey = match webauthn.finish_registration(&credential, &reg_state) {
        Ok(pk) => pk,
        Err(e) => {
            warn!("Failed to finish passkey registration: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "RegistrationFailed",
                    "message": "Failed to verify passkey registration"
                })),
            )
                .into_response();
        }
    };

    let passkey_id = match save_passkey(
        &state.db,
        &auth.0.did,
        &passkey,
        input.friendly_name.as_deref(),
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to save passkey: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(e) = delete_registration_state(&state.db, &auth.0.did).await {
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
    let passkeys = match get_passkeys_for_user(&state.db, &auth.0.did).await {
        Ok(pks) => pks,
        Err(e) => {
            error!("DB error fetching passkeys: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
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
    let id: uuid::Uuid = match input.id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidId", "message": "Invalid passkey ID"})),
            )
                .into_response();
        }
    };

    match db_delete_passkey(&state.db, id, &auth.0.did).await {
        Ok(true) => {
            info!(did = %auth.0.did, passkey_id = %id, "Passkey deleted");
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "PasskeyNotFound", "message": "Passkey not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error deleting passkey: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
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
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidId", "message": "Invalid passkey ID"})),
            )
                .into_response();
        }
    };

    match db_update_passkey_name(&state.db, id, &auth.0.did, &input.friendly_name).await {
        Ok(true) => {
            info!(did = %auth.0.did, passkey_id = %id, "Passkey renamed");
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "PasskeyNotFound", "message": "Passkey not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error updating passkey: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

pub async fn has_passkeys_for_user(state: &AppState, did: &str) -> bool {
    has_passkeys_for_user_db(&state.db, did).await
}

pub async fn has_passkeys_for_user_db(db: &sqlx::PgPool, did: &str) -> bool {
    webauthn::has_passkeys(db, did).await.unwrap_or(false)
}
