use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::{Admin, Auth};
use crate::state::AppState;
use crate::types::{Did, Handle, PlainPassword};
use crate::util::pds_hostname_without_port;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tracing::{error, warn};

#[derive(Deserialize)]
pub struct UpdateAccountEmailInput {
    pub account: String,
    pub email: String,
}

pub async fn update_account_email(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
    Json(input): Json<UpdateAccountEmailInput>,
) -> Result<Response, ApiError> {
    let account = input.account.trim();
    let email = input.email.trim();
    if account.is_empty() || email.is_empty() {
        return Err(ApiError::InvalidRequest(
            "account and email are required".into(),
        ));
    }
    let account_did: Did = account
        .parse()
        .map_err(|_| ApiError::InvalidDid("Invalid DID format".into()))?;

    match state
        .user_repo
        .admin_update_email(&account_did, email)
        .await
    {
        Ok(0) => Err(ApiError::AccountNotFound),
        Ok(_) => Ok(EmptyResponse::ok().into_response()),
        Err(e) => {
            error!("DB error updating email: {:?}", e);
            Err(ApiError::InternalError(None))
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateAccountHandleInput {
    pub did: Did,
    pub handle: String,
}

pub async fn update_account_handle(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
    Json(input): Json<UpdateAccountHandleInput>,
) -> Result<Response, ApiError> {
    let did = &input.did;
    let input_handle = input.handle.trim();
    if input_handle.is_empty() {
        return Err(ApiError::InvalidRequest("handle is required".into()));
    }
    if !input_handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(ApiError::InvalidHandle(None));
    }
    let hostname_for_handles = pds_hostname_without_port();
    let handle = if !input_handle.contains('.') {
        format!("{}.{}", input_handle, hostname_for_handles)
    } else {
        input_handle.to_string()
    };
    let old_handle = state.user_repo.get_handle_by_did(did).await.ok().flatten();
    let user_id = state
        .user_repo
        .get_id_by_did(did)
        .await
        .ok()
        .flatten()
        .ok_or(ApiError::AccountNotFound)?;
    let handle_for_check = unsafe { Handle::new_unchecked(&handle) };
    if let Ok(true) = state
        .user_repo
        .check_handle_exists(&handle_for_check, user_id)
        .await
    {
        return Err(ApiError::HandleTaken);
    }
    match state
        .user_repo
        .admin_update_handle(did, &handle_for_check)
        .await
    {
        Ok(0) => Err(ApiError::AccountNotFound),
        Ok(_) => {
            if let Some(old) = old_handle {
                let _ = state.cache.delete(&format!("handle:{}", old)).await;
            }
            let _ = state.cache.delete(&format!("handle:{}", handle)).await;
            if let Err(e) = crate::api::repo::record::sequence_identity_event(
                &state,
                did,
                Some(&handle_for_check),
            )
            .await
            {
                warn!(
                    "Failed to sequence identity event for admin handle update: {}",
                    e
                );
            }
            if let Err(e) =
                crate::api::identity::did::update_plc_handle(&state, did, &handle_for_check).await
            {
                warn!("Failed to update PLC handle for admin handle update: {}", e);
            }
            Ok(EmptyResponse::ok().into_response())
        }
        Err(e) => {
            error!("DB error updating handle: {:?}", e);
            Err(ApiError::InternalError(None))
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateAccountPasswordInput {
    pub did: Did,
    pub password: PlainPassword,
}

pub async fn update_account_password(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
    Json(input): Json<UpdateAccountPasswordInput>,
) -> Result<Response, ApiError> {
    let did = &input.did;
    let password = input.password.trim();
    if password.is_empty() {
        return Err(ApiError::InvalidRequest("password is required".into()));
    }
    let password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| {
        error!("Failed to hash password: {:?}", e);
        ApiError::InternalError(None)
    })?;

    match state
        .user_repo
        .admin_update_password(did, &password_hash)
        .await
    {
        Ok(0) => Err(ApiError::AccountNotFound),
        Ok(_) => Ok(EmptyResponse::ok().into_response()),
        Err(e) => {
            error!("DB error updating password: {:?}", e);
            Err(ApiError::InternalError(None))
        }
    }
}
