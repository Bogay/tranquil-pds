use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use crate::types::{Did, Handle, PlainPassword};
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
    _auth: BearerAuthAdmin,
    Json(input): Json<UpdateAccountEmailInput>,
) -> Response {
    let account = input.account.trim();
    let email = input.email.trim();
    if account.is_empty() || email.is_empty() {
        return ApiError::InvalidRequest("account and email are required".into()).into_response();
    }
    let account_did: Did = match account.parse() {
        Ok(d) => d,
        Err(_) => return ApiError::InvalidDid("Invalid DID format".into()).into_response(),
    };
    match state
        .user_repo
        .admin_update_email(&account_did, email)
        .await
    {
        Ok(0) => ApiError::AccountNotFound.into_response(),
        Ok(_) => EmptyResponse::ok().into_response(),
        Err(e) => {
            error!("DB error updating email: {:?}", e);
            ApiError::InternalError(None).into_response()
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
    _auth: BearerAuthAdmin,
    Json(input): Json<UpdateAccountHandleInput>,
) -> Response {
    let did = &input.did;
    let input_handle = input.handle.trim();
    if input_handle.is_empty() {
        return ApiError::InvalidRequest("handle is required".into()).into_response();
    }
    if !input_handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return ApiError::InvalidHandle(None).into_response();
    }
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let hostname_for_handles = hostname.split(':').next().unwrap_or(&hostname);
    let handle = if !input_handle.contains('.') {
        format!("{}.{}", input_handle, hostname_for_handles)
    } else {
        input_handle.to_string()
    };
    let old_handle = state.user_repo.get_handle_by_did(did).await.ok().flatten();
    let user_id = match state.user_repo.get_id_by_did(did).await {
        Ok(Some(id)) => id,
        _ => return ApiError::AccountNotFound.into_response(),
    };
    let handle_for_check = Handle::new_unchecked(&handle);
    if let Ok(true) = state
        .user_repo
        .check_handle_exists(&handle_for_check, user_id)
        .await
    {
        return ApiError::HandleTaken.into_response();
    }
    match state
        .user_repo
        .admin_update_handle(did, &handle_for_check)
        .await
    {
        Ok(0) => ApiError::AccountNotFound.into_response(),
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
            EmptyResponse::ok().into_response()
        }
        Err(e) => {
            error!("DB error updating handle: {:?}", e);
            ApiError::InternalError(None).into_response()
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
    _auth: BearerAuthAdmin,
    Json(input): Json<UpdateAccountPasswordInput>,
) -> Response {
    let did = &input.did;
    let password = input.password.trim();
    if password.is_empty() {
        return ApiError::InvalidRequest("password is required".into()).into_response();
    }
    let password_hash = match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to hash password: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    match state
        .user_repo
        .admin_update_password(did, &password_hash)
        .await
    {
        Ok(0) => ApiError::AccountNotFound.into_response(),
        Ok(_) => EmptyResponse::ok().into_response(),
        Err(e) => {
            error!("DB error updating password: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}
