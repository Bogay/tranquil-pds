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
    let result = sqlx::query!("UPDATE users SET email = $1 WHERE did = $2", email, account)
        .execute(&state.db)
        .await;
    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return ApiError::AccountNotFound.into_response();
            }
            EmptyResponse::ok().into_response()
        }
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
    let handle = if !input_handle.contains('.') {
        format!("{}.{}", input_handle, hostname)
    } else {
        input_handle.to_string()
    };
    let old_handle = sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", did.as_str())
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let existing = sqlx::query!(
        "SELECT id FROM users WHERE handle = $1 AND did != $2",
        handle,
        did.as_str()
    )
    .fetch_optional(&state.db)
    .await;
    if let Ok(Some(_)) = existing {
        return ApiError::HandleTaken.into_response();
    }
    let result = sqlx::query!(
        "UPDATE users SET handle = $1 WHERE did = $2",
        handle,
        did.as_str()
    )
    .execute(&state.db)
    .await;
    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return ApiError::AccountNotFound.into_response();
            }
            if let Some(old) = old_handle {
                let _ = state.cache.delete(&format!("handle:{}", old)).await;
            }
            let _ = state.cache.delete(&format!("handle:{}", handle)).await;
            let handle_typed = Handle::new_unchecked(&handle);
            if let Err(e) = crate::api::repo::record::sequence_identity_event(
                &state,
                did,
                Some(&handle_typed),
            )
            .await
            {
                warn!(
                    "Failed to sequence identity event for admin handle update: {}",
                    e
                );
            }
            if let Err(e) =
                crate::api::identity::did::update_plc_handle(&state, did.as_str(), &handle).await
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
    let result = sqlx::query!(
        "UPDATE users SET password_hash = $1 WHERE did = $2",
        password_hash,
        did.as_str()
    )
    .execute(&state.db)
    .await;
    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return ApiError::AccountNotFound.into_response();
            }
            EmptyResponse::ok().into_response()
        }
        Err(e) => {
            error!("DB error updating password: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}
