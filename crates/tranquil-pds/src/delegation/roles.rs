use axum::response::{IntoResponse, Response};

use crate::api::error::ApiError;
use crate::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::types::Did;

pub struct CanAddControllers<'a> {
    user: &'a AuthenticatedUser,
}

pub struct CanControlAccounts<'a> {
    user: &'a AuthenticatedUser,
}

pub struct CanBeController<'a> {
    controller_did: &'a Did,
}

impl<'a> CanAddControllers<'a> {
    pub fn did(&self) -> &Did {
        &self.user.did
    }

    pub fn user(&self) -> &AuthenticatedUser {
        self.user
    }
}

impl<'a> CanControlAccounts<'a> {
    pub fn did(&self) -> &Did {
        &self.user.did
    }

    pub fn user(&self) -> &AuthenticatedUser {
        self.user
    }
}

impl<'a> CanBeController<'a> {
    pub fn did(&self) -> &Did {
        self.controller_did
    }
}

pub async fn verify_can_add_controllers<'a>(
    state: &AppState,
    user: &'a AuthenticatedUser,
) -> Result<CanAddControllers<'a>, Response> {
    match state.delegation_repo.controls_any_accounts(&user.did).await {
        Ok(true) => Err(ApiError::InvalidDelegation(
            "Cannot add controllers to an account that controls other accounts".into(),
        )
        .into_response()),
        Ok(false) => Ok(CanAddControllers { user }),
        Err(e) => {
            tracing::error!("Failed to check delegation status: {:?}", e);
            Err(
                ApiError::InternalError(Some("Failed to verify delegation status".into()))
                    .into_response(),
            )
        }
    }
}

pub async fn verify_can_control_accounts<'a>(
    state: &AppState,
    user: &'a AuthenticatedUser,
) -> Result<CanControlAccounts<'a>, Response> {
    match state.delegation_repo.has_any_controllers(&user.did).await {
        Ok(true) => Err(ApiError::InvalidDelegation(
            "Cannot create delegated accounts from a controlled account".into(),
        )
        .into_response()),
        Ok(false) => Ok(CanControlAccounts { user }),
        Err(e) => {
            tracing::error!("Failed to check controller status: {:?}", e);
            Err(
                ApiError::InternalError(Some("Failed to verify controller status".into()))
                    .into_response(),
            )
        }
    }
}

pub async fn verify_can_be_controller<'a>(
    state: &AppState,
    controller_did: &'a Did,
) -> Result<CanBeController<'a>, Response> {
    match state
        .delegation_repo
        .has_any_controllers(controller_did)
        .await
    {
        Ok(true) => Err(ApiError::InvalidDelegation(
            "Cannot add a controlled account as a controller".into(),
        )
        .into_response()),
        Ok(false) => Ok(CanBeController { controller_did }),
        Err(e) => {
            tracing::error!("Failed to check controller status: {:?}", e);
            Err(
                ApiError::InternalError(Some("Failed to verify controller status".into()))
                    .into_response(),
            )
        }
    }
}
