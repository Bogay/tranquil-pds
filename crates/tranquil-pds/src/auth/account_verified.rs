use axum::response::{IntoResponse, Response};

use super::AuthenticatedUser;
use crate::api::error::ApiError;
use crate::state::AppState;
use crate::types::Did;

pub struct AccountVerified<'a> {
    user: &'a AuthenticatedUser,
}

impl<'a> AccountVerified<'a> {
    pub fn did(&self) -> &Did {
        &self.user.did
    }

    pub fn user(&self) -> &AuthenticatedUser {
        self.user
    }
}

pub async fn require_verified_or_delegated<'a>(
    state: &AppState,
    user: &'a AuthenticatedUser,
) -> Result<AccountVerified<'a>, Response> {
    let is_verified = state
        .user_repo
        .has_verified_comms_channel(&user.did)
        .await
        .unwrap_or(false);

    if is_verified {
        return Ok(AccountVerified { user });
    }

    let is_delegated = state
        .delegation_repo
        .is_delegated_account(&user.did)
        .await
        .unwrap_or(false);

    if is_delegated {
        return Ok(AccountVerified { user });
    }

    Err(ApiError::AccountNotVerified.into_response())
}

pub async fn require_not_migrated(state: &AppState, did: &Did) -> Result<(), Response> {
    match state.user_repo.is_account_migrated(did).await {
        Ok(true) => Err(ApiError::AccountMigrated.into_response()),
        Ok(false) => Ok(()),
        Err(e) => {
            tracing::error!("Failed to check migration status: {:?}", e);
            Err(
                ApiError::InternalError(Some("Failed to verify migration status".into()))
                    .into_response(),
            )
        }
    }
}
