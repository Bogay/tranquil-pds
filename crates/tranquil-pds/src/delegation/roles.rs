use std::marker::PhantomData;

use axum::response::{IntoResponse, Response};

use crate::api::error::ApiError;
use crate::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::types::Did;

pub struct AddControllersTag;
pub struct ControlAccountsTag;

pub struct DelegationProof<'a, Tag> {
    user: &'a AuthenticatedUser,
    _tag: PhantomData<Tag>,
}

pub type CanAddControllers<'a> = DelegationProof<'a, AddControllersTag>;
pub type CanControlAccounts<'a> = DelegationProof<'a, ControlAccountsTag>;

impl<'a, Tag> DelegationProof<'a, Tag> {
    pub fn did(&self) -> &Did {
        &self.user.did
    }
}

async fn check_delegation_flag(
    state: &AppState,
    did: &Did,
    check_is_delegated: bool,
    error_msg: &str,
) -> Result<bool, Response> {
    let result = if check_is_delegated {
        state.delegation_repo.is_delegated_account(did).await
    } else {
        state.delegation_repo.controls_any_accounts(did).await
    };
    match result {
        Ok(true) => Err(ApiError::InvalidDelegation(error_msg.into()).into_response()),
        Ok(false) => Ok(false),
        Err(e) => {
            tracing::error!("Failed to check delegation status: {:?}", e);
            Err(
                ApiError::InternalError(Some("Failed to verify delegation status".into()))
                    .into_response(),
            )
        }
    }
}

pub async fn verify_can_add_controllers<'a>(
    state: &AppState,
    user: &'a AuthenticatedUser,
) -> Result<CanAddControllers<'a>, Response> {
    check_delegation_flag(
        state,
        &user.did,
        false,
        "Cannot add controllers to an account that controls other accounts",
    )
    .await?;
    Ok(DelegationProof {
        user,
        _tag: PhantomData,
    })
}

pub async fn verify_can_control_accounts<'a>(
    state: &AppState,
    user: &'a AuthenticatedUser,
) -> Result<CanControlAccounts<'a>, Response> {
    check_delegation_flag(
        state,
        &user.did,
        true,
        "Cannot create delegated accounts from a controlled account",
    )
    .await?;
    Ok(DelegationProof {
        user,
        _tag: PhantomData,
    })
}
