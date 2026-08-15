pub mod roles;
pub mod scopes;

pub use roles::{
    CanAddControllers, CanControlAccounts, verify_can_add_controllers, verify_can_control_accounts,
};
pub use scopes::{
    ADMIN_FULL_SCOPES, EDITOR_FULL_SCOPES, GrantCoverage, InvalidDelegationScopeError,
    OWNER_FULL_SCOPES, SCOPE_PRESETS, ScopePreset, ValidatedDelegationScope, grant_coverage,
    intersect_scopes,
};
pub use tranquil_db_traits::DelegationActionType;

use crate::did::DidResolutionError;
use crate::state::AppState;
use crate::types::{Did, Handle};
use tranquil_types::did_doc::{PdsEndpointError, extract_handle, extract_pds_endpoint};
use tranquil_types::{InvalidHttpUrl, PdsUrl};

#[derive(Debug, thiserror::Error)]
pub enum IdentityResolutionError {
    #[error(transparent)]
    DidResolution(#[from] DidResolutionError),
    #[error("remote PDS endpoint is unusable: {0}")]
    PdsEndpoint(InvalidHttpUrl),
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedIdentity {
    pub did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<Handle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pds_url: Option<PdsUrl>,
    pub is_local: bool,
}

pub async fn resolve_identity(
    state: &AppState,
    did: &Did,
) -> Result<ResolvedIdentity, IdentityResolutionError> {
    let is_local = state
        .repos
        .user
        .get_by_did(did)
        .await
        .ok()
        .flatten()
        .is_some();

    let did_doc = state.did_resolver.fetch_did_document(did).await?;

    let pds_url = match (extract_pds_endpoint(&did_doc), is_local) {
        (Ok(url), _) => Some(url),
        (Err(PdsEndpointError::Missing), _) => None,
        (Err(PdsEndpointError::Invalid(e)), true) => {
            tracing::debug!(did = %did, error = %e, "local account has an unusable PDS endpoint");
            None
        }
        (Err(PdsEndpointError::Invalid(e)), false) => {
            return Err(IdentityResolutionError::PdsEndpoint(e));
        }
    };

    Ok(ResolvedIdentity {
        did: did.clone(),
        handle: extract_handle(&did_doc),
        pds_url,
        is_local,
    })
}
