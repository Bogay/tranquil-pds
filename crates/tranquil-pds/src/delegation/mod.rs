pub mod roles;
pub mod scopes;

pub use roles::{
    CanAddControllers, CanControlAccounts, verify_can_add_controllers, verify_can_control_accounts,
};
pub use scopes::{
    InvalidDelegationScopeError, SCOPE_PRESETS, ScopePreset, ValidatedDelegationScope,
    intersect_scopes,
};
pub use tranquil_db_traits::DelegationActionType;

use crate::state::AppState;
use crate::types::Did;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedIdentity {
    pub did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pds_url: Option<String>,
    pub is_local: bool,
}

pub async fn resolve_identity(state: &AppState, did: &Did) -> Option<ResolvedIdentity> {
    let is_local = state
        .user_repo
        .get_by_did(did)
        .await
        .ok()
        .flatten()
        .is_some();

    let did_doc = state
        .did_resolver
        .resolve_did_document(did.as_str())
        .await?;

    let pds_url = tranquil_types::did_doc::extract_pds_endpoint(&did_doc);
    let handle = tranquil_types::did_doc::extract_handle(&did_doc);

    Some(ResolvedIdentity {
        did: did.clone(),
        handle,
        pds_url,
        is_local,
    })
}
