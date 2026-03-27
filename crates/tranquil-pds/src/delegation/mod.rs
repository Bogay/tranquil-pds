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

use crate::did::DidResolutionError;
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

pub async fn resolve_identity(
    state: &AppState,
    did: &Did,
) -> Result<ResolvedIdentity, DidResolutionError> {
    let is_local = state
        .repos
        .user
        .get_by_did(did)
        .await
        .ok()
        .flatten()
        .is_some();

    let did_doc = state.did_resolver.resolve_did(did.as_str()).await?;

    let pds_url = did_doc.services.iter().find_map(|svc| {
        if (svc.id == "#atproto_pds" || svc.id.ends_with("#atproto_pds"))
            && svc.service_type == "AtprotoPersonalDataServer"
        {
            Some(svc.service_endpoint.clone())
        } else {
            None
        }
    });
    let handle = did_doc
        .also_known_as
        .iter()
        .find_map(|alias| alias.strip_prefix("at://").map(|s| s.to_string()));

    Ok(ResolvedIdentity {
        did: did.clone(),
        handle,
        pds_url,
        is_local,
    })
}
