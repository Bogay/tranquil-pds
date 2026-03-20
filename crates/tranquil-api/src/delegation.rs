use crate::identity::provision::{create_plc_did, init_genesis_repo};
use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info, warn};
use tranquil_pds::api::error::ApiError;
use tranquil_pds::api::{
    AccountsOutput, AuditLogOutput, ControllersOutput, PresetsOutput, SuccessResponse,
};
use tranquil_pds::auth::{Active, Auth};
use tranquil_pds::delegation::{
    DelegationActionType, SCOPE_PRESETS, ValidatedDelegationScope, verify_can_add_controllers,
    verify_can_control_accounts,
};
use tranquil_pds::rate_limit::{AccountCreationLimit, RateLimited};
use tranquil_pds::state::AppState;
use tranquil_pds::types::{Did, Handle};

pub async fn list_controllers(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Json<ControllersOutput<Vec<tranquil_db_traits::ControllerInfo>>>, ApiError> {
    let controllers = state
        .repos.delegation
        .get_delegations_for_account(&auth.did)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list controllers: {:?}", e);
            ApiError::InternalError(Some("Failed to list controllers".into()))
        })?;

    let resolve_futures = controllers.into_iter().map(|mut c| {
        let did_resolver = state.did_resolver.clone();
        async move {
            if c.handle.is_none() {
                c.handle = did_resolver
                    .resolve_did_document(c.did.as_str())
                    .await
                    .and_then(|doc| tranquil_types::did_doc::extract_handle(&doc))
                    .map(Into::into);
            }
            c
        }
    });

    let controllers = futures::future::join_all(resolve_futures).await;

    Ok(Json(ControllersOutput { controllers }))
}

#[derive(Debug, Deserialize)]
pub struct AddControllerInput {
    pub controller_did: Did,
    pub granted_scopes: ValidatedDelegationScope,
}

pub async fn add_controller(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<AddControllerInput>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let resolved = tranquil_pds::delegation::resolve_identity(&state, &input.controller_did)
        .await
        .ok_or(ApiError::ControllerNotFound)?;

    if !resolved.is_local
        && let Some(ref pds_url) = resolved.pds_url
    {
        if !pds_url.starts_with("https://") {
            return Err(ApiError::InvalidDelegation(
                "Controller PDS must use HTTPS".into(),
            ));
        }
        match state
            .cross_pds_oauth
            .check_remote_is_delegated(pds_url, input.controller_did.as_str())
            .await
        {
            Some(true) => {
                return Err(ApiError::InvalidDelegation(
                    "Cannot add a delegated account from another PDS as a controller".into(),
                ));
            }
            Some(false) => {}
            None => {
                warn!(
                    controller = %input.controller_did,
                    pds = %pds_url,
                    "Could not verify remote controller delegation status"
                );
            }
        }
    }

    let can_add = verify_can_add_controllers(&state, &auth).await?;

    if resolved.is_local
        && state
            .repos.delegation
            .is_delegated_account(&input.controller_did)
            .await
            .unwrap_or(false)
    {
        return Err(ApiError::InvalidDelegation(
            "Cannot add a controlled account as a controller".into(),
        ));
    }

    match state
        .repos.delegation
        .create_delegation(
            can_add.did(),
            &input.controller_did,
            &input.granted_scopes,
            can_add.did(),
        )
        .await
    {
        Ok(_) => {
            let _ = state
                .repos.delegation
                .log_delegation_action(
                    can_add.did(),
                    can_add.did(),
                    Some(&input.controller_did),
                    DelegationActionType::GrantCreated,
                    Some(json!({
                        "granted_scopes": input.granted_scopes.as_str(),
                        "is_local": resolved.is_local
                    })),
                    None,
                    None,
                )
                .await;

            Ok(Json(SuccessResponse { success: true }))
        }
        Err(e) => {
            tracing::error!("Failed to add controller: {:?}", e);
            Err(ApiError::InternalError(Some(
                "Failed to add controller".into(),
            )))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RemoveControllerInput {
    pub controller_did: Did,
}

pub async fn remove_controller(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<RemoveControllerInput>,
) -> Result<Json<SuccessResponse>, ApiError> {
    match state
        .repos.delegation
        .revoke_delegation(&auth.did, &input.controller_did, &auth.did)
        .await
    {
        Ok(true) => {
            let revoked_app_passwords = state
                .repos.session
                .delete_app_passwords_by_controller(&auth.did, &input.controller_did)
                .await
                .unwrap_or(0)
                .try_into()
                .unwrap_or(0usize);

            let revoked_oauth_tokens = state
                .repos.oauth
                .revoke_tokens_for_controller(&auth.did, &input.controller_did)
                .await
                .unwrap_or(0);

            let _ = state
                .repos.delegation
                .log_delegation_action(
                    &auth.did,
                    &auth.did,
                    Some(&input.controller_did),
                    DelegationActionType::GrantRevoked,
                    Some(json!({
                        "revoked_app_passwords": revoked_app_passwords,
                        "revoked_oauth_tokens": revoked_oauth_tokens
                    })),
                    None,
                    None,
                )
                .await;

            Ok(Json(SuccessResponse { success: true }))
        }
        Ok(false) => Err(ApiError::DelegationNotFound),
        Err(e) => {
            tracing::error!("Failed to remove controller: {:?}", e);
            Err(ApiError::InternalError(Some(
                "Failed to remove controller".into(),
            )))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateControllerScopesInput {
    pub controller_did: Did,
    pub granted_scopes: ValidatedDelegationScope,
}

pub async fn update_controller_scopes(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<UpdateControllerScopesInput>,
) -> Result<Json<SuccessResponse>, ApiError> {
    match state
        .repos.delegation
        .update_delegation_scopes(&auth.did, &input.controller_did, &input.granted_scopes)
        .await
    {
        Ok(true) => {
            let _ = state
                .repos.delegation
                .log_delegation_action(
                    &auth.did,
                    &auth.did,
                    Some(&input.controller_did),
                    DelegationActionType::ScopesModified,
                    Some(json!({
                        "new_scopes": input.granted_scopes.as_str()
                    })),
                    None,
                    None,
                )
                .await;

            Ok(Json(SuccessResponse { success: true }))
        }
        Ok(false) => Err(ApiError::DelegationNotFound),
        Err(e) => {
            tracing::error!("Failed to update controller scopes: {:?}", e);
            Err(ApiError::InternalError(Some(
                "Failed to update controller scopes".into(),
            )))
        }
    }
}

pub async fn list_controlled_accounts(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Json<AccountsOutput<Vec<tranquil_db_traits::DelegatedAccountInfo>>>, ApiError> {
    let accounts = state
        .repos.delegation
        .get_accounts_controlled_by(&auth.did)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list controlled accounts: {:?}", e);
            ApiError::InternalError(Some("Failed to list controlled accounts".into()))
        })?;

    Ok(Json(AccountsOutput { accounts }))
}

#[derive(Debug, Deserialize)]
pub struct AuditLogParams {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

pub async fn get_audit_log(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Query(params): Query<AuditLogParams>,
) -> Result<Json<AuditLogOutput<Vec<tranquil_db_traits::AuditLogEntry>>>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let entries = state
        .repos.delegation
        .get_audit_log_for_account(&auth.did, limit, offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get audit log: {:?}", e);
            ApiError::InternalError(Some("Failed to get audit log".into()))
        })?;

    let total = state
        .repos.delegation
        .count_audit_log_entries(&auth.did)
        .await
        .unwrap_or_default();

    Ok(Json(AuditLogOutput { entries, total }))
}

pub async fn get_scope_presets()
-> Json<PresetsOutput<&'static [tranquil_pds::delegation::ScopePreset]>> {
    Json(PresetsOutput {
        presets: SCOPE_PRESETS,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDelegatedAccountInput {
    pub handle: String,
    pub email: Option<String>,
    pub controller_scopes: ValidatedDelegationScope,
    pub invite_code: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDelegatedAccountOutput {
    pub did: Did,
    pub handle: Handle,
}

pub async fn create_delegated_account(
    State(state): State<AppState>,
    _rate_limit: RateLimited<AccountCreationLimit>,
    auth: Auth<Active>,
    Json(input): Json<CreateDelegatedAccountInput>,
) -> Result<Json<CreateDelegatedAccountOutput>, ApiError> {
    let can_control = verify_can_control_accounts(&state, &auth).await?;

    let handle = tranquil_pds::api::validation::resolve_handle_input(&input.handle)
        .map_err(|e| ApiError::InvalidRequest(e.to_string()))?;

    let email = input
        .email
        .as_ref()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(ref email) = email
        && !tranquil_pds::api::validation::is_valid_email(email)
    {
        return Err(ApiError::InvalidEmail);
    }

    let validated_invite_code = if let Some(ref code) = input.invite_code {
        match state.repos.infra.validate_invite_code(code).await {
            Ok(validated) => Some(validated),
            Err(_) => return Err(ApiError::InvalidInviteCode),
        }
    } else {
        let invite_required = tranquil_config::get().server.invite_code_required;
        if invite_required {
            return Err(ApiError::InviteCodeRequired);
        }
        None
    };

    let plc = create_plc_did(&state, &handle).await.map_err(|e| {
        tracing::error!("PLC DID creation failed: {:?}", e);
        e
    })?;
    let did = plc.did;
    let handle: Handle = handle.parse().map_err(|_| ApiError::InvalidHandle(None))?;
    info!(did = %did, handle = %handle, controller = %can_control.did(), "Created DID for delegated account");

    let repo = init_genesis_repo(&state, &did, &plc.signing_key, &plc.signing_key_bytes).await?;
    let repo_for_seq = repo.clone();

    let create_input = tranquil_db_traits::CreateDelegatedAccountInput {
        handle: handle.clone(),
        email: email.clone(),
        did: did.clone(),
        controller_did: can_control.did().clone(),
        controller_scopes: input.controller_scopes.as_str().to_string(),
        encrypted_key_bytes: repo.encrypted_key_bytes,
        encryption_version: tranquil_pds::config::ENCRYPTION_VERSION,
        commit_cid: repo.commit_cid.to_string(),
        repo_rev: repo.repo_rev.clone(),
        genesis_block_cids: repo.genesis_block_cids,
        invite_code: input.invite_code.clone(),
    };

    let user_id = match state
        .repos.user
        .create_delegated_account(&create_input)
        .await
    {
        Ok(id) => id,
        Err(tranquil_db_traits::CreateAccountError::HandleTaken) => {
            return Err(ApiError::HandleNotAvailable(None));
        }
        Err(tranquil_db_traits::CreateAccountError::EmailTaken) => {
            return Err(ApiError::EmailTaken);
        }
        Err(e) => {
            error!("Error creating delegated account: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    if let Some(validated) = validated_invite_code
        && let Err(e) = state
            .repos.infra
            .record_invite_code_use(&validated, user_id)
            .await
    {
        warn!("Failed to record invite code use for {}: {:?}", did, e);
    }

    crate::identity::provision::sequence_new_account(
        &state,
        &did,
        &handle,
        &repo_for_seq,
        handle.as_str(),
    )
    .await;

    let _ = state
        .repos.delegation
        .log_delegation_action(
            &did,
            &auth.did,
            Some(&auth.did),
            DelegationActionType::GrantCreated,
            Some(json!({
                "account_created": true,
                "granted_scopes": input.controller_scopes.as_str()
            })),
            None,
            None,
        )
        .await;

    info!(did = %did, handle = %handle, controller = %&auth.did, "Delegated account created");

    Ok(Json(CreateDelegatedAccountOutput { did, handle }))
}

#[derive(Debug, Deserialize)]
pub struct ResolveControllerParams {
    pub identifier: String,
}

pub async fn resolve_controller(
    State(state): State<AppState>,
    Query(params): Query<ResolveControllerParams>,
) -> Result<Json<tranquil_pds::delegation::ResolvedIdentity>, ApiError> {
    let identifier = params.identifier.trim().trim_start_matches('@');

    let did: Did = if identifier.starts_with("did:") {
        identifier
            .parse()
            .map_err(|_| ApiError::ControllerNotFound)?
    } else {
        let local_handle: Option<Handle> = identifier.parse().ok();
        let local_user = match local_handle {
            Some(ref h) => state.repos.user.get_by_handle(h).await.ok().flatten(),
            None => None,
        };
        match local_user {
            Some(user) => user.did,
            None => tranquil_pds::handle::resolve_handle(identifier)
                .await
                .map_err(|_| ApiError::ControllerNotFound)?
                .parse()
                .map_err(|_| ApiError::ControllerNotFound)?,
        }
    };

    let resolved = tranquil_pds::delegation::resolve_identity(&state, &did)
        .await
        .ok_or(ApiError::ControllerNotFound)?;

    Ok(Json(resolved))
}
