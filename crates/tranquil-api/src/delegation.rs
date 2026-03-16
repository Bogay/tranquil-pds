use crate::identity::provision::{create_plc_did, init_genesis_repo};
use tranquil_pds::api::error::ApiError;
use tranquil_pds::auth::{Active, Auth};
use tranquil_pds::delegation::{
    DelegationActionType, SCOPE_PRESETS, ValidatedDelegationScope, verify_can_add_controllers,
    verify_can_control_accounts,
};
use tranquil_pds::rate_limit::{AccountCreationLimit, RateLimited};
use tranquil_pds::state::AppState;
use tranquil_pds::types::{Did, Handle};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info, warn};

pub async fn list_controllers(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let controllers = match state
        .delegation_repo
        .get_delegations_for_account(&auth.did)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to list controllers: {:?}", e);
            return Ok(
                ApiError::InternalError(Some("Failed to list controllers".into())).into_response(),
            );
        }
    };

    let resolve_futures = controllers.into_iter().map(|mut c| {
        let did_resolver = state.did_resolver.clone();
        async move {
            if c.handle.is_none() {
                c.handle = did_resolver
                    .resolve_did_document(c.did.as_str())
                    .await
                    .and_then(|doc| tranquil_types::did_doc::extract_handle(&doc))
                    .map(|h| h.into());
            }
            c
        }
    });

    let controllers = futures::future::join_all(resolve_futures).await;

    Ok(Json(serde_json::json!({ "controllers": controllers })).into_response())
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
) -> Result<Response, ApiError> {
    let resolved = tranquil_pds::delegation::resolve_identity(&state, &input.controller_did)
        .await
        .ok_or(ApiError::ControllerNotFound)?;

    if !resolved.is_local {
        if let Some(ref pds_url) = resolved.pds_url {
            if !pds_url.starts_with("https://") {
                return Ok(
                    ApiError::InvalidDelegation("Controller PDS must use HTTPS".into())
                        .into_response(),
                );
            }
            match state
                .cross_pds_oauth
                .check_remote_is_delegated(pds_url, input.controller_did.as_str())
                .await
            {
                Some(true) => {
                    return Ok(ApiError::InvalidDelegation(
                        "Cannot add a delegated account from another PDS as a controller".into(),
                    )
                    .into_response());
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
    }

    let can_add = match verify_can_add_controllers(&state, &auth).await {
        Ok(proof) => proof,
        Err(response) => return Ok(response),
    };

    if resolved.is_local {
        if state.delegation_repo.is_delegated_account(&input.controller_did).await.unwrap_or(false) {
            return Ok(ApiError::InvalidDelegation(
                "Cannot add a controlled account as a controller".into(),
            ).into_response());
        }
    }

    match state
        .delegation_repo
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
                .delegation_repo
                .log_delegation_action(
                    can_add.did(),
                    can_add.did(),
                    Some(&input.controller_did),
                    DelegationActionType::GrantCreated,
                    Some(serde_json::json!({
                        "granted_scopes": input.granted_scopes.as_str(),
                        "is_local": resolved.is_local
                    })),
                    None,
                    None,
                )
                .await;

            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true
                })),
            )
                .into_response())
        }
        Err(e) => {
            tracing::error!("Failed to add controller: {:?}", e);
            Ok(ApiError::InternalError(Some("Failed to add controller".into())).into_response())
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
) -> Result<Response, ApiError> {
    match state
        .delegation_repo
        .revoke_delegation(&auth.did, &input.controller_did, &auth.did)
        .await
    {
        Ok(true) => {
            let revoked_app_passwords = state
                .session_repo
                .delete_app_passwords_by_controller(&auth.did, &input.controller_did)
                .await
                .unwrap_or(0)
                .try_into()
                .unwrap_or(0usize);

            let revoked_oauth_tokens = state
                .oauth_repo
                .revoke_tokens_for_controller(&auth.did, &input.controller_did)
                .await
                .unwrap_or(0);

            let _ = state
                .delegation_repo
                .log_delegation_action(
                    &auth.did,
                    &auth.did,
                    Some(&input.controller_did),
                    DelegationActionType::GrantRevoked,
                    Some(serde_json::json!({
                        "revoked_app_passwords": revoked_app_passwords,
                        "revoked_oauth_tokens": revoked_oauth_tokens
                    })),
                    None,
                    None,
                )
                .await;

            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true
                })),
            )
                .into_response())
        }
        Ok(false) => Ok(ApiError::DelegationNotFound.into_response()),
        Err(e) => {
            tracing::error!("Failed to remove controller: {:?}", e);
            Ok(ApiError::InternalError(Some("Failed to remove controller".into())).into_response())
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
) -> Result<Response, ApiError> {
    match state
        .delegation_repo
        .update_delegation_scopes(&auth.did, &input.controller_did, &input.granted_scopes)
        .await
    {
        Ok(true) => {
            let _ = state
                .delegation_repo
                .log_delegation_action(
                    &auth.did,
                    &auth.did,
                    Some(&input.controller_did),
                    DelegationActionType::ScopesModified,
                    Some(serde_json::json!({
                        "new_scopes": input.granted_scopes.as_str()
                    })),
                    None,
                    None,
                )
                .await;

            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true
                })),
            )
                .into_response())
        }
        Ok(false) => Ok(ApiError::DelegationNotFound.into_response()),
        Err(e) => {
            tracing::error!("Failed to update controller scopes: {:?}", e);
            Ok(
                ApiError::InternalError(Some("Failed to update controller scopes".into()))
                    .into_response(),
            )
        }
    }
}

pub async fn list_controlled_accounts(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let accounts = match state
        .delegation_repo
        .get_accounts_controlled_by(&auth.did)
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Failed to list controlled accounts: {:?}", e);
            return Ok(
                ApiError::InternalError(Some("Failed to list controlled accounts".into()))
                    .into_response(),
            );
        }
    };

    Ok(Json(serde_json::json!({ "accounts": accounts })).into_response())
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
) -> Result<Response, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let entries = match state
        .delegation_repo
        .get_audit_log_for_account(&auth.did, limit, offset)
        .await
    {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to get audit log: {:?}", e);
            return Ok(
                ApiError::InternalError(Some("Failed to get audit log".into())).into_response(),
            );
        }
    };

    let total = state
        .delegation_repo
        .count_audit_log_entries(&auth.did)
        .await
        .unwrap_or_default();

    Ok(Json(serde_json::json!({ "entries": entries, "total": total })).into_response())
}

pub async fn get_scope_presets() -> Response {
    Json(serde_json::json!({ "presets": SCOPE_PRESETS })).into_response()
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
pub struct CreateDelegatedAccountResponse {
    pub did: Did,
    pub handle: Handle,
}

pub async fn create_delegated_account(
    State(state): State<AppState>,
    _rate_limit: RateLimited<AccountCreationLimit>,
    auth: Auth<Active>,
    Json(input): Json<CreateDelegatedAccountInput>,
) -> Result<Response, ApiError> {
    let can_control = match verify_can_control_accounts(&state, &auth).await {
        Ok(proof) => proof,
        Err(response) => return Ok(response),
    };

    let handle = match tranquil_pds::api::validation::resolve_handle_input(&input.handle) {
        Ok(h) => h,
        Err(e) => {
            return Ok(ApiError::InvalidRequest(e.to_string()).into_response());
        }
    };

    let email = input
        .email
        .as_ref()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(ref email) = email
        && !tranquil_pds::api::validation::is_valid_email(email)
    {
        return Ok(ApiError::InvalidEmail.into_response());
    }

    let validated_invite_code = if let Some(ref code) = input.invite_code {
        match state.infra_repo.validate_invite_code(code).await {
            Ok(validated) => Some(validated),
            Err(_) => return Ok(ApiError::InvalidInviteCode.into_response()),
        }
    } else {
        let invite_required = tranquil_config::get().server.invite_code_required;
        if invite_required {
            return Ok(ApiError::InviteCodeRequired.into_response());
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
        .user_repo
        .create_delegated_account(&create_input)
        .await
    {
        Ok(id) => id,
        Err(tranquil_db_traits::CreateAccountError::HandleTaken) => {
            return Ok(ApiError::HandleNotAvailable(None).into_response());
        }
        Err(tranquil_db_traits::CreateAccountError::EmailTaken) => {
            return Ok(ApiError::EmailTaken.into_response());
        }
        Err(e) => {
            error!("Error creating delegated account: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };

    if let Some(validated) = validated_invite_code
        && let Err(e) = state
            .infra_repo
            .record_invite_code_use(&validated, user_id)
            .await
    {
        warn!("Failed to record invite code use for {}: {:?}", did, e);
    }

    if let Err(e) =
        tranquil_pds::repo_ops::sequence_identity_event(&state, &did, Some(&handle)).await
    {
        warn!("Failed to sequence identity event for {}: {}", did, e);
    }
    if let Err(e) = tranquil_pds::repo_ops::sequence_account_event(
        &state,
        &did,
        tranquil_db_traits::AccountStatus::Active,
    )
    .await
    {
        warn!("Failed to sequence account event for {}: {}", did, e);
    }

    let profile_record = json!({
        "$type": "app.bsky.actor.profile",
        "displayName": handle
    });
    if let Err(e) = tranquil_pds::repo_ops::create_record_internal(
        &state,
        &did,
        &tranquil_pds::types::PROFILE_COLLECTION,
        &tranquil_pds::types::PROFILE_RKEY,
        &profile_record,
    )
    .await
    {
        warn!("Failed to create default profile for {}: {}", did, e);
    }

    let _ = state
        .delegation_repo
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

    Ok(Json(CreateDelegatedAccountResponse { did, handle }).into_response())
}

#[derive(Debug, Deserialize)]
pub struct ResolveControllerParams {
    pub identifier: String,
}

pub async fn resolve_controller(
    State(state): State<AppState>,
    Query(params): Query<ResolveControllerParams>,
) -> Result<Response, ApiError> {
    let identifier = params.identifier.trim().trim_start_matches('@');

    let did: Did = if identifier.starts_with("did:") {
        identifier.parse().map_err(|_| ApiError::ControllerNotFound)?
    } else {
        let local_handle: Option<Handle> = identifier.parse().ok();
        let local_user = match local_handle {
            Some(ref h) => state.user_repo.get_by_handle(h).await.ok().flatten(),
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

    Ok(Json(resolved).into_response())
}

