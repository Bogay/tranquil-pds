use crate::api::error::ApiError;
use crate::api::repo::record::utils::create_signed_commit;
use crate::auth::{Active, Auth};
use crate::delegation::{DelegationActionType, SCOPE_PRESETS, scopes};
use crate::state::{AppState, RateLimitKind};
use crate::types::{Did, Handle, Nsid, Rkey};
use crate::util::extract_client_ip;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use jacquard_common::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::{mst::Mst, storage::BlockStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControllerInfo {
    pub did: Did,
    pub handle: Handle,
    pub granted_scopes: String,
    pub granted_at: chrono::DateTime<chrono::Utc>,
    pub is_active: bool,
}

#[derive(Debug, Serialize)]
pub struct ListControllersResponse {
    pub controllers: Vec<ControllerInfo>,
}

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

    Ok(Json(ListControllersResponse {
        controllers: controllers
            .into_iter()
            .map(|c| ControllerInfo {
                did: c.did,
                handle: c.handle,
                granted_scopes: c.granted_scopes,
                granted_at: c.granted_at,
                is_active: c.is_active,
            })
            .collect(),
    })
    .into_response())
}

#[derive(Debug, Deserialize)]
pub struct AddControllerInput {
    pub controller_did: Did,
    pub granted_scopes: String,
}

pub async fn add_controller(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<AddControllerInput>,
) -> Result<Response, ApiError> {
    if let Err(e) = scopes::validate_delegation_scopes(&input.granted_scopes) {
        return Ok(ApiError::InvalidScopes(e).into_response());
    }

    let controller_exists = state
        .user_repo
        .get_by_did(&input.controller_did)
        .await
        .ok()
        .flatten()
        .is_some();

    if !controller_exists {
        return Ok(ApiError::ControllerNotFound.into_response());
    }

    match state.delegation_repo.controls_any_accounts(&auth.did).await {
        Ok(true) => {
            return Ok(ApiError::InvalidDelegation(
                "Cannot add controllers to an account that controls other accounts".into(),
            )
            .into_response());
        }
        Err(e) => {
            tracing::error!("Failed to check delegation status: {:?}", e);
            return Ok(
                ApiError::InternalError(Some("Failed to verify delegation status".into()))
                    .into_response(),
            );
        }
        Ok(false) => {}
    }

    match state
        .delegation_repo
        .has_any_controllers(&input.controller_did)
        .await
    {
        Ok(true) => {
            return Ok(ApiError::InvalidDelegation(
                "Cannot add a controlled account as a controller".into(),
            )
            .into_response());
        }
        Err(e) => {
            tracing::error!("Failed to check controller status: {:?}", e);
            return Ok(
                ApiError::InternalError(Some("Failed to verify controller status".into()))
                    .into_response(),
            );
        }
        Ok(false) => {}
    }

    match state
        .delegation_repo
        .create_delegation(
            &auth.did,
            &input.controller_did,
            &input.granted_scopes,
            &auth.did,
        )
        .await
    {
        Ok(_) => {
            let _ = state
                .delegation_repo
                .log_delegation_action(
                    &auth.did,
                    &auth.did,
                    Some(&input.controller_did),
                    DelegationActionType::GrantCreated,
                    Some(serde_json::json!({
                        "granted_scopes": input.granted_scopes
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
                .unwrap_or(0) as usize;

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
    pub granted_scopes: String,
}

pub async fn update_controller_scopes(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<UpdateControllerScopesInput>,
) -> Result<Response, ApiError> {
    if let Err(e) = scopes::validate_delegation_scopes(&input.granted_scopes) {
        return Ok(ApiError::InvalidScopes(e).into_response());
    }

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
                        "new_scopes": input.granted_scopes
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedAccountInfo {
    pub did: Did,
    pub handle: Handle,
    pub granted_scopes: String,
    pub granted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ListControlledAccountsResponse {
    pub accounts: Vec<DelegatedAccountInfo>,
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

    Ok(Json(ListControlledAccountsResponse {
        accounts: accounts
            .into_iter()
            .map(|a| DelegatedAccountInfo {
                did: a.did,
                handle: a.handle,
                granted_scopes: a.granted_scopes,
                granted_at: a.granted_at,
            })
            .collect(),
    })
    .into_response())
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogEntry {
    pub id: String,
    pub delegated_did: Did,
    pub actor_did: Did,
    pub controller_did: Option<Did>,
    pub action_type: String,
    pub action_details: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct GetAuditLogResponse {
    pub entries: Vec<AuditLogEntry>,
    pub total: i64,
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

    Ok(Json(GetAuditLogResponse {
        entries: entries
            .into_iter()
            .map(|e| AuditLogEntry {
                id: e.id.to_string(),
                delegated_did: e.delegated_did,
                actor_did: e.actor_did,
                controller_did: e.controller_did,
                action_type: format!("{:?}", e.action_type),
                action_details: e.action_details,
                created_at: e.created_at,
            })
            .collect(),
        total,
    })
    .into_response())
}

#[derive(Debug, Serialize)]
pub struct ScopePresetInfo {
    pub name: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub scopes: &'static str,
}

#[derive(Debug, Serialize)]
pub struct GetScopePresetsResponse {
    pub presets: Vec<ScopePresetInfo>,
}

pub async fn get_scope_presets() -> Response {
    Json(GetScopePresetsResponse {
        presets: SCOPE_PRESETS
            .iter()
            .map(|p| ScopePresetInfo {
                name: p.name,
                label: p.label,
                description: p.description,
                scopes: p.scopes,
            })
            .collect(),
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDelegatedAccountInput {
    pub handle: String,
    pub email: Option<String>,
    pub controller_scopes: String,
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
    headers: HeaderMap,
    auth: Auth<Active>,
    Json(input): Json<CreateDelegatedAccountInput>,
) -> Result<Response, ApiError> {
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::AccountCreation, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Delegated account creation rate limit exceeded");
        return Ok(ApiError::RateLimitExceeded(Some(
            "Too many account creation attempts. Please try again later.".into(),
        ))
        .into_response());
    }

    if let Err(e) = scopes::validate_delegation_scopes(&input.controller_scopes) {
        return Ok(ApiError::InvalidScopes(e).into_response());
    }

    match state.delegation_repo.has_any_controllers(&auth.did).await {
        Ok(true) => {
            return Ok(ApiError::InvalidDelegation(
                "Cannot create delegated accounts from a controlled account".into(),
            )
            .into_response());
        }
        Err(e) => {
            tracing::error!("Failed to check controller status: {:?}", e);
            return Ok(
                ApiError::InternalError(Some("Failed to verify controller status".into()))
                    .into_response(),
            );
        }
        Ok(false) => {}
    }

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let hostname_for_handles = hostname.split(':').next().unwrap_or(&hostname);
    let pds_suffix = format!(".{}", hostname_for_handles);

    let handle = if !input.handle.contains('.') || input.handle.ends_with(&pds_suffix) {
        let handle_to_validate = if input.handle.ends_with(&pds_suffix) {
            input
                .handle
                .strip_suffix(&pds_suffix)
                .unwrap_or(&input.handle)
        } else {
            &input.handle
        };
        match crate::api::validation::validate_short_handle(handle_to_validate) {
            Ok(h) => format!("{}.{}", h, hostname_for_handles),
            Err(e) => {
                return Ok(ApiError::InvalidRequest(e.to_string()).into_response());
            }
        }
    } else {
        input.handle.to_lowercase()
    };

    let email = input
        .email
        .as_ref()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(ref email) = email
        && !crate::api::validation::is_valid_email(email)
    {
        return Ok(ApiError::InvalidEmail.into_response());
    }

    if let Some(ref code) = input.invite_code {
        let valid = state
            .infra_repo
            .is_invite_code_valid(code)
            .await
            .unwrap_or(false);

        if !valid {
            return Ok(ApiError::InvalidInviteCode.into_response());
        }
    } else {
        let invite_required = std::env::var("INVITE_CODE_REQUIRED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        if invite_required {
            return Ok(ApiError::InviteCodeRequired.into_response());
        }
    }

    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    let pds_endpoint = format!("https://{}", hostname);
    let secret_key = k256::SecretKey::random(&mut OsRng);
    let secret_key_bytes = secret_key.to_bytes().to_vec();

    let signing_key = match SigningKey::from_slice(&secret_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            error!("Error creating signing key: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };

    let rotation_key = std::env::var("PLC_ROTATION_KEY")
        .unwrap_or_else(|_| crate::plc::signing_key_to_did_key(&signing_key));

    let genesis_result = match crate::plc::create_genesis_operation(
        &signing_key,
        &rotation_key,
        &handle,
        &pds_endpoint,
    ) {
        Ok(r) => r,
        Err(e) => {
            error!("Error creating PLC genesis operation: {:?}", e);
            return Ok(
                ApiError::InternalError(Some("Failed to create PLC operation".into()))
                    .into_response(),
            );
        }
    };

    let plc_client = crate::plc::PlcClient::with_cache(None, Some(state.cache.clone()));
    if let Err(e) = plc_client
        .send_operation(&genesis_result.did, &genesis_result.signed_operation)
        .await
    {
        error!("Failed to submit PLC genesis operation: {:?}", e);
        return Ok(ApiError::UpstreamErrorMsg(format!(
            "Failed to register DID with PLC directory: {}",
            e
        ))
        .into_response());
    }

    let did = Did::new_unchecked(&genesis_result.did);
    let handle = Handle::new_unchecked(&handle);
    info!(did = %did, handle = %handle, controller = %&auth.did, "Created DID for delegated account");

    let encrypted_key_bytes = match crate::config::encrypt_key(&secret_key_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Error encrypting signing key: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };

    let mst = Mst::new(Arc::new(state.block_store.clone()));
    let mst_root = match mst.persist().await {
        Ok(c) => c,
        Err(e) => {
            error!("Error persisting MST: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };
    let rev = Tid::now(LimitedU32::MIN);
    let (commit_bytes, _sig) =
        match create_signed_commit(&did, mst_root, rev.as_ref(), None, &signing_key) {
            Ok(result) => result,
            Err(e) => {
                error!("Error creating genesis commit: {:?}", e);
                return Ok(ApiError::InternalError(None).into_response());
            }
        };
    let commit_cid: cid::Cid = match state.block_store.put(&commit_bytes).await {
        Ok(c) => c,
        Err(e) => {
            error!("Error saving genesis commit: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };
    let genesis_block_cids = vec![mst_root.to_bytes(), commit_cid.to_bytes()];

    let create_input = tranquil_db_traits::CreateDelegatedAccountInput {
        handle: handle.clone(),
        email: email.clone(),
        did: did.clone(),
        controller_did: auth.did.clone(),
        controller_scopes: input.controller_scopes.clone(),
        encrypted_key_bytes,
        encryption_version: crate::config::ENCRYPTION_VERSION,
        commit_cid: commit_cid.to_string(),
        repo_rev: rev.as_ref().to_string(),
        genesis_block_cids,
        invite_code: input.invite_code.clone(),
    };

    let _user_id = match state
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

    if let Err(e) =
        crate::api::repo::record::sequence_identity_event(&state, &did, Some(&handle)).await
    {
        warn!("Failed to sequence identity event for {}: {}", did, e);
    }
    if let Err(e) = crate::api::repo::record::sequence_account_event(&state, &did, true, None).await
    {
        warn!("Failed to sequence account event for {}: {}", did, e);
    }

    let profile_record = json!({
        "$type": "app.bsky.actor.profile",
        "displayName": handle
    });
    let profile_collection = Nsid::new_unchecked("app.bsky.actor.profile");
    let profile_rkey = Rkey::new_unchecked("self");
    if let Err(e) = crate::api::repo::record::create_record_internal(
        &state,
        &did,
        &profile_collection,
        &profile_rkey,
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
                "granted_scopes": input.controller_scopes
            })),
            None,
            None,
        )
        .await;

    info!(did = %did, handle = %handle, controller = %&auth.did, "Delegated account created");

    Ok(Json(CreateDelegatedAccountResponse { did, handle }).into_response())
}
