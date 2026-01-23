use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::{Active, Auth, generate_app_password};
use crate::delegation::{DelegationActionType, intersect_scopes};
use crate::state::{AppState, RateLimitKind};
use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, warn};
use tranquil_db_traits::AppPasswordCreate;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPassword {
    pub name: String,
    pub created_at: String,
    pub privileged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by_controller: Option<String>,
}

#[derive(Serialize)]
pub struct ListAppPasswordsOutput {
    pub passwords: Vec<AppPassword>,
}

pub async fn list_app_passwords(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let user = state
        .user_repo
        .get_by_did(&auth.did)
        .await
        .map_err(|e| {
            error!("DB error getting user: {:?}", e);
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::AccountNotFound)?;

    let rows = state
        .session_repo
        .list_app_passwords(user.id)
        .await
        .map_err(|e| {
            error!("DB error listing app passwords: {:?}", e);
            ApiError::InternalError(None)
        })?;
    let passwords: Vec<AppPassword> = rows
        .iter()
        .map(|row| AppPassword {
            name: row.name.clone(),
            created_at: row.created_at.to_rfc3339(),
            privileged: row.privileged,
            scopes: row.scopes.clone(),
            created_by_controller: row
                .created_by_controller_did
                .as_ref()
                .map(|d| d.to_string()),
        })
        .collect();
    Ok(Json(ListAppPasswordsOutput { passwords }).into_response())
}

#[derive(Deserialize)]
pub struct CreateAppPasswordInput {
    pub name: String,
    pub privileged: Option<bool>,
    pub scopes: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAppPasswordOutput {
    pub name: String,
    pub password: String,
    pub created_at: String,
    pub privileged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<String>,
}

pub async fn create_app_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Auth<Active>,
    Json(input): Json<CreateAppPasswordInput>,
) -> Result<Response, ApiError> {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::AppPassword, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "App password creation rate limit exceeded");
        return Err(ApiError::RateLimitExceeded(None));
    }

    let user = state
        .user_repo
        .get_by_did(&auth.did)
        .await
        .map_err(|e| {
            error!("DB error getting user: {:?}", e);
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::AccountNotFound)?;

    let name = input.name.trim();
    if name.is_empty() {
        return Err(ApiError::InvalidRequest("name is required".into()));
    }

    if state
        .session_repo
        .get_app_password_by_name(user.id, name)
        .await
        .map_err(|e| {
            error!("DB error checking app password: {:?}", e);
            ApiError::InternalError(None)
        })?
        .is_some()
    {
        return Err(ApiError::DuplicateAppPassword);
    }

    let (final_scopes, controller_did) = if let Some(ref controller) = auth.controller_did {
        let grant = state
            .delegation_repo
            .get_delegation(&auth.did, controller)
            .await
            .ok()
            .flatten();
        let granted_scopes = grant.map(|g| g.granted_scopes).unwrap_or_default();

        let requested = input.scopes.as_deref().unwrap_or("atproto");
        let intersected = intersect_scopes(requested, &granted_scopes);

        if intersected.is_empty() && !granted_scopes.is_empty() {
            return Err(ApiError::InsufficientScope(None));
        }

        let scope_result = if intersected.is_empty() {
            None
        } else {
            Some(intersected)
        };
        (scope_result, Some(controller.clone()))
    } else {
        (input.scopes.clone(), None)
    };

    let password = generate_app_password();

    let password_clone = password.clone();
    let password_hash =
        tokio::task::spawn_blocking(move || bcrypt::hash(&password_clone, bcrypt::DEFAULT_COST))
            .await
            .map_err(|e| {
                error!("Failed to spawn blocking task: {:?}", e);
                ApiError::InternalError(None)
            })?
            .map_err(|e| {
                error!("Failed to hash password: {:?}", e);
                ApiError::InternalError(None)
            })?;

    let privileged = input.privileged.unwrap_or(false);
    let created_at = chrono::Utc::now();

    let create_data = AppPasswordCreate {
        user_id: user.id,
        name: name.to_string(),
        password_hash,
        privileged,
        scopes: final_scopes.clone(),
        created_by_controller_did: controller_did.clone(),
    };

    state
        .session_repo
        .create_app_password(&create_data)
        .await
        .map_err(|e| {
            error!("DB error creating app password: {:?}", e);
            ApiError::InternalError(None)
        })?;

    if let Some(ref controller) = controller_did {
        let _ = state
            .delegation_repo
            .log_delegation_action(
                &auth.did,
                controller,
                Some(controller),
                DelegationActionType::AccountAction,
                Some(json!({
                    "action": "create_app_password",
                    "name": name,
                    "scopes": final_scopes
                })),
                None,
                None,
            )
            .await;
    }
    Ok(Json(CreateAppPasswordOutput {
        name: name.to_string(),
        password,
        created_at: created_at.to_rfc3339(),
        privileged,
        scopes: final_scopes,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct RevokeAppPasswordInput {
    pub name: String,
}

pub async fn revoke_app_password(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<RevokeAppPasswordInput>,
) -> Result<Response, ApiError> {
    let user = state
        .user_repo
        .get_by_did(&auth.did)
        .await
        .map_err(|e| {
            error!("DB error getting user: {:?}", e);
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::AccountNotFound)?;

    let name = input.name.trim();
    if name.is_empty() {
        return Err(ApiError::InvalidRequest("name is required".into()));
    }

    let sessions_to_invalidate = state
        .session_repo
        .get_session_jtis_by_app_password(&auth.did, name)
        .await
        .unwrap_or_default();

    state
        .session_repo
        .delete_sessions_by_app_password(&auth.did, name)
        .await
        .map_err(|e| {
            error!("DB error revoking sessions for app password: {:?}", e);
            ApiError::InternalError(None)
        })?;

    futures::future::join_all(sessions_to_invalidate.iter().map(|jti| {
        let cache_key = format!("auth:session:{}:{}", &auth.did, jti);
        let cache = state.cache.clone();
        async move {
            let _ = cache.delete(&cache_key).await;
        }
    }))
    .await;

    state
        .session_repo
        .delete_app_password(user.id, name)
        .await
        .map_err(|e| {
            error!("DB error revoking app password: {:?}", e);
            ApiError::InternalError(None)
        })?;

    Ok(EmptyResponse::ok().into_response())
}
