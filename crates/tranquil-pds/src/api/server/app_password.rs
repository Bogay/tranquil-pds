use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::{BearerAuth, generate_app_password};
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
    BearerAuth(auth_user): BearerAuth,
) -> Response {
    let user = match state.user_repo.get_by_did(&auth_user.did).await {
        Ok(Some(u)) => u,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error getting user: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    match state.session_repo.list_app_passwords(user.id).await {
        Ok(rows) => {
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
            Json(ListAppPasswordsOutput { passwords }).into_response()
        }
        Err(e) => {
            error!("DB error listing app passwords: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
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
    BearerAuth(auth_user): BearerAuth,
    Json(input): Json<CreateAppPasswordInput>,
) -> Response {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::AppPassword, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "App password creation rate limit exceeded");
        return ApiError::RateLimitExceeded(None).into_response();
    }

    let user = match state.user_repo.get_by_did(&auth_user.did).await {
        Ok(Some(u)) => u,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error getting user: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let name = input.name.trim();
    if name.is_empty() {
        return ApiError::InvalidRequest("name is required".into()).into_response();
    }

    match state
        .session_repo
        .get_app_password_by_name(user.id, name)
        .await
    {
        Ok(Some(_)) => return ApiError::DuplicateAppPassword.into_response(),
        Err(e) => {
            error!("DB error checking app password: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
        Ok(None) => {}
    }

    let (final_scopes, controller_did) = if let Some(ref controller) = auth_user.controller_did {
        let grant = state
            .delegation_repo
            .get_delegation(&auth_user.did, controller)
            .await
            .ok()
            .flatten();
        let granted_scopes = grant.map(|g| g.granted_scopes).unwrap_or_default();

        let requested = input.scopes.as_deref().unwrap_or("atproto");
        let intersected = intersect_scopes(requested, &granted_scopes);

        if intersected.is_empty() && !granted_scopes.is_empty() {
            return ApiError::InsufficientScope(None).into_response();
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
    let password_hash = match tokio::task::spawn_blocking(move || {
        bcrypt::hash(&password_clone, bcrypt::DEFAULT_COST)
    })
    .await
    {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            error!("Failed to hash password: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
        Err(e) => {
            error!("Failed to spawn blocking task: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

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

    match state.session_repo.create_app_password(&create_data).await {
        Ok(_) => {
            if let Some(ref controller) = controller_did {
                let _ = state
                    .delegation_repo
                    .log_delegation_action(
                        &auth_user.did,
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
            Json(CreateAppPasswordOutput {
                name: name.to_string(),
                password,
                created_at: created_at.to_rfc3339(),
                privileged,
                scopes: final_scopes,
            })
            .into_response()
        }
        Err(e) => {
            error!("DB error creating app password: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct RevokeAppPasswordInput {
    pub name: String,
}

pub async fn revoke_app_password(
    State(state): State<AppState>,
    BearerAuth(auth_user): BearerAuth,
    Json(input): Json<RevokeAppPasswordInput>,
) -> Response {
    let user = match state.user_repo.get_by_did(&auth_user.did).await {
        Ok(Some(u)) => u,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error getting user: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let name = input.name.trim();
    if name.is_empty() {
        return ApiError::InvalidRequest("name is required".into()).into_response();
    }

    let sessions_to_invalidate = state
        .session_repo
        .get_session_jtis_by_app_password(&auth_user.did, name)
        .await
        .unwrap_or_default();

    if let Err(e) = state
        .session_repo
        .delete_sessions_by_app_password(&auth_user.did, name)
        .await
    {
        error!("DB error revoking sessions for app password: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    futures::future::join_all(sessions_to_invalidate.iter().map(|jti| {
        let cache_key = format!("auth:session:{}:{}", &auth_user.did, jti);
        let cache = state.cache.clone();
        async move {
            let _ = cache.delete(&cache_key).await;
        }
    }))
    .await;

    if let Err(e) = state.session_repo.delete_app_password(user.id, name).await {
        error!("DB error revoking app password: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    EmptyResponse::ok().into_response()
}
