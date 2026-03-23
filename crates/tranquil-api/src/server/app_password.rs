use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tranquil_db_traits::AppPasswordCreate;
use tranquil_pds::api::EmptyResponse;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::auth::{Auth, NotTakendown, Permissive, generate_app_password};
use tranquil_pds::delegation::{DelegationActionType, intersect_scopes};
use tranquil_pds::rate_limit::{AppPasswordLimit, RateLimited};
use tranquil_pds::state::AppState;

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
    auth: Auth<Permissive>,
) -> Result<Json<ListAppPasswordsOutput>, ApiError> {
    let user = state
        .repos
        .user
        .get_by_did(&auth.did)
        .await
        .log_db_err("getting user")?
        .ok_or(ApiError::AccountNotFound)?;

    let rows = state
        .repos
        .session
        .list_app_passwords(user.id)
        .await
        .log_db_err("listing app passwords")?;
    let passwords: Vec<AppPassword> = rows
        .iter()
        .map(|row| AppPassword {
            name: row.name.clone(),
            created_at: row.created_at.to_rfc3339(),
            privileged: row.privilege.is_privileged(),
            scopes: row.scopes.clone(),
            created_by_controller: row
                .created_by_controller_did
                .as_ref()
                .map(|d| d.to_string()),
        })
        .collect();
    Ok(Json(ListAppPasswordsOutput { passwords }))
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
    _rate_limit: RateLimited<AppPasswordLimit>,
    auth: Auth<NotTakendown>,
    Json(input): Json<CreateAppPasswordInput>,
) -> Result<Json<CreateAppPasswordOutput>, ApiError> {
    let user = state
        .repos
        .user
        .get_by_did(&auth.did)
        .await
        .log_db_err("getting user")?
        .ok_or(ApiError::AccountNotFound)?;

    let name = input.name.trim();
    if name.is_empty() {
        return Err(ApiError::InvalidRequest("name is required".into()));
    }

    if state
        .repos
        .session
        .get_app_password_by_name(user.id, name)
        .await
        .log_db_err("checking app password")?
        .is_some()
    {
        return Err(ApiError::DuplicateAppPassword);
    }

    let (final_scopes, controller_did) = if let Some(ref controller) = auth.controller_did {
        let grant = state
            .repos
            .delegation
            .get_delegation(&auth.did, controller)
            .await
            .ok()
            .flatten();
        let granted_scopes = grant.map(|g| g.granted_scopes).unwrap_or_default();

        let requested = input.scopes.as_deref().unwrap_or("atproto");
        let intersected = intersect_scopes(requested, granted_scopes.as_str());

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

    let password_hash = crate::common::hash_password_async(&password).await?;

    let privilege = tranquil_db_traits::AppPasswordPrivilege::from_privileged_flag(
        input.privileged.unwrap_or(false),
    );
    let created_at = chrono::Utc::now();

    let create_data = AppPasswordCreate {
        user_id: user.id,
        name: name.to_string(),
        password_hash,
        privilege,
        scopes: final_scopes.clone(),
        created_by_controller_did: controller_did.clone(),
    };

    state
        .repos
        .session
        .create_app_password(&create_data)
        .await
        .log_db_err("creating app password")?;

    if let Some(ref controller) = controller_did {
        let _ = state
            .repos
            .delegation
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
        privileged: privilege.is_privileged(),
        scopes: final_scopes,
    }))
}

#[derive(Deserialize)]
pub struct RevokeAppPasswordInput {
    pub name: String,
}

pub async fn revoke_app_password(
    State(state): State<AppState>,
    auth: Auth<Permissive>,
    Json(input): Json<RevokeAppPasswordInput>,
) -> Result<Json<EmptyResponse>, ApiError> {
    let user = state
        .repos
        .user
        .get_by_did(&auth.did)
        .await
        .log_db_err("getting user")?
        .ok_or(ApiError::AccountNotFound)?;

    let name = input.name.trim();
    if name.is_empty() {
        return Err(ApiError::InvalidRequest("name is required".into()));
    }

    let sessions_to_invalidate = state
        .repos
        .session
        .get_session_jtis_by_app_password(&auth.did, name)
        .await
        .unwrap_or_default();

    state
        .repos
        .session
        .delete_sessions_by_app_password(&auth.did, name)
        .await
        .log_db_err("revoking sessions for app password")?;

    futures::future::join_all(sessions_to_invalidate.iter().map(|jti| {
        let cache_key = tranquil_pds::cache_keys::session_key(&auth.did, jti);
        let cache = state.cache.clone();
        async move {
            let _ = cache.delete(&cache_key).await;
        }
    }))
    .await;

    state
        .repos
        .session
        .delete_app_password(user.id, name)
        .await
        .log_db_err("revoking app password")?;

    Ok(Json(EmptyResponse {}))
}
