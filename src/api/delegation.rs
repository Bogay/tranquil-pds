use crate::api::repo::record::utils::create_signed_commit;
use crate::auth::BearerAuth;
use crate::delegation::{self, DelegationActionType};
use crate::oauth::db as oauth_db;
use crate::state::{AppState, RateLimitKind};
use crate::util::extract_client_ip;
use crate::validation::is_valid_did;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use jacquard::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::{mst::Mst, storage::BlockStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControllerInfo {
    pub did: String,
    pub handle: String,
    pub granted_scopes: String,
    pub granted_at: chrono::DateTime<chrono::Utc>,
    pub is_active: bool,
}

#[derive(Debug, Serialize)]
pub struct ListControllersResponse {
    pub controllers: Vec<ControllerInfo>,
}

pub async fn list_controllers(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let controllers = match delegation::get_delegations_for_account(&state.db, &auth.0.did).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to list controllers: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "ServerError",
                    "message": "Failed to list controllers"
                })),
            )
                .into_response();
        }
    };

    Json(ListControllersResponse {
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
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct AddControllerInput {
    pub controller_did: String,
    pub granted_scopes: String,
}

pub async fn add_controller(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<AddControllerInput>,
) -> Response {
    if !is_valid_did(&input.controller_did) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "InvalidRequest",
                "message": "Invalid DID format"
            })),
        )
            .into_response();
    }

    if let Err(e) = delegation::scopes::validate_delegation_scopes(&input.granted_scopes) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "InvalidScopes",
                "message": e
            })),
        )
            .into_response();
    }

    let controller_exists: bool = sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM users WHERE did = $1) as "exists!""#,
        input.controller_did
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !controller_exists {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "ControllerNotFound",
                "message": "Controller account not found"
            })),
        )
            .into_response();
    }

    match delegation::controls_any_accounts(&state.db, &auth.0.did).await {
        Ok(true) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "InvalidDelegation",
                    "message": "Cannot add controllers to an account that controls other accounts"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to check delegation status: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "ServerError",
                    "message": "Failed to verify delegation status"
                })),
            )
                .into_response();
        }
        Ok(false) => {}
    }

    match delegation::has_any_controllers(&state.db, &input.controller_did).await {
        Ok(true) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "InvalidDelegation",
                    "message": "Cannot add a controlled account as a controller"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to check controller status: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "ServerError",
                    "message": "Failed to verify controller status"
                })),
            )
                .into_response();
        }
        Ok(false) => {}
    }

    match delegation::create_delegation(
        &state.db,
        &auth.0.did,
        &input.controller_did,
        &input.granted_scopes,
        &auth.0.did,
    )
    .await
    {
        Ok(_) => {
            let _ = delegation::log_delegation_action(
                &state.db,
                &auth.0.did,
                &auth.0.did,
                Some(&input.controller_did),
                DelegationActionType::GrantCreated,
                Some(serde_json::json!({
                    "granted_scopes": input.granted_scopes
                })),
                None,
                None,
            )
            .await;

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to add controller: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "ServerError",
                    "message": "Failed to add controller"
                })),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RemoveControllerInput {
    pub controller_did: String,
}

pub async fn remove_controller(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<RemoveControllerInput>,
) -> Response {
    if !is_valid_did(&input.controller_did) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "InvalidRequest",
                "message": "Invalid DID format"
            })),
        )
            .into_response();
    }

    match delegation::revoke_delegation(&state.db, &auth.0.did, &input.controller_did, &auth.0.did)
        .await
    {
        Ok(true) => {
            let revoked_app_passwords = sqlx::query_scalar!(
                r#"DELETE FROM app_passwords
                   WHERE user_id = (SELECT id FROM users WHERE did = $1)
                   AND created_by_controller_did = $2
                   RETURNING id"#,
                auth.0.did,
                input.controller_did
            )
            .fetch_all(&state.db)
            .await
            .map(|r| r.len())
            .unwrap_or(0);

            let revoked_oauth_tokens = oauth_db::revoke_tokens_for_controller(
                &state.db,
                &auth.0.did,
                &input.controller_did,
            )
            .await
            .unwrap_or(0);

            let _ = delegation::log_delegation_action(
                &state.db,
                &auth.0.did,
                &auth.0.did,
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

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true
                })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "DelegationNotFound",
                "message": "No active delegation found for this controller"
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to remove controller: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "ServerError",
                    "message": "Failed to remove controller"
                })),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateControllerScopesInput {
    pub controller_did: String,
    pub granted_scopes: String,
}

pub async fn update_controller_scopes(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<UpdateControllerScopesInput>,
) -> Response {
    if !is_valid_did(&input.controller_did) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "InvalidRequest",
                "message": "Invalid DID format"
            })),
        )
            .into_response();
    }

    if let Err(e) = delegation::scopes::validate_delegation_scopes(&input.granted_scopes) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "InvalidScopes",
                "message": e
            })),
        )
            .into_response();
    }

    match delegation::update_delegation_scopes(
        &state.db,
        &auth.0.did,
        &input.controller_did,
        &input.granted_scopes,
    )
    .await
    {
        Ok(true) => {
            let _ = delegation::log_delegation_action(
                &state.db,
                &auth.0.did,
                &auth.0.did,
                Some(&input.controller_did),
                DelegationActionType::ScopesModified,
                Some(serde_json::json!({
                    "new_scopes": input.granted_scopes
                })),
                None,
                None,
            )
            .await;

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true
                })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "DelegationNotFound",
                "message": "No active delegation found for this controller"
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to update controller scopes: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "ServerError",
                    "message": "Failed to update controller scopes"
                })),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedAccountInfo {
    pub did: String,
    pub handle: String,
    pub granted_scopes: String,
    pub granted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ListControlledAccountsResponse {
    pub accounts: Vec<DelegatedAccountInfo>,
}

pub async fn list_controlled_accounts(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let accounts = match delegation::get_accounts_controlled_by(&state.db, &auth.0.did).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Failed to list controlled accounts: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "ServerError",
                    "message": "Failed to list controlled accounts"
                })),
            )
                .into_response();
        }
    };

    Json(ListControlledAccountsResponse {
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
    .into_response()
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
    pub delegated_did: String,
    pub actor_did: String,
    pub controller_did: Option<String>,
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
    auth: BearerAuth,
    Query(params): Query<AuditLogParams>,
) -> Response {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let entries =
        match delegation::audit::get_audit_log_for_account(&state.db, &auth.0.did, limit, offset)
            .await
        {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("Failed to get audit log: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "ServerError",
                        "message": "Failed to get audit log"
                    })),
                )
                    .into_response();
            }
        };

    let total = delegation::audit::count_audit_log_entries(&state.db, &auth.0.did)
        .await
        .unwrap_or_default();

    Json(GetAuditLogResponse {
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
    .into_response()
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
        presets: delegation::SCOPE_PRESETS
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
    pub did: String,
    pub handle: String,
}

pub async fn create_delegated_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: BearerAuth,
    Json(input): Json<CreateDelegatedAccountInput>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::AccountCreation, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Delegated account creation rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "RateLimitExceeded",
                "message": "Too many account creation attempts. Please try again later."
            })),
        )
            .into_response();
    }

    if let Err(e) = delegation::scopes::validate_delegation_scopes(&input.controller_scopes) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidScopes",
                "message": e
            })),
        )
            .into_response();
    }

    match delegation::has_any_controllers(&state.db, &auth.0.did).await {
        Ok(true) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidDelegation",
                    "message": "Cannot create delegated accounts from a controlled account"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to check controller status: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "ServerError",
                    "message": "Failed to verify controller status"
                })),
            )
                .into_response();
        }
        Ok(false) => {}
    }

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_suffix = format!(".{}", hostname);

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
            Ok(h) => format!("{}.{}", h, hostname),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidHandle", "message": e.to_string()})),
                )
                    .into_response();
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
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidEmail", "message": "Invalid email format"})),
        )
            .into_response();
    }

    if let Some(ref code) = input.invite_code {
        let valid = sqlx::query_scalar!(
            "SELECT available_uses > 0 AND NOT disabled FROM invite_codes WHERE code = $1",
            code
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or(Some(false));

        if valid != Some(true) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidInviteCode", "message": "Invalid or expired invite code"})),
            )
                .into_response();
        }
    } else {
        let invite_required = std::env::var("INVITE_CODE_REQUIRED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        if invite_required {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InviteCodeRequired", "message": "An invite code is required to create an account"})),
            )
                .into_response();
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({"error": "InternalError", "message": "Failed to create PLC operation"}),
                ),
            )
                .into_response();
        }
    };

    let plc_client = crate::plc::PlcClient::new(None);
    if let Err(e) = plc_client
        .send_operation(&genesis_result.did, &genesis_result.signed_operation)
        .await
    {
        error!("Failed to submit PLC genesis operation: {:?}", e);
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": "UpstreamError",
                "message": format!("Failed to register DID with PLC directory: {}", e)
            })),
        )
            .into_response();
    }

    let did = genesis_result.did;
    info!(did = %did, handle = %handle, controller = %auth.0.did, "Created DID for delegated account");

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Error starting transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let user_insert: Result<(uuid::Uuid,), _> = sqlx::query_as(
        r#"INSERT INTO users (
            handle, email, did, password_hash, password_required,
            account_type, preferred_comms_channel
        ) VALUES ($1, $2, $3, NULL, FALSE, 'delegated'::account_type, 'email'::comms_channel) RETURNING id"#,
    )
    .bind(&handle)
    .bind(&email)
    .bind(&did)
    .fetch_one(&mut *tx)
    .await;

    let user_id = match user_insert {
        Ok((id,)) => id,
        Err(e) => {
            if let Some(db_err) = e.as_database_error()
                && db_err.code().as_deref() == Some("23505")
            {
                let constraint = db_err.constraint().unwrap_or("");
                if constraint.contains("handle") {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "HandleNotAvailable", "message": "Handle already taken"})),
                    )
                        .into_response();
                } else if constraint.contains("email") {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(
                            json!({"error": "InvalidEmail", "message": "Email already registered"}),
                        ),
                    )
                        .into_response();
                }
            }
            error!("Error inserting user: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let encrypted_key_bytes = match crate::config::encrypt_key(&secret_key_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Error encrypting signing key: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(e) = sqlx::query!(
        "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, NOW())",
        user_id,
        &encrypted_key_bytes[..],
        crate::config::ENCRYPTION_VERSION
    )
    .execute(&mut *tx)
    .await
    {
        error!("Error inserting user key: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Err(e) = sqlx::query!(
        r#"INSERT INTO account_delegations (delegated_did, controller_did, granted_scopes, granted_by)
           VALUES ($1, $2, $3, $4)"#,
        did,
        auth.0.did,
        input.controller_scopes,
        auth.0.did
    )
    .execute(&mut *tx)
    .await
    {
        error!("Error creating initial delegation: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let mst = Mst::new(Arc::new(state.block_store.clone()));
    let mst_root = match mst.persist().await {
        Ok(c) => c,
        Err(e) => {
            error!("Error persisting MST: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let rev = Tid::now(LimitedU32::MIN);
    let (commit_bytes, _sig) =
        match create_signed_commit(&did, mst_root, rev.as_ref(), None, &signing_key) {
            Ok(result) => result,
            Err(e) => {
                error!("Error creating genesis commit: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        };
    let commit_cid: cid::Cid = match state.block_store.put(&commit_bytes).await {
        Ok(c) => c,
        Err(e) => {
            error!("Error saving genesis commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let commit_cid_str = commit_cid.to_string();
    if let Err(e) = sqlx::query!(
        "INSERT INTO repos (user_id, repo_root_cid) VALUES ($1, $2)",
        user_id,
        commit_cid_str
    )
    .execute(&mut *tx)
    .await
    {
        error!("Error inserting repo: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Some(ref code) = input.invite_code {
        let _ = sqlx::query!(
            "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
            code
        )
        .execute(&mut *tx)
        .await;

        let _ = sqlx::query!(
            "INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)",
            code,
            user_id
        )
        .execute(&mut *tx)
        .await;
    }

    if let Err(e) = tx.commit().await {
        error!("Error committing transaction: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

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
    if let Err(e) = crate::api::repo::record::create_record_internal(
        &state,
        &did,
        "app.bsky.actor.profile",
        "self",
        &profile_record,
    )
    .await
    {
        warn!("Failed to create default profile for {}: {}", did, e);
    }

    let _ = delegation::log_delegation_action(
        &state.db,
        &did,
        &auth.0.did,
        Some(&auth.0.did),
        DelegationActionType::GrantCreated,
        Some(json!({
            "account_created": true,
            "granted_scopes": input.controller_scopes
        })),
        None,
        None,
    )
    .await;

    info!(did = %did, handle = %handle, controller = %auth.0.did, "Delegated account created");

    Json(CreateDelegatedAccountResponse { did, handle }).into_response()
}
