use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;

#[derive(Deserialize)]
pub struct GetAccountInfoParams {
    pub did: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub did: String,
    pub handle: String,
    pub email: Option<String>,
    pub indexed_at: String,
    pub invite_note: Option<String>,
    pub invites_disabled: bool,
    pub email_confirmed_at: Option<String>,
    pub deactivated_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAccountInfosOutput {
    pub infos: Vec<AccountInfo>,
}

pub async fn get_account_info(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetAccountInfoParams>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let did = params.did.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }

    let result = sqlx::query!(
        r#"
        SELECT did, handle, email, created_at
        FROM users
        WHERE did = $1
        "#,
        did
    )
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => {
            (
                StatusCode::OK,
                Json(AccountInfo {
                    did: row.did,
                    handle: row.handle,
                    email: Some(row.email),
                    indexed_at: row.created_at.to_rfc3339(),
                    invite_note: None,
                    invites_disabled: false,
                    email_confirmed_at: None,
                    deactivated_at: None,
                }),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error in get_account_info: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct GetAccountInfosParams {
    pub dids: String,
}

pub async fn get_account_infos(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetAccountInfosParams>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let dids: Vec<&str> = params.dids.split(',').map(|s| s.trim()).collect();
    if dids.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "dids is required"})),
        )
            .into_response();
    }

    let mut infos = Vec::new();

    for did in dids {
        if did.is_empty() {
            continue;
        }

        let result = sqlx::query!(
            r#"
            SELECT did, handle, email, created_at
            FROM users
            WHERE did = $1
            "#,
            did
        )
        .fetch_optional(&state.db)
        .await;

        if let Ok(Some(row)) = result {
            infos.push(AccountInfo {
                did: row.did,
                handle: row.handle,
                email: Some(row.email),
                indexed_at: row.created_at.to_rfc3339(),
                invite_note: None,
                invites_disabled: false,
                email_confirmed_at: None,
                deactivated_at: None,
            });
        }
    }

    (StatusCode::OK, Json(GetAccountInfosOutput { infos })).into_response()
}

#[derive(Deserialize)]
pub struct DeleteAccountInput {
    pub did: String,
}

pub async fn delete_account(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<DeleteAccountInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let did = input.did.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }

    let user = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;

    let user_id = match user {
        Ok(Some(row)) => row.id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in delete_account: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let _ = sqlx::query!("DELETE FROM sessions WHERE did = $1", did)
        .execute(&state.db)
        .await;

    let _ = sqlx::query!("DELETE FROM records WHERE repo_id = $1", user_id)
        .execute(&state.db)
        .await;

    let _ = sqlx::query!("DELETE FROM repos WHERE user_id = $1", user_id)
        .execute(&state.db)
        .await;

    let _ = sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
        .execute(&state.db)
        .await;

    let _ = sqlx::query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
        .execute(&state.db)
        .await;

    let result = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
        .execute(&state.db)
        .await;

    match result {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => {
            error!("DB error deleting account: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateAccountEmailInput {
    pub account: String,
    pub email: String,
}

pub async fn update_account_email(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateAccountEmailInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let account = input.account.trim();
    let email = input.email.trim();

    if account.is_empty() || email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "account and email are required"})),
        )
            .into_response();
    }

    let result = sqlx::query!("UPDATE users SET email = $1 WHERE did = $2", email, account)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error updating email: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateAccountHandleInput {
    pub did: String,
    pub handle: String,
}

pub async fn update_account_handle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateAccountHandleInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let did = input.did.trim();
    let handle = input.handle.trim();

    if did.is_empty() || handle.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did and handle are required"})),
        )
            .into_response();
    }

    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidHandle", "message": "Handle contains invalid characters"})),
        )
            .into_response();
    }

    let existing = sqlx::query!("SELECT id FROM users WHERE handle = $1 AND did != $2", handle, did)
        .fetch_optional(&state.db)
        .await;

    if let Ok(Some(_)) = existing {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "HandleTaken", "message": "Handle is already in use"})),
        )
            .into_response();
    }

    let result = sqlx::query!("UPDATE users SET handle = $1 WHERE did = $2", handle, did)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error updating handle: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateAccountPasswordInput {
    pub did: String,
    pub password: String,
}

pub async fn update_account_password(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateAccountPasswordInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let did = input.did.trim();
    let password = input.password.trim();

    if did.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did and password are required"})),
        )
            .into_response();
    }

    let password_hash = match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to hash password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let result = sqlx::query!("UPDATE users SET password_hash = $1 WHERE did = $2", password_hash, did)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error updating password: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
