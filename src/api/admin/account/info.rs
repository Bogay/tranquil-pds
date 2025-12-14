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
                    email: row.email,
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
                email: row.email,
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
