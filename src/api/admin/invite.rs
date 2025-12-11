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
#[serde(rename_all = "camelCase")]
pub struct DisableInviteCodesInput {
    pub codes: Option<Vec<String>>,
    pub accounts: Option<Vec<String>>,
}

pub async fn disable_invite_codes(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<DisableInviteCodesInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    if let Some(codes) = &input.codes {
        for code in codes {
            let _ = sqlx::query!("UPDATE invite_codes SET disabled = TRUE WHERE code = $1", code)
                .execute(&state.db)
                .await;
        }
    }

    if let Some(accounts) = &input.accounts {
        for account in accounts {
            let user = sqlx::query!("SELECT id FROM users WHERE did = $1", account)
                .fetch_optional(&state.db)
                .await;

            if let Ok(Some(user_row)) = user {
                let _ = sqlx::query!(
                    "UPDATE invite_codes SET disabled = TRUE WHERE created_by_user = $1",
                    user_row.id
                )
                .execute(&state.db)
                .await;
            }
        }
    }

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Deserialize)]
pub struct GetInviteCodesParams {
    pub sort: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCodeInfo {
    pub code: String,
    pub available: i32,
    pub disabled: bool,
    pub for_account: String,
    pub created_by: String,
    pub created_at: String,
    pub uses: Vec<InviteCodeUseInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCodeUseInfo {
    pub used_by: String,
    pub used_at: String,
}

#[derive(Serialize)]
pub struct GetInviteCodesOutput {
    pub cursor: Option<String>,
    pub codes: Vec<InviteCodeInfo>,
}

pub async fn get_invite_codes(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetInviteCodesParams>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let limit = params.limit.unwrap_or(100).clamp(1, 500);
    let sort = params.sort.as_deref().unwrap_or("recent");

    let order_clause = match sort {
        "usage" => "available_uses DESC",
        _ => "created_at DESC",
    };

    let codes_result = if let Some(cursor) = &params.cursor {
        sqlx::query_as::<_, (String, i32, Option<bool>, uuid::Uuid, chrono::DateTime<chrono::Utc>)>(&format!(
            r#"
            SELECT ic.code, ic.available_uses, ic.disabled, ic.created_by_user, ic.created_at
            FROM invite_codes ic
            WHERE ic.created_at < (SELECT created_at FROM invite_codes WHERE code = $1)
            ORDER BY {}
            LIMIT $2
            "#,
            order_clause
        ))
        .bind(cursor)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, (String, i32, Option<bool>, uuid::Uuid, chrono::DateTime<chrono::Utc>)>(&format!(
            r#"
            SELECT ic.code, ic.available_uses, ic.disabled, ic.created_by_user, ic.created_at
            FROM invite_codes ic
            ORDER BY {}
            LIMIT $1
            "#,
            order_clause
        ))
        .bind(limit)
        .fetch_all(&state.db)
        .await
    };

    let codes_rows = match codes_result {
        Ok(rows) => rows,
        Err(e) => {
            error!("DB error fetching invite codes: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let mut codes = Vec::new();
    for (code, available_uses, disabled, created_by_user, created_at) in &codes_rows {
        let creator_did = sqlx::query_scalar!("SELECT did FROM users WHERE id = $1", created_by_user)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "unknown".to_string());

        let uses_result = sqlx::query!(
            r#"
            SELECT u.did, icu.used_at
            FROM invite_code_uses icu
            JOIN users u ON icu.used_by_user = u.id
            WHERE icu.code = $1
            ORDER BY icu.used_at DESC
            "#,
            code
        )
        .fetch_all(&state.db)
        .await;

        let uses = match uses_result {
            Ok(use_rows) => use_rows
                .iter()
                .map(|u| InviteCodeUseInfo {
                    used_by: u.did.clone(),
                    used_at: u.used_at.to_rfc3339(),
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        codes.push(InviteCodeInfo {
            code: code.clone(),
            available: *available_uses,
            disabled: disabled.unwrap_or(false),
            for_account: creator_did.clone(),
            created_by: creator_did,
            created_at: created_at.to_rfc3339(),
            uses,
        });
    }

    let next_cursor = if codes_rows.len() == limit as usize {
        codes_rows.last().map(|(code, _, _, _, _)| code.clone())
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(GetInviteCodesOutput {
            cursor: next_cursor,
            codes,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct DisableAccountInvitesInput {
    pub account: String,
}

pub async fn disable_account_invites(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<DisableAccountInvitesInput>,
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
    if account.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "account is required"})),
        )
            .into_response();
    }

    let result = sqlx::query!("UPDATE users SET invites_disabled = TRUE WHERE did = $1", account)
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
            error!("DB error disabling account invites: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct EnableAccountInvitesInput {
    pub account: String,
}

pub async fn enable_account_invites(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<EnableAccountInvitesInput>,
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
    if account.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "account is required"})),
        )
            .into_response();
    }

    let result = sqlx::query!("UPDATE users SET invites_disabled = FALSE WHERE did = $1", account)
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
            error!("DB error enabling account invites: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
