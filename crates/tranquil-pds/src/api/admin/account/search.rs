use crate::api::error::{ApiError, DbResultExt};
use crate::auth::{Admin, Auth};
use crate::state::AppState;
use crate::types::{Did, Handle};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SearchAccountsParams {
    pub email: Option<String>,
    pub handle: Option<String>,
    pub cursor: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    pub did: Did,
    pub handle: Handle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub indexed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirmed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invites_disabled: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchAccountsOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub accounts: Vec<AccountView>,
}

pub async fn search_accounts(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
    Query(params): Query<SearchAccountsParams>,
) -> Result<Response, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let email_filter = params.email.as_deref().map(|e| format!("%{}%", e));
    let handle_filter = params.handle.as_deref().map(|h| format!("%{}%", h));
    let cursor_did: Option<Did> = params.cursor.as_ref().and_then(|c| c.parse().ok());
    let rows = state
        .user_repo
        .search_accounts(
            cursor_did.as_ref(),
            email_filter.as_deref(),
            handle_filter.as_deref(),
            limit + 1,
        )
        .await
        .log_db_err("in search_accounts")?;

    let limit_usize = usize::try_from(limit).unwrap_or(0);
    let has_more = rows.len() > limit_usize;
    let accounts: Vec<AccountView> = rows
        .into_iter()
        .take(limit_usize)
        .map(|row| AccountView {
            did: row.did.clone(),
            handle: row.handle,
            email: row.email,
            indexed_at: row.created_at.to_rfc3339(),
            email_confirmed_at: if row.email_verified {
                Some(row.created_at.to_rfc3339())
            } else {
                None
            },
            deactivated_at: row.deactivated_at.map(|dt| dt.to_rfc3339()),
            invites_disabled: row.invites_disabled,
        })
        .collect();
    let next_cursor = if has_more {
        accounts.last().map(|a| a.did.to_string())
    } else {
        None
    };
    Ok((
        StatusCode::OK,
        Json(SearchAccountsOutput {
            cursor: next_cursor,
            accounts,
        }),
    )
        .into_response())
}
