use crate::auth::BearerAuthAdmin;
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
pub struct SearchAccountsParams {
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
    pub did: String,
    pub handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub indexed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified_at: Option<String>,
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
    _auth: BearerAuthAdmin,
    Query(params): Query<SearchAccountsParams>,
) -> Response {
    let limit = params.limit.clamp(1, 100);
    let cursor_did = params.cursor.as_deref().unwrap_or("");
    let handle_filter = params.handle.as_deref().map(|h| format!("%{}%", h));
    let result = sqlx::query_as::<_, (String, String, Option<String>, chrono::DateTime<chrono::Utc>, bool, Option<chrono::DateTime<chrono::Utc>>)>(
        r#"
        SELECT did, handle, email, created_at, email_verified, deactivated_at
        FROM users
        WHERE did > $1 AND ($2::text IS NULL OR handle ILIKE $2)
        ORDER BY did ASC
        LIMIT $3
        "#,
    )
    .bind(cursor_did)
    .bind(&handle_filter)
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await;
    match result {
        Ok(rows) => {
            let has_more = rows.len() > limit as usize;
            let accounts: Vec<AccountView> = rows
                .into_iter()
                .take(limit as usize)
                .map(|(did, handle, email, created_at, email_verified, deactivated_at)| AccountView {
                    did: did.clone(),
                    handle,
                    email,
                    indexed_at: created_at.to_rfc3339(),
                    email_verified_at: if email_verified {
                        Some(created_at.to_rfc3339())
                    } else {
                        None
                    },
                    deactivated_at: deactivated_at.map(|dt| dt.to_rfc3339()),
                    invites_disabled: None,
                })
                .collect();
            let next_cursor = if has_more {
                accounts.last().map(|a| a.did.clone())
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(SearchAccountsOutput {
                    cursor: next_cursor,
                    accounts,
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("DB error in search_accounts: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
