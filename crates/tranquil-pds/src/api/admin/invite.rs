use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableInviteCodesInput {
    pub codes: Option<Vec<String>>,
    pub accounts: Option<Vec<String>>,
}

pub async fn disable_invite_codes(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    Json(input): Json<DisableInviteCodesInput>,
) -> Response {
    if let Some(codes) = &input.codes {
        let _ = sqlx::query!(
            "UPDATE invite_codes SET disabled = TRUE WHERE code = ANY($1)",
            codes as &[String]
        )
        .execute(&state.db)
        .await;
    }
    if let Some(accounts) = &input.accounts {
        let _ = sqlx::query!(
            "UPDATE invite_codes SET disabled = TRUE WHERE created_by_user IN (SELECT id FROM users WHERE did = ANY($1))",
            accounts as &[String]
        )
        .execute(&state.db)
        .await;
    }
    EmptyResponse::ok().into_response()
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

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCodeUseInfo {
    pub used_by: String,
    pub used_at: String,
}

#[derive(Serialize)]
pub struct GetInviteCodesOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub codes: Vec<InviteCodeInfo>,
}

pub async fn get_invite_codes(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    Query(params): Query<GetInviteCodesParams>,
) -> Response {
    let limit = params.limit.unwrap_or(100).clamp(1, 500);
    let sort = params.sort.as_deref().unwrap_or("recent");
    let order_clause = match sort {
        "usage" => "available_uses DESC",
        _ => "created_at DESC",
    };
    let codes_result = if let Some(cursor) = &params.cursor {
        sqlx::query_as::<
            _,
            (
                String,
                i32,
                Option<bool>,
                uuid::Uuid,
                chrono::DateTime<chrono::Utc>,
            ),
        >(&format!(
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
        sqlx::query_as::<
            _,
            (
                String,
                i32,
                Option<bool>,
                uuid::Uuid,
                chrono::DateTime<chrono::Utc>,
            ),
        >(&format!(
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
            return ApiError::InternalError(None).into_response();
        }
    };

    let user_ids: Vec<uuid::Uuid> = codes_rows.iter().map(|(_, _, _, uid, _)| *uid).collect();
    let code_strings: Vec<String> = codes_rows.iter().map(|(c, _, _, _, _)| c.clone()).collect();

    let mut creator_dids: std::collections::HashMap<uuid::Uuid, String> =
        std::collections::HashMap::new();
    sqlx::query!(
        "SELECT id, did FROM users WHERE id = ANY($1)",
        &user_ids
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .for_each(|r| {
        creator_dids.insert(r.id, r.did);
    });

    let mut uses_by_code: std::collections::HashMap<String, Vec<InviteCodeUseInfo>> =
        std::collections::HashMap::new();
    if !code_strings.is_empty() {
        sqlx::query!(
            r#"
            SELECT icu.code, u.did, icu.used_at
            FROM invite_code_uses icu
            JOIN users u ON icu.used_by_user = u.id
            WHERE icu.code = ANY($1)
            ORDER BY icu.used_at DESC
            "#,
            &code_strings
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .for_each(|r| {
            uses_by_code
                .entry(r.code)
                .or_default()
                .push(InviteCodeUseInfo {
                    used_by: r.did,
                    used_at: r.used_at.to_rfc3339(),
                });
        });
    }

    let codes: Vec<InviteCodeInfo> = codes_rows
        .iter()
        .map(|(code, available_uses, disabled, created_by_user, created_at)| {
            let creator_did = creator_dids
                .get(created_by_user)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            InviteCodeInfo {
                code: code.clone(),
                available: *available_uses,
                disabled: disabled.unwrap_or(false),
                for_account: creator_did.clone(),
                created_by: creator_did,
                created_at: created_at.to_rfc3339(),
                uses: uses_by_code.get(code).cloned().unwrap_or_default(),
            }
        })
        .collect();

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
    _auth: BearerAuthAdmin,
    Json(input): Json<DisableAccountInvitesInput>,
) -> Response {
    let account = input.account.trim();
    if account.is_empty() {
        return ApiError::InvalidRequest("account is required".into()).into_response();
    }
    let result = sqlx::query!(
        "UPDATE users SET invites_disabled = TRUE WHERE did = $1",
        account
    )
    .execute(&state.db)
    .await;
    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return ApiError::AccountNotFound.into_response();
            }
            EmptyResponse::ok().into_response()
        }
        Err(e) => {
            error!("DB error disabling account invites: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct EnableAccountInvitesInput {
    pub account: String,
}

pub async fn enable_account_invites(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    Json(input): Json<EnableAccountInvitesInput>,
) -> Response {
    let account = input.account.trim();
    if account.is_empty() {
        return ApiError::InvalidRequest("account is required".into()).into_response();
    }
    let result = sqlx::query!(
        "UPDATE users SET invites_disabled = FALSE WHERE did = $1",
        account
    )
    .execute(&state.db)
    .await;
    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return ApiError::AccountNotFound.into_response();
            }
            EmptyResponse::ok().into_response()
        }
        Err(e) => {
            error!("DB error enabling account invites: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}
