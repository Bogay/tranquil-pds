use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInviteCodeInput {
    pub use_count: i32,
    pub for_account: Option<String>,
}

#[derive(Serialize)]
pub struct CreateInviteCodeOutput {
    pub code: String,
}

pub async fn create_invite_code(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<CreateInviteCodeInput>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    if input.use_count < 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "useCount must be at least 1"})),
        )
            .into_response();
    }

    let auth_result = crate::auth::validate_bearer_token(&state.db, &token).await;
    let did = match auth_result {
        Ok(user) => user.did,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": e})),
            )
                .into_response();
        }
    };

    let user_id = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(id)) => id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let creator_user_id = if let Some(for_account) = &input.for_account {
        let target = sqlx::query!("SELECT id FROM users WHERE did = $1", for_account)
            .fetch_optional(&state.db)
            .await;

        match target {
            Ok(Some(row)) => row.id,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Target account not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error looking up target account: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        }
    } else {
        user_id
    };

    let user_invites_disabled = sqlx::query_scalar!(
        "SELECT invites_disabled FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .flatten()
    .unwrap_or(false);

    if user_invites_disabled {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "InvitesDisabled", "message": "Invites are disabled for this account"})),
        )
            .into_response();
    }

    let code = Uuid::new_v4().to_string();

    let result = sqlx::query!(
        "INSERT INTO invite_codes (code, available_uses, created_by_user) VALUES ($1, $2, $3)",
        code,
        input.use_count,
        creator_user_id
    )
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => (StatusCode::OK, Json(CreateInviteCodeOutput { code })).into_response(),
        Err(e) => {
            error!("DB error creating invite code: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInviteCodesInput {
    pub code_count: Option<i32>,
    pub use_count: i32,
    pub for_accounts: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct CreateInviteCodesOutput {
    pub codes: Vec<AccountCodes>,
}

#[derive(Serialize)]
pub struct AccountCodes {
    pub account: String,
    pub codes: Vec<String>,
}

pub async fn create_invite_codes(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<CreateInviteCodesInput>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    if input.use_count < 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "useCount must be at least 1"})),
        )
            .into_response();
    }

    let auth_result = crate::auth::validate_bearer_token(&state.db, &token).await;
    let did = match auth_result {
        Ok(user) => user.did,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": e})),
            )
                .into_response();
        }
    };

    let user_id = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(id)) => id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let code_count = input.code_count.unwrap_or(1).max(1);
    let for_accounts = input.for_accounts.unwrap_or_default();

    let mut result_codes = Vec::new();

    if for_accounts.is_empty() {
        let mut codes = Vec::new();
        for _ in 0..code_count {
            let code = Uuid::new_v4().to_string();

            let insert = sqlx::query!(
                "INSERT INTO invite_codes (code, available_uses, created_by_user) VALUES ($1, $2, $3)",
                code,
                input.use_count,
                user_id
            )
            .execute(&state.db)
            .await;

            if let Err(e) = insert {
                error!("DB error creating invite code: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }

            codes.push(code);
        }

        result_codes.push(AccountCodes {
            account: "admin".to_string(),
            codes,
        });
    } else {
        for account_did in for_accounts {
            let target = sqlx::query!("SELECT id FROM users WHERE did = $1", account_did)
                .fetch_optional(&state.db)
                .await;

            let target_user_id = match target {
                Ok(Some(row)) => row.id,
                Ok(None) => {
                    continue;
                }
                Err(e) => {
                    error!("DB error looking up target account: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            };

            let mut codes = Vec::new();
            for _ in 0..code_count {
                let code = Uuid::new_v4().to_string();

                let insert = sqlx::query!(
                    "INSERT INTO invite_codes (code, available_uses, created_by_user) VALUES ($1, $2, $3)",
                    code,
                    input.use_count,
                    target_user_id
                )
                .execute(&state.db)
                .await;

                if let Err(e) = insert {
                    error!("DB error creating invite code: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }

                codes.push(code);
            }

            result_codes.push(AccountCodes {
                account: account_did,
                codes,
            });
        }
    }

    (StatusCode::OK, Json(CreateInviteCodesOutput { codes: result_codes })).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAccountInviteCodesParams {
    pub include_used: Option<bool>,
    pub create_available: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCode {
    pub code: String,
    pub available: i32,
    pub disabled: bool,
    pub for_account: String,
    pub created_by: String,
    pub created_at: String,
    pub uses: Vec<InviteCodeUse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCodeUse {
    pub used_by: String,
    pub used_at: String,
}

#[derive(Serialize)]
pub struct GetAccountInviteCodesOutput {
    pub codes: Vec<InviteCode>,
}

pub async fn get_account_invite_codes(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<GetAccountInviteCodesParams>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    let auth_result = crate::auth::validate_bearer_token(&state.db, &token).await;
    let did = match auth_result {
        Ok(user) => user.did,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": e})),
            )
                .into_response();
        }
    };

    let user_id = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(id)) => id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let include_used = params.include_used.unwrap_or(true);

    let codes_result = sqlx::query!(
        r#"
        SELECT code, available_uses, created_at, disabled
        FROM invite_codes
        WHERE created_by_user = $1
        ORDER BY created_at DESC
        "#,
        user_id
    )
    .fetch_all(&state.db)
    .await;

    let codes_rows = match codes_result {
        Ok(rows) => {
            if include_used {
                rows
            } else {
                rows.into_iter().filter(|r| r.available_uses > 0).collect()
            }
        }
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
    for row in codes_rows {
        let uses_result = sqlx::query!(
            r#"
            SELECT u.did, icu.used_at
            FROM invite_code_uses icu
            JOIN users u ON icu.used_by_user = u.id
            WHERE icu.code = $1
            ORDER BY icu.used_at DESC
            "#,
            row.code
        )
        .fetch_all(&state.db)
        .await;

        let uses = match uses_result {
            Ok(use_rows) => use_rows
                .iter()
                .map(|u| InviteCodeUse {
                    used_by: u.did.clone(),
                    used_at: u.used_at.to_rfc3339(),
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        codes.push(InviteCode {
            code: row.code,
            available: row.available_uses,
            disabled: row.disabled.unwrap_or(false),
            for_account: did.clone(),
            created_by: did.clone(),
            created_at: row.created_at.to_rfc3339(),
            uses,
        });
    }

    (StatusCode::OK, Json(GetAccountInviteCodesOutput { codes })).into_response()
}
