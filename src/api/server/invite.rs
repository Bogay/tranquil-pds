use crate::api::ApiError;
use crate::auth::BearerAuth;
use crate::state::AppState;
use crate::util::get_user_id_by_did;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
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
    BearerAuth(auth_user): BearerAuth,
    Json(input): Json<CreateInviteCodeInput>,
) -> Response {
    if input.use_count < 1 {
        return ApiError::InvalidRequest("useCount must be at least 1".into()).into_response();
    }

    let user_id = match get_user_id_by_did(&state.db, &auth_user.did).await {
        Ok(id) => id,
        Err(e) => return ApiError::from(e).into_response(),
    };

    let creator_user_id = if let Some(for_account) = &input.for_account {
        match sqlx::query!("SELECT id FROM users WHERE did = $1", for_account)
            .fetch_optional(&state.db)
            .await
        {
            Ok(Some(row)) => row.id,
            Ok(None) => return ApiError::AccountNotFound.into_response(),
            Err(e) => {
                error!("DB error looking up target account: {:?}", e);
                return ApiError::InternalError.into_response();
            }
        }
    } else {
        user_id
    };

    let user_invites_disabled = sqlx::query_scalar!(
        "SELECT invites_disabled FROM users WHERE did = $1",
        auth_user.did
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("DB error checking invites_disabled: {:?}", e);
        ApiError::InternalError
    })
    .ok()
    .flatten()
    .flatten()
    .unwrap_or(false);

    if user_invites_disabled {
        return ApiError::InvitesDisabled.into_response();
    }

    let code = Uuid::new_v4().to_string();

    match sqlx::query!(
        "INSERT INTO invite_codes (code, available_uses, created_by_user) VALUES ($1, $2, $3)",
        code,
        input.use_count,
        creator_user_id
    )
    .execute(&state.db)
    .await
    {
        Ok(_) => Json(CreateInviteCodeOutput { code }).into_response(),
        Err(e) => {
            error!("DB error creating invite code: {:?}", e);
            ApiError::InternalError.into_response()
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
    BearerAuth(auth_user): BearerAuth,
    Json(input): Json<CreateInviteCodesInput>,
) -> Response {
    if input.use_count < 1 {
        return ApiError::InvalidRequest("useCount must be at least 1".into()).into_response();
    }

    let user_id = match get_user_id_by_did(&state.db, &auth_user.did).await {
        Ok(id) => id,
        Err(e) => return ApiError::from(e).into_response(),
    };

    let code_count = input.code_count.unwrap_or(1).max(1);
    let for_accounts = input.for_accounts.unwrap_or_default();

    let mut result_codes = Vec::new();

    if for_accounts.is_empty() {
        let mut codes = Vec::new();
        for _ in 0..code_count {
            let code = Uuid::new_v4().to_string();

            if let Err(e) = sqlx::query!(
                "INSERT INTO invite_codes (code, available_uses, created_by_user) VALUES ($1, $2, $3)",
                code,
                input.use_count,
                user_id
            )
            .execute(&state.db)
            .await
            {
                error!("DB error creating invite code: {:?}", e);
                return ApiError::InternalError.into_response();
            }

            codes.push(code);
        }

        result_codes.push(AccountCodes {
            account: "admin".to_string(),
            codes,
        });
    } else {
        for account_did in for_accounts {
            let target_user_id = match sqlx::query!("SELECT id FROM users WHERE did = $1", account_did)
                .fetch_optional(&state.db)
                .await
            {
                Ok(Some(row)) => row.id,
                Ok(None) => continue,
                Err(e) => {
                    error!("DB error looking up target account: {:?}", e);
                    return ApiError::InternalError.into_response();
                }
            };

            let mut codes = Vec::new();
            for _ in 0..code_count {
                let code = Uuid::new_v4().to_string();

                if let Err(e) = sqlx::query!(
                    "INSERT INTO invite_codes (code, available_uses, created_by_user) VALUES ($1, $2, $3)",
                    code,
                    input.use_count,
                    target_user_id
                )
                .execute(&state.db)
                .await
                {
                    error!("DB error creating invite code: {:?}", e);
                    return ApiError::InternalError.into_response();
                }

                codes.push(code);
            }

            result_codes.push(AccountCodes {
                account: account_did,
                codes,
            });
        }
    }

    Json(CreateInviteCodesOutput { codes: result_codes }).into_response()
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
    BearerAuth(auth_user): BearerAuth,
    axum::extract::Query(params): axum::extract::Query<GetAccountInviteCodesParams>,
) -> Response {
    let user_id = match get_user_id_by_did(&state.db, &auth_user.did).await {
        Ok(id) => id,
        Err(e) => return ApiError::from(e).into_response(),
    };

    let include_used = params.include_used.unwrap_or(true);

    let codes_rows = match sqlx::query!(
        r#"
        SELECT code, available_uses, created_at, disabled
        FROM invite_codes
        WHERE created_by_user = $1
        ORDER BY created_at DESC
        "#,
        user_id
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => {
            if include_used {
                rows
            } else {
                rows.into_iter().filter(|r| r.available_uses > 0).collect()
            }
        }
        Err(e) => {
            error!("DB error fetching invite codes: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    let mut codes = Vec::new();
    for row in codes_rows {
        let uses = sqlx::query!(
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
        .await
        .map(|use_rows| {
            use_rows
                .iter()
                .map(|u| InviteCodeUse {
                    used_by: u.did.clone(),
                    used_at: u.used_at.to_rfc3339(),
                })
                .collect()
        })
        .unwrap_or_default();

        codes.push(InviteCode {
            code: row.code,
            available: row.available_uses,
            disabled: row.disabled.unwrap_or(false),
            for_account: auth_user.did.clone(),
            created_by: auth_user.did.clone(),
            created_at: row.created_at.to_rfc3339(),
            uses,
        });
    }

    Json(GetAccountInviteCodesOutput { codes }).into_response()
}
