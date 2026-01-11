use crate::api::ApiError;
use crate::auth::BearerAuth;
use crate::auth::extractor::BearerAuthAdmin;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::error;

const BASE32_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

fn gen_random_token() -> String {
    let mut rng = rand::thread_rng();
    let gen_segment = |rng: &mut rand::rngs::ThreadRng, len: usize| -> String {
        (0..len)
            .map(|_| BASE32_ALPHABET[rng.gen_range(0..32)] as char)
            .collect()
    };
    format!("{}-{}", gen_segment(&mut rng, 5), gen_segment(&mut rng, 5))
}

fn gen_invite_code() -> String {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let hostname_prefix = hostname.replace('.', "-");
    format!("{}-{}", hostname_prefix, gen_random_token())
}

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
    BearerAuthAdmin(auth_user): BearerAuthAdmin,
    Json(input): Json<CreateInviteCodeInput>,
) -> Response {
    if input.use_count < 1 {
        return ApiError::InvalidRequest("useCount must be at least 1".into()).into_response();
    }

    let for_account = input
        .for_account
        .unwrap_or_else(|| auth_user.did.to_string());
    let code = gen_invite_code();

    match sqlx::query!(
        "INSERT INTO invite_codes (code, available_uses, created_by_user, for_account)
         SELECT $1, $2, id, $3 FROM users WHERE is_admin = true LIMIT 1",
        code,
        input.use_count,
        for_account
    )
    .execute(&state.db)
    .await
    {
        Ok(result) => {
            if result.rows_affected() == 0 {
                error!("No admin user found to create invite code");
                return ApiError::InternalError(None).into_response();
            }
            Json(CreateInviteCodeOutput { code }).into_response()
        }
        Err(e) => {
            error!("DB error creating invite code: {:?}", e);
            ApiError::InternalError(None).into_response()
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
    BearerAuthAdmin(auth_user): BearerAuthAdmin,
    Json(input): Json<CreateInviteCodesInput>,
) -> Response {
    if input.use_count < 1 {
        return ApiError::InvalidRequest("useCount must be at least 1".into()).into_response();
    }

    let code_count = input.code_count.unwrap_or(1).max(1);
    let for_accounts = input
        .for_accounts
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec![auth_user.did.to_string()]);

    let admin_user_id =
        match sqlx::query_scalar!("SELECT id FROM users WHERE is_admin = true LIMIT 1")
            .fetch_optional(&state.db)
            .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                error!("No admin user found to create invite codes");
                return ApiError::InternalError(None).into_response();
            }
            Err(e) => {
                error!("DB error looking up admin user: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        };

    let result = futures::future::try_join_all(for_accounts.into_iter().map(|account| {
        let db = state.db.clone();
        let use_count = input.use_count;
        async move {
            let codes: Vec<String> = (0..code_count).map(|_| gen_invite_code()).collect();
            sqlx::query!(
                r#"
                INSERT INTO invite_codes (code, available_uses, created_by_user, for_account)
                SELECT code, $2, $3, $4 FROM UNNEST($1::text[]) AS t(code)
                "#,
                &codes[..],
                use_count,
                admin_user_id,
                account
            )
            .execute(&db)
            .await
            .map(|_| AccountCodes { account, codes })
        }
    }))
    .await;

    match result {
        Ok(result_codes) => Json(CreateInviteCodesOutput {
            codes: result_codes,
        })
        .into_response(),
        Err(e) => {
            error!("DB error creating invite codes: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_by_handle: Option<String>,
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
    let include_used = params.include_used.unwrap_or(true);

    let codes_rows = match sqlx::query!(
        r#"
        SELECT
            ic.code,
            ic.available_uses,
            ic.created_at,
            ic.disabled,
            ic.for_account,
            (SELECT COUNT(*) FROM invite_code_uses icu WHERE icu.code = ic.code)::int as "use_count!"
        FROM invite_codes ic
        WHERE ic.for_account = $1
        ORDER BY ic.created_at DESC
        "#,
        &auth_user.did
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("DB error fetching invite codes: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let filtered_rows: Vec<_> = codes_rows
        .into_iter()
        .filter(|row| {
            let disabled = row.disabled.unwrap_or(false);
            !disabled && (include_used || row.use_count < row.available_uses)
        })
        .collect();

    let codes = futures::future::join_all(filtered_rows.into_iter().map(|row| {
        let db = state.db.clone();
        async move {
            let uses = sqlx::query!(
                r#"
                SELECT u.did, u.handle, icu.used_at
                FROM invite_code_uses icu
                JOIN users u ON icu.used_by_user = u.id
                WHERE icu.code = $1
                ORDER BY icu.used_at DESC
                "#,
                row.code
            )
            .fetch_all(&db)
            .await
            .map(|use_rows| {
                use_rows
                    .iter()
                    .map(|u| InviteCodeUse {
                        used_by: u.did.clone(),
                        used_by_handle: Some(u.handle.clone()),
                        used_at: u.used_at.to_rfc3339(),
                    })
                    .collect()
            })
            .unwrap_or_default();

            InviteCode {
                code: row.code,
                available: row.available_uses,
                disabled: false,
                for_account: row.for_account,
                created_by: "admin".to_string(),
                created_at: row.created_at.to_rfc3339(),
                uses,
            }
        }
    }))
    .await;

    Json(GetAccountInviteCodesOutput { codes }).into_response()
}
