use crate::api::ApiError;
use crate::auth::BearerAuth;
use crate::auth::extractor::BearerAuthAdmin;
use crate::state::AppState;
use crate::types::Did;
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

    let for_account: Did = match &input.for_account {
        Some(acct) => match acct.parse() {
            Ok(d) => d,
            Err(_) => return ApiError::InvalidDid("Invalid DID format".into()).into_response(),
        },
        None => auth_user.did.clone(),
    };
    let code = gen_invite_code();

    match state
        .infra_repo
        .create_invite_code(&code, input.use_count, Some(&for_account))
        .await
    {
        Ok(true) => Json(CreateInviteCodeOutput { code }).into_response(),
        Ok(false) => {
            error!("No admin user found to create invite code");
            ApiError::InternalError(None).into_response()
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
    let for_accounts: Vec<Did> = match &input.for_accounts {
        Some(accounts) if !accounts.is_empty() => {
            let parsed: Result<Vec<Did>, _> = accounts.iter().map(|a| a.parse()).collect();
            match parsed {
                Ok(dids) => dids,
                Err(_) => return ApiError::InvalidDid("Invalid DID format".into()).into_response(),
            }
        }
        _ => vec![auth_user.did.clone()],
    };

    let admin_user_id = match state.user_repo.get_any_admin_user_id().await {
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
        let infra_repo = state.infra_repo.clone();
        let use_count = input.use_count;
        async move {
            let codes: Vec<String> = (0..code_count).map(|_| gen_invite_code()).collect();
            infra_repo
                .create_invite_codes_batch(&codes, use_count, admin_user_id, Some(&account))
                .await
                .map(|_| AccountCodes {
                    account: account.to_string(),
                    codes,
                })
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

    let codes_info = match state
        .infra_repo
        .get_invite_codes_for_account(&auth_user.did)
        .await
    {
        Ok(info) => info,
        Err(e) => {
            error!("DB error fetching invite codes: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let filtered_codes: Vec<_> = codes_info
        .into_iter()
        .filter(|info| !info.disabled)
        .collect();

    let codes = futures::future::join_all(filtered_codes.into_iter().map(|info| {
        let infra_repo = state.infra_repo.clone();
        async move {
            let uses = infra_repo
                .get_invite_code_uses(&info.code)
                .await
                .map(|use_rows| {
                    use_rows
                        .into_iter()
                        .map(|u| InviteCodeUse {
                            used_by: u.used_by_did.to_string(),
                            used_by_handle: u.used_by_handle.map(|h| h.to_string()),
                            used_at: u.used_at.to_rfc3339(),
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let use_count = uses.len() as i32;
            if !include_used && use_count >= info.available_uses {
                return None;
            }

            Some(InviteCode {
                code: info.code,
                available: info.available_uses,
                disabled: false,
                for_account: info.for_account.map(|d| d.to_string()).unwrap_or_default(),
                created_by: info
                    .created_by
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "admin".to_string()),
                created_at: info.created_at.to_rfc3339(),
                uses,
            })
        }
    }))
    .await;

    let codes: Vec<InviteCode> = codes.into_iter().flatten().collect();
    Json(GetAccountInviteCodesOutput { codes }).into_response()
}
