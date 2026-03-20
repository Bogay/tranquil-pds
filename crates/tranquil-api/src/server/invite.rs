use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing::error;
use tranquil_pds::api::ApiError;
use tranquil_pds::api::error::DbResultExt;
use tranquil_pds::auth::{Admin, Auth, NotTakendown};
use tranquil_pds::state::AppState;
use tranquil_pds::types::Did;
use tranquil_pds::util::gen_invite_code;

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
    auth: Auth<Admin>,
    Json(input): Json<CreateInviteCodeInput>,
) -> Result<Json<CreateInviteCodeOutput>, ApiError> {
    if input.use_count < 1 {
        return Err(ApiError::InvalidRequest(
            "useCount must be at least 1".into(),
        ));
    }

    let for_account: Did = match &input.for_account {
        Some(acct) => acct
            .parse()
            .map_err(|_| ApiError::InvalidDid("Invalid DID format".into()))?,
        None => auth.did.clone(),
    };
    let code = gen_invite_code();

    match state
        .repos.infra
        .create_invite_code(&code, input.use_count, Some(&for_account))
        .await
    {
        Ok(true) => Ok(Json(CreateInviteCodeOutput { code })),
        Ok(false) => {
            error!("No admin user found to create invite code");
            Err(ApiError::InternalError(None))
        }
        Err(e) => {
            error!("DB error creating invite code: {:?}", e);
            Err(ApiError::InternalError(None))
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
    auth: Auth<Admin>,
    Json(input): Json<CreateInviteCodesInput>,
) -> Result<Json<CreateInviteCodesOutput>, ApiError> {
    if input.use_count < 1 {
        return Err(ApiError::InvalidRequest(
            "useCount must be at least 1".into(),
        ));
    }

    let code_count = input.code_count.unwrap_or(1).max(1);
    let for_accounts: Vec<Did> = match &input.for_accounts {
        Some(accounts) if !accounts.is_empty() => accounts
            .iter()
            .map(|a| a.parse())
            .collect::<Result<Vec<Did>, _>>()
            .map_err(|_| ApiError::InvalidDid("Invalid DID format".into()))?,
        _ => vec![auth.did.clone()],
    };

    let admin_user_id = state
        .repos.user
        .get_any_admin_user_id()
        .await
        .log_db_err("looking up admin user")?
        .ok_or_else(|| {
            error!("No admin user found to create invite codes");
            ApiError::InternalError(None)
        })?;

    let result = futures::future::try_join_all(for_accounts.into_iter().map(|account| {
        let infra_repo = state.repos.infra.clone();
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
        Ok(result_codes) => Ok(Json(CreateInviteCodesOutput {
            codes: result_codes,
        })),
        Err(e) => {
            error!("DB error creating invite codes: {:?}", e);
            Err(ApiError::InternalError(None))
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
    auth: Auth<NotTakendown>,
    axum::extract::Query(params): axum::extract::Query<GetAccountInviteCodesParams>,
) -> Result<Json<GetAccountInviteCodesOutput>, ApiError> {
    let include_used = params.include_used.unwrap_or(true);

    let codes_info = state
        .repos.infra
        .get_invite_codes_for_account(&auth.did)
        .await
        .log_db_err("fetching invite codes")?;

    let filtered_codes: Vec<_> = codes_info
        .into_iter()
        .filter(|info| info.state.is_active())
        .collect();

    let codes = futures::future::join_all(filtered_codes.into_iter().map(|info| {
        let infra_repo = state.repos.infra.clone();
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

            let use_count = i32::try_from(uses.len()).unwrap_or(i32::MAX);
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
    Ok(Json(GetAccountInviteCodesOutput { codes }))
}
