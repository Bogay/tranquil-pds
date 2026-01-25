use crate::api::EmptyResponse;
use crate::api::error::{ApiError, DbResultExt};
use crate::auth::{Admin, Auth};
use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::error;
use tranquil_db_traits::InviteCodeSortOrder;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableInviteCodesInput {
    pub codes: Option<Vec<String>>,
    pub accounts: Option<Vec<String>>,
}

pub async fn disable_invite_codes(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
    Json(input): Json<DisableInviteCodesInput>,
) -> Result<Response, ApiError> {
    if let Some(codes) = &input.codes
        && let Err(e) = state.infra_repo.disable_invite_codes_by_code(codes).await
    {
        error!("DB error disabling invite codes: {:?}", e);
    }
    if let Some(accounts) = &input.accounts {
        let accounts_typed: Vec<tranquil_types::Did> =
            accounts.iter().filter_map(|a| a.parse().ok()).collect();
        if let Err(e) = state
            .infra_repo
            .disable_invite_codes_by_account(&accounts_typed)
            .await
        {
            error!("DB error disabling invite codes by account: {:?}", e);
        }
    }
    Ok(EmptyResponse::ok().into_response())
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
    _auth: Auth<Admin>,
    Query(params): Query<GetInviteCodesParams>,
) -> Result<Response, ApiError> {
    let limit = params.limit.unwrap_or(100).clamp(1, 500);
    let sort_order = match params.sort.as_deref() {
        Some("usage") => InviteCodeSortOrder::Usage,
        _ => InviteCodeSortOrder::Recent,
    };

    let codes_rows = state
        .infra_repo
        .list_invite_codes(params.cursor.as_deref(), limit, sort_order)
        .await
        .log_db_err("fetching invite codes")?;

    let user_ids: Vec<uuid::Uuid> = codes_rows.iter().map(|r| r.created_by_user).collect();
    let code_strings: Vec<String> = codes_rows.iter().map(|r| r.code.clone()).collect();

    let creator_dids: std::collections::HashMap<uuid::Uuid, tranquil_types::Did> = state
        .infra_repo
        .get_user_dids_by_ids(&user_ids)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();

    let uses_by_code: std::collections::HashMap<String, Vec<InviteCodeUseInfo>> =
        if code_strings.is_empty() {
            std::collections::HashMap::new()
        } else {
            state
                .infra_repo
                .get_invite_code_uses_batch(&code_strings)
                .await
                .unwrap_or_default()
                .into_iter()
                .fold(std::collections::HashMap::new(), |mut acc, u| {
                    acc.entry(u.code.clone())
                        .or_default()
                        .push(InviteCodeUseInfo {
                            used_by: u.used_by_did.to_string(),
                            used_at: u.used_at.to_rfc3339(),
                        });
                    acc
                })
        };

    let codes: Vec<InviteCodeInfo> = codes_rows
        .iter()
        .map(|r| {
            let creator_did = creator_dids
                .get(&r.created_by_user)
                .map(|d| d.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            InviteCodeInfo {
                code: r.code.clone(),
                available: r.available_uses,
                disabled: r.state().is_disabled(),
                for_account: creator_did.clone(),
                created_by: creator_did,
                created_at: r.created_at.to_rfc3339(),
                uses: uses_by_code.get(&r.code).cloned().unwrap_or_default(),
            }
        })
        .collect();

    let next_cursor = if codes_rows.len() == limit as usize {
        codes_rows.last().map(|r| r.code.clone())
    } else {
        None
    };
    Ok((
        StatusCode::OK,
        Json(GetInviteCodesOutput {
            cursor: next_cursor,
            codes,
        }),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct DisableAccountInvitesInput {
    pub account: String,
}

pub async fn disable_account_invites(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
    Json(input): Json<DisableAccountInvitesInput>,
) -> Result<Response, ApiError> {
    let account = input.account.trim();
    if account.is_empty() {
        return Err(ApiError::InvalidRequest("account is required".into()));
    }
    let account_did: tranquil_types::Did = account
        .parse()
        .map_err(|_| ApiError::InvalidDid("Invalid DID format".into()))?;

    match state
        .user_repo
        .set_invites_disabled(&account_did, true)
        .await
    {
        Ok(true) => Ok(EmptyResponse::ok().into_response()),
        Ok(false) => Err(ApiError::AccountNotFound),
        Err(e) => {
            error!("DB error disabling account invites: {:?}", e);
            Err(ApiError::InternalError(None))
        }
    }
}

#[derive(Deserialize)]
pub struct EnableAccountInvitesInput {
    pub account: String,
}

pub async fn enable_account_invites(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
    Json(input): Json<EnableAccountInvitesInput>,
) -> Result<Response, ApiError> {
    let account = input.account.trim();
    if account.is_empty() {
        return Err(ApiError::InvalidRequest("account is required".into()));
    }
    let account_did: tranquil_types::Did = account
        .parse()
        .map_err(|_| ApiError::InvalidDid("Invalid DID format".into()))?;

    match state
        .user_repo
        .set_invites_disabled(&account_did, false)
        .await
    {
        Ok(true) => Ok(EmptyResponse::ok().into_response()),
        Ok(false) => Err(ApiError::AccountNotFound),
        Err(e) => {
            error!("DB error enabling account invites: {:?}", e);
            Err(ApiError::InternalError(None))
        }
    }
}
