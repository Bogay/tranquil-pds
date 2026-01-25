use crate::api::error::{ApiError, DbResultExt};
use crate::auth::{Admin, Auth};
use crate::state::AppState;
use crate::types::{Did, Handle};
use axum::{
    Json,
    extract::{Query, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct GetAccountInfoParams {
    pub did: Did,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub did: Did,
    pub handle: Handle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub indexed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_note: Option<String>,
    pub invites_disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirmed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invited_by: Option<InviteCodeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invites: Option<Vec<InviteCodeInfo>>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InviteCodeInfo {
    pub code: String,
    pub available: i32,
    pub disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub for_account: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Did>,
    pub created_at: String,
    pub uses: Vec<InviteCodeUseInfo>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InviteCodeUseInfo {
    pub used_by: Did,
    pub used_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAccountInfosOutput {
    pub infos: Vec<AccountInfo>,
}

pub async fn get_account_info(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
    Query(params): Query<GetAccountInfoParams>,
) -> Result<Response, ApiError> {
    let account = state
        .infra_repo
        .get_admin_account_info_by_did(&params.did)
        .await
        .log_db_err("in get_account_info")?
        .ok_or(ApiError::AccountNotFound)?;

    let invited_by = get_invited_by(&state, account.id).await;
    let invites = get_invites_for_user(&state, account.id).await;

    Ok((
        StatusCode::OK,
        Json(AccountInfo {
            did: account.did,
            handle: account.handle,
            email: account.email,
            indexed_at: account.created_at.to_rfc3339(),
            invite_note: None,
            invites_disabled: account.invites_disabled,
            email_confirmed_at: if account.email_verified {
                Some(account.created_at.to_rfc3339())
            } else {
                None
            },
            deactivated_at: account.deactivated_at.map(|dt| dt.to_rfc3339()),
            invited_by,
            invites,
        }),
    )
        .into_response())
}

async fn get_invited_by(state: &AppState, user_id: uuid::Uuid) -> Option<InviteCodeInfo> {
    let code = state
        .infra_repo
        .get_invite_code_used_by_user(user_id)
        .await
        .ok()??;

    get_invite_code_info(state, &code).await
}

async fn get_invites_for_user(
    state: &AppState,
    user_id: uuid::Uuid,
) -> Option<Vec<InviteCodeInfo>> {
    let invite_codes = state
        .infra_repo
        .get_invites_created_by_user(user_id)
        .await
        .ok()?;

    if invite_codes.is_empty() {
        return None;
    }

    let code_strings: Vec<String> = invite_codes.iter().map(|ic| ic.code.clone()).collect();

    let uses = state
        .infra_repo
        .get_invite_code_uses_batch(&code_strings)
        .await
        .ok()?;

    let uses_by_code: HashMap<String, Vec<InviteCodeUseInfo>> =
        uses.into_iter().fold(HashMap::new(), |mut acc, u| {
            acc.entry(u.code.clone())
                .or_default()
                .push(InviteCodeUseInfo {
                    used_by: u.used_by_did,
                    used_at: u.used_at.to_rfc3339(),
                });
            acc
        });

    let invites: Vec<InviteCodeInfo> = invite_codes
        .into_iter()
        .map(|ic| InviteCodeInfo {
            code: ic.code.clone(),
            available: ic.available_uses,
            disabled: ic.state.is_disabled(),
            for_account: ic.for_account,
            created_by: ic.created_by,
            created_at: ic.created_at.to_rfc3339(),
            uses: uses_by_code.get(&ic.code).cloned().unwrap_or_default(),
        })
        .collect();

    if invites.is_empty() {
        None
    } else {
        Some(invites)
    }
}

async fn get_invite_code_info(state: &AppState, code: &str) -> Option<InviteCodeInfo> {
    let info = state.infra_repo.get_invite_code_info(code).await.ok()??;

    let uses = state
        .infra_repo
        .get_invite_code_uses(code)
        .await
        .ok()
        .unwrap_or_default();

    Some(InviteCodeInfo {
        code: info.code,
        available: info.available_uses,
        disabled: info.state.is_disabled(),
        for_account: info.for_account,
        created_by: info.created_by,
        created_at: info.created_at.to_rfc3339(),
        uses: uses
            .into_iter()
            .map(|u| InviteCodeUseInfo {
                used_by: u.used_by_did,
                used_at: u.used_at.to_rfc3339(),
            })
            .collect(),
    })
}

pub async fn get_account_infos(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, ApiError> {
    let dids: Vec<String> = crate::util::parse_repeated_query_param(raw_query.as_deref(), "dids")
        .into_iter()
        .filter(|d| !d.is_empty())
        .collect();

    if dids.is_empty() {
        return Err(ApiError::InvalidRequest("dids is required".into()));
    }

    let dids_typed: Vec<Did> = dids.iter().filter_map(|d| d.parse().ok()).collect();
    let accounts = state
        .infra_repo
        .get_admin_account_infos_by_dids(&dids_typed)
        .await
        .log_db_err("fetching account infos")?;

    let user_ids: Vec<uuid::Uuid> = accounts.iter().map(|u| u.id).collect();

    let all_invite_codes = state
        .infra_repo
        .get_invite_codes_by_users(&user_ids)
        .await
        .unwrap_or_default();

    let all_codes: Vec<String> = all_invite_codes
        .iter()
        .map(|(_, c)| c.code.clone())
        .collect();

    let all_invite_uses = if !all_codes.is_empty() {
        state
            .infra_repo
            .get_invite_code_uses_batch(&all_codes)
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let invited_by_map: HashMap<uuid::Uuid, String> = state
        .infra_repo
        .get_invite_code_uses_by_users(&user_ids)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();

    let uses_by_code: HashMap<String, Vec<InviteCodeUseInfo>> =
        all_invite_uses
            .into_iter()
            .fold(HashMap::new(), |mut acc, u| {
                acc.entry(u.code.clone())
                    .or_default()
                    .push(InviteCodeUseInfo {
                        used_by: u.used_by_did,
                        used_at: u.used_at.to_rfc3339(),
                    });
                acc
            });

    let (codes_by_user, code_info_map): (
        HashMap<uuid::Uuid, Vec<InviteCodeInfo>>,
        HashMap<String, InviteCodeInfo>,
    ) = all_invite_codes.into_iter().fold(
        (HashMap::new(), HashMap::new()),
        |(mut by_user, mut by_code), (user_id, ic)| {
            let info = InviteCodeInfo {
                code: ic.code.clone(),
                available: ic.available_uses,
                disabled: ic.state.is_disabled(),
                for_account: ic.for_account,
                created_by: ic.created_by,
                created_at: ic.created_at.to_rfc3339(),
                uses: uses_by_code.get(&ic.code).cloned().unwrap_or_default(),
            };
            by_code.insert(ic.code.clone(), info.clone());
            by_user.entry(user_id).or_default().push(info);
            (by_user, by_code)
        },
    );

    let infos: Vec<AccountInfo> = accounts
        .into_iter()
        .map(|account| {
            let invited_by = invited_by_map
                .get(&account.id)
                .and_then(|code| code_info_map.get(code).cloned());
            let invites = codes_by_user.get(&account.id).cloned();
            AccountInfo {
                did: account.did,
                handle: account.handle,
                email: account.email,
                indexed_at: account.created_at.to_rfc3339(),
                invite_note: None,
                invites_disabled: account.invites_disabled,
                email_confirmed_at: if account.email_verified {
                    Some(account.created_at.to_rfc3339())
                } else {
                    None
                },
                deactivated_at: account.deactivated_at.map(|dt| dt.to_rfc3339()),
                invited_by,
                invites,
            }
        })
        .collect();

    Ok((StatusCode::OK, Json(GetAccountInfosOutput { infos })).into_response())
}
