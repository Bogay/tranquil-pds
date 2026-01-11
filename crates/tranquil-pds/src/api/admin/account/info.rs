use crate::api::error::ApiError;
use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use crate::types::{Did, Handle};
use axum::{
    Json,
    extract::{Query, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::error;

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
    pub for_account: Did,
    pub created_by: Did,
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
    _auth: BearerAuthAdmin,
    Query(params): Query<GetAccountInfoParams>,
) -> Response {
    let result = sqlx::query!(
        r#"
        SELECT id, did, handle, email, created_at, invites_disabled, email_verified, deactivated_at
        FROM users
        WHERE did = $1
        "#,
        params.did.as_str()
    )
    .fetch_optional(&state.db)
    .await;
    match result {
        Ok(Some(row)) => {
            let invited_by = get_invited_by(&state.db, row.id).await;
            let invites = get_invites_for_user(&state.db, row.id).await;
            (
                StatusCode::OK,
                Json(AccountInfo {
                    did: row.did.into(),
                    handle: row.handle.into(),
                    email: row.email,
                    indexed_at: row.created_at.to_rfc3339(),
                    invite_note: None,
                    invites_disabled: row.invites_disabled.unwrap_or(false),
                    email_confirmed_at: if row.email_verified {
                        Some(row.created_at.to_rfc3339())
                    } else {
                        None
                    },
                    deactivated_at: row.deactivated_at.map(|dt| dt.to_rfc3339()),
                    invited_by,
                    invites,
                }),
            )
                .into_response()
        }
        Ok(None) => ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error in get_account_info: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

async fn get_invited_by(db: &sqlx::PgPool, user_id: uuid::Uuid) -> Option<InviteCodeInfo> {
    let use_row = sqlx::query!(
        r#"
        SELECT icu.code
        FROM invite_code_uses icu
        WHERE icu.used_by_user = $1
        LIMIT 1
        "#,
        user_id
    )
    .fetch_optional(db)
    .await
    .ok()??;
    get_invite_code_info(db, &use_row.code).await
}

async fn get_invites_for_user(
    db: &sqlx::PgPool,
    user_id: uuid::Uuid,
) -> Option<Vec<InviteCodeInfo>> {
    let invite_codes = sqlx::query!(
        r#"
        SELECT ic.code, ic.available_uses, ic.disabled, ic.for_account, ic.created_at, u.did as created_by
        FROM invite_codes ic
        JOIN users u ON ic.created_by_user = u.id
        WHERE ic.created_by_user = $1
        "#,
        user_id
    )
    .fetch_all(db)
    .await
    .ok()?;

    if invite_codes.is_empty() {
        return None;
    }

    let code_strings: Vec<String> = invite_codes.iter().map(|ic| ic.code.clone()).collect();
    let mut uses_by_code: std::collections::HashMap<String, Vec<InviteCodeUseInfo>> =
        std::collections::HashMap::new();
    sqlx::query!(
        r#"
        SELECT icu.code, u.did as used_by, icu.used_at
        FROM invite_code_uses icu
        JOIN users u ON icu.used_by_user = u.id
        WHERE icu.code = ANY($1)
        "#,
        &code_strings
    )
    .fetch_all(db)
    .await
    .ok()?
    .into_iter()
    .for_each(|r| {
        uses_by_code
            .entry(r.code)
            .or_default()
            .push(InviteCodeUseInfo {
                used_by: r.used_by.into(),
                used_at: r.used_at.to_rfc3339(),
            });
    });

    let invites: Vec<InviteCodeInfo> = invite_codes
        .into_iter()
        .map(|ic| InviteCodeInfo {
            code: ic.code.clone(),
            available: ic.available_uses,
            disabled: ic.disabled.unwrap_or(false),
            for_account: ic.for_account.into(),
            created_by: ic.created_by.into(),
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

async fn get_invite_code_info(db: &sqlx::PgPool, code: &str) -> Option<InviteCodeInfo> {
    let row = sqlx::query!(
        r#"
        SELECT ic.code, ic.available_uses, ic.disabled, ic.for_account, ic.created_at, u.did as created_by
        FROM invite_codes ic
        JOIN users u ON ic.created_by_user = u.id
        WHERE ic.code = $1
        "#,
        code
    )
    .fetch_optional(db)
    .await
    .ok()??;
    let uses = sqlx::query!(
        r#"
        SELECT u.did as used_by, icu.used_at
        FROM invite_code_uses icu
        JOIN users u ON icu.used_by_user = u.id
        WHERE icu.code = $1
        "#,
        code
    )
    .fetch_all(db)
    .await
    .ok()?;
    Some(InviteCodeInfo {
        code: row.code,
        available: row.available_uses,
        disabled: row.disabled.unwrap_or(false),
        for_account: row.for_account.into(),
        created_by: row.created_by.into(),
        created_at: row.created_at.to_rfc3339(),
        uses: uses
            .into_iter()
            .map(|u| InviteCodeUseInfo {
                used_by: u.used_by.into(),
                used_at: u.used_at.to_rfc3339(),
            })
            .collect(),
    })
}

pub async fn get_account_infos(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let dids: Vec<String> = crate::util::parse_repeated_query_param(raw_query.as_deref(), "dids")
        .into_iter()
        .filter(|d| !d.is_empty())
        .collect();
    if dids.is_empty() {
        return ApiError::InvalidRequest("dids is required".into()).into_response();
    }
    let users = match sqlx::query!(
        r#"
        SELECT id, did, handle, email, created_at, invites_disabled, email_verified, deactivated_at
        FROM users
        WHERE did = ANY($1)
        "#,
        &dids
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to fetch account infos: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let user_ids: Vec<uuid::Uuid> = users.iter().map(|u| u.id).collect();

    let all_invite_codes = sqlx::query!(
        r#"
        SELECT ic.code, ic.available_uses, ic.disabled, ic.for_account, ic.created_at,
               ic.created_by_user, u.did as created_by
        FROM invite_codes ic
        JOIN users u ON ic.created_by_user = u.id
        WHERE ic.created_by_user = ANY($1)
        "#,
        &user_ids
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let all_codes: Vec<String> = all_invite_codes.iter().map(|c| c.code.clone()).collect();
    let all_invite_uses = if !all_codes.is_empty() {
        sqlx::query!(
            r#"
            SELECT icu.code, u.did as used_by, icu.used_at
            FROM invite_code_uses icu
            JOIN users u ON icu.used_by_user = u.id
            WHERE icu.code = ANY($1)
            "#,
            &all_codes
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    let invited_by_map: std::collections::HashMap<uuid::Uuid, String> = sqlx::query!(
        r#"
        SELECT icu.used_by_user, icu.code
        FROM invite_code_uses icu
        WHERE icu.used_by_user = ANY($1)
        "#,
        &user_ids
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| (r.used_by_user, r.code))
    .collect();

    let uses_by_code: std::collections::HashMap<String, Vec<InviteCodeUseInfo>> =
        all_invite_uses
            .into_iter()
            .fold(std::collections::HashMap::new(), |mut acc, u| {
                acc.entry(u.code.clone()).or_default().push(InviteCodeUseInfo {
                    used_by: u.used_by.into(),
                    used_at: u.used_at.to_rfc3339(),
                });
                acc
            });

    let (codes_by_user, code_info_map): (
        std::collections::HashMap<uuid::Uuid, Vec<InviteCodeInfo>>,
        std::collections::HashMap<String, InviteCodeInfo>,
    ) = all_invite_codes.into_iter().fold(
        (std::collections::HashMap::new(), std::collections::HashMap::new()),
        |(mut by_user, mut by_code), ic| {
            let info = InviteCodeInfo {
                code: ic.code.clone(),
                available: ic.available_uses,
                disabled: ic.disabled.unwrap_or(false),
                for_account: ic.for_account.into(),
                created_by: ic.created_by.into(),
                created_at: ic.created_at.to_rfc3339(),
                uses: uses_by_code.get(&ic.code).cloned().unwrap_or_default(),
            };
            by_code.insert(ic.code.clone(), info.clone());
            by_user.entry(ic.created_by_user).or_default().push(info);
            (by_user, by_code)
        },
    );

    let infos: Vec<AccountInfo> = users
        .into_iter()
        .map(|row| {
            let invited_by = invited_by_map
                .get(&row.id)
                .and_then(|code| code_info_map.get(code).cloned());
            let invites = codes_by_user.get(&row.id).cloned();
            AccountInfo {
                did: row.did.into(),
                handle: row.handle.into(),
                email: row.email,
                indexed_at: row.created_at.to_rfc3339(),
                invite_note: None,
                invites_disabled: row.invites_disabled.unwrap_or(false),
                email_confirmed_at: if row.email_verified {
                    Some(row.created_at.to_rfc3339())
                } else {
                    None
                },
                deactivated_at: row.deactivated_at.map(|dt| dt.to_rfc3339()),
                invited_by,
                invites,
            }
        })
        .collect();
    (StatusCode::OK, Json(GetAccountInfosOutput { infos })).into_response()
}
