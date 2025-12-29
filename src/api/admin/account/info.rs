use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;

#[derive(Deserialize)]
pub struct GetAccountInfoParams {
    pub did: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub did: String,
    pub handle: String,
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
    pub for_account: String,
    pub created_by: String,
    pub created_at: String,
    pub uses: Vec<InviteCodeUseInfo>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InviteCodeUseInfo {
    pub used_by: String,
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
    let did = params.did.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }
    let result = sqlx::query!(
        r#"
        SELECT id, did, handle, email, created_at, invites_disabled, email_verified, deactivated_at
        FROM users
        WHERE did = $1
        "#,
        did
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
                    did: row.did,
                    handle: row.handle,
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
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error in get_account_info: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

async fn get_invited_by(
    db: &sqlx::PgPool,
    user_id: uuid::Uuid,
) -> Option<InviteCodeInfo> {
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
    let codes = sqlx::query_scalar!(
        r#"
        SELECT code FROM invite_codes WHERE created_by_user = $1
        "#,
        user_id
    )
    .fetch_all(db)
    .await
    .ok()?;
    if codes.is_empty() {
        return None;
    }
    let mut invites = Vec::new();
    for code in codes {
        if let Some(info) = get_invite_code_info(db, &code).await {
            invites.push(info);
        }
    }
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
        for_account: row.for_account,
        created_by: row.created_by,
        created_at: row.created_at.to_rfc3339(),
        uses: uses
            .into_iter()
            .map(|u| InviteCodeUseInfo {
                used_by: u.used_by,
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
    let dids = crate::util::parse_repeated_query_param(raw_query.as_deref(), "dids");
    if dids.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "dids is required"})),
        )
            .into_response();
    }
    let mut infos = Vec::new();
    for did in &dids {
        if did.is_empty() {
            continue;
        }
        let result = sqlx::query!(
            r#"
            SELECT id, did, handle, email, created_at, invites_disabled, email_verified, deactivated_at
            FROM users
            WHERE did = $1
            "#,
            did
        )
        .fetch_optional(&state.db)
        .await;
        if let Ok(Some(row)) = result {
            let invited_by = get_invited_by(&state.db, row.id).await;
            let invites = get_invites_for_user(&state.db, row.id).await;
            infos.push(AccountInfo {
                did: row.did,
                handle: row.handle,
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
            });
        }
    }
    (StatusCode::OK, Json(GetAccountInfosOutput { infos })).into_response()
}
