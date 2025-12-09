use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, warn};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableInviteCodesInput {
    pub codes: Option<Vec<String>>,
    pub accounts: Option<Vec<String>>,
}

pub async fn disable_invite_codes(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<DisableInviteCodesInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    if let Some(codes) = &input.codes {
        for code in codes {
            let _ = sqlx::query!("UPDATE invite_codes SET disabled = TRUE WHERE code = $1", code)
                .execute(&state.db)
                .await;
        }
    }

    if let Some(accounts) = &input.accounts {
        for account in accounts {
            let user = sqlx::query!("SELECT id FROM users WHERE did = $1", account)
                .fetch_optional(&state.db)
                .await;

            if let Ok(Some(user_row)) = user {
                let _ = sqlx::query!(
                    "UPDATE invite_codes SET disabled = TRUE WHERE created_by_user = $1",
                    user_row.id
                )
                .execute(&state.db)
                .await;
            }
        }
    }

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Deserialize)]
pub struct GetSubjectStatusParams {
    pub did: Option<String>,
    pub uri: Option<String>,
    pub blob: Option<String>,
}

#[derive(Serialize)]
pub struct SubjectStatus {
    pub subject: serde_json::Value,
    pub takedown: Option<StatusAttr>,
    pub deactivated: Option<StatusAttr>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusAttr {
    pub applied: bool,
    pub r#ref: Option<String>,
}

pub async fn get_subject_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetSubjectStatusParams>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    if params.did.is_none() && params.uri.is_none() && params.blob.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Must provide did, uri, or blob"})),
        )
            .into_response();
    }

    if let Some(did) = &params.did {
        let user = sqlx::query!(
            "SELECT did, deactivated_at, takedown_ref FROM users WHERE did = $1",
            did
        )
        .fetch_optional(&state.db)
        .await;

        match user {
            Ok(Some(row)) => {
                let deactivated = row.deactivated_at.map(|_| StatusAttr {
                    applied: true,
                    r#ref: None,
                });
                let takedown = row.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });

                return (
                    StatusCode::OK,
                    Json(SubjectStatus {
                        subject: json!({
                            "$type": "com.atproto.admin.defs#repoRef",
                            "did": row.did
                        }),
                        takedown,
                        deactivated,
                    }),
                )
                    .into_response();
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "SubjectNotFound", "message": "Subject not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        }
    }

    if let Some(uri) = &params.uri {
        let record = sqlx::query!(
            "SELECT r.id, r.takedown_ref FROM records r WHERE r.record_cid = $1",
            uri
        )
        .fetch_optional(&state.db)
        .await;

        match record {
            Ok(Some(row)) => {
                let takedown = row.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });

                return (
                    StatusCode::OK,
                    Json(SubjectStatus {
                        subject: json!({
                            "$type": "com.atproto.repo.strongRef",
                            "uri": uri,
                            "cid": uri
                        }),
                        takedown,
                        deactivated: None,
                    }),
                )
                    .into_response();
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "SubjectNotFound", "message": "Subject not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        }
    }

    if let Some(blob_cid) = &params.blob {
        let blob = sqlx::query!("SELECT cid, takedown_ref FROM blobs WHERE cid = $1", blob_cid)
            .fetch_optional(&state.db)
            .await;

        match blob {
            Ok(Some(row)) => {
                let takedown = row.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });

                return (
                    StatusCode::OK,
                    Json(SubjectStatus {
                        subject: json!({
                            "$type": "com.atproto.admin.defs#repoBlobRef",
                            "did": "",
                            "cid": row.cid
                        }),
                        takedown,
                        deactivated: None,
                    }),
                )
                    .into_response();
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "SubjectNotFound", "message": "Subject not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "InvalidRequest", "message": "Invalid subject type"})),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSubjectStatusInput {
    pub subject: serde_json::Value,
    pub takedown: Option<StatusAttrInput>,
    pub deactivated: Option<StatusAttrInput>,
}

#[derive(Deserialize)]
pub struct StatusAttrInput {
    pub apply: bool,
    pub r#ref: Option<String>,
}

pub async fn update_subject_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateSubjectStatusInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let subject_type = input.subject.get("$type").and_then(|t| t.as_str());

    match subject_type {
        Some("com.atproto.admin.defs#repoRef") => {
            let did = input.subject.get("did").and_then(|d| d.as_str());
            if let Some(did) = did {
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.apply {
                        takedown.r#ref.clone()
                    } else {
                        None
                    };
                    let _ = sqlx::query!(
                        "UPDATE users SET takedown_ref = $1 WHERE did = $2",
                        takedown_ref,
                        did
                    )
                    .execute(&state.db)
                    .await;
                }

                if let Some(deactivated) = &input.deactivated {
                    if deactivated.apply {
                        let _ = sqlx::query!(
                            "UPDATE users SET deactivated_at = NOW() WHERE did = $1",
                            did
                        )
                        .execute(&state.db)
                        .await;
                    } else {
                        let _ = sqlx::query!(
                            "UPDATE users SET deactivated_at = NULL WHERE did = $1",
                            did
                        )
                        .execute(&state.db)
                        .await;
                    }
                }

                return (
                    StatusCode::OK,
                    Json(json!({
                        "subject": input.subject,
                        "takedown": input.takedown.as_ref().map(|t| json!({
                            "applied": t.apply,
                            "ref": t.r#ref
                        })),
                        "deactivated": input.deactivated.as_ref().map(|d| json!({
                            "applied": d.apply
                        }))
                    })),
                )
                    .into_response();
            }
        }
        Some("com.atproto.repo.strongRef") => {
            let uri = input.subject.get("uri").and_then(|u| u.as_str());
            if let Some(uri) = uri {
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.apply {
                        takedown.r#ref.clone()
                    } else {
                        None
                    };
                    let _ = sqlx::query!(
                        "UPDATE records SET takedown_ref = $1 WHERE record_cid = $2",
                        takedown_ref,
                        uri
                    )
                    .execute(&state.db)
                    .await;
                }

                return (
                    StatusCode::OK,
                    Json(json!({
                        "subject": input.subject,
                        "takedown": input.takedown.as_ref().map(|t| json!({
                            "applied": t.apply,
                            "ref": t.r#ref
                        }))
                    })),
                )
                    .into_response();
            }
        }
        Some("com.atproto.admin.defs#repoBlobRef") => {
            let cid = input.subject.get("cid").and_then(|c| c.as_str());
            if let Some(cid) = cid {
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.apply {
                        takedown.r#ref.clone()
                    } else {
                        None
                    };
                    let _ = sqlx::query!(
                        "UPDATE blobs SET takedown_ref = $1 WHERE cid = $2",
                        takedown_ref,
                        cid
                    )
                    .execute(&state.db)
                    .await;
                }

                return (
                    StatusCode::OK,
                    Json(json!({
                        "subject": input.subject,
                        "takedown": input.takedown.as_ref().map(|t| json!({
                            "applied": t.apply,
                            "ref": t.r#ref
                        }))
                    })),
                )
                    .into_response();
            }
        }
        _ => {}
    }

    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "InvalidRequest", "message": "Invalid subject type"})),
    )
        .into_response()
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCodeUseInfo {
    pub used_by: String,
    pub used_at: String,
}

#[derive(Serialize)]
pub struct GetInviteCodesOutput {
    pub cursor: Option<String>,
    pub codes: Vec<InviteCodeInfo>,
}

pub async fn get_invite_codes(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetInviteCodesParams>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let limit = params.limit.unwrap_or(100).min(500);
    let sort = params.sort.as_deref().unwrap_or("recent");

    let order_clause = match sort {
        "usage" => "available_uses DESC",
        _ => "created_at DESC",
    };

    let codes_result = if let Some(cursor) = &params.cursor {
        sqlx::query_as::<_, (String, i32, Option<bool>, uuid::Uuid, chrono::DateTime<chrono::Utc>)>(&format!(
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
        sqlx::query_as::<_, (String, i32, Option<bool>, uuid::Uuid, chrono::DateTime<chrono::Utc>)>(&format!(
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let mut codes = Vec::new();
    for (code, available_uses, disabled, created_by_user, created_at) in &codes_rows {
        let creator_did = sqlx::query_scalar!("SELECT did FROM users WHERE id = $1", created_by_user)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "unknown".to_string());

        let uses_result = sqlx::query!(
            r#"
            SELECT u.did, icu.used_at
            FROM invite_code_uses icu
            JOIN users u ON icu.used_by_user = u.id
            WHERE icu.code = $1
            ORDER BY icu.used_at DESC
            "#,
            code
        )
        .fetch_all(&state.db)
        .await;

        let uses = match uses_result {
            Ok(use_rows) => use_rows
                .iter()
                .map(|u| InviteCodeUseInfo {
                    used_by: u.did.clone(),
                    used_at: u.used_at.to_rfc3339(),
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        codes.push(InviteCodeInfo {
            code: code.clone(),
            available: *available_uses,
            disabled: disabled.unwrap_or(false),
            for_account: creator_did.clone(),
            created_by: creator_did,
            created_at: created_at.to_rfc3339(),
            uses,
        });
    }

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
    headers: axum::http::HeaderMap,
    Json(input): Json<DisableAccountInvitesInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let account = input.account.trim();
    if account.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "account is required"})),
        )
            .into_response();
    }

    let result = sqlx::query!("UPDATE users SET invites_disabled = TRUE WHERE did = $1", account)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error disabling account invites: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct EnableAccountInvitesInput {
    pub account: String,
}

pub async fn enable_account_invites(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<EnableAccountInvitesInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let account = input.account.trim();
    if account.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "account is required"})),
        )
            .into_response();
    }

    let result = sqlx::query!("UPDATE users SET invites_disabled = FALSE WHERE did = $1", account)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error enabling account invites: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct GetAccountInfoParams {
    pub did: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub did: String,
    pub handle: String,
    pub email: Option<String>,
    pub indexed_at: String,
    pub invite_note: Option<String>,
    pub invites_disabled: bool,
    pub email_confirmed_at: Option<String>,
    pub deactivated_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAccountInfosOutput {
    pub infos: Vec<AccountInfo>,
}

pub async fn get_account_info(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetAccountInfoParams>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

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
        SELECT did, handle, email, created_at
        FROM users
        WHERE did = $1
        "#,
        did
    )
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => {
            (
                StatusCode::OK,
                Json(AccountInfo {
                    did: row.did,
                    handle: row.handle,
                    email: Some(row.email),
                    indexed_at: row.created_at.to_rfc3339(),
                    invite_note: None,
                    invites_disabled: false,
                    email_confirmed_at: None,
                    deactivated_at: None,
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

#[derive(Deserialize)]
pub struct GetAccountInfosParams {
    pub dids: String,
}

pub async fn get_account_infos(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetAccountInfosParams>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let dids: Vec<&str> = params.dids.split(',').map(|s| s.trim()).collect();
    if dids.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "dids is required"})),
        )
            .into_response();
    }

    let mut infos = Vec::new();

    for did in dids {
        if did.is_empty() {
            continue;
        }

        let result = sqlx::query!(
            r#"
            SELECT did, handle, email, created_at
            FROM users
            WHERE did = $1
            "#,
            did
        )
        .fetch_optional(&state.db)
        .await;

        if let Ok(Some(row)) = result {
            infos.push(AccountInfo {
                did: row.did,
                handle: row.handle,
                email: Some(row.email),
                indexed_at: row.created_at.to_rfc3339(),
                invite_note: None,
                invites_disabled: false,
                email_confirmed_at: None,
                deactivated_at: None,
            });
        }
    }

    (StatusCode::OK, Json(GetAccountInfosOutput { infos })).into_response()
}

#[derive(Deserialize)]
pub struct DeleteAccountInput {
    pub did: String,
}

pub async fn delete_account(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<DeleteAccountInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let did = input.did.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }

    let user = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;

    let user_id = match user {
        Ok(Some(row)) => row.id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in delete_account: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let _ = sqlx::query!("DELETE FROM sessions WHERE did = $1", did)
        .execute(&state.db)
        .await;

    let _ = sqlx::query!("DELETE FROM records WHERE repo_id = $1", user_id)
        .execute(&state.db)
        .await;

    let _ = sqlx::query!("DELETE FROM repos WHERE user_id = $1", user_id)
        .execute(&state.db)
        .await;

    let _ = sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
        .execute(&state.db)
        .await;

    let _ = sqlx::query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
        .execute(&state.db)
        .await;

    let result = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
        .execute(&state.db)
        .await;

    match result {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => {
            error!("DB error deleting account: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateAccountEmailInput {
    pub account: String,
    pub email: String,
}

pub async fn update_account_email(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateAccountEmailInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let account = input.account.trim();
    let email = input.email.trim();

    if account.is_empty() || email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "account and email are required"})),
        )
            .into_response();
    }

    let result = sqlx::query!("UPDATE users SET email = $1 WHERE did = $2", email, account)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error updating email: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateAccountHandleInput {
    pub did: String,
    pub handle: String,
}

pub async fn update_account_handle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateAccountHandleInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let did = input.did.trim();
    let handle = input.handle.trim();

    if did.is_empty() || handle.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did and handle are required"})),
        )
            .into_response();
    }

    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidHandle", "message": "Handle contains invalid characters"})),
        )
            .into_response();
    }

    let existing = sqlx::query!("SELECT id FROM users WHERE handle = $1 AND did != $2", handle, did)
        .fetch_optional(&state.db)
        .await;

    if let Ok(Some(_)) = existing {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "HandleTaken", "message": "Handle is already in use"})),
        )
            .into_response();
    }

    let result = sqlx::query!("UPDATE users SET handle = $1 WHERE did = $2", handle, did)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error updating handle: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateAccountPasswordInput {
    pub did: String,
    pub password: String,
}

pub async fn update_account_password(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateAccountPasswordInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let did = input.did.trim();
    let password = input.password.trim();

    if did.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did and password are required"})),
        )
            .into_response();
    }

    let password_hash = match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to hash password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let result = sqlx::query!("UPDATE users SET password_hash = $1 WHERE did = $2", password_hash, did)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error updating password: {:?}", e);
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
pub struct SendEmailInput {
    pub recipient_did: String,
    pub sender_did: String,
    pub content: String,
    pub subject: Option<String>,
    pub comment: Option<String>,
}

#[derive(Serialize)]
pub struct SendEmailOutput {
    pub sent: bool,
}

pub async fn send_email(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<SendEmailInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let recipient_did = input.recipient_did.trim();
    let content = input.content.trim();

    if recipient_did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "recipientDid is required"})),
        )
            .into_response();
    }

    if content.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "content is required"})),
        )
            .into_response();
    }

    let user = sqlx::query!(
        "SELECT id, email, handle FROM users WHERE did = $1",
        recipient_did
    )
    .fetch_optional(&state.db)
    .await;

    let (user_id, email, handle) = match user {
        Ok(Some(row)) => (row.id, row.email, row.handle),
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound", "message": "Recipient account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in send_email: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let subject = input
        .subject
        .clone()
        .unwrap_or_else(|| format!("Message from {}", hostname));

    let notification = crate::notifications::NewNotification::email(
        user_id,
        crate::notifications::NotificationType::AdminEmail,
        email,
        subject,
        content.to_string(),
    );

    let result = crate::notifications::enqueue_notification(&state.db, notification).await;

    match result {
        Ok(_) => {
            tracing::info!(
                "Admin email queued for {} ({})",
                handle,
                recipient_did
            );
            (StatusCode::OK, Json(SendEmailOutput { sent: true })).into_response()
        }
        Err(e) => {
            warn!("Failed to enqueue admin email: {:?}", e);
            (StatusCode::OK, Json(SendEmailOutput { sent: false })).into_response()
        }
    }
}
