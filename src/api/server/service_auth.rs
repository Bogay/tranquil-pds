use crate::api::ApiError;
use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;

const HOUR_SECS: i64 = 3600;
const MINUTE_SECS: i64 = 60;

const PROTECTED_METHODS: &[&str] = &[
    "com.atproto.admin.sendEmail",
    "com.atproto.identity.requestPlcOperationSignature",
    "com.atproto.identity.signPlcOperation",
    "com.atproto.identity.updateHandle",
    "com.atproto.server.activateAccount",
    "com.atproto.server.confirmEmail",
    "com.atproto.server.createAppPassword",
    "com.atproto.server.deactivateAccount",
    "com.atproto.server.getAccountInviteCodes",
    "com.atproto.server.getSession",
    "com.atproto.server.listAppPasswords",
    "com.atproto.server.requestAccountDelete",
    "com.atproto.server.requestEmailConfirmation",
    "com.atproto.server.requestEmailUpdate",
    "com.atproto.server.revokeAppPassword",
    "com.atproto.server.updateEmail",
];

#[derive(Deserialize)]
pub struct GetServiceAuthParams {
    pub aud: String,
    pub lxm: Option<String>,
    pub exp: Option<i64>,
}

#[derive(Serialize)]
pub struct GetServiceAuthOutput {
    pub token: String,
}

pub async fn get_service_auth(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetServiceAuthParams>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let auth_user =
        match crate::auth::validate_bearer_token_for_service_auth(&state.db, &token).await {
            Ok(user) => user,
            Err(e) => return ApiError::from(e).into_response(),
        };
    let key_bytes = match &auth_user.key_bytes {
        Some(kb) => kb.clone(),
        None => {
            return ApiError::AuthenticationFailedMsg(
                "OAuth tokens cannot create service auth".into(),
            )
            .into_response();
        }
    };

    let lxm = params.lxm.as_deref();
    let lxm_for_token = lxm.unwrap_or("*");

    if let Some(method) = lxm {
        if let Err(e) = crate::auth::scope_check::check_rpc_scope(
            auth_user.is_oauth,
            auth_user.scope.as_deref(),
            &params.aud,
            method,
        ) {
            return e;
        }
    } else if auth_user.is_oauth {
        let permissions = auth_user.permissions();
        if !permissions.has_full_access() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": "OAuth tokens with granular scopes must specify an lxm parameter"
                })),
            )
                .into_response();
        }
    }

    let user_status = sqlx::query!(
        "SELECT takedown_ref FROM users WHERE did = $1",
        auth_user.did
    )
    .fetch_optional(&state.db)
    .await;

    let is_takendown = match user_status {
        Ok(Some(row)) => row.takedown_ref.is_some(),
        _ => false,
    };

    if is_takendown && lxm != Some("com.atproto.server.createAccount") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidToken",
                "message": "Bad token scope"
            })),
        )
            .into_response();
    }

    if let Some(method) = lxm
        && PROTECTED_METHODS.contains(&method)
    {
        return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": format!("cannot request a service auth token for the following protected method: {}", method)
                })),
            )
                .into_response();
    }

    if let Some(exp) = params.exp {
        let now = chrono::Utc::now().timestamp();
        let diff = exp - now;

        if diff < 0 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "BadExpiration",
                    "message": "expiration is in past"
                })),
            )
                .into_response();
        }

        if diff > HOUR_SECS {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "BadExpiration",
                    "message": "cannot request a token with an expiration more than an hour in the future"
                })),
            )
                .into_response();
        }

        if lxm.is_none() && diff > MINUTE_SECS {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "BadExpiration",
                    "message": "cannot request a method-less token with an expiration more than a minute in the future"
                })),
            )
                .into_response();
        }
    }

    let service_token = match crate::auth::create_service_token(
        &auth_user.did,
        &params.aud,
        lxm_for_token,
        &key_bytes,
    ) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to create service token: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    (
        StatusCode::OK,
        Json(GetServiceAuthOutput {
            token: service_token,
        }),
    )
        .into_response()
}
