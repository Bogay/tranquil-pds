use crate::AccountStatus;
use crate::api::error::ApiError;
use crate::state::AppState;
use crate::types::Did;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info, warn};

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
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    info!(
        has_auth_header = auth_header.is_some(),
        has_dpop_proof = dpop_proof.is_some(),
        aud = %params.aud,
        lxm = ?params.lxm,
        "getServiceAuth called"
    );
    let auth_header = match auth_header {
        Some(h) => h.trim(),
        None => {
            warn!("getServiceAuth: no Authorization header");
            return ApiError::AuthenticationRequired.into_response();
        }
    };

    let (token, is_dpop) = if auth_header.len() >= 7
        && auth_header[..7].eq_ignore_ascii_case("bearer ")
    {
        (auth_header[7..].trim().to_string(), false)
    } else if auth_header.len() >= 5 && auth_header[..5].eq_ignore_ascii_case("dpop ") {
        (auth_header[5..].trim().to_string(), true)
    } else {
        warn!(auth_scheme = ?auth_header.split_whitespace().next(), "getServiceAuth: invalid auth scheme");
        return ApiError::AuthenticationRequired.into_response();
    };

    let auth_user = if is_dpop {
        match crate::oauth::verify::verify_oauth_access_token(
            &state.db,
            &token,
            dpop_proof,
            "GET",
            &format!(
                "/xrpc/com.atproto.server.getServiceAuth?aud={}&lxm={}",
                params.aud,
                params.lxm.as_deref().unwrap_or("")
            ),
        )
        .await
        {
            Ok(result) => crate::auth::AuthenticatedUser {
                did: Did::new_unchecked(result.did),
                is_oauth: true,
                is_admin: false,
                status: AccountStatus::Active,
                scope: result.scope,
                key_bytes: None,
                controller_did: None,
            },
            Err(crate::oauth::OAuthError::UseDpopNonce(nonce)) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    [("DPoP-Nonce", nonce)],
                    Json(json!({
                        "error": "use_dpop_nonce",
                        "message": "DPoP nonce required"
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                warn!(error = ?e, "getServiceAuth DPoP auth validation failed");
                return ApiError::AuthenticationFailed(Some(format!("{:?}", e))).into_response();
            }
        }
    } else {
        match crate::auth::validate_bearer_token_for_service_auth(&state.db, &token).await {
            Ok(user) => user,
            Err(e) => {
                warn!(error = ?e, "getServiceAuth auth validation failed");
                return ApiError::from(e).into_response();
            }
        }
    };
    info!(
        did = %&auth_user.did,
        is_oauth = auth_user.is_oauth,
        has_key = auth_user.key_bytes.is_some(),
        "getServiceAuth auth validated"
    );
    let key_bytes = match &auth_user.key_bytes {
        Some(kb) => kb.clone(),
        None => {
            warn!(did = %&auth_user.did, "getServiceAuth: OAuth token has no key_bytes, fetching from DB");
            match sqlx::query_as::<_, (Vec<u8>, Option<i32>)>(
                "SELECT k.key_bytes, k.encryption_version
                 FROM users u
                 JOIN user_keys k ON u.id = k.user_id
                 WHERE u.did = $1",
            )
            .bind(&auth_user.did)
            .fetch_optional(&state.db)
            .await
            {
                Ok(Some((key_bytes_enc, encryption_version))) => {
                    match crate::config::decrypt_key(&key_bytes_enc, encryption_version) {
                        Ok(key) => key,
                        Err(e) => {
                            error!(error = ?e, "Failed to decrypt user key for service auth");
                            return ApiError::AuthenticationFailed(Some(
                                "Failed to get signing key".into(),
                            ))
                            .into_response();
                        }
                    }
                }
                Ok(None) => {
                    return ApiError::AuthenticationFailed(Some("User has no signing key".into()))
                        .into_response();
                }
                Err(e) => {
                    error!(error = ?e, "DB error fetching user key");
                    return ApiError::AuthenticationFailed(Some(
                        "Failed to get signing key".into(),
                    ))
                    .into_response();
                }
            }
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
            return ApiError::InvalidRequest(
                "OAuth tokens with granular scopes must specify an lxm parameter".into(),
            )
            .into_response();
        }
    }

    let user_status = sqlx::query!(
        "SELECT takedown_ref FROM users WHERE did = $1",
        &auth_user.did
    )
    .fetch_optional(&state.db)
    .await;

    let is_takendown = match user_status {
        Ok(Some(row)) => row.takedown_ref.is_some(),
        _ => false,
    };

    if is_takendown && lxm != Some("com.atproto.server.createAccount") {
        return ApiError::InvalidToken(Some("Bad token scope".into())).into_response();
    }

    if let Some(method) = lxm
        && PROTECTED_METHODS.contains(&method)
    {
        return ApiError::InvalidRequest(format!(
            "cannot request a service auth token for the following protected method: {}",
            method
        ))
        .into_response();
    }

    if let Some(exp) = params.exp {
        let now = chrono::Utc::now().timestamp();
        let diff = exp - now;

        if diff < 0 {
            return ApiError::InvalidRequest("expiration is in past".into()).into_response();
        }

        if diff > HOUR_SECS {
            return ApiError::InvalidRequest(
                "cannot request a token with an expiration more than an hour in the future".into(),
            )
            .into_response();
        }

        if lxm.is_none() && diff > MINUTE_SECS {
            return ApiError::InvalidRequest(
                "cannot request a method-less token with an expiration more than a minute in the future".into(),
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
            return ApiError::InternalError(None).into_response();
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
