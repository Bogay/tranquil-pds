use crate::AccountStatus;
use crate::api::error::ApiError;
use crate::state::AppState;
use crate::types::Did;
use axum::http::Method;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::sync::LazyLock;
use tracing::{error, info, warn};
use tranquil_types::Nsid;

static CREATE_ACCOUNT_NSID: LazyLock<Nsid> =
    LazyLock::new(|| "com.atproto.server.createAccount".parse().unwrap());

const HOUR_SECS: i64 = 3600;
const MINUTE_SECS: i64 = 60;

static PROTECTED_METHODS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
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
    ]
    .into_iter()
    .collect()
});

#[derive(Deserialize)]
pub struct GetServiceAuthParams {
    pub aud: Did,
    pub lxm: Option<Nsid>,
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
    let auth_header = crate::util::get_header_str(&headers, axum::http::header::AUTHORIZATION);
    let dpop_proof = crate::util::get_header_str(&headers, crate::util::HEADER_DPOP);
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

    let extracted = match crate::auth::extract_auth_token_from_header(Some(auth_header)) {
        Some(e) => e,
        None => {
            warn!(auth_scheme = ?auth_header.split_whitespace().next(), "getServiceAuth: invalid auth scheme");
            return ApiError::AuthenticationRequired.into_response();
        }
    };
    let token = extracted.token;

    let auth_user = if extracted.scheme.is_dpop() {
        match crate::oauth::verify::verify_oauth_access_token(
            state.oauth_repo.as_ref(),
            &token,
            dpop_proof,
            Method::GET.as_str(),
            &crate::util::build_full_url(&format!(
                "/xrpc/com.atproto.server.getServiceAuth?aud={}&lxm={}",
                params.aud,
                params.lxm.as_ref().map_or("", |n| n.as_str())
            )),
        )
        .await
        {
            Ok(result) => {
                let did: Did = match result.did.parse() {
                    Ok(d) => d,
                    Err(_) => {
                        return ApiError::InternalError(Some("Invalid DID in token".into()))
                            .into_response();
                    }
                };
                crate::auth::AuthenticatedUser {
                    did,
                    is_admin: false,
                    status: AccountStatus::Active,
                    scope: result.scope,
                    key_bytes: None,
                    controller_did: None,
                    auth_source: crate::auth::AuthSource::OAuth,
                }
            }
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
            Err(crate::oauth::OAuthError::ExpiredToken(msg)) => {
                warn!(error = %msg, "getServiceAuth DPoP token expired");
                return ApiError::OAuthExpiredToken(Some(msg)).into_response();
            }
            Err(e) => {
                warn!(error = ?e, "getServiceAuth DPoP auth validation failed");
                return ApiError::AuthenticationFailed(Some(format!("{:?}", e))).into_response();
            }
        }
    } else {
        match crate::auth::validate_bearer_token_for_service_auth(state.user_repo.as_ref(), &token)
            .await
        {
            Ok(user) => user,
            Err(e) => {
                warn!(error = ?e, "getServiceAuth auth validation failed");
                return ApiError::from(e).into_response();
            }
        }
    };
    info!(
        did = %&auth_user.did,
        is_oauth = auth_user.is_oauth(),
        has_key = auth_user.key_bytes.is_some(),
        "getServiceAuth auth validated"
    );
    let key_bytes = match &auth_user.key_bytes {
        Some(kb) => kb.clone(),
        None => {
            warn!(did = %&auth_user.did, "getServiceAuth: OAuth token has no key_bytes, fetching from DB");
            match state.user_repo.get_user_info_by_did(&auth_user.did).await {
                Ok(Some(info)) => match info.key_bytes {
                    Some(key_bytes_enc) => {
                        match crate::config::decrypt_key(&key_bytes_enc, info.encryption_version) {
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
                    None => {
                        return ApiError::AuthenticationFailed(Some(
                            "User has no signing key".into(),
                        ))
                        .into_response();
                    }
                },
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

    let lxm = params.lxm.as_ref();
    let lxm_for_token = lxm.map_or("*", |n| n.as_str());

    if let Some(method) = lxm {
        if let Err(e) = crate::auth::scope_check::check_rpc_scope(
            &auth_user.auth_source,
            auth_user.scope.as_deref(),
            params.aud.as_str(),
            method.as_str(),
        ) {
            return e;
        }
    } else if auth_user.is_oauth() {
        let permissions = auth_user.permissions();
        if !permissions.has_full_access() {
            return ApiError::InvalidRequest(
                "OAuth tokens with granular scopes must specify an lxm parameter".into(),
            )
            .into_response();
        }
    }

    let is_takendown = state
        .user_repo
        .get_status_by_did(&auth_user.did)
        .await
        .ok()
        .flatten()
        .is_some_and(|s| s.takedown_ref.is_some());

    if is_takendown && lxm != Some(&*CREATE_ACCOUNT_NSID) {
        return ApiError::InvalidToken(Some("Bad token scope".into())).into_response();
    }

    if let Some(method) = lxm
        && PROTECTED_METHODS.contains(&method.as_str())
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
        params.aud.as_str(),
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
