use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;
use tracing::{error, info, warn};
use tranquil_pds::api::error::ApiError;
use tranquil_pds::auth::extractor::{Auth, Permissive};
use tranquil_pds::state::AppState;
use tranquil_pds::types::Did;
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
    auth: Auth<Permissive>,
    Query(params): Query<GetServiceAuthParams>,
) -> Response {
    info!(
        did = %&auth.did,
        is_oauth = auth.is_oauth(),
        aud = %params.aud,
        lxm = ?params.lxm,
        "getServiceAuth called"
    );

    let key_bytes = match &auth.key_bytes {
        Some(kb) => kb.clone(),
        None => {
            warn!(did = %&auth.did, "getServiceAuth: no key_bytes in auth, fetching from DB");
            match state.repos.user.get_user_info_by_did(&auth.did).await {
                Ok(Some(info)) => match info.key_bytes {
                    Some(key_bytes_enc) => {
                        match tranquil_pds::config::decrypt_key(
                            &key_bytes_enc,
                            info.encryption_version,
                        ) {
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

    if let Some(method) = lxm {
        if let Err(e) = tranquil_pds::auth::scope_check::check_rpc_scope(
            &auth.auth_source,
            auth.scope.as_deref(),
            params.aud.as_str(),
            method.as_str(),
        ) {
            return e.into_response();
        }
    } else if auth.is_oauth() {
        let permissions = auth.permissions();
        if !permissions.has_full_access() {
            return ApiError::InvalidRequest(
                "OAuth tokens with granular scopes must specify an lxm parameter".into(),
            )
            .into_response();
        }
    }

    if auth.status.is_takendown() && lxm != Some(&*CREATE_ACCOUNT_NSID) {
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

    let service_token = match tranquil_pds::auth::create_service_token(
        &auth.did,
        params.aud.as_str(),
        lxm.map(|v| v.as_str()),
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
