use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use tranquil_pds::auth::{Active, Auth};
use tranquil_pds::delegation::DelegationActionType;
use tranquil_pds::oauth::client::{build_client_metadata, delegation_oauth_urls};
use tranquil_pds::oauth::{AuthStage, RequestData};
use tranquil_pds::rate_limit::{LoginLimit, OAuthRateLimited, TotpVerifyLimit};
use tranquil_pds::state::AppState;
use tranquil_pds::types::PlainPassword;
use tranquil_pds::util::ClientIp;
use tranquil_types::did_doc::{PdsEndpointError, extract_handle, extract_pds_endpoint};
use tranquil_types::url_kind;
use tranquil_types::{Did, RequestId};

use crate::endpoints::authorize::{
    SecondFactorRequirement, UNDELIVERABLE_CODE, begin_second_factor,
};

#[allow(clippy::result_large_err)]
fn parse_did(s: &str, label: &str) -> Result<Did, Response> {
    s.parse()
        .map_err(|_| DelegationAuthResponse::err(format!("Invalid {} DID", label)))
}

async fn get_auth_request(state: &AppState, request_uri: &str) -> Result<RequestData, Response> {
    let request_id = RequestId::from(request_uri.to_string());
    match state
        .repos
        .oauth
        .get_authorization_request(&request_id)
        .await
    {
        Ok(Some(r)) => Ok(r),
        Ok(None) => Err(DelegationAuthResponse::err(
            "Authorization request not found",
        )),
        Err(_) => Err(DelegationAuthResponse::err("Server error")),
    }
}

async fn get_delegation_grant(
    state: &AppState,
    delegated_did: &Did,
    controller_did: &Did,
) -> Result<tranquil_db_traits::DelegationGrant, Response> {
    match state
        .repos
        .delegation
        .get_delegation(delegated_did, controller_did)
        .await
    {
        Ok(Some(g)) => Ok(g),
        Ok(None) => Err(DelegationAuthResponse::err(
            "No delegation grant found for this controller",
        )),
        Err(_) => Err(DelegationAuthResponse::err("Server error")),
    }
}

async fn finalize_delegation_auth(
    state: &AppState,
    request_uri: &str,
    delegated_did: &Did,
    controller_did: &Did,
    details: serde_json::Value,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Response {
    let _ = state
        .repos
        .delegation
        .log_delegation_action(
            delegated_did,
            controller_did,
            Some(controller_did),
            DelegationActionType::TokenIssued,
            Some(details),
            ip,
            user_agent,
        )
        .await;
    consent_redirect(request_uri)
}

async fn bind_delegation(
    state: &AppState,
    request_uri: &str,
    delegated_did: &Did,
    controller_did: &Did,
    stage: AuthStage,
) -> Result<(), Response> {
    let request_id = RequestId::from(request_uri.to_string());
    state
        .repos
        .oauth
        .set_delegation(&request_id, delegated_did, controller_did, stage)
        .await
        .map_err(|_| DelegationAuthResponse::err("Failed to update authorization request"))
}

fn consent_url(request_uri: &str) -> String {
    format!(
        "/app/oauth/consent?request_uri={}",
        urlencoding::encode(request_uri)
    )
}

fn consent_redirect(request_uri: &str) -> Response {
    DelegationAuthResponse::redirect(consent_url(request_uri))
}

#[derive(Debug, Deserialize)]
pub struct DelegationAuthSubmit {
    pub request_uri: String,
    pub delegated_did: Option<String>,
    pub controller_did: String,
    pub password: Option<PlainPassword>,
    #[serde(default)]
    pub remember_device: bool,
    pub auth_method: Option<String>,
}

enum DelegationAuthResponse {
    Redirect(String),
    NeedsTotp(String),
    Needs2fa {
        channel: String,
        redirect_uri: String,
    },
    Error(String),
    TotpError(String),
}

impl DelegationAuthResponse {
    fn err(msg: impl Into<String>) -> Response {
        Self::Error(msg.into()).into_response()
    }

    fn redirect(uri: impl Into<String>) -> Response {
        Self::Redirect(uri.into()).into_response()
    }

    fn needs_totp(uri: impl Into<String>) -> Response {
        Self::NeedsTotp(uri.into()).into_response()
    }

    fn needs_2fa(channel: impl Into<String>, redirect_uri: impl Into<String>) -> Response {
        Self::Needs2fa {
            channel: channel.into(),
            redirect_uri: redirect_uri.into(),
        }
        .into_response()
    }

    fn totp_error(msg: impl Into<String>) -> Response {
        Self::TotpError(msg.into()).into_response()
    }
}

impl IntoResponse for DelegationAuthResponse {
    fn into_response(self) -> Response {
        let (success, needs_totp, needs_2fa, redirect_uri, channel, error) = match self {
            Self::Redirect(uri) => (true, None, None, Some(uri), None, None),
            Self::NeedsTotp(uri) => (true, Some(true), None, Some(uri), None, None),
            Self::Needs2fa {
                channel,
                redirect_uri,
            } => (
                true,
                None,
                Some(true),
                Some(redirect_uri),
                Some(channel),
                None,
            ),
            Self::Error(msg) => (false, None, None, None, None, Some(msg)),
            Self::TotpError(msg) => (false, Some(true), None, None, None, Some(msg)),
        };

        #[derive(Serialize)]
        struct Body {
            success: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            needs_totp: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            needs_2fa: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            redirect_uri: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            channel: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            error: Option<String>,
        }

        Json(Body {
            success,
            needs_totp,
            needs_2fa,
            redirect_uri,
            channel,
            error,
        })
        .into_response()
    }
}

pub async fn delegation_auth(
    State(state): State<AppState>,
    rate_limit: OAuthRateLimited<LoginLimit>,
    headers: HeaderMap,
    Json(form): Json<DelegationAuthSubmit>,
) -> Response {
    let client_ip = rate_limit.client_ip();
    let request = match get_auth_request(&state, &form.request_uri).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let delegated_did = if let Some(did_str) = form.delegated_did.as_ref() {
        match parse_did(did_str, "delegated") {
            Ok(d) => d,
            Err(resp) => return resp,
        }
    } else if let Some(did) = request.did.clone() {
        did
    } else {
        return DelegationAuthResponse::err("No delegated account selected");
    };

    let controller_did = match parse_did(&form.controller_did, "controller") {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    let grant = match get_delegation_grant(&state, &delegated_did, &controller_did).await {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    let is_cross_pds = form.auth_method.as_deref() == Some("cross_pds");
    let controller_local = state
        .repos
        .user
        .get_auth_info_by_did(&controller_did)
        .await
        .ok()
        .flatten();

    if is_cross_pds || controller_local.is_none() {
        let did_doc = match state.plc_client().get_document(&controller_did).await {
            Ok(doc) => doc,
            Err(_) => {
                return DelegationAuthResponse::err("Failed to resolve controller DID");
            }
        };

        let pds_url = match extract_pds_endpoint::<url_kind::Pds>(&did_doc) {
            Ok(url) => url,
            Err(PdsEndpointError::Missing) => {
                return DelegationAuthResponse::err("Controller has no PDS endpoint");
            }
            Err(PdsEndpointError::Invalid(e)) => {
                tracing::warn!(controller = %controller_did, error = %e, "Controller PDS endpoint rejected");
                return DelegationAuthResponse::err(
                    "Controller PDS endpoint isn't a usable https URL",
                );
            }
        };

        let hostname = &tranquil_config::get().server.hostname;
        let urls = delegation_oauth_urls(hostname);
        let login_hint = extract_handle(&did_doc);
        let (par_result, auth_state, oauth_state) = match state
            .cross_pds_oauth
            .initiate_par(
                &pds_url,
                &urls,
                login_hint.as_deref(),
                &form.request_uri,
                &controller_did,
                &delegated_did,
            )
            .await
        {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Cross-PDS PAR failed: {:?}", e);
                return DelegationAuthResponse::err("Failed to initiate cross-PDS authentication");
            }
        };

        if let Err(e) = state
            .cross_pds_oauth
            .store_auth_state(&oauth_state, &auth_state)
            .await
        {
            tracing::error!("Failed to store cross-PDS auth state: {:?}", e);
            return DelegationAuthResponse::err(
                "Internal error preparing cross-PDS authentication",
            );
        }

        return DelegationAuthResponse::redirect(par_result.authorize_url);
    }

    let controller = controller_local.unwrap();

    if controller.deactivated_at.is_some() {
        return DelegationAuthResponse::err("Controller account is deactivated");
    }

    if controller.takedown_ref.is_some() {
        return DelegationAuthResponse::err("Controller account has been taken down");
    }

    let password = match form.password {
        Some(ref pw) => pw,
        None => {
            return DelegationAuthResponse::err("Password required for local controller");
        }
    };

    let password_valid = controller
        .password_hash
        .as_ref()
        .map(|hash| tranquil_pds::auth::verify_password(password, hash))
        .unwrap_or_default();

    if !password_valid {
        return DelegationAuthResponse::err("Invalid password");
    }

    let request_id = RequestId::from(form.request_uri.clone());
    let hostname = &tranquil_config::get().server.hostname;
    let requirement = match begin_second_factor(&state, &controller_did, &request_id, None).await {
        Ok(req) => req,
        Err(e) => {
            tracing::error!(did = %controller_did, error = %e, "begin_second_factor failed in delegation_auth");
            return DelegationAuthResponse::err("Server error");
        }
    };
    let stage = match requirement {
        SecondFactorRequirement::None => AuthStage::Complete,
        _ => AuthStage::FirstFactor,
    };
    if let Err(resp) = bind_delegation(
        &state,
        &form.request_uri,
        &delegated_did,
        &controller_did,
        stage,
    )
    .await
    {
        return resp;
    }
    match requirement {
        SecondFactorRequirement::Totp => {
            return DelegationAuthResponse::needs_totp(format!(
                "/app/oauth/delegation-totp?request_uri={}",
                urlencoding::encode(&form.request_uri)
            ));
        }
        SecondFactorRequirement::Code { channel, notice } => {
            if notice
                .dispatch(&state, hostname, &controller_did)
                .await
                .is_err()
            {
                return DelegationAuthResponse::err(UNDELIVERABLE_CODE);
            }
            return DelegationAuthResponse::needs_2fa(
                channel,
                format!(
                    "/app/oauth/2fa?request_uri={}&channel={}",
                    urlencoding::encode(&form.request_uri),
                    urlencoding::encode(channel)
                ),
            );
        }
        SecondFactorRequirement::None => {}
    }

    let user_agent = tranquil_pds::util::extract_user_agent(&headers);

    finalize_delegation_auth(
        &state,
        &form.request_uri,
        &delegated_did,
        &controller_did,
        serde_json::json!({
            "client_id": request.client_id,
            "granted_scopes": grant.granted_scopes
        }),
        Some(client_ip),
        user_agent.as_deref(),
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct DelegationTotpSubmit {
    pub request_uri: String,
    pub code: String,
}

pub async fn delegation_totp_verify(
    State(state): State<AppState>,
    rate_limit: OAuthRateLimited<TotpVerifyLimit>,
    headers: HeaderMap,
    Json(form): Json<DelegationTotpSubmit>,
) -> Response {
    let client_ip = rate_limit.client_ip();
    let request = match get_auth_request(&state, &form.request_uri).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let controller_did = match request.controller_did {
        Some(did) if request.auth_stage == AuthStage::FirstFactor => did,
        _ => return DelegationAuthResponse::err("Controller not authenticated"),
    };

    let delegated_did = match request.did {
        Some(did) => did,
        None => return DelegationAuthResponse::err("No delegated account"),
    };

    let grant = match get_delegation_grant(&state, &delegated_did, &controller_did).await {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    let totp_valid =
        tranquil_api::server::verify_totp_or_backup_for_user(&state, &controller_did, &form.code)
            .await;
    if !totp_valid {
        return DelegationAuthResponse::totp_error("Invalid TOTP code");
    }
    match state
        .repos
        .oauth
        .advance_auth_stage(
            &RequestId::from(form.request_uri.clone()),
            &controller_did,
            AuthStage::FirstFactor,
            AuthStage::Complete,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return DelegationAuthResponse::err("Controller not authenticated"),
        Err(_) => return DelegationAuthResponse::err("Failed to update authorization request"),
    }

    let user_agent = tranquil_pds::util::extract_user_agent(&headers);

    finalize_delegation_auth(
        &state,
        &form.request_uri,
        &delegated_did,
        &controller_did,
        serde_json::json!({
            "client_id": request.client_id,
            "granted_scopes": grant.granted_scopes
        }),
        Some(client_ip),
        user_agent.as_deref(),
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct DelegationTokenAuthSubmit {
    pub request_uri: String,
    pub delegated_did: String,
}

pub async fn delegation_auth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    client_ip: ClientIp,
    auth: Auth<Active>,
    Json(form): Json<DelegationTokenAuthSubmit>,
) -> Response {
    let controller_did = &auth.did;

    let delegated_did = match parse_did(&form.delegated_did, "delegated") {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    let request = match get_auth_request(&state, &form.request_uri).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let grant = match get_delegation_grant(&state, &delegated_did, controller_did).await {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    if let Err(resp) = bind_delegation(
        &state,
        &form.request_uri,
        &delegated_did,
        controller_did,
        AuthStage::Complete,
    )
    .await
    {
        return resp;
    }

    let ip = client_ip.into_string();
    let user_agent = tranquil_pds::util::extract_user_agent(&headers);

    finalize_delegation_auth(
        &state,
        &form.request_uri,
        &delegated_did,
        controller_did,
        serde_json::json!({
            "client_id": request.client_id,
            "granted_scopes": grant.granted_scopes,
            "auth_method": "token"
        }),
        Some(&ip),
        user_agent.as_deref(),
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct CrossPdsCallbackParams {
    pub code: tranquil_types::AuthorizationCode,
    pub state: tranquil_types::CrossPdsState,
    pub iss: Option<String>,
}

pub async fn delegation_callback(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<LoginLimit>,
    Query(params): Query<CrossPdsCallbackParams>,
) -> Response {
    let auth_state = match state
        .cross_pds_oauth
        .retrieve_auth_state(&params.state)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to retrieve cross-PDS auth state: {:?}", e);
            return (
                axum::http::StatusCode::BAD_REQUEST,
                "Cross-PDS auth state expired or invalid",
            )
                .into_response();
        }
    };

    if let Some(ref expected_issuer) = auth_state.expected_issuer {
        match &params.iss {
            Some(iss) if iss.as_str() != expected_issuer.as_str() => {
                tracing::error!(
                    "Cross-PDS issuer mismatch: expected {}, got {}",
                    expected_issuer,
                    iss
                );
                return (
                    axum::http::StatusCode::FORBIDDEN,
                    "Authorization server issuer mismatch",
                )
                    .into_response();
            }
            None => {
                tracing::error!(
                    "Cross-PDS callback missing iss parameter (expected {}), possible mix-up attack",
                    expected_issuer
                );
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    "Missing required iss parameter",
                )
                    .into_response();
            }
            _ => {}
        }
    }

    let hostname = &tranquil_config::get().server.hostname;
    let urls = delegation_oauth_urls(hostname);

    let returned_sub = match state
        .cross_pds_oauth
        .exchange_code(
            &auth_state,
            &params.code,
            &urls.client_id,
            &urls.redirect_uri,
        )
        .await
    {
        Ok(sub) => sub,
        Err(e) => {
            tracing::error!("Cross-PDS token exchange failed: {:?}", e);
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                "Controller authentication failed",
            )
                .into_response();
        }
    };

    if returned_sub != auth_state.controller_did.as_str() {
        tracing::error!(
            "Cross-PDS DID mismatch: expected {}, got {}",
            auth_state.controller_did,
            returned_sub
        );
        return (axum::http::StatusCode::FORBIDDEN, "Controller DID mismatch").into_response();
    }

    let delegated_did = &auth_state.delegated_did;
    let controller_did = &auth_state.controller_did;

    if get_delegation_grant(&state, delegated_did, controller_did)
        .await
        .is_err()
    {
        tracing::warn!(
            "Delegation grant revoked during cross-PDS auth: {} -> {}",
            controller_did,
            delegated_did
        );
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Delegation grant has been revoked",
        )
            .into_response();
    }

    if let Err(resp) = bind_delegation(
        &state,
        &auth_state.original_request_uri,
        delegated_did,
        controller_did,
        AuthStage::Complete,
    )
    .await
    {
        return resp;
    }

    let _ = state
        .repos
        .delegation
        .log_delegation_action(
            delegated_did,
            controller_did,
            Some(controller_did),
            DelegationActionType::TokenIssued,
            Some(serde_json::json!({
                "auth_method": "cross_pds",
                "controller_pds": auth_state.controller_pds_url
            })),
            None,
            None,
        )
        .await;

    Redirect::temporary(&consent_url(&auth_state.original_request_uri)).into_response()
}

pub async fn delegation_client_metadata(State(_state): State<AppState>) -> Response {
    let hostname = &tranquil_config::get().server.hostname;
    let metadata = build_client_metadata(hostname);
    Json(metadata).into_response()
}
