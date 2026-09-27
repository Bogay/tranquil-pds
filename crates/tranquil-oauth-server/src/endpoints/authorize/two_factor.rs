use super::*;
use tranquil_pds::comms::Notice;
use tranquil_pds::comms::comms_repo::enqueue_notice;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct Authorize2faQuery {
    pub request_uri: String,
    pub channel: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Authorize2faSubmit {
    pub request_uri: String,
    pub code: String,
    #[serde(default)]
    pub trust_device: bool,
}

const MAX_2FA_ATTEMPTS: i32 = 5;

pub async fn authorize_2fa_get(
    State(state): State<AppState>,
    Query(query): Query<Authorize2faQuery>,
) -> Response {
    let twofa_request_id = RequestId::from(query.request_uri.clone());
    let challenge = match state.repos.oauth.get_2fa_challenge(&twofa_request_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return redirect_to_frontend_error(
                "invalid_request",
                "No 2FA challenge found. Please start over.",
            );
        }
        Err(_) => {
            return redirect_to_frontend_error(
                "server_error",
                "An error occurred. Please try again.",
            );
        }
    };
    if challenge.expires_at < Utc::now() {
        let _ = state.repos.oauth.delete_2fa_challenge(challenge.id).await;
        return redirect_to_frontend_error(
            "invalid_request",
            "2FA code has expired. Please start over.",
        );
    }
    let _request_data = match state
        .repos
        .oauth
        .get_authorization_request(&twofa_request_id)
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => {
            return redirect_to_frontend_error(
                "invalid_request",
                "Authorization request not found. Please start over.",
            );
        }
        Err(_) => {
            return redirect_to_frontend_error(
                "server_error",
                "An error occurred. Please try again.",
            );
        }
    };
    let channel = query.channel.as_deref().unwrap_or("email");
    redirect_see_other(&format!(
        "/app/oauth/2fa?request_uri={}&channel={}",
        url_encode(&query.request_uri),
        url_encode(channel)
    ))
}

pub async fn authorize_2fa_post(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthAuthorizeLimit>,
    headers: HeaderMap,
    client_ip: ClientIp,
    Json(form): Json<Authorize2faSubmit>,
) -> Response {
    let json_error = |status: StatusCode, error: &str, description: &str| -> Response {
        (
            status,
            Json(serde_json::json!({
                "error": error,
                "error_description": description
            })),
        )
            .into_response()
    };
    let twofa_post_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .repos
        .oauth
        .get_authorization_request(&twofa_post_request_id)
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Authorization request not found.",
            );
        }
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "An error occurred.",
            );
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = state
            .repos
            .oauth
            .delete_authorization_request(&twofa_post_request_id)
            .await;
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request has expired.",
        );
    }
    if request_data.auth_stage != AuthStage::FirstFactor {
        return first_factor_required();
    }
    let challenge = state
        .repos
        .oauth
        .get_2fa_challenge(&twofa_post_request_id)
        .await
        .ok()
        .flatten();
    if let Some(challenge) = challenge {
        if challenge.expires_at < Utc::now() {
            let _ = state.repos.oauth.delete_2fa_challenge(challenge.id).await;
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "2FA code has expired. Please start over.",
            );
        }
        if challenge.attempts >= MAX_2FA_ATTEMPTS {
            let _ = state.repos.oauth.delete_2fa_challenge(challenge.id).await;
            return json_error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Too many failed attempts. Please start over.",
            );
        }
        let code_valid: bool = form
            .code
            .trim()
            .as_bytes()
            .ct_eq(challenge.code.as_bytes())
            .into();
        if !code_valid {
            let _ = state.repos.oauth.increment_2fa_attempts(challenge.id).await;
            return json_error(
                StatusCode::FORBIDDEN,
                "invalid_code",
                "Invalid verification code. Please try again.",
            );
        }
        if let Err(response) =
            complete_second_factor(&state, &twofa_post_request_id, &challenge.did).await
        {
            return response;
        }
        let _ = state.repos.oauth.delete_2fa_challenge(challenge.id).await;
        let code = match store_authorization_code(
            &state,
            &twofa_post_request_id,
            &challenge.did,
            None,
            extract_device_cookie(&headers).as_ref(),
        )
        .await
        {
            Ok(code) => code,
            Err(e) => return e.into_response(),
        };
        let redirect_url = build_intermediate_redirect_url(
            &request_data.parameters.redirect_uri,
            code.as_str(),
            request_data.parameters.state.as_deref(),
            request_data.parameters.response_mode.map(|m| m.as_str()),
        );
        return Json(serde_json::json!({
            "redirect_uri": redirect_url
        }))
        .into_response();
    }
    let did_str = match &request_data.did {
        Some(d) => d.clone(),
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "No 2FA challenge found. Please start over.",
            );
        }
    };
    let did: tranquil_types::Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid DID format.",
            );
        }
    };
    if !tranquil_api::server::has_totp_enabled(&state, &did).await {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "No 2FA challenge found. Please start over.",
        );
    }
    let _rate_proof = match check_user_rate_limit::<TotpVerifyLimit>(&state, &did).await {
        Ok(proof) => proof,
        Err(_) => {
            return json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "RateLimitExceeded",
                "Too many verification attempts. Please try again in a few minutes.",
            );
        }
    };
    let totp_valid =
        tranquil_api::server::verify_totp_or_backup_for_user(&state, &did, &form.code).await;
    if !totp_valid {
        return json_error(
            StatusCode::FORBIDDEN,
            "invalid_code",
            "Invalid verification code. Please try again.",
        );
    }
    if let Err(response) = complete_second_factor(&state, &twofa_post_request_id, &did).await {
        return response;
    }
    let mut device_id = extract_device_cookie(&headers);
    let mut new_cookie: Option<String> = None;
    if form.trust_device {
        let trust_device_id = match &device_id {
            Some(existing_id) => existing_id.clone(),
            None => {
                let new_device_id = DeviceId::generate();
                let device_data = DeviceData {
                    session_id: SessionId::generate(),
                    user_agent: extract_user_agent(&headers),
                    ip_address: client_ip.into_string(),
                    last_seen_at: Utc::now(),
                };
                if state
                    .repos
                    .oauth
                    .create_device(&new_device_id, &device_data)
                    .await
                    .is_ok()
                {
                    new_cookie = Some(make_device_cookie(&new_device_id));
                    device_id = Some(new_device_id.clone());
                }
                new_device_id
            }
        };
        let _ = state
            .repos
            .oauth
            .upsert_account_device(&did, &trust_device_id)
            .await;
        let _ =
            tranquil_api::server::trust_device(state.repos.oauth.as_ref(), &trust_device_id, &did)
                .await;
    }
    let requested_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .unwrap_or("atproto");
    let requested_scopes: Vec<String> = requested_scope_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let needs_consent = should_show_consent(
        state.repos.oauth.as_ref(),
        &did,
        &request_data.parameters.client_id,
        &requested_scopes,
    )
    .await
    .unwrap_or(true);
    if needs_consent {
        let consent_url = format!(
            "/app/oauth/consent?request_uri={}",
            url_encode(&form.request_uri)
        );
        if let Some(cookie) = new_cookie {
            return (
                StatusCode::OK,
                [(SET_COOKIE, cookie)],
                Json(serde_json::json!({"redirect_uri": consent_url})),
            )
                .into_response();
        }
        return Json(serde_json::json!({"redirect_uri": consent_url})).into_response();
    }
    let code = match store_authorization_code(
        &state,
        &twofa_post_request_id,
        &did,
        None,
        device_id.as_ref(),
    )
    .await
    {
        Ok(code) => code,
        Err(e) => return e.into_response(),
    };
    let redirect_url = build_intermediate_redirect_url(
        &request_data.parameters.redirect_uri,
        code.as_str(),
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.map(|m| m.as_str()),
    );
    if let Some(cookie) = new_cookie {
        (
            StatusCode::OK,
            [(SET_COOKIE, cookie)],
            Json(serde_json::json!({"redirect_uri": redirect_url})),
        )
            .into_response()
    } else {
        Json(serde_json::json!({"redirect_uri": redirect_url})).into_response()
    }
}

fn first_factor_required() -> Response {
    json_error(
        StatusCode::FORBIDDEN,
        "access_denied",
        "First factor not completed for this request.",
    )
}

#[derive(Debug)]
pub(crate) enum SecondFactorRequirement {
    None,
    Totp,
    Code {
        channel: &'static str,
        notice: CodeNotice,
    },
}

#[derive(Debug)]
pub(crate) struct CodeNotice {
    user_id: Uuid,
    code: String,
}

impl CodeNotice {
    pub(crate) async fn dispatch(
        self,
        state: &AppState,
        hostname: &str,
        did: &Did,
    ) -> Result<(), NoticeDeliveryError> {
        match enqueue_notice(
            state.repos.user.as_ref(),
            state.repos.infra.as_ref(),
            self.user_id,
            Notice::TwoFactorCode { code: &self.code },
            hostname,
        )
        .await
        {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(NoticeDeliveryError),
            Err(e) => {
                tracing::warn!(
                    did = %did,
                    error = %e,
                    "Failed to enqueue 2FA notification"
                );
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct BeginSecondFactorError {
    step: &'static str,
    cause: String,
}

impl BeginSecondFactorError {
    fn new(step: &'static str, cause: impl std::fmt::Display) -> Self {
        Self {
            step,
            cause: cause.to_string(),
        }
    }
}

impl std::fmt::Display for BeginSecondFactorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.step, self.cause)
    }
}

#[derive(Debug)]
pub(crate) struct NoticeDeliveryError;

pub(crate) const UNDELIVERABLE_CODE: &str = "We couldn't deliver the verification code to your notification channels. Please contact the PDS owner! <3";

pub(crate) async fn begin_second_factor(
    state: &AppState,
    did: &Did,
    request_id: &RequestId,
    device_cookie: Option<&DeviceId>,
) -> Result<SecondFactorRequirement, BeginSecondFactorError> {
    let has_totp = state
        .repos
        .user
        .has_totp_enabled(did)
        .await
        .map_err(|e| BeginSecondFactorError::new("has_totp_enabled", e))?;

    let twofa_status = state
        .repos
        .user
        .get_2fa_status_by_did(did)
        .await
        .map_err(|e| BeginSecondFactorError::new("get_2fa_status_by_did", e))?
        .ok_or_else(|| BeginSecondFactorError::new("get_2fa_status_by_did", "no user row"))?;

    if has_totp {
        let trusted = match device_cookie {
            Some(dev_id) => {
                tranquil_api::server::is_device_trusted(state.repos.oauth.as_ref(), dev_id, did)
                    .await
            }
            None => false,
        };
        let _ = state
            .repos
            .oauth
            .delete_2fa_challenge_by_request_uri(request_id)
            .await;
        if trusted {
            if let Some(dev_id) = device_cookie {
                let _ = tranquil_api::server::extend_device_trust(
                    state.repos.oauth.as_ref(),
                    dev_id,
                    did,
                )
                .await;
            }
            return Ok(SecondFactorRequirement::None);
        }
        return Ok(SecondFactorRequirement::Totp);
    }

    if twofa_status.two_factor_enabled {
        let _ = state
            .repos
            .oauth
            .delete_2fa_challenge_by_request_uri(request_id)
            .await;
        let challenge = state
            .repos
            .oauth
            .create_2fa_challenge(did, request_id)
            .await
            .map_err(|e| BeginSecondFactorError::new("create_2fa_challenge", e))?;
        return Ok(SecondFactorRequirement::Code {
            channel: twofa_status.preferred_comms_channel.display_name(),
            notice: CodeNotice {
                user_id: twofa_status.id,
                code: challenge.code,
            },
        });
    }

    Ok(SecondFactorRequirement::None)
}

async fn complete_second_factor(
    state: &AppState,
    request_id: &RequestId,
    did: &tranquil_types::Did,
) -> Result<(), Response> {
    match state
        .repos
        .oauth
        .advance_auth_stage(request_id, did, AuthStage::FirstFactor, AuthStage::Complete)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(first_factor_required()),
        Err(_) => Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "An error occurred. Please try again.",
        )),
    }
}
