use super::*;

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
        let _ = state.repos.oauth.delete_2fa_challenge(challenge.id).await;
        let code = Code::generate();
        let device_id = extract_device_cookie(&headers);
        let twofa_totp_device_id = device_id.clone();
        let twofa_totp_code = AuthorizationCode::from(code.0.clone());
        if state
            .repos
            .oauth
            .update_authorization_request(
                &twofa_post_request_id,
                &challenge.did,
                twofa_totp_device_id.as_ref(),
                &twofa_totp_code,
            )
            .await
            .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "An error occurred. Please try again.",
            );
        }
        let redirect_url = build_intermediate_redirect_url(
            &request_data.parameters.redirect_uri,
            &code.0,
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
    let mut device_id = extract_device_cookie(&headers);
    let mut new_cookie: Option<String> = None;
    if form.trust_device {
        let trust_device_id = match &device_id {
            Some(existing_id) => existing_id.clone(),
            None => {
                let new_id = DeviceId::generate();
                let new_device_id_typed = DeviceIdType::new(new_id.0.clone());
                let device_data = DeviceData {
                    session_id: SessionId::generate(),
                    user_agent: extract_user_agent(&headers),
                    ip_address: extract_client_ip(&headers, None),
                    last_seen_at: Utc::now(),
                };
                if state
                    .repos
                    .oauth
                    .create_device(&new_device_id_typed, &device_data)
                    .await
                    .is_ok()
                {
                    new_cookie = Some(make_device_cookie(&new_device_id_typed));
                    device_id = Some(new_device_id_typed.clone());
                }
                new_device_id_typed
            }
        };
        let _ = state
            .repos
            .oauth
            .upsert_account_device(&did, &trust_device_id)
            .await;
        let _ =
            tranquil_api::server::trust_device(state.repos.oauth.as_ref(), &trust_device_id).await;
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
    let twofa_post_client_id = ClientId::from(request_data.parameters.client_id.clone());
    let needs_consent = should_show_consent(
        state.repos.oauth.as_ref(),
        &did,
        &twofa_post_client_id,
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
    let code = Code::generate();
    let twofa_final_device_id = device_id.clone();
    let twofa_final_code = AuthorizationCode::from(code.0.clone());
    if state
        .repos
        .oauth
        .update_authorization_request(
            &twofa_post_request_id,
            &did,
            twofa_final_device_id.as_ref(),
            &twofa_final_code,
        )
        .await
        .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "An error occurred. Please try again.",
        );
    }
    let redirect_url = build_intermediate_redirect_url(
        &request_data.parameters.redirect_uri,
        &code.0,
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
