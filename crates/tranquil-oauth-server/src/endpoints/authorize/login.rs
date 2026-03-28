use super::*;

pub async fn authorize_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let request_uri = match query.request_uri {
        Some(uri) => uri,
        None => {
            if wants_json(&headers) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Missing request_uri parameter. Use PAR to initiate authorization."
                    })),
                ).into_response();
            }
            return redirect_to_frontend_error(
                "invalid_request",
                "Missing request_uri parameter. Use PAR to initiate authorization.",
            );
        }
    };
    let request_id = RequestId::from(request_uri.clone());
    let request_data = match state
        .repos
        .oauth
        .get_authorization_request(&request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            if wants_json(&headers) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Invalid or expired request_uri. Please start a new authorization request."
                    })),
                ).into_response();
            }
            return redirect_to_frontend_error(
                "invalid_request",
                "Invalid or expired request_uri. Please start a new authorization request.",
            );
        }
        Err(e) => {
            if wants_json(&headers) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": format!("Database error: {:?}", e)
                    })),
                )
                    .into_response();
            }
            return redirect_to_frontend_error("server_error", "A database error occurred.");
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = state
            .repos
            .oauth
            .delete_authorization_request(&request_id)
            .await;
        if wants_json(&headers) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Authorization request has expired. Please start a new request."
                })),
            ).into_response();
        }
        return redirect_to_frontend_error(
            "invalid_request",
            "Authorization request has expired. Please start a new request.",
        );
    }
    let client_cache = ClientMetadataCache::new(3600);
    let client_name = client_cache
        .get(&request_data.parameters.client_id)
        .await
        .ok()
        .and_then(|m| m.client_name);
    if wants_json(&headers) {
        return Json(AuthorizeResponse {
            client_id: request_data.parameters.client_id.clone(),
            client_name: client_name.clone(),
            scope: request_data.parameters.scope.clone(),
            redirect_uri: request_data.parameters.redirect_uri.clone(),
            state: request_data.parameters.state.clone(),
            login_hint: request_data.parameters.login_hint.clone(),
        })
        .into_response();
    }
    let force_new_account = query.new_account.unwrap_or(false);

    if let Some(ref login_hint) = request_data.parameters.login_hint {
        tracing::info!(login_hint = %login_hint, "Checking login_hint for delegation");
        let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
        let normalized = NormalizedLoginIdentifier::normalize(login_hint, hostname_for_handles);
        tracing::info!(normalized = %normalized, "Normalized login_hint");

        match state
            .repos
            .user
            .get_login_check_by_handle_or_email(normalized.as_str())
            .await
        {
            Ok(Some(user)) => {
                tracing::info!(did = %user.did, has_password = user.password_hash.is_some(), "Found user for login_hint");
                let is_delegated = state
                    .repos
                    .delegation
                    .is_delegated_account(&user.did)
                    .await
                    .unwrap_or(false);
                let has_password = user.password_hash.is_some();
                tracing::info!(is_delegated = %is_delegated, has_password = %has_password, "Delegation check");

                if is_delegated {
                    tracing::info!("Redirecting to delegation auth");
                    if let Err(e) = state
                        .repos
                        .oauth
                        .set_request_did(&request_id, &user.did)
                        .await
                    {
                        tracing::error!(error = %e, "Failed to set delegated DID on authorization request");
                        return redirect_to_frontend_error(
                            "server_error",
                            "Failed to initialize delegation flow",
                        );
                    }
                    return redirect_see_other(&format!(
                        "/app/oauth/delegation?request_uri={}&delegated_did={}",
                        url_encode(&request_uri),
                        url_encode(&user.did)
                    ));
                }
            }
            Ok(None) => {
                tracing::info!(normalized = %normalized, "No user found for login_hint");
            }
            Err(e) => {
                tracing::error!(error = %e, "Error looking up user for login_hint");
            }
        }
    } else {
        tracing::info!("No login_hint in request");
    }

    if request_data.parameters.prompt == Some(Prompt::Create) {
        return redirect_see_other(&format!(
            "/app/oauth/register?request_uri={}",
            url_encode(&request_uri)
        ));
    }

    if !force_new_account
        && let Some(device_id) = extract_device_cookie(&headers)
        && let Ok(accounts) = state
            .repos
            .oauth
            .get_device_accounts(&device_id.clone())
            .await
        && !accounts.is_empty()
    {
        let login_hint_param = request_data
            .parameters
            .login_hint
            .as_ref()
            .map(|h| format!("&login_hint={}", url_encode(h)))
            .unwrap_or_default();
        return redirect_see_other(&format!(
            "/app/oauth/accounts?request_uri={}{}",
            url_encode(&request_uri),
            login_hint_param
        ));
    }
    redirect_see_other(&format!(
        "/app/oauth/login?request_uri={}",
        url_encode(&request_uri)
    ))
}

pub async fn authorize_get_json(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Json<AuthorizeResponse>, OAuthError> {
    let request_uri = query
        .request_uri
        .ok_or_else(|| OAuthError::InvalidRequest("request_uri is required".to_string()))?;
    let request_id_json = RequestId::from(request_uri.clone());
    let request_data = state
        .repos
        .oauth
        .get_authorization_request(&request_id_json)
        .await
        .map_err(tranquil_pds::oauth::db_err_to_oauth)?
        .ok_or_else(|| OAuthError::InvalidRequest("Invalid or expired request_uri".to_string()))?;
    if request_data.expires_at < Utc::now() {
        let _ = state
            .repos
            .oauth
            .delete_authorization_request(&request_id_json)
            .await;
        return Err(OAuthError::InvalidRequest(
            "request_uri has expired".to_string(),
        ));
    }
    Ok(Json(AuthorizeResponse {
        client_id: request_data.parameters.client_id.clone(),
        client_name: None,
        scope: request_data.parameters.scope.clone(),
        redirect_uri: request_data.parameters.redirect_uri.clone(),
        state: request_data.parameters.state.clone(),
        login_hint: request_data.parameters.login_hint.clone(),
    }))
}

#[derive(Debug, Serialize)]
pub struct AccountInfo {
    pub did: String,
    pub handle: Handle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AccountsResponse {
    pub accounts: Vec<AccountInfo>,
    pub request_uri: String,
}

fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos..];
        if local.len() <= 2 {
            format!("{}***{}", local.chars().next().unwrap_or('*'), domain)
        } else {
            let first = local.chars().next().unwrap_or('*');
            let last = local.chars().last().unwrap_or('*');
            format!("{}***{}{}", first, last, domain)
        }
    } else {
        "***".to_string()
    }
}

pub async fn authorize_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let request_uri = match query.request_uri {
        Some(uri) => uri,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Missing request_uri parameter"
                })),
            )
                .into_response();
        }
    };
    let device_id = match extract_device_cookie(&headers) {
        Some(id) => id,
        None => {
            return Json(AccountsResponse {
                accounts: vec![],
                request_uri,
            })
            .into_response();
        }
    };
    let accounts = match state.repos.oauth.get_device_accounts(&device_id).await {
        Ok(accts) => accts,
        Err(_) => {
            return Json(AccountsResponse {
                accounts: vec![],
                request_uri,
            })
            .into_response();
        }
    };
    let account_infos: Vec<AccountInfo> = accounts
        .into_iter()
        .map(|row| AccountInfo {
            did: row.did.to_string(),
            handle: row.handle,
            email: row.email.map(|e| mask_email(&e)),
        })
        .collect();
    Json(AccountsResponse {
        accounts: account_infos,
        request_uri,
    })
    .into_response()
}

pub async fn authorize_post(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthAuthorizeLimit>,
    headers: HeaderMap,
    Json(form): Json<AuthorizeSubmit>,
) -> Response {
    let json_response = wants_json(&headers);
    let form_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .repos
        .oauth
        .get_authorization_request(&form_request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            if json_response {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Invalid or expired request_uri."
                    })),
                )
                    .into_response();
            }
            return redirect_to_frontend_error(
                "invalid_request",
                "Invalid or expired request_uri. Please start a new authorization request.",
            );
        }
        Err(e) => {
            if json_response {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": format!("Database error: {:?}", e)
                    })),
                )
                    .into_response();
            }
            return redirect_to_frontend_error("server_error", &format!("Database error: {:?}", e));
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = state
            .repos
            .oauth
            .delete_authorization_request(&form_request_id)
            .await;
        if json_response {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Authorization request has expired."
                })),
            )
                .into_response();
        }
        return redirect_to_frontend_error(
            "invalid_request",
            "Authorization request has expired. Please start a new request.",
        );
    }
    let show_login_error = |error_msg: &str, json: bool| -> Response {
        if json {
            return (
                axum::http::StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": error_msg
                })),
            )
                .into_response();
        }
        redirect_see_other(&format!(
            "/app/oauth/login?request_uri={}&error={}",
            url_encode(&form.request_uri),
            url_encode(error_msg)
        ))
    };
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let normalized_username =
        NormalizedLoginIdentifier::normalize(&form.username, hostname_for_handles);
    tracing::debug!(
        original_username = %form.username,
        normalized_username = %normalized_username,
        pds_hostname = %tranquil_config::get().server.hostname,
        "Normalized username for lookup"
    );
    let user = match state
        .repos
        .user
        .get_login_info_by_handle_or_email(normalized_username.as_str())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            let _ = bcrypt::verify(
                &form.password,
                "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYw1ZzQKZqmK",
            );
            return show_login_error("Invalid handle/email or password.", json_response);
        }
        Err(_) => return show_login_error("An error occurred. Please try again.", json_response),
    };
    if user.deactivated_at.is_some() {
        return show_login_error("This account has been deactivated.", json_response);
    }
    if user.takedown_ref.is_some() {
        return show_login_error("This account has been taken down.", json_response);
    }
    if user.account_type.is_delegated() {
        if state
            .repos
            .oauth
            .set_authorization_did(&form_request_id, &user.did, None)
            .await
            .is_err()
        {
            return show_login_error("An error occurred. Please try again.", json_response);
        }
        let redirect_url = format!(
            "/app/oauth/delegation?request_uri={}&delegated_did={}",
            url_encode(&form.request_uri),
            url_encode(&user.did)
        );
        if json_response {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "next": "delegation",
                    "delegated_did": user.did,
                    "redirect": redirect_url
                })),
            )
                .into_response();
        }
        return redirect_see_other(&redirect_url);
    }

    if !user.password_required {
        if state
            .repos
            .oauth
            .set_authorization_did(&form_request_id, &user.did, None)
            .await
            .is_err()
        {
            return show_login_error("An error occurred. Please try again.", json_response);
        }
        let redirect_url = format!(
            "/app/oauth/passkey?request_uri={}",
            url_encode(&form.request_uri)
        );
        if json_response {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "next": "passkey",
                    "redirect": redirect_url
                })),
            )
                .into_response();
        }
        return redirect_see_other(&redirect_url);
    }

    let password_valid = match &user.password_hash {
        Some(hash) => match bcrypt::verify(&form.password, hash) {
            Ok(valid) => valid,
            Err(_) => {
                return show_login_error("An error occurred. Please try again.", json_response);
            }
        },
        None => false,
    };
    if !password_valid {
        return show_login_error("Invalid handle/email or password.", json_response);
    }
    let is_verified = user.channel_verification.has_any_verified();
    if !is_verified {
        let resend_info = tranquil_api::server::auto_resend_verification(&state, &user.did).await;
        let handle = resend_info
            .as_ref()
            .map(|r| r.handle.to_string())
            .unwrap_or_else(|| form.username.clone());
        let channel = resend_info
            .map(|r| r.channel.as_str().to_owned())
            .unwrap_or_else(|| user.preferred_comms_channel.as_str().to_owned());
        if json_response {
            return (
                axum::http::StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "account_not_verified",
                    "error_description": "Please verify your account before logging in.",
                    "did": user.did,
                    "handle": handle,
                    "channel": channel
                })),
            )
                .into_response();
        }
        return redirect_see_other(&format!(
            "/app/oauth/login?request_uri={}&error={}",
            url_encode(&form.request_uri),
            url_encode("account_not_verified")
        ));
    }
    let has_totp = tranquil_api::server::has_totp_enabled(&state, &user.did).await;
    if has_totp {
        let device_cookie = extract_device_cookie(&headers);
        let device_is_trusted = if let Some(ref dev_id) = device_cookie {
            tranquil_api::server::is_device_trusted(state.repos.oauth.as_ref(), dev_id, &user.did)
                .await
        } else {
            false
        };

        if device_is_trusted {
            if let Some(ref dev_id) = device_cookie {
                let _ = tranquil_api::server::extend_device_trust(
                    state.repos.oauth.as_ref(),
                    dev_id,
                    &user.did,
                )
                .await;
            }
        } else {
            if state
                .repos
                .oauth
                .set_authorization_did(&form_request_id, &user.did, None)
                .await
                .is_err()
            {
                return show_login_error("An error occurred. Please try again.", json_response);
            }
            if json_response {
                return Json(serde_json::json!({
                    "needs_totp": true
                }))
                .into_response();
            }
            return redirect_see_other(&format!(
                "/app/oauth/totp?request_uri={}",
                url_encode(&form.request_uri)
            ));
        }
    }
    if user.two_factor_enabled {
        let _ = state
            .repos
            .oauth
            .delete_2fa_challenge_by_request_uri(&form_request_id)
            .await;
        match state
            .repos
            .oauth
            .create_2fa_challenge(&user.did, &form_request_id)
            .await
        {
            Ok(challenge) => {
                let hostname = &tranquil_config::get().server.hostname;
                if let Err(e) = enqueue_2fa_code(
                    state.repos.user.as_ref(),
                    state.repos.infra.as_ref(),
                    user.id,
                    &challenge.code,
                    hostname,
                )
                .await
                {
                    tracing::warn!(
                        did = %user.did,
                        error = %e,
                        "Failed to enqueue 2FA notification"
                    );
                }
                let channel_name = user.preferred_comms_channel.display_name();
                if json_response {
                    return Json(serde_json::json!({
                        "needs_2fa": true,
                        "channel": channel_name
                    }))
                    .into_response();
                }
                return redirect_see_other(&format!(
                    "/app/oauth/2fa?request_uri={}&channel={}",
                    url_encode(&form.request_uri),
                    url_encode(channel_name)
                ));
            }
            Err(_) => {
                return show_login_error("An error occurred. Please try again.", json_response);
            }
        }
    }
    let mut device_id: Option<DeviceIdType> = extract_device_cookie(&headers);
    let mut new_cookie: Option<String> = None;
    if form.remember_device {
        let final_device_id = if let Some(existing_id) = &device_id {
            existing_id.clone()
        } else {
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
        };
        let _ = state
            .repos
            .oauth
            .upsert_account_device(&user.did, &final_device_id)
            .await;
    }
    let set_auth_device_id = device_id.clone();
    if state
        .repos
        .oauth
        .set_authorization_did(&form_request_id, &user.did, set_auth_device_id.as_ref())
        .await
        .is_err()
    {
        return show_login_error("An error occurred. Please try again.", json_response);
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
    let client_id_typed = ClientId::from(request_data.parameters.client_id.clone());
    let needs_consent = should_show_consent(
        state.repos.oauth.as_ref(),
        &user.did,
        &client_id_typed,
        &requested_scopes,
    )
    .await
    .unwrap_or(true);
    if needs_consent {
        let consent_url = format!(
            "/app/oauth/consent?request_uri={}",
            url_encode(&form.request_uri)
        );
        if json_response {
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
        if let Some(cookie) = new_cookie {
            return (
                StatusCode::SEE_OTHER,
                [(SET_COOKIE, cookie), (LOCATION, consent_url)],
            )
                .into_response();
        }
        return redirect_see_other(&consent_url);
    }
    let code = Code::generate();
    let auth_post_device_id = device_id.clone();
    let auth_post_code = AuthorizationCode::from(code.0.clone());
    if state
        .repos
        .oauth
        .update_authorization_request(
            &form_request_id,
            &user.did,
            auth_post_device_id.as_ref(),
            &auth_post_code,
        )
        .await
        .is_err()
    {
        return show_login_error("An error occurred. Please try again.", json_response);
    }
    if json_response {
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
    } else {
        let redirect_url = build_success_redirect(
            &request_data.parameters.redirect_uri,
            &code.0,
            request_data.parameters.state.as_deref(),
            request_data.parameters.response_mode.map(|m| m.as_str()),
        );
        if let Some(cookie) = new_cookie {
            (
                StatusCode::SEE_OTHER,
                [(SET_COOKIE, cookie), (LOCATION, redirect_url)],
            )
                .into_response()
        } else {
            redirect_see_other(&redirect_url)
        }
    }
}

pub async fn authorize_select(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<AuthorizeSelectSubmit>,
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
    let select_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .repos
        .oauth
        .get_authorization_request(&select_request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid or expired request_uri. Please start a new authorization request.",
            );
        }
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "An error occurred. Please try again.",
            );
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = state
            .repos
            .oauth
            .delete_authorization_request(&select_request_id)
            .await;
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request has expired. Please start a new request.",
        );
    }
    let device_id = match extract_device_cookie(&headers) {
        Some(id) => id,
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "No device session found. Please sign in.",
            );
        }
    };
    let did: Did = match form.did.parse() {
        Ok(d) => d,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid DID format.",
            );
        }
    };
    let verify_device_id = device_id.clone();
    let account_valid = match state
        .repos
        .oauth
        .verify_account_on_device(&verify_device_id, &did)
        .await
    {
        Ok(valid) => valid,
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "An error occurred. Please try again.",
            );
        }
    };
    if !account_valid {
        return json_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "This account is not available on this device. Please sign in.",
        );
    }
    let user = match state.repos.user.get_2fa_status_by_did(&did).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return json_error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Account not found. Please sign in.",
            );
        }
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "An error occurred. Please try again.",
            );
        }
    };
    let is_verified = user.channel_verification.has_any_verified();
    if !is_verified {
        let resend_info = tranquil_api::server::auto_resend_verification(&state, &did).await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "account_not_verified",
                "error_description": "Please verify your account before logging in.",
                "did": did,
                "handle": resend_info.as_ref().map(|r| r.handle.to_string()),
                "channel": resend_info.as_ref().map(|r| r.channel.as_str())
            })),
        )
            .into_response();
    }
    let has_totp = tranquil_api::server::has_totp_enabled(&state, &did).await;
    let select_early_device_typed = device_id.clone();
    if has_totp {
        let device_is_trusted =
            tranquil_api::server::is_device_trusted(state.repos.oauth.as_ref(), &device_id, &did)
                .await;
        if !device_is_trusted {
            if state
                .repos
                .oauth
                .set_authorization_did(&select_request_id, &did, Some(&select_early_device_typed))
                .await
                .is_err()
            {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "An error occurred. Please try again.",
                );
            }
            return Json(serde_json::json!({
                "needs_totp": true
            }))
            .into_response();
        }
        let _ =
            tranquil_api::server::extend_device_trust(state.repos.oauth.as_ref(), &device_id, &did)
                .await;
    }
    if user.two_factor_enabled {
        let _ = state
            .repos
            .oauth
            .delete_2fa_challenge_by_request_uri(&select_request_id)
            .await;
        match state
            .repos
            .oauth
            .create_2fa_challenge(&did, &select_request_id)
            .await
        {
            Ok(challenge) => {
                let hostname = &tranquil_config::get().server.hostname;
                if let Err(e) = enqueue_2fa_code(
                    state.repos.user.as_ref(),
                    state.repos.infra.as_ref(),
                    user.id,
                    &challenge.code,
                    hostname,
                )
                .await
                {
                    tracing::warn!(
                        did = %form.did,
                        error = %e,
                        "Failed to enqueue 2FA notification"
                    );
                }
                let channel_name = user.preferred_comms_channel.display_name();
                return Json(serde_json::json!({
                    "needs_2fa": true,
                    "channel": channel_name
                }))
                .into_response();
            }
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "An error occurred. Please try again.",
                );
            }
        }
    }
    let select_device_typed = device_id.clone();
    let _ = state
        .repos
        .oauth
        .upsert_account_device(&did, &select_device_typed)
        .await;

    if state
        .repos
        .oauth
        .set_authorization_did(&select_request_id, &did, Some(&select_device_typed))
        .await
        .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "An error occurred. Please try again.",
        );
    }
    let consent_url = format!(
        "/app/oauth/consent?request_uri={}",
        url_encode(&form.request_uri)
    );
    Json(serde_json::json!({"redirect_uri": consent_url})).into_response()
}
