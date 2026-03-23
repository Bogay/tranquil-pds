use super::*;

#[derive(Debug, Deserialize)]
pub struct RegisterCompleteInput {
    pub request_uri: String,
    pub did: String,
    pub app_password: String,
}

pub async fn register_complete(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthRegisterCompleteLimit>,
    Json(form): Json<RegisterCompleteInput>,
) -> Response {
    let did = Did::from(form.did.clone());

    let request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .repos
        .oauth
        .get_authorization_request(&request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid or expired request_uri."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(
                request_uri = %form.request_uri,
                error = ?e,
                "register_complete: failed to fetch authorization request"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    if request_data.expires_at < Utc::now() {
        let _ = state
            .repos
            .oauth
            .delete_authorization_request(&request_id)
            .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired."
            })),
        )
            .into_response();
    }

    if request_data.parameters.prompt != Some(Prompt::Create) {
        tracing::warn!(
            request_uri = %form.request_uri,
            prompt = ?request_data.parameters.prompt,
            "register_complete called on non-registration OAuth flow"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "This endpoint is only for registration flows."
            })),
        )
            .into_response();
    }

    if request_data.code.is_some() {
        tracing::warn!(
            request_uri = %form.request_uri,
            "register_complete called on already-completed OAuth flow"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization has already been completed."
            })),
        )
            .into_response();
    }

    if let Some(existing_did) = &request_data.did
        && existing_did != &form.did
    {
        tracing::warn!(
            request_uri = %form.request_uri,
            existing_did = %existing_did,
            attempted_did = %form.did,
            "register_complete attempted with different DID than already bound"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request is already bound to a different account."
            })),
        )
            .into_response();
    }

    let password_hashes = match state
        .repos
        .session
        .get_app_password_hashes_by_did(&did)
        .await
    {
        Ok(hashes) => hashes,
        Err(e) => {
            tracing::error!(
                did = %did,
                error = ?e,
                "register_complete: failed to fetch app password hashes"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    let mut password_valid = password_hashes.iter().fold(false, |acc, hash| {
        acc | bcrypt::verify(&form.app_password, hash).unwrap_or(false)
    });

    if !password_valid
        && let Ok(Some(account_hash)) = state.repos.user.get_password_hash_by_did(&did).await
    {
        password_valid = bcrypt::verify(&form.app_password, &account_hash).unwrap_or(false);
    }

    if !password_valid {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "access_denied",
                "error_description": "Invalid credentials."
            })),
        )
            .into_response();
    }

    let is_verified = match state.repos.user.get_session_info_by_did(&did).await {
        Ok(Some(info)) => info.channel_verification.has_any_verified(),
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Account not found."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(
                did = %did,
                error = ?e,
                "register_complete: failed to fetch session info"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    if !is_verified {
        let resend_info = tranquil_api::server::auto_resend_verification(&state, &did).await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "account_not_verified",
                "error_description": "Please verify your account before continuing.",
                "did": did,
                "handle": resend_info.as_ref().map(|r| r.handle.to_string()),
                "channel": resend_info.as_ref().map(|r| r.channel.as_str())
            })),
        )
            .into_response();
    }

    if let Err(e) = state
        .repos
        .oauth
        .set_authorization_did(&request_id, &did, None)
        .await
    {
        tracing::error!(
            request_uri = %form.request_uri,
            did = %did,
            error = ?e,
            "register_complete: failed to set authorization DID"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "An error occurred."
            })),
        )
            .into_response();
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
        &did,
        &client_id_typed,
        &requested_scopes,
    )
    .await
    .unwrap_or(true);

    if needs_consent {
        tracing::info!(
            did = %did,
            client_id = %request_data.parameters.client_id,
            "OAuth registration complete, redirecting to consent"
        );
        let consent_url = format!(
            "/app/oauth/consent?request_uri={}",
            url_encode(&form.request_uri)
        );
        return Json(serde_json::json!({"redirect_uri": consent_url})).into_response();
    }

    let code = Code::generate();
    let auth_code = AuthorizationCode::from(code.0.clone());
    if let Err(e) = state
        .repos
        .oauth
        .update_authorization_request(&request_id, &did, None, &auth_code)
        .await
    {
        tracing::error!(
            request_uri = %form.request_uri,
            did = %did,
            error = ?e,
            "register_complete: failed to update authorization request with code"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "An error occurred."
            })),
        )
            .into_response();
    }

    tracing::info!(
        did = %did,
        client_id = %request_data.parameters.client_id,
        "OAuth registration flow completed successfully"
    );

    let redirect_url = build_intermediate_redirect_url(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.map(|m| m.as_str()),
    );
    Json(serde_json::json!({"redirect_uri": redirect_url})).into_response()
}

pub async fn establish_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: tranquil_pds::auth::Auth<tranquil_pds::auth::Active>,
) -> Response {
    let did = &auth.did;

    let existing_device = extract_device_cookie(&headers);

    let (device_id, new_cookie) = match existing_device {
        Some(id) => {
            let _ = state.repos.oauth.upsert_account_device(did, &id).await;
            (id, None)
        }
        None => {
            let new_id = DeviceId::generate();
            let device_typed = DeviceIdType::new(new_id.0.clone());
            let device_data = DeviceData {
                session_id: SessionId::generate(),
                user_agent: extract_user_agent(&headers),
                ip_address: extract_client_ip(&headers, None),
                last_seen_at: Utc::now(),
            };

            if let Err(e) = state
                .repos
                .oauth
                .create_device(&device_typed, &device_data)
                .await
            {
                tracing::error!(error = ?e, "Failed to create device");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Failed to establish session"
                    })),
                )
                    .into_response();
            }

            if let Err(e) = state
                .repos
                .oauth
                .upsert_account_device(did, &device_typed)
                .await
            {
                tracing::error!(error = ?e, "Failed to link device to account");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Failed to establish session"
                    })),
                )
                    .into_response();
            }

            let cookie = make_device_cookie(&device_typed);
            (device_typed, Some(cookie))
        }
    };

    tracing::info!(did = %did, device_id = %device_id, "Device session established");

    match new_cookie {
        Some(cookie) => (
            StatusCode::OK,
            [(SET_COOKIE, cookie)],
            Json(serde_json::json!({
                "success": true,
                "device_id": device_id
            })),
        )
            .into_response(),
        None => Json(serde_json::json!({
            "success": true,
            "device_id": device_id
        }))
        .into_response(),
    }
}
