use super::*;

#[derive(Debug, Deserialize)]
pub struct CheckPasskeysQuery {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckPasskeysResponse {
    pub has_passkeys: bool,
}

pub async fn check_user_has_passkeys(
    State(state): State<AppState>,
    Query(query): Query<CheckPasskeysQuery>,
) -> Response {
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let bare_identifier =
        BareLoginIdentifier::from_identifier(&query.identifier, hostname_for_handles);

    let user = state
        .repos.user
        .get_login_check_by_handle_or_email(bare_identifier.as_str())
        .await;

    let has_passkeys = match user {
        Ok(Some(u)) => tranquil_api::server::has_passkeys_for_user(&state, &u.did).await,
        _ => false,
    };

    Json(CheckPasskeysResponse { has_passkeys }).into_response()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityStatusResponse {
    pub has_passkeys: bool,
    pub has_totp: bool,
    pub has_password: bool,
    pub is_delegated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
}

pub async fn check_user_security_status(
    State(state): State<AppState>,
    Query(query): Query<CheckPasskeysQuery>,
) -> Response {
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let normalized_identifier =
        NormalizedLoginIdentifier::normalize(&query.identifier, hostname_for_handles);

    let user = state
        .repos.user
        .get_login_check_by_handle_or_email(normalized_identifier.as_str())
        .await;

    let (has_passkeys, has_totp, has_password, is_delegated, did): (
        bool,
        bool,
        bool,
        bool,
        Option<String>,
    ) = match user {
        Ok(Some(u)) => {
            let passkeys = tranquil_api::server::has_passkeys_for_user(&state, &u.did).await;
            let totp = tranquil_api::server::has_totp_enabled(&state, &u.did).await;
            let has_pw = u.password_hash.is_some();
            let has_controllers = state
                .repos.delegation
                .is_delegated_account(&u.did)
                .await
                .unwrap_or(false);
            (
                passkeys,
                totp,
                has_pw,
                has_controllers,
                Some(u.did.to_string()),
            )
        }
        _ => (false, false, false, false, None),
    };

    Json(SecurityStatusResponse {
        has_passkeys,
        has_totp,
        has_password,
        is_delegated,
        did,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct PasskeyStartInput {
    pub request_uri: String,
    pub identifier: String,
    pub delegated_did: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyStartResponse {
    pub options: serde_json::Value,
}

pub async fn passkey_start(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthAuthorizeLimit>,
    Json(form): Json<PasskeyStartInput>,
) -> Response {
    let passkey_start_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .repos.oauth
        .get_authorization_request(&passkey_start_request_id)
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
        Err(_) => {
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
            .repos.oauth
            .delete_authorization_request(&passkey_start_request_id)
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

    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let normalized_username =
        NormalizedLoginIdentifier::normalize(&form.identifier, hostname_for_handles);

    let user = match state
        .repos.user
        .get_login_info_by_handle_or_email(normalized_username.as_str())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "User not found or has no passkeys."
                })),
            )
                .into_response();
        }
        Err(_) => {
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

    if user.deactivated_at.is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "access_denied",
                "error_description": "This account has been deactivated."
            })),
        )
            .into_response();
    }

    if user.takedown_ref.is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "access_denied",
                "error_description": "This account has been taken down."
            })),
        )
            .into_response();
    }

    let is_verified = user.channel_verification.has_any_verified();

    if !is_verified {
        let resend_info = tranquil_api::server::auto_resend_verification(&state, &user.did).await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "account_not_verified",
                "error_description": "Please verify your account before logging in.",
                "did": user.did,
                "handle": resend_info.as_ref().map(|r| r.handle.to_string()),
                "channel": resend_info.as_ref().map(|r| r.channel.as_str())
            })),
        )
            .into_response();
    }

    let stored_passkeys = match state.repos.user.get_passkeys_for_user(&user.did).await {
        Ok(pks) => pks,
        Err(e) => {
            tracing::error!(error = %e, "Failed to get passkeys");
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

    if stored_passkeys.is_empty() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "access_denied",
                "error_description": "User not found or has no passkeys."
            })),
        )
            .into_response();
    }

    let passkeys: Vec<webauthn_rs::prelude::SecurityKey> = stored_passkeys
        .iter()
        .filter_map(|sp| serde_json::from_slice(&sp.public_key).ok())
        .collect();

    if passkeys.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to load passkeys."
            })),
        )
            .into_response();
    }

    let (rcr, auth_state) = match state.webauthn_config.start_authentication(passkeys) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, "Failed to start passkey authentication");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Failed to start authentication."
                })),
            )
                .into_response();
        }
    };

    let state_json = match serde_json::to_string(&auth_state) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize authentication state");
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

    if let Err(e) = state
        .repos.user
        .save_webauthn_challenge(
            &user.did,
            WebauthnChallengeType::Authentication,
            &state_json,
        )
        .await
    {
        tracing::error!(error = %e, "Failed to save authentication state");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "An error occurred."
            })),
        )
            .into_response();
    }

    let delegation_from_param = match &form.delegated_did {
        Some(delegated_did_str) => match delegated_did_str.parse::<tranquil_types::Did>() {
            Ok(delegated_did) if delegated_did != user.did => {
                match state
                    .repos.delegation
                    .get_delegation(&delegated_did, &user.did)
                    .await
                {
                    Ok(Some(_)) => Some(delegated_did),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            delegated_did = %delegated_did,
                            controller_did = %user.did,
                            "Failed to verify delegation relationship"
                        );
                        None
                    }
                }
            }
            _ => None,
        },
        None => None,
    };

    let is_delegation_flow = delegation_from_param.is_some()
        || request_data.did.as_ref().is_some_and(|existing_did| {
            existing_did
                .parse::<tranquil_types::Did>()
                .ok()
                .is_some_and(|parsed| parsed != user.did)
        });

    if let Some(delegated_did) = delegation_from_param {
        tracing::info!(
            delegated_did = %delegated_did,
            controller_did = %user.did,
            "Passkey auth with delegated_did param - setting delegation flow"
        );
        if state
            .repos.oauth
            .set_authorization_did(&passkey_start_request_id, &delegated_did, None)
            .await
            .is_err()
        {
            return OAuthError::ServerError("An error occurred.".into()).into_response();
        }
        if state
            .repos.oauth
            .set_controller_did(&passkey_start_request_id, &user.did)
            .await
            .is_err()
        {
            return OAuthError::ServerError("An error occurred.".into()).into_response();
        }
    } else if is_delegation_flow {
        tracing::info!(
            delegated_did = ?request_data.did,
            controller_did = %user.did,
            "Passkey auth in delegation flow - preserving delegated DID"
        );
        if state
            .repos.oauth
            .set_controller_did(&passkey_start_request_id, &user.did)
            .await
            .is_err()
        {
            return OAuthError::ServerError("An error occurred.".into()).into_response();
        }
    } else if state
        .repos.oauth
        .set_authorization_did(&passkey_start_request_id, &user.did, None)
        .await
        .is_err()
    {
        return OAuthError::ServerError("An error occurred.".into()).into_response();
    }

    let options = serde_json::to_value(&rcr).unwrap_or(serde_json::json!({}));

    Json(PasskeyStartResponse { options }).into_response()
}

#[derive(Debug, Deserialize)]
pub struct PasskeyFinishInput {
    pub request_uri: String,
    pub credential: serde_json::Value,
}

pub async fn passkey_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<PasskeyFinishInput>,
) -> Response {
    let passkey_finish_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .repos.oauth
        .get_authorization_request(&passkey_finish_request_id)
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
        Err(_) => {
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
            .repos.oauth
            .delete_authorization_request(&passkey_finish_request_id)
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

    let did_str = match request_data.did {
        Some(d) => d,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "No passkey authentication in progress."
                })),
            )
                .into_response();
        }
    };
    let did: tranquil_types::Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid DID format."
                })),
            )
                .into_response();
        }
    };

    let controller_did: Option<tranquil_types::Did> = request_data
        .controller_did
        .as_ref()
        .and_then(|s| s.parse().ok());
    let passkey_owner_did = controller_did.as_ref().unwrap_or(&did);

    let auth_state_json = match state
        .repos.user
        .load_webauthn_challenge(passkey_owner_did, WebauthnChallengeType::Authentication)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "No passkey authentication in progress or challenge expired."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to load authentication state");
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

    let auth_state: webauthn_rs::prelude::SecurityKeyAuthentication =
        match serde_json::from_str(&auth_state_json) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "Failed to deserialize authentication state");
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

    let credential: webauthn_rs::prelude::PublicKeyCredential =
        match serde_json::from_value(form.credential) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse credential");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Failed to parse credential response."
                    })),
                )
                    .into_response();
            }
        };

    let auth_result = match state
        .webauthn_config
        .finish_authentication(&credential, &auth_state)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, did = %did, "Failed to verify passkey authentication");
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Passkey verification failed."
                })),
            )
                .into_response();
        }
    };

    if let Err(e) = state
        .repos.user
        .delete_webauthn_challenge(passkey_owner_did, WebauthnChallengeType::Authentication)
        .await
    {
        tracing::warn!(error = %e, "Failed to delete authentication state");
    }

    if auth_result.needs_update() {
        let cred_id_bytes = auth_result.cred_id().as_slice();
        match state
            .repos.user
            .update_passkey_counter(
                cred_id_bytes,
                i32::try_from(auth_result.counter()).unwrap_or(i32::MAX),
            )
            .await
        {
            Ok(false) => {
                tracing::warn!(did = %did, "Passkey counter anomaly detected - possible cloned key");
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "access_denied",
                        "error_description": "Security key counter anomaly detected. This may indicate a cloned key."
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to update passkey counter");
            }
            Ok(true) => {}
        }
    }

    tracing::info!(did = %did, "Passkey authentication successful");

    let device_id = extract_device_cookie(&headers);
    let requested_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .unwrap_or("atproto");
    let requested_scopes: Vec<String> = requested_scope_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let passkey_finish_client_id = ClientId::from(request_data.parameters.client_id.clone());
    let needs_consent = should_show_consent(
        state.repos.oauth.as_ref(),
        &did,
        &passkey_finish_client_id,
        &requested_scopes,
    )
    .await
    .unwrap_or(true);

    if needs_consent {
        let consent_url = format!(
            "/app/oauth/consent?request_uri={}",
            url_encode(&form.request_uri)
        );
        return Json(serde_json::json!({"redirect_uri": consent_url})).into_response();
    }

    let code = Code::generate();
    let passkey_final_device_id = device_id.clone();
    let passkey_final_code = AuthorizationCode::from(code.0.clone());
    if state
        .repos.oauth
        .update_authorization_request(
            &passkey_finish_request_id,
            &did,
            passkey_final_device_id.as_ref(),
            &passkey_final_code,
        )
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "An error occurred."
            })),
        )
            .into_response();
    }

    let redirect_url = build_intermediate_redirect_url(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.map(|m| m.as_str()),
    );

    Json(serde_json::json!({
        "redirect_uri": redirect_url
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct AuthorizePasskeyQuery {
    pub request_uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthResponse {
    pub options: serde_json::Value,
    pub request_uri: String,
}

pub async fn authorize_passkey_start(
    State(state): State<AppState>,
    Query(query): Query<AuthorizePasskeyQuery>,
) -> Response {
    let auth_passkey_start_request_id = RequestId::from(query.request_uri.clone());
    let request_data = match state
        .repos.oauth
        .get_authorization_request(&auth_passkey_start_request_id)
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Authorization request not found."
                })),
            )
                .into_response();
        }
        Err(_) => {
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
            .repos.oauth
            .delete_authorization_request(&auth_passkey_start_request_id)
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

    let did_str = match &request_data.did {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "User not authenticated yet."
                })),
            )
                .into_response();
        }
    };

    let did: tranquil_types::Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid DID format."
                })),
            )
                .into_response();
        }
    };

    let stored_passkeys = match state.repos.user.get_passkeys_for_user(&did).await {
        Ok(pks) => pks,
        Err(e) => {
            tracing::error!("Failed to get passkeys: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            )
                .into_response();
        }
    };

    if stored_passkeys.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "No passkeys registered for this account."
            })),
        )
            .into_response();
    }

    let passkeys: Vec<webauthn_rs::prelude::SecurityKey> = stored_passkeys
        .iter()
        .filter_map(|sp| serde_json::from_slice(&sp.public_key).ok())
        .collect();

    if passkeys.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "server_error", "error_description": "Failed to load passkeys."})),
        )
            .into_response();
    }

    let (rcr, auth_state) = match state.webauthn_config.start_authentication(passkeys) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to start passkey authentication: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            )
                .into_response();
        }
    };

    let state_json = match serde_json::to_string(&auth_state) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("Failed to serialize authentication state: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            )
                .into_response();
        }
    };

    if let Err(e) = state
        .repos.user
        .save_webauthn_challenge(&did, WebauthnChallengeType::Authentication, &state_json)
        .await
    {
        tracing::error!("Failed to save authentication state: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
        )
            .into_response();
    }

    let options = serde_json::to_value(&rcr).unwrap_or(serde_json::json!({}));
    Json(PasskeyAuthResponse {
        options,
        request_uri: query.request_uri,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizePasskeySubmit {
    pub request_uri: String,
    pub credential: serde_json::Value,
}

pub async fn authorize_passkey_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<AuthorizePasskeySubmit>,
) -> Response {
    let pds_hostname = &tranquil_config::get().server.hostname;
    let passkey_finish_request_id = RequestId::from(form.request_uri.clone());

    let request_data = match state
        .repos.oauth
        .get_authorization_request(&passkey_finish_request_id)
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Authorization request not found."
                })),
            )
                .into_response();
        }
        Err(_) => {
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
            .repos.oauth
            .delete_authorization_request(&passkey_finish_request_id)
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

    let did_str = match &request_data.did {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "User not authenticated yet."
                })),
            )
                .into_response();
        }
    };

    let did: tranquil_types::Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid DID format."
                })),
            )
                .into_response();
        }
    };

    let auth_state_json = match state
        .repos.user
        .load_webauthn_challenge(&did, WebauthnChallengeType::Authentication)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "No passkey challenge found. Please start over."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to load authentication state: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            )
                .into_response();
        }
    };

    let auth_state: webauthn_rs::prelude::SecurityKeyAuthentication = match serde_json::from_str(
        &auth_state_json,
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to deserialize authentication state: {:?}", e);
            return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
                )
                    .into_response();
        }
    };

    let credential: webauthn_rs::prelude::PublicKeyCredential =
        match serde_json::from_value(form.credential.clone()) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to parse credential: {:?}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Invalid credential format."
                    })),
                )
                    .into_response();
            }
        };

    let auth_result = match state
        .webauthn_config
        .finish_authentication(&credential, &auth_state)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Passkey authentication failed: {:?}", e);
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Passkey authentication failed."
                })),
            )
                .into_response();
        }
    };

    let _ = state
        .repos.user
        .delete_webauthn_challenge(&did, WebauthnChallengeType::Authentication)
        .await;

    match state
        .repos.user
        .update_passkey_counter(
            credential.id.as_ref(),
            i32::try_from(auth_result.counter()).unwrap_or(i32::MAX),
        )
        .await
    {
        Ok(false) => {
            tracing::warn!(did = %did, "Passkey counter anomaly detected - possible cloned key");
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Security key counter anomaly detected. This may indicate a cloned key."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::warn!("Failed to update passkey counter: {:?}", e);
        }
        Ok(true) => {}
    }

    let has_totp = state
        .repos.user
        .has_totp_enabled(&did)
        .await
        .unwrap_or(false);
    if has_totp {
        let device_cookie = extract_device_cookie(&headers);
        let device_is_trusted = if let Some(ref dev_id) = device_cookie {
            tranquil_api::server::is_device_trusted(state.repos.oauth.as_ref(), dev_id, &did).await
        } else {
            false
        };

        if device_is_trusted {
            if let Some(ref dev_id) = device_cookie {
                let _ =
                    tranquil_api::server::extend_device_trust(state.repos.oauth.as_ref(), dev_id)
                        .await;
            }
        } else {
            let user = match state.repos.user.get_2fa_status_by_did(&did).await {
                Ok(Some(u)) => u,
                _ => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
                    )
                        .into_response();
                }
            };

            let _ = state
                .repos.oauth
                .delete_2fa_challenge_by_request_uri(&passkey_finish_request_id)
                .await;
            match state
                .repos.oauth
                .create_2fa_challenge(&did, &passkey_finish_request_id)
                .await
            {
                Ok(challenge) => {
                    if let Err(e) = enqueue_2fa_code(
                        state.repos.user.as_ref(),
                        state.repos.infra.as_ref(),
                        user.id,
                        &challenge.code,
                        pds_hostname,
                    )
                    .await
                    {
                        tracing::warn!(did = %did, error = %e, "Failed to enqueue 2FA notification");
                    }
                    let channel_name = user.preferred_comms_channel.display_name();
                    let redirect_url = format!(
                        "/app/oauth/2fa?request_uri={}&channel={}",
                        url_encode(&form.request_uri),
                        url_encode(channel_name)
                    );
                    return (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "next": "2fa",
                            "redirect": redirect_url
                        })),
                    )
                        .into_response();
                }
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
                    )
                        .into_response();
                }
            }
        }
    }

    let redirect_url = format!(
        "/app/oauth/consent?request_uri={}",
        url_encode(&form.request_uri)
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "next": "consent",
            "redirect": redirect_url
        })),
    )
        .into_response()
}
