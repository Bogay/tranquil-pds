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

    let user = match tranquil_types::AtIdentifier::new(bare_identifier.as_str()) {
        Ok(ref id) => state.repos.user.get_login_check_by_identifier(id).await,
        Err(_) => Ok(None),
    };

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

    let user = match tranquil_types::AtIdentifier::new(normalized_identifier.as_str()) {
        Ok(ref id) => state.repos.user.get_login_check_by_identifier(id).await,
        Err(_) => Ok(None),
    };

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
                .repos
                .delegation
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
    pub identifier: Option<String>,
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
        .repos
        .oauth
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
            .repos
            .oauth
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

    match form.identifier.filter(|s| !s.trim().is_empty()) {
        Some(identifier) => {
            passkey_start_named(
                state,
                identifier,
                form.delegated_did,
                request_data,
                passkey_start_request_id,
            )
            .await
        }
        None => passkey_start_discoverable(state, passkey_start_request_id).await,
    }
}

async fn passkey_start_discoverable(state: AppState, request_id: RequestId) -> Response {
    let (rcr, auth_state) = match state.webauthn_config.start_discoverable_authentication() {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, "Failed to start discoverable passkey authentication");
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
        .repos
        .user
        .save_discoverable_challenge(request_id.as_str(), &state_json)
        .await
    {
        tracing::error!(error = %e, "Failed to save discoverable authentication state");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "An error occurred."
            })),
        )
            .into_response();
    }

    let options = serde_json::to_value(&rcr).unwrap_or(serde_json::json!({}));
    Json(PasskeyStartResponse { options }).into_response()
}

async fn passkey_start_named(
    state: AppState,
    identifier: String,
    delegated_did: Option<String>,
    request_data: tranquil_pds::oauth::RequestData,
    passkey_start_request_id: RequestId,
) -> Response {
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let normalized_username =
        NormalizedLoginIdentifier::normalize(&identifier, hostname_for_handles);

    let passkey_lookup = match tranquil_types::AtIdentifier::new(normalized_username.as_str()) {
        Ok(ref id) => state.repos.user.get_login_info_by_identifier(id).await,
        Err(_) => Ok(None),
    };
    let user = match passkey_lookup {
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

    if tranquil_api::server::verification_blocks_login(&user.channel_verification) {
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

    let passkey_target = match resolve_passkey_target(
        &state,
        delegated_did.as_deref(),
        request_data.did.as_ref(),
        &user.did,
    )
    .await
    {
        Ok(target) => target,
        Err(response) => return response,
    };

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
        .repos
        .user
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

    let bind_result = match passkey_target {
        PasskeyTarget::Delegated(delegated_did) => {
            tracing::info!(
                delegated_did = %delegated_did,
                controller_did = %user.did,
                "Passkey auth in delegation flow"
            );
            state
                .repos
                .oauth
                .set_delegation(
                    &passkey_start_request_id,
                    &delegated_did,
                    &user.did,
                    AuthStage::None,
                )
                .await
        }
        PasskeyTarget::Own => {
            state
                .repos
                .oauth
                .set_authorization_did(&passkey_start_request_id, &user.did, None, AuthStage::None)
                .await
        }
    };
    if bind_result.is_err() {
        return OAuthError::ServerError("An error occurred.".into()).into_response();
    }

    let options = serde_json::to_value(&rcr).unwrap_or(serde_json::json!({}));

    Json(PasskeyStartResponse { options }).into_response()
}

enum PasskeyTarget {
    Own,
    Delegated(tranquil_types::Did),
}

async fn has_delegation_grant(
    state: &AppState,
    delegated_did: &tranquil_types::Did,
    controller_did: &tranquil_types::Did,
) -> Result<bool, Response> {
    state
        .repos
        .delegation
        .get_delegation(delegated_did, controller_did)
        .await
        .map(|grant| grant.is_some())
        .map_err(|e| {
            tracing::error!(
                error = %e,
                delegated_did = %delegated_did,
                controller_did = %controller_did,
                "Failed to verify delegation relationship"
            );
            OAuthError::ServerError("An error occurred.".into()).into_response()
        })
}

async fn resolve_passkey_target(
    state: &AppState,
    delegated_did_param: Option<&str>,
    request_did: Option<&tranquil_types::Did>,
    controller_did: &tranquil_types::Did,
) -> Result<PasskeyTarget, Response> {
    if let Some(delegated_did) = delegated_did_param
        .and_then(|s| s.parse::<tranquil_types::Did>().ok())
        .filter(|d| d != controller_did)
    {
        return if has_delegation_grant(state, &delegated_did, controller_did).await? {
            Ok(PasskeyTarget::Delegated(delegated_did))
        } else {
            Err(OAuthError::AccessDenied(
                "No delegation relationship exists between these accounts.".into(),
            )
            .into_response())
        };
    }

    if let Some(delegated_did) = request_did.filter(|d| *d != controller_did)
        && has_delegation_grant(state, delegated_did, controller_did).await?
    {
        return Ok(PasskeyTarget::Delegated(delegated_did.clone()));
    }

    Ok(PasskeyTarget::Own)
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
        .repos
        .oauth
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
            .repos
            .oauth
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

    let (did, passkey_owner_did, auth_result) = match request_data.did.clone() {
        Some(did) => {
            let passkey_owner_did = request_data
                .controller_did
                .clone()
                .unwrap_or_else(|| did.clone());
            match passkey_finish_named(&state, &passkey_owner_did, &credential).await {
                Ok(auth_result) => (did, passkey_owner_did, auth_result),
                Err(response) => return response,
            }
        }
        None => {
            match passkey_finish_discoverable(&state, &credential, &passkey_finish_request_id).await
            {
                Ok((did, auth_result)) => (did.clone(), did, auth_result),
                Err(response) => return response,
            }
        }
    };

    if auth_result.needs_update() {
        let cred_id_bytes = auth_result.cred_id().as_slice();
        match state
            .repos
            .user
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

    let device_id = extract_device_cookie(&headers);
    let hostname = &tranquil_config::get().server.hostname;
    let requirement = match begin_second_factor(
        &state,
        &passkey_owner_did,
        &passkey_finish_request_id,
        device_id.as_ref(),
    )
    .await
    {
        Ok(req) => req,
        Err(e) => {
            tracing::error!(did = %passkey_owner_did, error = %e, "begin_second_factor failed in passkey_finish");
            return OAuthError::ServerError("An error occurred.".into()).into_response();
        }
    };
    let (passkey_stage, next_redirect, notice) = match requirement {
        SecondFactorRequirement::None => (AuthStage::Complete, None, None),
        SecondFactorRequirement::Totp => (
            AuthStage::FirstFactor,
            Some(if request_data.controller_did.is_some() {
                format!(
                    "/app/oauth/delegation-totp?request_uri={}",
                    url_encode(&form.request_uri)
                )
            } else {
                format!(
                    "/app/oauth/totp?request_uri={}",
                    url_encode(&form.request_uri)
                )
            }),
            None,
        ),
        SecondFactorRequirement::Code { channel, notice } => (
            AuthStage::FirstFactor,
            Some(format!(
                "/app/oauth/2fa?request_uri={}&channel={}",
                url_encode(&form.request_uri),
                url_encode(channel)
            )),
            Some(notice),
        ),
    };

    let completed = match request_data.did {
        Some(_) => {
            advance_passkey_stage(
                &state,
                &passkey_finish_request_id,
                &passkey_owner_did,
                passkey_stage,
            )
            .await
        }
        None => state
            .repos
            .oauth
            .set_authorization_did(&passkey_finish_request_id, &did, None, passkey_stage)
            .await
            .map_err(|_| OAuthError::ServerError("An error occurred.".into()).into_response()),
    };
    if let Err(response) = completed {
        return response;
    }

    if let Some(notice) = notice
        && notice
            .dispatch(&state, hostname, &passkey_owner_did)
            .await
            .is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": UNDELIVERABLE_CODE
            })),
        )
            .into_response();
    }

    if let Some(redirect_uri) = next_redirect {
        return Json(serde_json::json!({ "redirect_uri": redirect_uri })).into_response();
    }

    tracing::info!(did = %did, "Passkey authentication successful");
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
        return Json(serde_json::json!({"redirect_uri": consent_url})).into_response();
    }

    let code = match store_authorization_code(
        &state,
        &passkey_finish_request_id,
        &did,
        request_data.controller_did.as_ref(),
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

    Json(serde_json::json!({
        "redirect_uri": redirect_url
    }))
    .into_response()
}

async fn advance_passkey_stage(
    state: &AppState,
    request_id: &RequestId,
    passkey_owner_did: &tranquil_types::Did,
    to: AuthStage,
) -> Result<(), Response> {
    match state
        .repos
        .oauth
        .advance_auth_stage(request_id, passkey_owner_did, AuthStage::None, to)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(OAuthError::AccessDenied(
            "Passkey authentication state is not valid.".into(),
        )
        .into_response()),
        Err(_) => Err(OAuthError::ServerError("An error occurred.".into()).into_response()),
    }
}

async fn passkey_finish_named(
    state: &AppState,
    passkey_owner_did: &tranquil_types::Did,
    credential: &webauthn_rs::prelude::PublicKeyCredential,
) -> Result<webauthn_rs::prelude::AuthenticationResult, Response> {
    let auth_state_json = state
        .repos
        .user
        .load_webauthn_challenge(passkey_owner_did, WebauthnChallengeType::Authentication)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to load authentication state");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            ).into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "No passkey authentication in progress or challenge expired."
                })),
            ).into_response()
        })?;

    let auth_state: webauthn_rs::prelude::SecurityKeyAuthentication =
        serde_json::from_str(&auth_state_json).map_err(|e| {
            tracing::error!(error = %e, "Failed to deserialize authentication state");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            ).into_response()
        })?;

    let auth_result = state
        .webauthn_config
        .finish_authentication(credential, &auth_state)
        .map_err(|e| {
            tracing::warn!(error = %e, did = %passkey_owner_did, "Failed to verify passkey authentication");
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Passkey verification failed."
                })),
            )
                .into_response()
        })?;

    let _ = state
        .repos
        .user
        .delete_webauthn_challenge(passkey_owner_did, WebauthnChallengeType::Authentication)
        .await;

    Ok(auth_result)
}

async fn passkey_finish_discoverable(
    state: &AppState,
    credential: &webauthn_rs::prelude::PublicKeyCredential,
    request_id: &RequestId,
) -> Result<
    (
        tranquil_types::Did,
        webauthn_rs::prelude::AuthenticationResult,
    ),
    Response,
> {
    let auth_state_json = state
        .repos
        .user
        .load_discoverable_challenge(request_id.as_str())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to load discoverable authentication state");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            ).into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "No passkey authentication in progress or challenge expired."
                })),
            ).into_response()
        })?;

    let auth_state: webauthn_rs::prelude::DiscoverableAuthentication =
        serde_json::from_str(&auth_state_json).map_err(|e| {
            tracing::error!(error = %e, "Failed to deserialize discoverable authentication state");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            ).into_response()
        })?;

    let (_user_uuid, cred_id) = state
        .webauthn_config
        .identify_discoverable_authentication(credential)
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to identify discoverable credential");
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Passkey verification failed."
                })),
            )
                .into_response()
        })?;

    let stored_passkey = state
        .repos
        .user
        .get_passkey_by_credential_id(cred_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to look up passkey by credential ID");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            ).into_response()
        })?
        .ok_or_else(|| {
            tracing::warn!("Discoverable credential not found in database");
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Passkey not recognized."
                })),
            ).into_response()
        })?;

    let discoverable_key: webauthn_rs::prelude::DiscoverableKey =
        serde_json::from_slice(&stored_passkey.public_key).map_err(|e| {
            tracing::error!(error = %e, "Failed to deserialize stored passkey as DiscoverableKey");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            ).into_response()
        })?;

    let auth_result = state
        .webauthn_config
        .finish_discoverable_authentication(credential, auth_state, &[discoverable_key])
        .map_err(|e| {
            tracing::warn!(error = %e, did = %stored_passkey.did, "Failed to verify discoverable passkey authentication");
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Passkey verification failed."
                })),
            ).into_response()
        })?;

    let _ = state
        .repos
        .user
        .delete_discoverable_challenge(request_id.as_str())
        .await;

    Ok((stored_passkey.did, auth_result))
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
        .repos
        .oauth
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
            .repos
            .oauth
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
        .repos
        .user
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
        .repos
        .oauth
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
            .repos
            .oauth
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
        .repos
        .user
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
        .repos
        .user
        .delete_webauthn_challenge(&did, WebauthnChallengeType::Authentication)
        .await;

    match state
        .repos
        .user
        .update_passkey_counter(
            auth_result.cred_id().as_slice(),
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

    let device_cookie = extract_device_cookie(&headers);
    let requirement = match begin_second_factor(
        &state,
        &did,
        &passkey_finish_request_id,
        device_cookie.as_ref(),
    )
    .await
    {
        Ok(req) => req,
        Err(e) => {
            tracing::error!(did = %did, error = %e, "begin_second_factor failed in authorize_passkey_finish");
            return OAuthError::ServerError("An error occurred.".into()).into_response();
        }
    };

    if let SecondFactorRequirement::Code { channel, notice } = requirement {
        if let Err(response) = advance_passkey_stage(
            &state,
            &passkey_finish_request_id,
            &did,
            AuthStage::FirstFactor,
        )
        .await
        {
            return response;
        }
        if notice.dispatch(&state, pds_hostname, &did).await.is_err() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": UNDELIVERABLE_CODE
                })),
            )
                .into_response();
        }
        let redirect_url = format!(
            "/app/oauth/2fa?request_uri={}&channel={}",
            url_encode(&form.request_uri),
            url_encode(channel)
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

    if matches!(requirement, SecondFactorRequirement::Totp) {
        if let Err(response) = advance_passkey_stage(
            &state,
            &passkey_finish_request_id,
            &did,
            AuthStage::FirstFactor,
        )
        .await
        {
            return response;
        }
        let redirect_url = format!(
            "/app/oauth/totp?request_uri={}",
            url_encode(&form.request_uri)
        );
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "next": "totp",
                "redirect": redirect_url
            })),
        )
            .into_response();
    }

    if let Err(response) = advance_passkey_stage(
        &state,
        &passkey_finish_request_id,
        &did,
        AuthStage::Complete,
    )
    .await
    {
        return response;
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
