use super::*;

#[derive(Debug, Serialize)]
pub struct ScopeInfo {
    pub scope: String,
    pub category: String,
    pub required: bool,
    pub description: String,
    pub display_name: String,
    pub granted: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ConsentResponse {
    pub request_uri: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub scopes: Vec<ScopeInfo>,
    pub show_consent: bool,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_delegation: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_level: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConsentQuery {
    pub request_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct ConsentSubmit {
    pub request_uri: String,
    pub approved_scopes: Vec<String>,
    pub remember: bool,
}

pub async fn consent_get(
    State(state): State<AppState>,
    Query(query): Query<ConsentQuery>,
) -> Response {
    let consent_request_id = RequestId::from(query.request_uri.clone());
    let request_data = match state
        .repos.oauth
        .get_authorization_request(&consent_request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid or expired request_uri",
            );
        }
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &format!("Database error: {:?}", e),
            );
        }
    };
    let flow_with_user = match AuthFlow::from_request_data(request_data.clone()) {
        Ok(flow) => match flow.require_user() {
            Ok(u) => u,
            Err(_) => {
                return json_error(StatusCode::FORBIDDEN, "access_denied", "Not authenticated");
            }
        },
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "expired_request",
                "Authorization request has expired",
            );
        }
    };

    let did = flow_with_user.did().clone();
    let client_cache = ClientMetadataCache::new(3600);
    let client_metadata = client_cache
        .get(&request_data.parameters.client_id)
        .await
        .ok();
    let requested_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("atproto");

    let controller_did_parsed: Option<Did> = request_data
        .controller_did
        .as_ref()
        .and_then(|s| s.parse().ok());
    let delegation_grant = if let Some(ref ctrl_did) = controller_did_parsed {
        state
            .repos.delegation
            .get_delegation(&did, ctrl_did)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    let effective_scope_str = if let Some(ref grant) = delegation_grant {
        tranquil_pds::delegation::intersect_scopes(
            requested_scope_str,
            grant.granted_scopes.as_str(),
        )
    } else {
        requested_scope_str.to_string()
    };

    let expanded_scope_str = match expand_include_scopes(&effective_scope_str).await {
        Ok(s) => s,
        Err(e) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                &format!("Failed to expand permission set: {e}"),
            );
        }
    };
    let requested_scopes: Vec<&str> = expanded_scope_str.split_whitespace().collect();
    let consent_client_id = ClientId::from(request_data.parameters.client_id.clone());
    let preferences = state
        .repos.oauth
        .get_scope_preferences(&did, &consent_client_id)
        .await
        .unwrap_or_default();
    let pref_map: std::collections::HashMap<_, _> = preferences
        .iter()
        .map(|p| (p.scope.as_str(), p.granted))
        .collect();
    let requested_scope_strings: Vec<String> =
        requested_scopes.iter().map(|s| s.to_string()).collect();
    let show_consent = should_show_consent(
        state.repos.oauth.as_ref(),
        &did,
        &consent_client_id,
        &requested_scope_strings,
    )
    .await
    .unwrap_or(true);
    let has_granular_scopes = requested_scopes.iter().any(|s| is_granular_scope(s));
    let scopes: Vec<ScopeInfo> = requested_scopes
        .iter()
        .map(|scope| {
            let (category, required, description, display_name) = if let Some(def) =
                tranquil_pds::oauth::scopes::SCOPE_DEFINITIONS.get(*scope)
            {
                let desc = if *scope == "atproto" && has_granular_scopes {
                    "AT Protocol baseline scope (permissions determined by selected options below)"
                        .to_string()
                } else {
                    def.description.to_string()
                };
                let name = if *scope == "atproto" && has_granular_scopes {
                    "AT Protocol Access".to_string()
                } else {
                    def.display_name.to_string()
                };
                (
                    def.category.display_name().to_string(),
                    def.required,
                    desc,
                    name,
                )
            } else if scope.starts_with("ref:") {
                (
                    "Reference".to_string(),
                    false,
                    "Referenced scope".to_string(),
                    scope.to_string(),
                )
            } else {
                (
                    "Other".to_string(),
                    false,
                    format!("Access to {}", scope),
                    scope.to_string(),
                )
            };
            let granted = pref_map.get(*scope).copied();
            ScopeInfo {
                scope: scope.to_string(),
                category,
                required,
                description,
                display_name,
                granted,
            }
        })
        .collect();

    let account_handle = state
        .repos.user
        .get_handle_by_did(&did)
        .await
        .ok()
        .flatten()
        .map(|h| h.to_string());

    let (is_delegation, controller_did_resp, controller_handle, delegation_level) =
        if let Some(ref ctrl_did) = controller_did_parsed {
            let ctrl_handle = state
                .repos.user
                .get_handle_by_did(ctrl_did)
                .await
                .ok()
                .flatten()
                .map(|h| h.to_string());

            let level = if let Some(ref grant) = delegation_grant {
                let preset = tranquil_pds::delegation::SCOPE_PRESETS
                    .iter()
                    .find(|p| p.scopes == grant.granted_scopes.as_str());
                preset
                    .map(|p| p.label.to_string())
                    .unwrap_or_else(|| "Custom".to_string())
            } else {
                "Unknown".to_string()
            };

            (
                Some(true),
                Some(ctrl_did.to_string()),
                ctrl_handle,
                Some(level),
            )
        } else {
            (None, None, None, None)
        };

    Json(ConsentResponse {
        request_uri: query.request_uri.clone(),
        client_id: request_data.parameters.client_id.clone(),
        client_name: client_metadata.as_ref().and_then(|m| m.client_name.clone()),
        client_uri: client_metadata.as_ref().and_then(|m| m.client_uri.clone()),
        logo_uri: client_metadata.as_ref().and_then(|m| m.logo_uri.clone()),
        scopes,
        show_consent,
        did: did.to_string(),
        handle: account_handle,
        is_delegation,
        controller_did: controller_did_resp,
        controller_handle,
        delegation_level,
    })
    .into_response()
}

pub async fn consent_post(
    State(state): State<AppState>,
    Json(form): Json<ConsentSubmit>,
) -> Response {
    tracing::info!(
        "consent_post: approved_scopes={:?}, remember={}",
        form.approved_scopes,
        form.remember
    );
    let consent_post_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .repos.oauth
        .get_authorization_request(&consent_post_request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid or expired request_uri",
            );
        }
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &format!("Database error: {:?}", e),
            );
        }
    };
    let flow_with_user = match AuthFlow::from_request_data(request_data.clone()) {
        Ok(flow) => match flow.require_user() {
            Ok(u) => u,
            Err(_) => {
                return json_error(StatusCode::FORBIDDEN, "access_denied", "Not authenticated");
            }
        },
        Err(_) => {
            let _ = state
                .repos.oauth
                .delete_authorization_request(&consent_post_request_id)
                .await;
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Authorization request has expired",
            );
        }
    };

    let did = flow_with_user.did().clone();
    let original_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .unwrap_or("atproto");

    let controller_did_parsed: Option<Did> = request_data
        .controller_did
        .as_ref()
        .and_then(|s| s.parse().ok());

    let delegation_grant = match controller_did_parsed.as_ref() {
        Some(ctrl_did) => state
            .repos.delegation
            .get_delegation(&did, ctrl_did)
            .await
            .ok()
            .flatten(),
        None => None,
    };

    let effective_scope_str = if let Some(ref grant) = delegation_grant {
        tranquil_pds::delegation::intersect_scopes(
            original_scope_str,
            grant.granted_scopes.as_str(),
        )
    } else {
        original_scope_str.to_string()
    };

    let requested_scopes: Vec<&str> = effective_scope_str.split_whitespace().collect();
    let has_granular_scopes = requested_scopes.iter().any(|s| is_granular_scope(s));
    let user_denied_some_granular = has_granular_scopes
        && requested_scopes
            .iter()
            .filter(|s| is_granular_scope(s))
            .any(|s| !form.approved_scopes.contains(&s.to_string()));
    let atproto_was_requested = requested_scopes.contains(&"atproto");
    if atproto_was_requested
        && !has_granular_scopes
        && !form.approved_scopes.contains(&"atproto".to_string())
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The atproto scope was requested and must be approved",
        );
    }
    let final_approved: Vec<String> = if user_denied_some_granular {
        form.approved_scopes
            .iter()
            .filter(|s| *s != "atproto")
            .cloned()
            .collect()
    } else {
        form.approved_scopes.clone()
    };
    if final_approved.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "At least one scope must be approved",
        );
    }
    let approved_scope_str = final_approved.join(" ");
    let has_valid_scope = final_approved.iter().all(|s| is_valid_scope(s));
    if !has_valid_scope {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid scope format",
        );
    }
    if form.remember {
        let preferences: Vec<ScopePreference> = requested_scopes
            .iter()
            .map(|s| ScopePreference {
                scope: s.to_string(),
                granted: form.approved_scopes.contains(&s.to_string()),
            })
            .collect();
        let consent_post_client_id = ClientId::from(request_data.parameters.client_id.clone());
        let _ = state
            .repos.oauth
            .upsert_scope_preferences(&did, &consent_post_client_id, &preferences)
            .await;
    }
    if let Err(e) = state
        .repos.oauth
        .update_request_scope(&consent_post_request_id, &approved_scope_str)
        .await
    {
        tracing::warn!("Failed to update request scope: {:?}", e);
    }
    let code = Code::generate();
    let consent_post_device_id = request_data
        .device_id
        .as_ref()
        .map(|d| DeviceIdType::new(d.0.clone()));
    let consent_post_code = AuthorizationCode::from(code.0.clone());
    if state
        .repos.oauth
        .update_authorization_request(
            &consent_post_request_id,
            &did,
            consent_post_device_id.as_ref(),
            &consent_post_code,
        )
        .await
        .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Failed to complete authorization",
        );
    }
    let redirect_uri = &request_data.parameters.redirect_uri;
    let intermediate_url = build_intermediate_redirect_url(
        redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.map(|m| m.as_str()),
    );
    tracing::info!(
        intermediate_url = %intermediate_url,
        client_redirect = %redirect_uri,
        "consent_post returning JSON with intermediate URL (for 303 redirect)"
    );
    Json(serde_json::json!({ "redirect_uri": intermediate_url })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct RenewRequest {
    pub request_uri: String,
}

pub async fn authorize_renew(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthAuthorizeLimit>,
    Json(form): Json<RenewRequest>,
) -> Response {
    let request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .repos.oauth
        .get_authorization_request(&request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Unknown authorization request",
            );
        }
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            );
        }
    };

    if request_data.did.is_none() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request not yet authenticated",
        );
    }

    let now = Utc::now();
    if request_data.expires_at >= now {
        return Json(serde_json::json!({
            "request_uri": form.request_uri,
            "renewed": false
        }))
        .into_response();
    }

    let staleness = now - request_data.expires_at;
    if staleness.num_seconds() > MAX_RENEWAL_STALENESS_SECONDS {
        let _ = state
            .repos.oauth
            .delete_authorization_request(&request_id)
            .await;
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request expired too long ago to renew",
        );
    }

    let new_expires_at = now + chrono::Duration::seconds(RENEW_EXPIRY_SECONDS);
    match state
        .repos.oauth
        .extend_authorization_request_expiry(&request_id, new_expires_at)
        .await
    {
        Ok(true) => Json(serde_json::json!({
            "request_uri": form.request_uri,
            "renewed": true
        }))
        .into_response(),
        Ok(false) => json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request could not be renewed",
        ),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Database error",
        ),
    }
}
